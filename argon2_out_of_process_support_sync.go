// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package secboot

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/snapcore/secboot/internal/paths"
	"golang.org/x/sys/unix"
)

// Due to the amount of memory an Argon2 KDF request comsumes, we try to serialize
// the requests system-wide to avoid triggering memory pressure. The system-wide
// lock is represented by a file in /run. A process must open this file and
// hold an exclusive advisory lock on the open file descriptor before processing
// an Argon2 KDF request. It must maintain this exclusive lock until the request
// completes, and ideally should maintain hold of the lock until the process has
// handed the memory the operation consumed back to the operating system, which is
// only guaranteed to happen once the program exits or until after a call to
// [runtime.GC].
//
// This means that processes that are handling Argon2 KDF requests should generally
// not explicitly release the lock if they actually execute the KDF, and should just
// let it be released implicitly by calling [os.Exit] and the file descriptor being
// closed as part of normal process termination.
//
// Implicit release of the lock does leave a lock file in /run. If so desired, this
// can be removed by the parent process, although the parent process would need to
// temporarily acquire the lock to do this (it could do this with a timeout of 0 to
// avoid any delays).
//
// Note the comments below wrt race conditions when removing the lock file, which
// explains why the file can only be removed by the current lock holder.
//
// Care must be taken wrt race conditions between other process or goroutines when
// removing the system-wide lock file. Eg, in between opening the system-wide lock
// file and obtaining an exlusive lock on the opened file descriptor, it's possible
// that another lock holder in another process or goroutine explicitly releases its
// lock on the same file and unlinks the system-wide lock file that we opened. In this
// case, the calling goroutine doesn't really hold the system-wide lock as nothing
// prevents another process or goroutine from taking another one by creating a new file.
// It's also possible that in-between opening the system-wide lock file and obtaining
// an exclusive lock on the opened file descriptor, another lock holder explicitly
// released its lock on the same file (unlinking the system-wide lock file that we
// opened), and another process or goroutine has since created a new file in preparation
// for taking its own lock. Again, the calling goroutine doesn't really hold the
// system-wide lock in this case because we don't hold a lock on the file that the lock
// file path currently points to, so nothing prevents multiple processes or goroutines
// from thinking that they have taken the lock. Both of these cases can be tested for by
// doing the following after acquiring an exclusive advisory lock on the open file
// descriptor for the system lock file:
// - Ensure that there is still a file at the system-wide lock file path.
// - Ensure the inode that the system-wide lock file path currently points to matches
//   the inode that we acquired an exclusive lock on.
// If either of these checks fail, the calling gorouitine does not own the system-wide
// lock and another attempt must be made to attempt to acquire it.
//
// For this to work reliably and without race conditions, the system-wide lock file must
// only be unlinked by the current lock holder.

var (
	argon2SysLockStderr                                          io.Writer = os.Stderr
	acquireArgon2OutOfProcessHandlerSystemLockAcquiredCheckpoint           = func() {}

	errArgon2OutOfProcessHandlerSystemLockTimeout = errors.New("request timeout")
)

// acquireArgon2OutOfProcessHandlerSystemLock acquires the system-wide lock
// for serializing Argon2 execution system-wide via this package. If the
// function returns with an error, then the lock was not acquired. If the
// function returns wthout an error, the returned callback can be used to
// explicitly release the lock (note that the lock will be relinquished
// automatically when the process exits too, although the lock-file won't
// be unlinked).
//
// The specified timeout determines how long this function will wait before
// aborting its attempt to acquire the lock. If set to 0, the function will
// only perform a single attempt.
func acquireArgon2OutOfProcessHandlerSystemLock(timeout time.Duration) (release func(), err error) {
	var lockFile *os.File // The opened lock file

	// Ensure that we close the open lockFile descriptor (if there is one)
	// on error paths. Note that this does leave a lock file laying around,
	// but this isn't a problem and unlinking it can only happen inside of
	// an exclusive lock without breaking the locking contract anyway.
	defer func() {
		if err == nil || lockFile == nil {
			return
		}
		if err := lockFile.Close(); err != nil {
			fmt.Fprintf(argon2SysLockStderr, "Cannot close argon2 lock file descriptor on error: %v", err)
		}
	}()

	timeoutTimer := time.NewTimer(timeout) // Begin the request timeout timer
	triedOnce := false                     // Handle the case of timeout == 0

	// Run a loop to try to acquire the lock.
	for {
		skipBackoffCh := make(chan struct{}, 1) // Don't wait 100ms before trying again
		if triedOnce {
			// If the loop has executed at least once, make sure that
			// the timeout hasn't expired.
			select {
			case <-timeoutTimer.C:
				// The timeout has expired.
				return nil, errArgon2OutOfProcessHandlerSystemLockTimeout
			case <-skipBackoffCh:
				// continue trying without waiting
			case <-time.NewTimer(100 * time.Millisecond).C:
				// Wait for 100ms before trying again
			}
		}
		triedOnce = true

		// Make sure that we close the lock file left open from the previous
		// attempt, if there is one. Note that this does leave a lock file
		// laying around, but this isn't a problem and unlinking it can only
		// happen inside of an exclusive lock without breaking the locking
		// contract anyway.
		if lockFile != nil {
			if err := lockFile.Close(); err != nil {
				return nil, fmt.Errorf("cannot close lock file from previous attempt before starting new attempt: %w", err)
			}
		}

		// Attempt to open the lock file for writing.
		lockFile, err = os.OpenFile(paths.Argon2OutOfProcessHandlerSystemLockPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			// No error is expected here.
			return nil, fmt.Errorf("cannot open lock file for writing: %w", err)
		}

		// Grab information about the lock file we just opened, via its descriptor.
		var lockFileSt unix.Stat_t
		if err := unix.Fstat(int(lockFile.Fd()), &lockFileSt); err != nil {
			// No error is expected here
			return nil, fmt.Errorf("cannot obtain lock file info from open descriptor: %w", err)
		}

		// Make sure we have opened a regular file
		if lockFileSt.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return nil, errors.New("opened lock file is not a regular file")
		}

		// Attempt to acquire an exclusive, non-blocking, advisory lock.
		if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			// We failed to acquire the lock.
			if os.IsTimeout(err) {
				// The EWOULDBLOCK case. Someone else already has a lock on the
				// file we have opened. Try again with a 100ms backoff time.
				continue
			}

			// No other error is expected.
			return nil, fmt.Errorf("cannot obtain lock on open lock file descriptor: %w", err)
		}

		// This is useful for blocking the function here in unit tests
		acquireArgon2OutOfProcessHandlerSystemLockAcquiredCheckpoint()

		// We have acquired an exclusive advisory lock on the file that we opened, but perform
		// some checks to ensure we haven't hit a race condition with another process.

		// Grab information about the inode that the lock file path currently points to.
		// It's possible that in the window between opening the lock file and taking
		// the exclusive lock on the open descriptor, another process might have released
		// its own lock on the file we opened, unlinking the path in the meantime.
		var updatedSt unix.Stat_t
		if err := unix.Stat(paths.Argon2OutOfProcessHandlerSystemLockPath, &updatedSt); err != nil {
			if os.IsNotExist(err) {
				// The lock file path no longer exists because it was unlinked by
				// another process. Try again immediately.
				skipBackoffCh <- struct{}{}
				continue
			}

			// No other error is expected.
			return nil, fmt.Errorf("cannot obtain lock file info from path: %w", err)
		}

		// Make sure that the inode we have an exclusive lock on is the same inode that
		// the lock file path currently points to. It's possible that in the window between
		// opening the lock file and acquiring the exclusive lock, another process might have
		// released its own lock on the same file we opened - unlinking the path in the meantime,
		// and another process has since created a new file in order to try to acquire its own
		// lock. Note that as part of the lock contract, the system-wide lock file path must
		// only be unlinked inside an exclusive lock - a process cannot unlink it it doesn't have
		// the lock or relinquishes it momentarily - in which case, it would need to perform the
		// same steps to re-acquire it again in a non-racey way.
		if lockFileSt.Ino == updatedSt.Ino {
			// At this point, we hold the system-wide lock, so break out of the loop.
			break
		}

		// The inode that we have a lock on is not the same one that the lock file
		// path currently points to, so nothing is stopping another process from acquiring
		// a lock. We should try again immediately.
		skipBackoffCh <- struct{}{}
	}

	if lockFile == nil {
		// This shouldn't happen. The loop either returns from the function immediately
		// on error or breaks only once we have the lock.
		panic("locking loop finished without leaving an open lock file descriptor")
	}

	release = func() {
		if lockFile == nil {
			// Handle being called more than once
			return
		}

		// We can remove the lock file because we still have an exclusive lock on it
		unlinkErr := os.Remove(paths.Argon2OutOfProcessHandlerSystemLockPath)
		if unlinkErr != nil {
			// Log a message if it fails - it just means that we leave the lock
			// file laying around which isn't really a problem in /run. We will
			// still carry on to release the lock by closing the descriptor.
			fmt.Fprintf(argon2SysLockStderr, "Cannot unlink argon2 lock file: %v\n", unlinkErr)
		}

		// If the lock file was successfully unlinked, another process is free to
		// acquire the lock now.

		// Closing the open descriptor will release our exclusive advisory lock. If the
		// previous unlink succeeded, only proceeses that already have a descriptor open
		// to it can acquire a lock on it. They will only do this temporarily though
		// because they will detect that the lock file path no longer exists, or exists
		// but points to a different inode (if another process recreates it).
		closeErr := lockFile.Close()
		if closeErr != nil {
			fmt.Fprintf(argon2SysLockStderr, "Cannot close argon2 lock file descriptor: %v", closeErr)
		}

		switch {
		case unlinkErr != nil && closeErr != nil:
			fmt.Fprintf(argon2SysLockStderr, "Releasing the Argon2 system lock failed\n")
		case unlinkErr == nil || closeErr == nil:
			// The lock has been successfully released
			lockFile = nil
		}
	}

	return release, nil
}
