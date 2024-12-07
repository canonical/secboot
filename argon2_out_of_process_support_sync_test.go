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

package secboot_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"
)

type argon2OutOfProcessSupportSyncSuite struct {
	lockPath        string
	restoreLockPath func()
}

func (s *argon2OutOfProcessSupportSyncSuite) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_ARGON2_TESTS"); exists {
		c.Skip("skipping expensive argon2 tests")
	}
}

func (s *argon2OutOfProcessSupportSyncSuite) SetUpTest(c *C) {
	s.lockPath = filepath.Join(c.MkDir(), "argon2.lock")
	s.restoreLockPath = MockArgon2OutOfProcessHandlerSystemLockPath(s.lockPath)
}

func (s *argon2OutOfProcessSupportSyncSuite) TearDownTest(c *C) {
	if s.restoreLockPath != nil {
		s.restoreLockPath()
	}
}

var _ = Suite(&argon2OutOfProcessSupportSyncSuite{})

func (s *argon2OutOfProcessSupportSyncSuite) TestAcquireAndReleaseArgon2OutOfProcessHandlerSystemLock(c *C) {
	release, err := AcquireArgon2OutOfProcessHandlerSystemLock(0)
	c.Assert(err, IsNil)
	defer release()

	f, err := os.OpenFile(s.lockPath, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, `resource temporarily unavailable`)
	c.Check(errors.Is(err, syscall.Errno(syscall.EWOULDBLOCK)), testutil.IsTrue)

	release()
	_, err = os.Stat(s.lockPath)
	c.Check(os.IsNotExist(err), testutil.IsTrue)
}

func (s *argon2OutOfProcessSupportSyncSuite) TestAcquireAndReleaseArgon2OutOfProcessHandlerSystemLockTimeout(c *C) {
	// Note that this test could potentially deadlock if the timeout
	// functionality is broken.
	release, err := AcquireArgon2OutOfProcessHandlerSystemLock(0)
	c.Assert(err, IsNil)
	defer release()

	_, err = AcquireArgon2OutOfProcessHandlerSystemLock(1 * time.Second)
	c.Check(err, Equals, ErrArgon2OutOfProcessHandlerSystemLockTimeout)
}

func (s *argon2OutOfProcessSupportSyncSuite) TestAcquireAndReleaseArgon2OutOfProcessHandlerSystemLockDeletedFile(c *C) {
	loopedOnce := false
	restore := MockAcquireArgon2OutOfProcessHandlerSystemLockAcquiredCheckpoint(func() {
		if loopedOnce {
			return
		}
		loopedOnce = true
		c.Check(os.Remove(s.lockPath), IsNil)
	})
	defer restore()

	release, err := AcquireArgon2OutOfProcessHandlerSystemLock(10 * time.Second)
	c.Assert(err, IsNil)
	defer release()

	c.Check(loopedOnce, testutil.IsTrue)

	f, err := os.OpenFile(s.lockPath, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, `resource temporarily unavailable`)
	c.Check(errors.Is(err, syscall.Errno(syscall.EWOULDBLOCK)), testutil.IsTrue)

	release()
	_, err = os.Stat(s.lockPath)
	c.Check(os.IsNotExist(err), testutil.IsTrue)
}

func (s *argon2OutOfProcessSupportSyncSuite) TestAcquireAndReleaseArgon2OutOfProcessHandlerSystemLockChangedInode(c *C) {
	loopedOnce := false
	restore := MockAcquireArgon2OutOfProcessHandlerSystemLockAcquiredCheckpoint(func() {
		if loopedOnce {
			return
		}
		loopedOnce = true
		c.Check(os.Remove(s.lockPath), IsNil)
		f, err := os.OpenFile(s.lockPath, os.O_RDWR|os.O_CREATE, 0600)
		c.Assert(err, IsNil)
		c.Check(f.Close(), IsNil)
	})
	defer restore()

	release, err := AcquireArgon2OutOfProcessHandlerSystemLock(10 * time.Second)
	c.Assert(err, IsNil)
	defer release()

	c.Check(loopedOnce, testutil.IsTrue)

	f, err := os.OpenFile(s.lockPath, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, `resource temporarily unavailable`)
	c.Check(errors.Is(err, syscall.Errno(syscall.EWOULDBLOCK)), testutil.IsTrue)

	release()
	_, err = os.Stat(s.lockPath)
	c.Check(os.IsNotExist(err), testutil.IsTrue)
}

func (s *argon2OutOfProcessSupportSyncSuite) TestAcquireAndReleaseArgon2OutOfProcessHandlerSystemLockMultipleLoops(c *C) {
	loopCount := 0
	restore := MockAcquireArgon2OutOfProcessHandlerSystemLockAcquiredCheckpoint(func() {
		loopCount += 1
		switch loopCount {
		case 1, 3:
			c.Check(os.Remove(s.lockPath), IsNil)
		case 2, 4:
			c.Check(os.Remove(s.lockPath), IsNil)
			f, err := os.OpenFile(s.lockPath, os.O_RDWR|os.O_CREATE, 0600)
			c.Assert(err, IsNil)
			c.Check(f.Close(), IsNil)
		}
	})
	defer restore()

	release, err := AcquireArgon2OutOfProcessHandlerSystemLock(10 * time.Second)
	c.Assert(err, IsNil)
	defer release()

	f, err := os.OpenFile(s.lockPath, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, `resource temporarily unavailable`)
	c.Check(errors.Is(err, syscall.Errno(syscall.EWOULDBLOCK)), testutil.IsTrue)

	release()
	_, err = os.Stat(s.lockPath)
	c.Check(os.IsNotExist(err), testutil.IsTrue)
}
