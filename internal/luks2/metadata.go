// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package luks2

import (
	"bytes"
	"context"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/snapcore/secboot/internal/paths"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

var (
	dataDeviceFstat = unix.Fstat
)

func cryptsetupLockDir() string {
	return filepath.Join(paths.RunDir, "cryptsetup")
}

var isBlockDevice = func(mode os.FileMode) bool {
	return mode&os.ModeDevice > 0 && mode&os.ModeCharDevice == 0
}

// acquireSharedLock acquires an advisory shared lock on the LUKS volume associated with the
// specified path. The path can either be a block device or file containing a LUKS2 volume with
// an integral header, or a detached header file associated with a LUKS device.
//
// If the supplied context cannot be canceled or cannot expire, then this function may block
// forever.
//
// A shared lock is for read-only access. There can be multiple parallel shared lock holders.
// Shared and exclusive locks are mutually exclusive, and there can only ever be a single
// exclusive lock acqired at any time.
//
// This function does not provide a way to acquire an advisory exclusive lock - this would only
// be required if we add functionality that performs writes to the LUKS header without delegating
// this to the cryptsetup binary or libcryptsetup via cgo.
//
// This function implements the locking logic implemented by libcryptsetup - see
// lib/utils_device_locking.c from the cryptsetup source code (tag:v2.3.1).
//
// On success, a callback is returned which should be called to release the lock. If it
// doesn't acquire a lock before the supplied context is canceled or expires, the reason
// is returned as an error.
func acquireSharedLock(ctx context.Context, path string) (release func(), err error) {
	// Initially open the device or file for reading.
	f, err := os.Open(path)
	if err != nil {
		switch e := err.(type) {
		case *os.PathError:
			// Make it possible to distinguish this open for reading vs the
			// future open for writing.
			e.Err = fmt.Errorf("whilst opening data device or file for reading: %w", e.Err)
			return nil, e
		default:
			// We shouldn't really hit this because os.Open should only return *os.PathError.
			return nil, fmt.Errorf("cannot open data device or file %s for reading: %w", path, err)
		}
	}
	defer f.Close()

	// Obtain information about the opened device or file.
	fi, err := f.Stat()
	if err != nil {
		// This should only be *os.PathError, so not much need for us to add context.
		return nil, err
	}

	var lockPath string
	var openFlags int

	switch {
	case isBlockDevice(fi.Mode()):
		// For block devices, libcryptsetup uses an advisory lock on a file in /run/cryptsetup.
		// The lock file filename is of the format "L_<major>:<minor>".

		// Don't assume that the lock directory exists.
		if err := os.Mkdir(cryptsetupLockDir(), 0700); err != nil && !os.IsExist(err) {
			// This should only be *os.PathError, so not much need for us to add context.
			return nil, err
		}

		// Obtain information about the opened block device using the fstat syscall,
		// where we get more information.
		//
		// XXX: do we need the call to unix.Fstat in this case? Can't we obtain a
		// *syscall.Stat_t from the implementaton of os.FileInfo.Sys that was returned
		// earlier for this opened file?
		sc, err := f.SyscallConn()
		if err != nil {
			return nil, fmt.Errorf("cannot obtain syscall.RawConn implementation for data device or file %s: %w", f.Name(), err)
		}

		var st unix.Stat_t
		if cErr := sc.Control(func(fd uintptr) {
			if e := dataDeviceFstat(int(fd), &st); e != nil {
				err = &os.PathError{Op: "raw-fstat", Path: f.Name(), Err: e}
			}
		}); cErr != nil {
			return nil, fmt.Errorf("cannot complete syscall.RawConn.Control call on data device or file %s: %w", f.Name(), cErr)
		}
		if err != nil {
			// unix.Fstat failed.
			return nil, err
		}
		lockPath = filepath.Join(cryptsetupLockDir(), fmt.Sprintf("L_%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev)))
		openFlags = os.O_RDWR | os.O_CREATE
	case fi.Mode().IsRegular():
		// For regular files, libcryptsetup uses an advisory lock directly on the file.
		lockPath = path
		openFlags = os.O_RDWR
	default:
		return nil, errors.New("unsupported file type")
	}

	var lockFile *os.File
	var origSt unix.Stat_t

	// Define a mechanism to release the lock.
	internalRelease := func() {
		// Ensure multiple calls are benign
		if lockFile == nil {
			return
		}

		sc, err := lockFile.SyscallConn()
		if err != nil {
			fmt.Fprintf(stderr, "luks2.acquireSharedLock release: cannot obtain syscall.RawConn implementation for lock file %s: %v", lockFile.Name(), err)
			return
		}

		// Release the shared lock
		if cErr := sc.Control(func(fd uintptr) {
			if e := unix.Flock(int(fd), unix.LOCK_UN); e != nil {
				fmt.Fprintf(stderr, "luks2.acquireSharedLock release: %v\n", &os.PathError{Op: "raw-flock(un)", Path: lockFile.Name(), Err: e})
			}
		}); cErr != nil {
			fmt.Fprintf(stderr, "luks2.acquireSharedLock release: cannot perform control action on locked lock file FD: %v\n", cErr)
		}
		defer func() {
			// Ensure that the lock file is closed and cleared when the function exits.
			lockFile.Close()
			lockFile = nil
		}()

		if !isBlockDevice(fi.Mode()) {
			// If we didn't lock a block device, then we are finished now.
			return
		}

		// If we locked a block device then we need to clean up the lock file, being careful
		// not to race with potential new lock owners.

		// Although this function only supports shared locks for read-only access (where an
		// implementation bug might cause data inconsistency issues in the decoded data but
		// doesn't lead to data loss), the following code is responsible for cleaning up the
		// lock file on release. This is carefully implemented using the same steps as
		// libcryptsetup to avoid racing with other lock holders, some of whom could be
		// exclusive lock holders. Implementation bugs here that result in us unlinking a
		// lock file that another processes has an exclusive lock on could result in data
		// loss - please be careful when changing any of the code below.

		// The lock file should only be cleaned up if we can get an exclusive lock on the
		// inode we originally opened, and the lock file path still points to this inode.

		// First of all, attempt to acquire an exclusive lock on the same inode we had a lock
		// on previously, without blocking.
		hasExclusiveLock := false
		if cErr := sc.Control(func(fd uintptr) {
			if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				// We failed to acquire an exclusive lock. Only log the error in the case
				// where the error isn't EWOULDBLOCK, as this is not an unexpected error.
				if errno, ok := err.(syscall.Errno); !ok || errno != syscall.EWOULDBLOCK {
					fmt.Fprintf(stderr, "luks2.acquireSharedLock release: %v\n", &os.PathError{Op: "raw-flock(ex|nb)", Path: lockFile.Name(), Err: err})
				}
				return
			}
			hasExclusiveLock = true
		}); cErr != nil {
			fmt.Fprintf(stderr, "luks2.acquireSharedLock release: cannot perform control action on unlocked lock file FD: %v\n", err)
		}

		if !hasExclusiveLock {
			// We can't acquire an exclusive lock on the inode we originally had a lock
			// on. This means that another process has acquired a lock on it since we
			// released the shared lock. There's nothing else for us to do - the new
			// lock owner is now responsible for cleaning up the lock file.
			return
		}

		// We've got an exclusive lock on the inode we originally opened and locked.
		// Obtain the information about the inode currently at the lock file path.
		var st unix.Stat_t
		if err := unix.Stat(lockPath, &st); err != nil {
			if errno, ok := err.(syscall.Errno); !ok || errno != syscall.ENOENT {
				fmt.Fprintf(stderr, "luks2.acquireSharedLock release: %v\n", &os.PathError{Op: "stat", Path: lockPath, Err: err})
			}
			// The lock file we opened has been cleaned up by another process, which acquired
			// and released it in between us releasing the lock at the start of this function,
			// and then acquiring an exclusive lock again. There's nothing else for us to do.
			return
		}
		if origSt.Ino != st.Ino {
			// The inode at the lock file path is different to the one we opened. The lock file
			// has been cleaned up by another process, which acquired and released it in between
			// us releasing the lock at the start of this function, and then acquiring an
			// exclusive lock again. Another process has since created a new lock file. There's
			// nothing else for us to do - the new process is responsible for cleaning up the new
			// lock file. Erasing this lock file would create a potentially dangerous race condition.
			return
		}

		// The lock file path still points to the inode that we originally opened and locked, and we
		// have an exclusive lock on it again. As other processes participating in locking require
		// an exclusive lock for cleaning it up, it os now safe to unlink it.
		if err := os.Remove(lockPath); err != nil {
			fmt.Fprintf(stderr, "luks2.acquireSharedLock release: %v\n", err)
		}
	}

	defer func() {
		if err == nil {
			return
		}

		// Make sure the lock is released if we return an error.
		internalRelease()
	}()

	// Loop whilst the context is active.
	for ctx.Err() == nil {
		// Attempt to open the lock file for writing.
		lockFile, err = os.OpenFile(lockPath, openFlags, 0600)
		if err != nil {
			switch e := err.(type) {
			case *os.PathError:
				// Make it possible to distinguish this open for writing vs the
				// previous open for reading.
				e.Err = fmt.Errorf("whilst opening lock file for writing: %w", e.Err)
				return nil, e
			default:
				// We shouldn't really hit this because os.Open should only return *os.PathError.
				return nil, fmt.Errorf("cannot open lock file %s for writing: %w", lockPath, err)
			}
		}

		// XXX: do we need the direct call to unix.Fstat in this case? Can't we obtain and
		// use a *syscall.Stat_t from the implementaton of os.FileInfo.Sys that can be obtained
		// by calling os.File.Stat on lockFile?
		sc, err := lockFile.SyscallConn()
		if err != nil {
			return nil, fmt.Errorf("cannot obtain syscall.RawConn implementation for lock file %s: %w", lockFile.Name(), err)
		}

		if cErr := sc.Control(func(fd uintptr) {
			// Obtain and save information about the opened lock file.
			if e := unix.Fstat(int(fd), &origSt); e != nil {
				err = &os.PathError{Op: "raw-fstat", Path: lockFile.Name(), Err: e}
			}
		}); cErr != nil {
			return nil, fmt.Errorf("cannot complete syscall.RawConn.Control call on unlocked lock file %s: %w", lockFile.Name(), cErr)
		}
		if err != nil {
			// unix.Fstat failed.
			return nil, err
		}

		// Attempt to acquire the requested lock in non-blocking mode in a loop as there is no
		// way for us to unblock a blocking flock call if the supplied context is canceled
		// or expires. We introduce some randomness to the retry timeout.
		for {
			if cErr := sc.Control(func(fd uintptr) {
				err = unix.Flock(int(fd), unix.LOCK_SH|unix.LOCK_NB)
			}); cErr != nil {
				return nil, fmt.Errorf("cannot complete syscall.RawConn.Control call on unlocked lock file %s: %w", lockFile.Name(), cErr)
			}
			if err == nil {
				// We have acquired the lock
				break
			}
			if errno, ok := err.(syscall.Errno); !ok || errno != syscall.EWOULDBLOCK {
				// We failed to acquire the lock for an unexpected reason.
				return nil, &os.PathError{Op: "raw-flock(sh)", Path: lockFile.Name(), Err: err}
			}

			// Have another go with a pseudorandom delay between 5ms and 100ms,
			// or until the context is canceled or expires.
			n := rand.Intn(95)
			select {
			case <-time.After((time.Millisecond * time.Duration(n)) + (time.Millisecond * 5)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// We have acquired the lock at this point.

		if isBlockDevice(fi.Mode()) {
			// If we are attempting to acquire a lock on a block device, make sure that we
			// aren't racing with a previous lock holder or a new lock holder.
			//
			// Obtain information about the inode that the lock file path currently points to.
			//
			// XXX: do we need the direct call to unix.Stat in this case? Can't we obtain and
			// use a *syscall.Stat_t from the implementaton of os.FileInfo.Sys that can be
			// obtained by calling os.Stat with lockPath?
			var st unix.Stat_t
			if err := unix.Stat(lockPath, &st); err != nil {
				// The lock file we opened was unlinked by another lock owner between us
				// opening the file and acquiring the lock. We need to try again.
				internalRelease()
				continue
			}

			if origSt.Ino != st.Ino {
				// The lock file we opened was unlinked by another lock owner between us
				// opening the file and acquiring the lock, and another process has created a
				// new lock file. We need to try again.
				internalRelease()
				continue
			}

			// The lock file path still points to the inode that we opened and have a shared lock
			// on. As applications participating in locking require an exclusive lock to unlink it,
			// we know that we have a lock on the inode linked from the lock file path.
		}

		// We've successfully acquired the requested lock - return the release callback.
		return internalRelease, nil
	}

	return nil, ctx.Err()
}

// KDFType corresponds to a key derivation function.
type KDFType string

const (
	KDFTypePBKDF2   KDFType = "pbkdf2"
	KDFTypeArgon2i  KDFType = "argon2i"
	KDFTypeArgon2id KDFType = "argon2id"
)

// Hash corresponds to a cryptpgraphic digest algorithm.
type Hash string

const (
	HashSHA1   Hash = "sha1"
	HashSHA224 Hash = "sha224"
	HashSHA256 Hash = "sha256"
	HashSHA384 Hash = "sha384"
	HashSHA512 Hash = "sha512"
)

func (h Hash) GetHash() crypto.Hash {
	switch h {
	case HashSHA1:
		return crypto.SHA1
	case HashSHA224:
		return crypto.SHA224
	case HashSHA256:
		return crypto.SHA256
	case HashSHA384:
		return crypto.SHA384
	case HashSHA512:
		return crypto.SHA512
	default:
		return 0
	}
}

// KeyslotType corresponds to the type of a keyslot.
type KeyslotType string

const (
	KeyslotTypeLUKS2 KeyslotType = "luks2"
)

type TokenType string

const (
	TokenTypeKeyring TokenType = "luks2-keyring"
)

// AFType corresponds to an anti-forensic splitter algorithm.
type AFType string

const (
	AFTypeLUKS1 AFType = "luks1"
)

// AreaType corresponds to the type of a storage area in the binary
// keyslots area.
type AreaType string

const (
	AreaTypeRaw AreaType = "raw"
)

type label [48]byte

func (l label) String() string {
	return strings.TrimRight(string(l[:]), "\x00")
}

type csumAlg [32]byte

func (a csumAlg) GetHash() crypto.Hash {
	return Hash(strings.TrimRight(string(a[:]), "\x00")).GetHash()
}

type binaryHdr struct {
	Magic       [6]byte
	Version     uint16
	HdrSize     uint64
	SeqId       uint64
	Label       label
	CsumAlg     csumAlg
	Salt        [64]byte
	Uuid        [40]byte
	Subsystem   [48]byte
	HdrOffset   uint64
	Padding     [184]byte
	Csum        [64]byte
	Padding4096 [7 * 512]byte
}

// JsonNumber represents a JSON number literal. It is similar to
// json.Number but supports uint64 and int literals as required by
// the LUKS2 specification.
type JsonNumber string

func (n JsonNumber) Int() (int, error) {
	return strconv.Atoi(string(n))
}

func (n JsonNumber) Uint64() (uint64, error) {
	return strconv.ParseUint(string(n), 10, 64)
}

// Requirements corresponds to the requirements object in the JSON metadata of
// a LUKS2 volume.
type Requirements struct {
	Mandatory []string // mandatory requirements. This is the only field currently defined by cryptsetup
}

// Config corresponds to a config object in the JSON metadata of a LUKS2 volume.
type Config struct {
	JSONSize     uint64        // Size of the JSON area, in bytes
	KeyslotsSize uint64        // Size of the keyslots area, in bytes
	Flags        []string      // Optional flags
	Requirements *Requirements // Optional required features
}

func (c *Config) UnmarshalJSON(data []byte) error {
	var d struct {
		JSONSize     JsonNumber `json:"json_size"`
		KeyslotsSize JsonNumber `json:"keyslots_size"`
		Flags        []string

		// The LUKS2 on disk header format defines this as an array of strings, but it has
		// always been implemented in cryptsetup as an object:
		// See https://gitlab.com/cryptsetup/cryptsetup/-/blob/v2.0.0/lib/luks2/luks2_json_metadata.c?ref_type=tags#L1281
		Requirements *Requirements
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	*c = Config{
		Flags:        d.Flags,
		Requirements: d.Requirements}
	jsonSize, err := d.JSONSize.Uint64()
	if err != nil {
		return xerrors.Errorf("invalid json_size value: %w", err)
	}
	c.JSONSize = jsonSize

	keyslotsSize, err := d.KeyslotsSize.Uint64()
	if err != nil {
		return xerrors.Errorf("invalid keyslots_size value: %w", err)
	}
	c.KeyslotsSize = keyslotsSize

	return nil
}

type rawToken struct {
	typ  TokenType
	data []byte
}

func (t *rawToken) UnmarshalJSON(data []byte) error {
	var d struct {
		Type TokenType
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	t.typ = d.Type
	t.data = data
	return nil
}

// Token corresponds to a token object in the JSON metadata of a LUKS2 volume. It
// describes how to retrieve a passphrase or key for a keyslot. Tokens decoded by
// ReadHeader will be represented by a type-specific implementation if a
// TokenDecoder is registered for it, or GenericToken.
type Token interface {
	Type() TokenType // Token type ("luks2-" prefixed types are reserved for cryptsetup)
	Keyslots() []int // Keyslots assigned to this token
}

// TokenDecoder provides a mechanism for an external package to decode
// custom token types.
type TokenDecoder func([]byte) (Token, error)

var tokenDecoders = make(map[TokenType]TokenDecoder)

// GenericToken corresponds to a token that doesn't have a more type-specific
// representation.
type GenericToken struct {
	TokenType     TokenType              // Token type ("luks2-" prefixed types are reserved for cryptsetup)
	TokenKeyslots []int                  // Keyslots assigned to this token
	Params        map[string]interface{} // Type-specific parameters for this token
}

func (t *GenericToken) Type() TokenType {
	return t.TokenType
}

func (t *GenericToken) Keyslots() []int {
	return t.TokenKeyslots
}

func (t *GenericToken) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	for k, v := range t.Params {
		m[k] = v
	}

	m["type"] = t.TokenType

	var keyslots []JsonNumber
	for _, s := range t.TokenKeyslots {
		keyslots = append(keyslots, JsonNumber(strconv.Itoa(s)))
	}
	m["keyslots"] = keyslots

	return json.Marshal(m)
}

func (t *GenericToken) UnmarshalJSON(data []byte) error {
	var d struct {
		Type     TokenType
		Keyslots []JsonNumber
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	t.TokenType = d.Type
	for _, v := range d.Keyslots {
		s, err := v.Int()
		if err != nil {
			return xerrors.Errorf("invalid keyslot id: %w", err)
		}
		t.TokenKeyslots = append(t.TokenKeyslots, s)
	}

	t.Params = make(map[string]interface{})
	if err := json.Unmarshal(data, &t.Params); err != nil {
		return err
	}
	delete(t.Params, "type")
	delete(t.Params, "keyslots")

	return nil
}

// Digest corresponds to a digest object in the JSON metadata area of a LUKS2 volume,
// and provides a way to verify that a key decrypted from a keyslot is correct. It
// also links keyslots to their corresponding segments.
type Digest struct {
	Type       KDFType // Digest type
	Keyslots   []int   // The keyslots assigned to this digest
	Segments   []int   // The segments assigned to this digest
	Salt       []byte  // Salt for this digest
	Digest     []byte  // The actual digest
	Hash       Hash    // Hash algorithm (pbkdf2 only)
	Iterations int     // The number of iterations (pbkdf2 only)
}

func (d *Digest) UnmarshalJSON(data []byte) error {
	var t struct {
		Type       KDFType
		Keyslots   []JsonNumber
		Segments   []JsonNumber
		Salt       []byte
		Digest     []byte
		Hash       Hash
		Iterations int
	}
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}

	*d = Digest{
		Type:       t.Type,
		Salt:       t.Salt,
		Digest:     t.Digest,
		Hash:       t.Hash,
		Iterations: t.Iterations}

	for _, v := range t.Keyslots {
		s, err := v.Int()
		if err != nil {
			return xerrors.Errorf("invalid keyslot id: %w", err)
		}
		d.Keyslots = append(d.Keyslots, s)
	}

	for _, v := range t.Segments {
		s, err := v.Int()
		if err != nil {
			return xerrors.Errorf("invalid segment id: %w", err)
		}
		d.Segments = append(d.Segments, s)
	}

	return nil
}

// Integrity corresponds to an integrity object in the JSON metadata of a LUKS2 volume,
// and details the data integrity parameters for a segment.
type Integrity struct {
	Type              string // Integirty type in dm-crypt notation
	JournalEncryption string `json:"journal_encryption"`
	JournalIntegrity  string `json:"journal_integrity"`
}

// Segment corresponds to a segment object in the JSON metadata of a LUKS2 volume,
// and details an encrypted area on disk.
type Segment struct {
	Type        string
	Offset      uint64     // Offset from the device start to the beginning of this segment, in bytes
	Size        uint64     // Size of this segment, in bytes (only if DynamicSize is false)
	DynamicSize bool       // The size is the size of the underlying device
	IVTweak     uint64     // The starting offset of the IV tweak
	Encryption  string     // The encryption algorithm for this segment in dm-crypt notation
	SectorSize  uint32     // The sector size for this segment, in bytes
	Integrity   *Integrity // Data integrity parameters for this segment (optional)
	Flags       []string   // Additional options for this segment
}

func (s *Segment) UnmarshalJSON(data []byte) error {
	var d struct {
		Type       string
		Offset     JsonNumber
		Size       JsonNumber
		IVTweak    JsonNumber `json:"iv_tweak"`
		Encryption string
		SectorSize uint32 `json:"sector_size"`
		Integrity  *Integrity
		Flags      []string
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	*s = Segment{
		Type:       d.Type,
		Encryption: d.Encryption,
		SectorSize: d.SectorSize,
		Integrity:  d.Integrity,
		Flags:      d.Flags}

	offset, err := d.Offset.Uint64()
	if err != nil {
		return xerrors.Errorf("invalid offset value: %w", err)
	}
	s.Offset = offset

	switch string(d.Size) {
	case "dynamic":
		s.DynamicSize = true
	default:
		sz, err := d.Size.Uint64()
		if err != nil {
			return xerrors.Errorf("invalid size value: %w", err)
		}
		s.Size = sz
	}

	ivTweak, err := d.IVTweak.Uint64()
	if err != nil {
		return xerrors.Errorf("invalid iv_tweak value: %w", err)
	}
	s.IVTweak = ivTweak

	return nil
}

// Area corresponds to an area object in the JSON metadata of a LUKS2 volume, and
// details the parameters for the storage area in the binary keyslots area for a
// keyslot.
type Area struct {
	Type       AreaType
	Offset     uint64 // Offset from the device start to the beginning of this area, in bytes
	Size       uint64 // Size of this area in bytes
	Encryption string // Encryption algorithm used for this area in dm-crypt notation
	KeySize    int    // The size of the encryption key for this area, in bytes
}

func (a *Area) UnmarshalJSON(data []byte) error {
	var d struct {
		Type       AreaType
		Offset     JsonNumber
		Size       JsonNumber
		Encryption string
		KeySize    int `json:"key_size"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	*a = Area{
		Type:       d.Type,
		Encryption: d.Encryption,
		KeySize:    d.KeySize}

	offset, err := d.Offset.Uint64()
	if err != nil {
		return xerrors.Errorf("invalid offset value: %w", err)
	}
	a.Offset = offset

	sz, err := d.Size.Uint64()
	if err != nil {
		return xerrors.Errorf("invalid size value: %w", err)
	}
	a.Size = sz

	return nil
}

// AF correspnds to an af object in the JSON metadata of a LUKS2 volume, and details
// the anti-forensic splitter parameters for a keyslot.
type AF struct {
	Type    AFType
	Stripes int  // Number of stripes
	Hash    Hash // Hash algorith.
}

// KDF corresponds to a kdf object in the JSON metadata of a LUKS2 volume, and details
// the KDF parameters for a keyslot.
type KDF struct {
	Type       KDFType // KDF type (pbkdf2, argon2i or argon2id)
	Salt       []byte  // Salt for the KDF
	Hash       Hash    // Hash algorithm (pbkdf2 only)
	Iterations int     // Number of iterations (pbkdf2 only)
	Time       int     // Number of iterations (argon2 only)
	Memory     int     // Memory cost in kB (argon2 only)
	CPUs       int     // Number of threads (argon2 only)
}

// Keyslot corresponds to a keyslot object in the JSON metadata of a LUKS2 volume, and
// contains information about a stored protected key.
type Keyslot struct {
	Type     KeyslotType
	KeySize  int          // The size of the key protected by this keyslot, in bytes
	Area     *Area        // The allocated area in the keyslots area
	KDF      *KDF         // The KDF parameters used for this keyslot
	AF       *AF          // The anti-forensic splitter parameters used for this keyslot
	Priority SlotPriority // Priority of this keyslot (0:ignore, 1:normal, 2:high)
}

func (s *Keyslot) UnmarshalJSON(data []byte) error {
	var d struct {
		Type     KeyslotType
		KeySize  int `json:"key_size"`
		Area     *Area
		KDF      *KDF
		AF       *AF
		Priority *int
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	*s = Keyslot{
		Type:    d.Type,
		KeySize: d.KeySize,
		Area:    d.Area,
		KDF:     d.KDF,
		AF:      d.AF}
	if d.Priority != nil {
		s.Priority = SlotPriority(*d.Priority)
	} else {
		s.Priority = SlotPriorityNormal
	}
	return nil
}

// Metadata corresponds to the top level object in the JSON metadata area of a LUKS2 volume.
type Metadata struct {
	Keyslots map[int]*Keyslot // Keyslot objects
	Segments map[int]*Segment // Segment objects
	Digests  map[int]*Digest  // Digest objects
	Tokens   map[int]Token    // Token objects
	Config   Config           // Config object
}

func (m *Metadata) UnmarshalJSON(data []byte) error {
	var d struct {
		Keyslots map[JsonNumber]*Keyslot
		Segments map[JsonNumber]*Segment
		Digests  map[JsonNumber]*Digest
		Tokens   map[JsonNumber]*rawToken
		Config   Config
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	m.Keyslots = make(map[int]*Keyslot)
	for k, v := range d.Keyslots {
		id, err := k.Int()
		if err != nil {
			return xerrors.Errorf("invalid keyslot index: %w", err)
		}
		m.Keyslots[id] = v
	}

	m.Segments = make(map[int]*Segment)
	for k, v := range d.Segments {
		id, err := k.Int()
		if err != nil {
			return xerrors.Errorf("invalid segment index: %w", err)
		}
		m.Segments[id] = v
	}

	m.Digests = make(map[int]*Digest)
	for k, v := range d.Digests {
		id, err := k.Int()
		if err != nil {
			return xerrors.Errorf("invalid digest index: %w", err)
		}
		m.Digests[id] = v
	}

	m.Tokens = make(map[int]Token)
	for k, v := range d.Tokens {
		id, err := k.Int()
		if err != nil {
			return xerrors.Errorf("invalid token index: %w", err)
		}
		var token Token
		if decoder, ok := tokenDecoders[v.typ]; ok {
			token, err = decoder(v.data)
			if err != nil {
				return err
			}
		} else {
			var t *GenericToken
			if err := json.Unmarshal(v.data, &t); err != nil {
				return err
			}
			token = t
		}
		m.Tokens[id] = token
	}

	m.Config = d.Config
	return nil
}

// HeaderInfo corresponds to the header (binary header and JSON metadata) for a LUKS2 volume.
type HeaderInfo struct {
	HeaderSize uint64   // The total size of the binary header and JSON metadata in bytes
	Label      string   // The label
	Metadata   Metadata // JSON metadata
}

func decodeAndCheckHeader(r io.ReadSeeker, offset int64, primary bool) (*binaryHdr, *bytes.Buffer, error) {
	if _, err := r.Seek(offset, io.SeekStart); err != nil {
		return nil, nil, err
	}

	var hdr binaryHdr
	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return nil, nil, xerrors.Errorf("cannot read header: %w", err)
	}
	switch {
	case primary && bytes.Equal(hdr.Magic[:], []byte("LUKS\xba\xbe")):
	case !primary && bytes.Equal(hdr.Magic[:], []byte("SKUL\xba\xbe")):
	default:
		return nil, nil, errors.New("invalid magic")
	}
	if hdr.Version != 2 {
		return nil, nil, errors.New("invalid version")
	}
	if hdr.HdrSize > uint64(math.MaxInt64) {
		return nil, nil, errors.New("header size too large")
	}
	if hdr.HdrOffset > uint64(math.MaxInt64) {
		return nil, nil, errors.New("header offset too large")
	}
	if int64(hdr.HdrOffset) != offset {
		return nil, nil, errors.New("invalid header offset")
	}

	// Verify the header checksum, which includes the JSON metadata
	csumHash := hdr.CsumAlg.GetHash()
	if csumHash == 0 {
		return nil, nil, errors.New("unsupported checksum alg")
	}

	h := csumHash.New()

	// Hash the binary header without the checksum
	hdrTmp := hdr
	hdrTmp.Csum = [64]byte{}
	if err := binary.Write(h, binary.BigEndian, &hdrTmp); err != nil {
		return nil, nil, xerrors.Errorf("cannot calculate checksum, error serializing header: %w", err)
	}

	// Hash the JSON metadata area, keeping a copy of the hashed metadata in memory
	jsonBuffer := new(bytes.Buffer)
	tr := io.TeeReader(r, jsonBuffer)
	if _, err := io.CopyN(h, tr, int64(hdr.HdrSize)-int64(binary.Size(hdr))); err != nil {
		return nil, nil, xerrors.Errorf("cannot calculate checksum, error reading JSON metadata: %w", err)
	}

	if !bytes.Equal(h.Sum(nil), hdr.Csum[0:csumHash.Size()]) {
		return nil, nil, errors.New("invalid header checksum")
	}

	// Return the binary header and the memory buffer containing the verified JSON metadata
	return &hdr, jsonBuffer, nil
}

// ReadHeader will decode the LUKS header at the specified path. The path can either be a block device
// or file containing a LUKS2 volume with an integral header, or it can be a detached header file.
// Data is interpreted in accordance with the LUKS2 On-Disk Format specification
// (https://gitlab.com/cryptsetup/LUKS2-docs/blob/master/luks2_doc_wip.pdf).
//
// This function will verify the checksum of both the primary and secondary headers if found, and will
// return the decoded form of one of the headers according to the following rules:
//   - If both headers have valid checksums and the same sequence ID, return the primary header.
//   - If both headers have valid checksums but different sequence IDs, return the newest header.
//   - If only one header has a valid checksum, return that header.
//
// libcryptsetup performs some additional validation of the JSON metadata from both the primary
// and secondary headers, and rejects a header if the JSON metadata isn't correctly formed. We don't
// duplicate that logic here - we assume that anything that modifies the LUKS2 headers (which should
// only be libcryptsetup) will write well-formed JSON metadata. Corruption of the JSON metadata outside
// of modifications by libcryptsetup will be detected by the checksum verification.
//
// Note that this function does not attempt recovery of either header in the event that one of the
// headers is not valid - we leave this to libcryptsetup, which happens automatically on any
// cryptsetup or systemd-cryptsetup invocation. This package does not directly perform any
// modifications to the header.
//
// This function requires an advisory shared lock on the LUKS container associated with the
// specified path, and will block until it acquires one. The supplied context can be used to set
// a deadline of provide a mechanism for cancellation. If a lock isn't acquired before the supplied
// context is canceled or expires, the reason is returned as an error.
func ReadHeader(ctx context.Context, path string) (*HeaderInfo, error) {
	releaseLock, err := acquireSharedLock(ctx, path)
	if err != nil {
		return nil, xerrors.Errorf("cannot acquire shared lock: %w", err)
	}
	defer releaseLock()

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Try to decode and check the primary header
	primaryHdr, primaryJSONData, primaryErr := decodeAndCheckHeader(f, 0, true)
	var primaryMetadata Metadata
	if primaryErr == nil {
		if err := json.NewDecoder(primaryJSONData).Decode(&primaryMetadata); err != nil {
			primaryErr = xerrors.Errorf("cannot decode JSON metadata area: %w", err)
		}
	}

	var secondaryHdr *binaryHdr
	var secondaryJSONData *bytes.Buffer
	var secondaryErr error
	if primaryErr != nil {
		// No valid primary header. Try to decode and check a secondary header from one of the
		// well known offsets (see Table 1: Possible LUKS2 secondary header offsets and JSON area
		// size in the LUKS2 On-Disk Format specification).
		for _, off := range []int64{0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000} {
			secondaryHdr, secondaryJSONData, secondaryErr = decodeAndCheckHeader(f, off, false)
			if secondaryErr == nil {
				break
			}
		}
	} else {
		// Try to decode and check the secondary header immediately after the primary header.
		secondaryHdr, secondaryJSONData, secondaryErr = decodeAndCheckHeader(f, int64(primaryHdr.HdrSize), false)
	}
	var secondaryMetadata Metadata
	if secondaryErr == nil {
		if err := json.NewDecoder(secondaryJSONData).Decode(&secondaryMetadata); err != nil {
			secondaryErr = xerrors.Errorf("cannot decode JSON metadata area: %w", err)
		}
	}

	var hdr *binaryHdr
	var metadata *Metadata
	switch {
	case primaryErr == nil && secondaryErr == nil:
		// Both headers are valid
		hdr = primaryHdr
		metadata = &primaryMetadata
		switch {
		case secondaryHdr.SeqId < primaryHdr.SeqId:
			// The secondary header is obsolete. Cryptsetup will recover this automatically.
			fmt.Fprintf(stderr, "luks2.ReadHeader: secondary header for %s is obsolete\n", path)
		case secondaryHdr.SeqId > primaryHdr.SeqId:
			// The primary header is obsolete, so use the secondary header. This shouldn't
			// normally happen as the primary header is updated first. Cryptsetup will recover
			// this automatically.
			hdr = secondaryHdr
			metadata = &secondaryMetadata
			fmt.Fprintf(stderr, "luks2.ReadHeader: primary header for %s is obsolete\n", path)
		}
	case primaryErr == nil:
		// We only have a valid primary header so use that. Cryptsetup will recover this automatically.
		hdr = primaryHdr
		metadata = &primaryMetadata
		fmt.Fprintf(stderr, "luks2.ReadHeader: secondary header for %s is invalid: %v\n", path, secondaryErr)
	case secondaryErr == nil:
		// We only have a valid secondary header so use that. Cryptsetup will recover this automatically.
		hdr = secondaryHdr
		metadata = &secondaryMetadata
		fmt.Fprintf(stderr, "luks2.ReadHeader: primary header for %s is invalid: %v\n", path, primaryErr)
	default:
		// No valid headers :(
		return nil, xerrors.Errorf("no valid header found, error from decoding primary header: %w", primaryErr)
	}

	return &HeaderInfo{
		HeaderSize: hdr.HdrSize,
		Label:      hdr.Label.String(),
		Metadata:   *metadata}, nil
}

// RegisterTokenDecoder registers a custom decoder for the specified token type,
// in order for external packages to be able to create type-specific token structures
// as opposed to relying on GenericToken.
func RegisterTokenDecoder(typ TokenType, decoder TokenDecoder) {
	tokenDecoders[typ] = decoder
}
