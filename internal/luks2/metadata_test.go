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

package luks2_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	. "github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/paths/pathstest"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
	"gopkg.in/tomb.v2"
)

type metadataSuite struct {
	snapd_testutil.BaseTest
	runDir string
}

func (s *metadataSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.runDir = c.MkDir()
	s.AddCleanup(pathstest.MockRunDir(s.runDir))
}

func (s *metadataSuite) decompress(c *C, path string) string {
	dir := c.MkDir()
	name := filepath.Base(path)
	dst := filepath.Join(dir, name)
	c.Assert(testutil.CopyFile(dst+".xz", path+".xz", 0600), IsNil)
	c.Assert(exec.Command("unxz", dst+".xz").Run(), IsNil)
	return dst
}

var _ = Suite(&metadataSuite{})

func (s *metadataSuite) TestAcquireSharedLockOnFile(c *C) {
	// Test acquiring a shared lock on a file.
	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	release, err := AcquireSharedLock(context.Background(), path)
	c.Assert(err, IsNil)
	defer release()

	// We shouldn't be able to obtain an exclusive lock.
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, "resource temporarily unavailable")

	// We should be able to obtain a shared lock.
	err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Check(err, IsNil)

	release()

	// We should now be able to upgrade our shared lock to an
	// exclusive lock.
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, IsNil)
}

func (s *metadataSuite) TestFailAcquireSharedLockOnFileWithTimeout(c *C) {
	// Test trying to acquire a shared lock on a file that already
	// has an exclusive lock on it, using a context with a 200ms timeout.
	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	// Obtain an exclusive lock.
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Assert(err, IsNil)

	// Trying to acquire a shared lock should timeout after 200ms
	ctx, _ := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, err = AcquireSharedLock(ctx, path)
	c.Check(err, ErrorMatches, "context deadline exceeded")
	c.Check(errors.Is(err, context.DeadlineExceeded), testutil.IsTrue)

	// Release our exclusive lock.
	err = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	c.Assert(err, IsNil)

	// We should be able acquire a shared lock within the 200ms timeout now.
	ctx, _ = context.WithTimeout(context.Background(), 200*time.Millisecond)
	release, err := AcquireSharedLock(ctx, path)
	c.Assert(err, IsNil)

	release()
}

func (s *metadataSuite) TestAcquireSharedLockOnUnsupportedFile(c *C) {
	// Test that acquireSharedLock fails on invalid file types - it
	// should only work for regular files or block devices.
	_, err := AcquireSharedLock(context.Background(), "/dev/null")
	c.Check(err, ErrorMatches, "unsupported file type")
}

func (s *metadataSuite) TestAcquireSharedLockOnDevice(c *C) {
	// Test acquiring a shared lock on a block device. We mock the
	// data device so that it looks like a block device.
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	release, err := AcquireSharedLock(context.Background(), path)
	c.Assert(err, IsNil)
	defer release()

	// Check that there exists a lock file at the expected location
	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	c.Assert(err, IsNil)
	defer lockFile.Close()

	// We shouldn't be able to obtain an exclusive lock.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, "resource temporarily unavailable")

	// We should be able to obtain a shared lock.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Check(err, IsNil)

	// We need to release our shared lock so that the lock file cleanup
	// works and can be tested.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	c.Assert(err, IsNil)

	release()

	// We should be able to obtain an exclusive lock on our open FD now.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, IsNil)

	// The lock file should have been deleted.
	_, err = os.Open(lockPath)
	c.Check(err, ErrorMatches, ".*: no such file or directory")
}

func (s *metadataSuite) TestFailAcquireSharedLockOnDeviceWithTimeout(c *C) {
	// Test trying to acquire a shared lock on a block device that already
	// has an exclusive lock on it, using a context with a 200ms timeout.
	// We mock the data device so that it looks like a block device.
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	// Create a lock file to accompany our block device and grab an exclusive lock.
	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	c.Assert(os.Mkdir(filepath.Dir(lockPath), 0700), IsNil)
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer lockFile.Close()

	// Obtain an exclusive lock.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Assert(err, IsNil)

	// We should not be able acquire a shared lock within the 200ms timeout.
	ctx, _ := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, err = AcquireSharedLock(ctx, path)
	c.Check(err, ErrorMatches, "context deadline exceeded")
	c.Check(errors.Is(err, context.DeadlineExceeded), testutil.IsTrue)

	// Release our exclusive lock.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	c.Assert(err, IsNil)

	// We should be able acquire a shared lock within the 200ms timeout now.
	ctx, _ = context.WithTimeout(context.Background(), 200*time.Millisecond)
	release, err := AcquireSharedLock(ctx, path)
	c.Assert(err, IsNil)
	defer release()

	release()

	// The lock file should have been deleted.
	_, err = os.Open(lockPath)
	c.Check(err, ErrorMatches, ".*: no such file or directory")
}

func (s *metadataSuite) TestAcquireSharedLockOnDeviceWithAlreadyCanceledContext(c *C) {
	// Test that we get the expected error when trying to acquire a shared lock
	// on a block device with a context that is already canceled.
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = AcquireSharedLock(ctx, path)
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)

	// There shouldn't be a lock file at the expected location.
	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	_, err = os.OpenFile(lockPath, os.O_RDWR, 0)
	c.Check(os.IsNotExist(err), testutil.IsTrue)

	// It should still work if we try again with a non-canceled context.
	release, err := AcquireSharedLock(context.Background(), path)
	c.Assert(err, IsNil)
	defer release()

	// Check that there exists a lock file at the expected location
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	c.Assert(err, IsNil)
	defer lockFile.Close()

	// We shouldn't be able to obtain an exclusive lock.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, "resource temporarily unavailable")

	// We should be able to obtain a shared lock.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Check(err, IsNil)

	// We need to release our shared lock so that the lock file cleanup
	// works and can be tested.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	c.Assert(err, IsNil)

	release()

	// We should be able to obtain an exclusive lock on our open FD now.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, IsNil)

	// The lock file should have been deleted.
	_, err = os.Open(lockPath)
	c.Check(err, ErrorMatches, ".*: no such file or directory")
}

func (s *metadataSuite) TestAcquireSharedLockOnDeviceAfterWait(c *C) {
	// Test acquiring a shared lock on a block device after having to wait. We
	// mock the data device so that it looks like a block device.
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	// Create the expected lock file.
	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	c.Assert(os.Mkdir(filepath.Dir(lockPath), 0700), IsNil)
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer lockFile.Close()

	// Obtain an exclusive lock.
	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Assert(err, IsNil)

	tmb := new(tomb.Tomb)
	tmb.Go(func() error {
		<-time.After(100 * time.Millisecond)

		// Release our exclusive lock.
		return unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	})
	<-tmb.Dead()
	c.Check(tmb.Err(), IsNil)

	ctx, _ := context.WithTimeout(context.Background(), 200*time.Millisecond)
	release, err := AcquireSharedLock(ctx, path)
	c.Assert(err, IsNil)
	defer release()

	release()

	// The lock file should have been deleted.
	_, err = os.Open(lockPath)
	c.Check(err, ErrorMatches, ".*: no such file or directory")
}

func (s *metadataSuite) TestAcquireSharedLockOnDeviceNoCleanupLackOfExclusiveLock(c *C) {
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	release, err := AcquireSharedLock(context.Background(), path)
	c.Assert(err, IsNil)
	defer release()

	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	c.Assert(err, IsNil)
	defer lockFile.Close()

	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Check(err, IsNil)

	release()

	// The lock file shouldn't have been deleted because we have a shared lock on it.
	lockFile, err = os.Open(lockPath)
	c.Assert(err, IsNil)
	defer lockFile.Close()
}

func (s *metadataSuite) TestAcquireSharedLockOnDeviceWithExistingLockDir(c *C) {
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	c.Assert(os.Mkdir(filepath.Join(s.runDir, "cryptsetup"), 0700), IsNil)

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	release, err := AcquireSharedLock(context.Background(), path)
	c.Assert(err, IsNil)
	defer release()

	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	c.Assert(err, IsNil)
	defer lockFile.Close()
}

func (s *metadataSuite) TestAcquireManySharedLocksOnDevice(c *C) {
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	var wg sync.WaitGroup

	routine := func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			release, err := AcquireSharedLock(context.Background(), path)
			c.Assert(err, IsNil)
			time.Sleep(time.Duration(rand.Intn(15000)) * time.Microsecond)
			release()
		}
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go routine()
	}

	wg.Wait()

	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	_, err = os.Open(lockPath)
	c.Check(err, ErrorMatches, ".*: no such file or directory")
}

type testMarshalGenericTokenData struct {
	token          *GenericToken
	expectedParams map[string]interface{}
}

func (s *metadataSuite) testMarshalGenericToken(c *C, data *testMarshalGenericTokenData) {
	b, err := json.Marshal(data.token)
	c.Assert(err, IsNil)

	var token *GenericToken
	c.Assert(json.Unmarshal(b, &token), IsNil)
	c.Check(token.TokenType, Equals, data.token.TokenType)
	c.Check(token.TokenKeyslots, DeepEquals, data.token.TokenKeyslots)
	c.Check(token.Params, DeepEquals, data.expectedParams)
}

func (s *metadataSuite) TestMarshalGenericToken1(c *C) {
	s.testMarshalGenericToken(c, &testMarshalGenericTokenData{
		token: &GenericToken{
			TokenType:     "luks2-keyring",
			TokenKeyslots: []int{0},
			Params: map[string]interface{}{
				"key_description": "foo",
			},
		},
		expectedParams: map[string]interface{}{
			"key_description": "foo",
		},
	})
}

func (s *metadataSuite) TestMarshalGenericToken2(c *C) {
	data := make([]byte, 128)
	rand.Read(data)

	s.testMarshalGenericToken(c, &testMarshalGenericTokenData{
		token: &GenericToken{
			TokenType:     "secboot-test",
			TokenKeyslots: []int{1, 2},
			Params: map[string]interface{}{
				"secboot-a": 50,
				"secboot-b": data,
			},
		},
		expectedParams: map[string]interface{}{
			"secboot-a": float64(50),
			"secboot-b": base64.StdEncoding.EncodeToString(data),
		},
	})
}

type testReadHeaderData struct {
	path             string
	hdrSize          uint64
	keyslotsSize     uint64
	keyslot2Priority SlotPriority
	segmentOffset    uint64
	sectorSize       uint32
	requirements     []string
	stderr           string
}

func (s *metadataSuite) testReadHeader(c *C, data *testReadHeaderData) {
	stderr := new(bytes.Buffer)
	s.AddCleanup(MockStderr(stderr))

	hdr, err := ReadHeader(context.Background(), s.decompress(c, data.path))
	c.Assert(err, IsNil)

	c.Check(hdr.HeaderSize, Equals, data.hdrSize)
	c.Check(hdr.Label, Equals, "data")

	c.Assert(hdr.Metadata.Keyslots, HasLen, 2)

	c.Check(hdr.Metadata.Keyslots[0].Type, Equals, KeyslotTypeLUKS2)
	c.Check(hdr.Metadata.Keyslots[0].KeySize, Equals, 64)
	c.Assert(hdr.Metadata.Keyslots[0].Area, NotNil)
	c.Check(hdr.Metadata.Keyslots[0].Area.Type, Equals, AreaTypeRaw)
	c.Check(hdr.Metadata.Keyslots[0].Area.Offset, Equals, data.hdrSize*2)
	c.Check(hdr.Metadata.Keyslots[0].Area.Size, Equals, uint64(258048))
	c.Check(hdr.Metadata.Keyslots[0].Area.Encryption, Equals, "aes-xts-plain64")
	c.Check(hdr.Metadata.Keyslots[0].Area.KeySize, Equals, 64)
	c.Assert(hdr.Metadata.Keyslots[0].KDF, NotNil)
	c.Check(hdr.Metadata.Keyslots[0].KDF.Type, Equals, KDFTypeArgon2i)
	c.Check(hdr.Metadata.Keyslots[0].KDF.Salt, HasLen, 32)
	c.Assert(hdr.Metadata.Keyslots[0].AF, NotNil)
	c.Check(hdr.Metadata.Keyslots[0].AF.Type, Equals, AFTypeLUKS1)
	c.Check(hdr.Metadata.Keyslots[0].AF.Stripes, Equals, 4000)
	c.Check(hdr.Metadata.Keyslots[0].AF.Hash, Equals, HashSHA256)
	c.Check(hdr.Metadata.Keyslots[0].Priority, Equals, SlotPriorityHigh)

	c.Check(hdr.Metadata.Keyslots[1].Type, Equals, KeyslotTypeLUKS2)
	c.Check(hdr.Metadata.Keyslots[1].KeySize, Equals, 64)
	c.Assert(hdr.Metadata.Keyslots[1].Area, NotNil)
	c.Check(hdr.Metadata.Keyslots[1].Area.Type, Equals, AreaTypeRaw)
	c.Check(hdr.Metadata.Keyslots[1].Area.Offset, Equals, (data.hdrSize*2)+258048)
	c.Check(hdr.Metadata.Keyslots[1].Area.Size, Equals, uint64(258048))
	c.Check(hdr.Metadata.Keyslots[1].Area.Encryption, Equals, "aes-xts-plain64")
	c.Check(hdr.Metadata.Keyslots[1].Area.KeySize, Equals, 64)
	c.Assert(hdr.Metadata.Keyslots[1].KDF, NotNil)
	c.Check(hdr.Metadata.Keyslots[1].KDF.Type, Equals, KDFTypePBKDF2)
	c.Check(hdr.Metadata.Keyslots[1].KDF.Salt, HasLen, 32)
	c.Check(hdr.Metadata.Keyslots[1].KDF.Hash, Equals, HashSHA256)
	c.Assert(hdr.Metadata.Keyslots[1].AF, NotNil)
	c.Check(hdr.Metadata.Keyslots[1].AF.Type, Equals, AFTypeLUKS1)
	c.Check(hdr.Metadata.Keyslots[1].AF.Stripes, Equals, 4000)
	c.Check(hdr.Metadata.Keyslots[1].AF.Hash, Equals, HashSHA256)
	c.Check(hdr.Metadata.Keyslots[1].Priority, Equals, data.keyslot2Priority)

	c.Assert(hdr.Metadata.Segments, HasLen, 1)
	c.Check(hdr.Metadata.Segments[0].Type, Equals, "crypt")
	c.Check(hdr.Metadata.Segments[0].Offset, Equals, data.segmentOffset)
	c.Check(hdr.Metadata.Segments[0].DynamicSize, Equals, true)
	c.Check(hdr.Metadata.Segments[0].Encryption, Equals, "aes-xts-plain64")
	c.Check(hdr.Metadata.Segments[0].SectorSize, Equals, data.sectorSize)
	c.Check(hdr.Metadata.Segments[0].Integrity, IsNil)

	c.Assert(hdr.Metadata.Tokens, HasLen, 1)
	c.Check(hdr.Metadata.Tokens[0].Type(), Equals, TokenType("secboot-test"))
	c.Check(hdr.Metadata.Tokens[0].Keyslots(), DeepEquals, []int{0})
	token, ok := hdr.Metadata.Tokens[0].(*GenericToken)
	c.Assert(ok, testutil.IsTrue)
	c.Check(token.Params, DeepEquals, map[string]interface{}{"secboot-a": "foo", "secboot-b": float64(7)})

	c.Assert(hdr.Metadata.Digests, HasLen, 1)
	c.Check(hdr.Metadata.Digests[0].Type, Equals, KDFTypePBKDF2)
	c.Check(hdr.Metadata.Digests[0].Keyslots, DeepEquals, []int{0, 1})
	c.Check(hdr.Metadata.Digests[0].Segments, DeepEquals, []int{0})
	c.Check(hdr.Metadata.Digests[0].Salt, HasLen, 32)
	c.Check(hdr.Metadata.Digests[0].Digest, HasLen, 32)
	c.Check(hdr.Metadata.Digests[0].Hash, Equals, HashSHA256)

	c.Check(hdr.Metadata.Config.JSONSize, Equals, data.hdrSize-4096)
	c.Check(hdr.Metadata.Config.KeyslotsSize, Equals, data.keyslotsSize)
	if len(data.requirements) == 0 {
		c.Check(hdr.Metadata.Config.Requirements, IsNil)
	} else {
		c.Check(hdr.Metadata.Config.Requirements, NotNil)
		c.Check(hdr.Metadata.Config.Requirements.Mandatory, DeepEquals, data.requirements)
	}

	c.Check(stderr.String(), Matches, data.stderr)
}

func (s *metadataSuite) TestReadHeaderValid(c *C) {
	// Test a valid header
	s.testReadHeader(c, &testReadHeaderData{
		path:             "testdata/luks2-valid-hdr.img",
		hdrSize:          16384,
		keyslotsSize:     16744448,
		keyslot2Priority: SlotPriorityNormal,
		sectorSize:       512,
	})
}

func (s *metadataSuite) TestReadHeaderValidICE(c *C) {
	// Test a valid header
	s.testReadHeader(c, &testReadHeaderData{
		path:             "testdata/luks2-valid-hdr-ice.img",
		hdrSize:          16384,
		keyslotsSize:     16744448,
		keyslot2Priority: SlotPriorityNormal,
		sectorSize:       4096,
		segmentOffset:    0x1000000,
		requirements:     []string{"x-ubuntu-inline-crypto-engine"},
	})
}

func (s *metadataSuite) TestReadHeaderInvalidPrimary(c *C) {
	// Test where the primary header has an invalid checksum. The primary header has an
	// invalid JSON size, so the test will fail if the secondary header isn't selected.
	s.testReadHeader(c, &testReadHeaderData{
		path:             "testdata/luks2-hdr-invalid-checksum0.img",
		hdrSize:          16384,
		keyslotsSize:     16744448,
		keyslot2Priority: SlotPriorityNormal,
		sectorSize:       512,
		stderr:           "luks2.ReadHeader: primary header for /.*/luks2-hdr-invalid-checksum0.img is invalid: invalid header checksum\n",
	})
}

func (s *metadataSuite) TestReadHeaderInvalidSecondary(c *C) {
	// Test where the secondary header has an invalid checksum. The secondary header has an
	// invalid JSON size, so the test will fail if the primary header isn't selected.
	s.testReadHeader(c, &testReadHeaderData{
		path:             "testdata/luks2-hdr-invalid-checksum1.img",
		hdrSize:          16384,
		keyslotsSize:     16744448,
		keyslot2Priority: SlotPriorityNormal,
		sectorSize:       512,
		stderr:           "luks2.ReadHeader: secondary header for /.*/luks2-hdr-invalid-checksum1.img is invalid: invalid header checksum\n",
	})
}

func (s *metadataSuite) TestReadHeaderCustomMetadataSize(c *C) {
	// Test a valid header with different metadata and binary keyslot area sizes
	s.testReadHeader(c, &testReadHeaderData{
		path:             "testdata/luks2-valid-hdr2.img",
		hdrSize:          65536,
		keyslotsSize:     8257536,
		keyslot2Priority: SlotPriorityNormal,
		sectorSize:       512,
	})
}

func (s *metadataSuite) TestReadHeaderCustomMetadataSizeInvalidPrimary(c *C) {
	// Test a valid header with different metadata and binary keyslot area sizes. The
	// primary header has an invalid checksum because of an invalid JSON size, so the
	// test will fail if the secondary header isn't selected.
	s.testReadHeader(c, &testReadHeaderData{
		path:             "testdata/luks2-hdr2-invalid-checksum0.img",
		hdrSize:          65536,
		keyslotsSize:     8257536,
		keyslot2Priority: SlotPriorityNormal,
		sectorSize:       512,
		stderr:           "luks2.ReadHeader: primary header for /.*/luks2-hdr2-invalid-checksum0.img is invalid: invalid header checksum\n",
	})
}

func (s *metadataSuite) TestReadHeaderObsoletePrimary(c *C) {
	// Test where the primary header is obsolete. The secondary header has a modified
	// keyslot priority, so the test will fail if the secondary header is not selected.
	s.testReadHeader(c, &testReadHeaderData{
		path:             "testdata/luks2-hdr-obsolete0.img",
		hdrSize:          16384,
		keyslotsSize:     16744448,
		keyslot2Priority: SlotPriorityIgnore,
		sectorSize:       512,
		stderr:           "luks2.ReadHeader: primary header for /.*/luks2-hdr-obsolete0.img is obsolete\n",
	})
}

func (s *metadataSuite) TestReadHeaderInvalidMagic(c *C) {
	// Test where both headers have invalid magic values to check we get the right error.
	_, err := ReadHeader(context.Background(), s.decompress(c, "testdata/luks2-hdr-invalid-magic-both.img"))
	c.Check(err, ErrorMatches, "no valid header found, error from decoding primary header: invalid magic")
}

func (s *metadataSuite) TestReadHeaderInvalidVersion(c *C) {
	// Test where both headers have an invalid version to check we get the right error.
	_, err := ReadHeader(context.Background(), s.decompress(c, "testdata/luks2-hdr-invalid-version-both.img"))
	c.Check(err, ErrorMatches, "no valid header found, error from decoding primary header: invalid version")
}

func (s *metadataSuite) TestReadHeaderWithExternalToken(c *C) {
	RegisterTokenDecoder("secboot-test", func(data []byte) (Token, error) {
		var token *mockToken
		if err := json.Unmarshal(data, &token); err != nil {
			return nil, err
		}
		return token, nil
	})
	defer RegisterTokenDecoder("secboot-test", nil)

	hdr, err := ReadHeader(context.Background(), s.decompress(c, "testdata/luks2-valid-hdr.img"))
	c.Assert(err, IsNil)

	c.Assert(hdr.Metadata.Tokens, HasLen, 1)

	token, ok := hdr.Metadata.Tokens[0].(*mockToken)
	c.Assert(ok, testutil.IsTrue)
	c.Check(token.TokenType, Equals, TokenType("secboot-test"))
	c.Check(token.TokenKeyslots, DeepEquals, []JsonNumber{"0"})
	c.Check(token.A, Equals, "foo")
	c.Check(token.B, Equals, 7)
}
