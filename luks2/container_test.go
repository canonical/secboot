// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/snapcore/secboot/internal/testutil"
	. "github.com/snapcore/secboot/luks2"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"
)

type containerSuite struct {
	snapd_testutil.BaseTest

	sysfsRoot    string
	devRoot      string
	dmDeviceErrs map[string]error
	dmDevices    map[string]string
	info         map[string]unix.Stat_t

	commands []string

	activateErr error
}

func (s *containerSuite) SetUpTest(c *C) {
	restore := MockLUKS2Ops(&Luks2Api{
		Activate: s.activate,
	})
	s.AddCleanup(restore)

	s.sysfsRoot = c.MkDir()
	restore = MockSysfsRoot(s.sysfsRoot)
	s.AddCleanup(restore)

	s.devRoot = c.MkDir()
	restore = MockDevRoot(s.devRoot)
	s.AddCleanup(restore)

	s.dmDeviceErrs = make(map[string]error)
	s.dmDevices = make(map[string]string)
	restore = MockSourceDeviceFromDMDevice(func(ctx context.Context, path string) (string, error) {
		err, exists := s.dmDeviceErrs[path]
		if exists {
			return "", err
		}
		sourcePath, exists := s.dmDevices[path]
		if !exists {
			return "", ErrNotDMBlockDevice
		}
		return sourcePath, nil
	})
	s.AddCleanup(restore)

	s.info = make(map[string]unix.Stat_t)
	restore = MockUnixStat(func(path string, st *unix.Stat_t) error {
		s, exists := s.info[path]
		if !exists {
			return syscall.ENOENT
		}
		*st = s
		return nil
	})
	s.AddCleanup(restore)

	restore = MockAcquireSharedLock()
	s.AddCleanup(restore)

	s.commands = nil

	s.activateErr = nil
}

func (s *containerSuite) activate(volumeName, sourceDevicePath string, key []byte, slot int) error {
	s.commands = append(s.commands, fmt.Sprintf("Activate(%s,%s,%x,%d)", volumeName, sourceDevicePath, key, slot))
	return s.activateErr
}

func (s *containerSuite) addDMDeviceErr(c *C, num int, e error) {
	// Create the DM volume device node, relative to the mock /dev location.
	path := filepath.Join(s.devRoot, fmt.Sprintf("dm-%d", num))
	f, err := os.Create(path)
	c.Assert(err, IsNil)
	c.Assert(f.Close(), IsNil)

	s.dmDeviceErrs[path] = e
}

func (s *containerSuite) addDMDevice(c *C, num int, volumeName, sourceDevicePath string) {
	// Create the DM volume device node, relative to the mock /dev location.
	path := filepath.Join(s.devRoot, fmt.Sprintf("dm-%d", num))
	f, err := os.Create(path)
	c.Assert(err, IsNil)
	c.Assert(f.Close(), IsNil)

	// Create a mapping of the DM volume node to the source device.
	s.dmDevices[path] = sourceDevicePath

	// Create a unix.Stat_t for the DM volume.
	s.info[path] = unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, uint32(num))}

	// Create a mapping of DM volume to volume name in sysfs
	dir := filepath.Join(s.sysfsRoot, "dev/block", fmt.Sprintf("252:%d", num), "dm")
	c.Assert(os.MkdirAll(dir, 0755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(dir, "name"), []byte(volumeName+"\n"), 0644), IsNil)
}

func (s *containerSuite) addFileInfo(path string, st unix.Stat_t) {
	s.info[path] = st
}

var _ = Suite(&containerSuite{})

func (s *containerSuite) TestContainerOpenRead(c *C) {
	// Test that OpenRead returns a StorageContainerReader
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)
	c.Assert(r, NotNil)
	c.Check(r, testutil.ConvertibleTo, &StorageContainerReader{})
}

func (s *containerSuite) TestContainerOpenReadReturnsDifferentReaders(c *C) {
	// Test that OpenRead returns a new StorageContainerReader for
	// each call.
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	r1, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)
	c.Assert(r1, NotNil)

	r2, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)
	c.Check(r2, Not(Equals), r1)
}

func (s *containerSuite) TestContainerDev1(c *C) {
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	c.Check(container.Dev(), Equals, unix.Mkdev(259, 3))
}

func (s *containerSuite) TestContainerDev2(c *C) {
	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	c.Check(container.Dev(), Equals, unix.Mkdev(8, 1))
}

func (s *containerSuite) TestContainerActivatePlatform(c *C) {
	// Test the StorageContainer.Activate implementation.
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	key := testutil.DecodeHexString(c, "a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56")
	err := container.Activate(context.Background(), &mockKeyslot{keyslotIds: []int{2}}, key, makeMockActivateConfigGetter(WithVolumeName("data")))
	c.Check(err, IsNil)
	c.Check(s.commands, DeepEquals, []string{
		"Activate(data,/dev/nvme0n1p3,a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56,2)",
	})
}

func (s *containerSuite) TestContainerActivatePlatformDifferentPath(c *C) {
	// Test the StorageContainer.Activate implementation with a
	// different device path.
	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	key := testutil.DecodeHexString(c, "a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56")
	err := container.Activate(context.Background(), &mockKeyslot{keyslotIds: []int{2}}, key, makeMockActivateConfigGetter(WithVolumeName("data")))
	c.Check(err, IsNil)
	c.Check(s.commands, DeepEquals, []string{
		"Activate(data,/dev/sda1,a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56,2)",
	})
}

func (s *containerSuite) TestContainerActivatePlatformDifferentVolume(c *C) {
	// Test the StorageContainer.Activate implementation with a
	// different volume name.
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	key := testutil.DecodeHexString(c, "a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56")
	err := container.Activate(context.Background(), &mockKeyslot{keyslotIds: []int{2}}, key, makeMockActivateConfigGetter(WithVolumeName("save")))
	c.Check(err, IsNil)
	c.Check(s.commands, DeepEquals, []string{
		"Activate(save,/dev/nvme0n1p3,a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56,2)",
	})
}

func (s *containerSuite) TestContainerActivatePlatformDifferentKey(c *C) {
	// Test the StorageContainer.Activate implementation with a different key.
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	key := testutil.DecodeHexString(c, "dcb4b6cfc0d9671e096a149f172978c587e9d7a0c7c1436e87fc45db9715777e")
	err := container.Activate(context.Background(), &mockKeyslot{keyslotIds: []int{2}}, key, makeMockActivateConfigGetter(WithVolumeName("data")))
	c.Check(err, IsNil)
	c.Check(s.commands, DeepEquals, []string{
		"Activate(data,/dev/nvme0n1p3,dcb4b6cfc0d9671e096a149f172978c587e9d7a0c7c1436e87fc45db9715777e,2)",
	})
}

func (s *containerSuite) TestContainerActivatePlatformDifferentKeyslot(c *C) {
	// Test the StorageContainer.Activate implementation with a different LUKS2 keyslot ID.
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	key := testutil.DecodeHexString(c, "a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56")
	err := container.Activate(context.Background(), &mockKeyslot{keyslotIds: []int{1}}, key, makeMockActivateConfigGetter(WithVolumeName("data")))
	c.Check(err, IsNil)
	c.Check(s.commands, DeepEquals, []string{
		"Activate(data,/dev/nvme0n1p3,a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56,1)",
	})
}

func (s *containerSuite) TestContainerActivatePlatformNoKeyslot(c *C) {
	// Test the StorageContainer.Activate implementation with a nil Keyslot.
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	key := testutil.DecodeHexString(c, "a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56")
	err := container.Activate(context.Background(), nil, key, makeMockActivateConfigGetter(WithVolumeName("data")))
	c.Check(err, IsNil)
	c.Check(s.commands, DeepEquals, []string{
		"Activate(data,/dev/nvme0n1p3,a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56,-1)",
	})
}

func (s *containerSuite) TestContainerActivatePlatformUnrecognizedKeyslotType(c *C) {
	// Test the StorageContainer.Activate implementation with a Keyslot implementation
	// other than the LUKS2 one. This will test the "external key data file" case with
	// the eventual new activation API, as these will get their own Keyslot type.
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	key := testutil.DecodeHexString(c, "a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56")
	err := container.Activate(context.Background(), new(mockExternalKeyslot), key, makeMockActivateConfigGetter(WithVolumeName("data")))
	c.Check(err, IsNil)
	c.Check(s.commands, DeepEquals, []string{
		"Activate(data,/dev/nvme0n1p3,a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56,-1)",
	})
}

func (s *containerSuite) TestContainerActivatePlatformMissingVolumeName(c *C) {
	// Test that StorageContainer.Activate fails if the WithVolumeName option is missing.
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	key := testutil.DecodeHexString(c, "a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56")
	err := container.Activate(context.Background(), &mockKeyslot{keyslotIds: []int{2}}, key, makeMockActivateConfigGetter())
	c.Check(err, ErrorMatches, `missing WithVolumeName option for LUKS2 container`)
}

func (s *containerSuite) TestContainerActivateError(c *C) {
	// Test that StorageContainer.Activate fails if the call to internal_luks2.Activate fails.
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	key := testutil.DecodeHexString(c, "a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56")
	s.activateErr = errors.New("some error")
	err := container.Activate(context.Background(), &mockKeyslot{keyslotIds: []int{2}}, key, makeMockActivateConfigGetter(WithVolumeName("data")))
	c.Check(err, ErrorMatches, `cannot activate container /dev/nvme0n1p3 with volume name "data": some error`)
	c.Check(s.commands, DeepEquals, []string{
		"Activate(data,/dev/nvme0n1p3,a7bfa9a642b897bc13c58b84cf8237d7d1b224b2e63cb3dc10414ff1f9052c56,2)",
	})
}
