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
	"syscall"

	internal_luks2 "github.com/snapcore/secboot/internal/luks2"
	. "github.com/snapcore/secboot/luks2"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"
)

type backendSuite struct {
	snapd_testutil.BaseTest

	backend *StorageContainerBackend

	probeCtxs []context.Context

	luks2Devices map[string]struct{}
	newViewErrs  map[string]error
	dmDevices    map[string]string
	dmDeviceErrs map[string]error
	symlinks     map[string]string
	info         map[string]unix.Stat_t
}

func (s *backendSuite) SetUpTest(c *C) {
	s.backend = NewStorageContainerBackend()
	s.probeCtxs = nil

	s.luks2Devices = make(map[string]struct{})
	s.newViewErrs = make(map[string]error)
	restore := MockNewLuksView(func(ctx context.Context, path string) (LuksView, error) {
		s.probeCtxs = append(s.probeCtxs, ctx)

		target, exists := s.symlinks[path]
		if exists {
			path = target
		}

		err, exists := s.newViewErrs[path]
		if exists {
			return nil, err
		}
		_, exists = s.luks2Devices[path]
		if !exists {
			return nil, fmt.Errorf("error with binary header: %w", internal_luks2.ErrInvalidMagic)
		}
		return nil, nil
	})
	s.AddCleanup(restore)

	s.dmDevices = make(map[string]string)
	s.dmDeviceErrs = make(map[string]error)
	restore = MockSourceDeviceFromDMDevice(func(ctx context.Context, path string) (string, error) {
		target, exists := s.symlinks[path]
		if exists {
			path = target
		}

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

	s.symlinks = make(map[string]string)
	restore = MockFilepathEvalSymlinks(s.symlinks)
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
}

func (s *backendSuite) addLUKS2Device(path string) {
	s.luks2Devices[path] = struct{}{}
}

func (s *backendSuite) addNewViewErr(path string, err error) {
	s.newViewErrs[path] = err
}

func (s *backendSuite) addDMDevice(dev, source string) {
	s.dmDevices[dev] = source
}

func (s *backendSuite) addDMDeviceErr(dev string, err error) {
	s.dmDeviceErrs[dev] = err
}

func (s *backendSuite) addSymlink(target, link string) {
	s.symlinks[link] = target
}

func (s *backendSuite) addFile(path string, st unix.Stat_t) {
	s.info[path] = st
}

var _ = Suite(&backendSuite{})

func (s *backendSuite) TestBackendProbeCryptDevice(c *C) {
	// Test Probe with the device node for the LUKS2 container.
	s.addLUKS2Device("/dev/nvme0n1p3")
	s.addFile("/dev/nvme0n1p3", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(259, 3)})

	ctx := context.Background()
	container, err := s.backend.Probe(ctx, "/dev/nvme0n1p3")
	c.Assert(err, IsNil)
	c.Assert(container, NotNil)
	c.Check(container.Path(), Equals, "/dev/nvme0n1p3")
	var tmpl StorageContainer
	c.Assert(container, Implements, &tmpl)
	c.Check(container.(StorageContainer).Dev(), Equals, unix.Mkdev(259, 3))

	c.Check(s.probeCtxs, DeepEquals, []context.Context{ctx})
}

func (s *backendSuite) TestBackendProbeCryptDeviceSymlink(c *C) {
	// Test Probe with a symlink to the device node for the LUKS2 container.
	s.addLUKS2Device("/dev/nvme0n1p3")
	s.addFile("/dev/nvme0n1p3", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(259, 3)})
	s.addSymlink("/dev/nvme0n1p3", "/dev/disk/by-path/pci-0000:00:0e.0-pci-10000:e1:00.0-nvme-1-part3")

	ctx := context.Background()
	container, err := s.backend.Probe(ctx, "/dev/disk/by-path/pci-0000:00:0e.0-pci-10000:e1:00.0-nvme-1-part3")
	c.Assert(err, IsNil)
	c.Assert(container, NotNil)
	c.Check(container.Path(), Equals, "/dev/nvme0n1p3")
	var tmpl StorageContainer
	c.Assert(container, Implements, &tmpl)
	c.Check(container.(StorageContainer).Dev(), Equals, unix.Mkdev(259, 3))

	c.Check(s.probeCtxs, DeepEquals, []context.Context{ctx})
}

func (s *backendSuite) TestBackendProbeNoCryptOrDMDevice(c *C) {
	// Test Probe with a device node that is not a LUKS2 or DM device.
	ctx := context.Background()
	container, err := s.backend.Probe(ctx, "/dev/sda1")
	c.Assert(err, IsNil)
	c.Assert(container, IsNil)

	c.Check(s.probeCtxs, DeepEquals, []context.Context{ctx})
}

func (s *backendSuite) TestBackendProbeDMDeviceWithUnrecognizedTarget(c *C) {
	// Test Probe with a device node that is a DM device with an unrecognized target type
	s.addDMDeviceErr("/dev/dm-0", ErrUnsupportedTargetType)

	ctx := context.Background()
	container, err := s.backend.Probe(ctx, "/dev/dm-0")
	c.Assert(err, IsNil)
	c.Assert(container, IsNil)

	c.Check(s.probeCtxs, DeepEquals, []context.Context{ctx})
}

func (s *backendSuite) TestBackendProbeUnexpectedSourceDeviceFromDMDeviceError(c *C) {
	// Test Probe with a device node that is not a LUKS2 or DM device
	// and an unexpected error is returned from sourceDeviceFromDMDevice.
	s.addDMDeviceErr("/dev/dm-1", errors.New("some error"))

	ctx := context.Background()
	_, err := s.backend.Probe(ctx, "/dev/dm-1")
	c.Check(err, ErrorMatches, `cannot obtain source device for dm device /dev/dm-1: some error`)

	c.Check(s.probeCtxs, DeepEquals, []context.Context{ctx})
}

func (s *backendSuite) TestBackendProbeMappedCryptDevice(c *C) {
	// Test Probe by passing a path to DM device that is backed by
	// a LUKS2 device.
	s.addLUKS2Device("/dev/nvme0n1p3")
	s.addDMDevice("/dev/dm-0", "/dev/nvme0n1p3")
	s.addFile("/dev/nvme0n1p3", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(259, 3)})

	ctx := context.Background()
	container, err := s.backend.Probe(ctx, "/dev/dm-0")
	c.Assert(err, IsNil)
	c.Assert(container, NotNil)
	c.Check(container.Path(), Equals, "/dev/nvme0n1p3")
	var tmpl StorageContainer
	c.Assert(container, Implements, &tmpl)
	c.Check(container.(StorageContainer).Dev(), Equals, unix.Mkdev(259, 3))

	ctx2 := context.WithValue(ctx, ProbeDepthKey, uint(1))
	c.Check(s.probeCtxs, DeepEquals, []context.Context{ctx, ctx2})
}

func (s *backendSuite) TestBackendProbeMappedNestedLinearAndCryptDevice(c *C) {
	// Test Probe by passing a path to DM device that is backed by
	// a LUKS2 device - in this case, using linear inside a crypt device.
	s.addLUKS2Device("/dev/nvme0n1p3")
	s.addFile("/dev/nvme0n1p3", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(259, 3)})
	s.addDMDevice("/dev/dm-0", "/dev/nvme0n1p3")
	s.addDMDevice("/dev/dm-1", "/dev/dm-0")

	ctx := context.Background()
	container, err := s.backend.Probe(ctx, "/dev/dm-1")
	c.Assert(err, IsNil)
	c.Assert(container, NotNil)
	c.Check(container.Path(), Equals, "/dev/nvme0n1p3")
	var tmpl StorageContainer
	c.Assert(container, Implements, &tmpl)
	c.Check(container.(StorageContainer).Dev(), Equals, unix.Mkdev(259, 3))

	ctx2 := context.WithValue(ctx, ProbeDepthKey, uint(1))
	ctx3 := context.WithValue(ctx2, ProbeDepthKey, uint(2))
	c.Check(s.probeCtxs, DeepEquals, []context.Context{ctx, ctx2, ctx3})
}

func (s *backendSuite) TestBackendProbeReturnsCachedDevice(c *C) {
	// Test that Probe always returns the same container for the same
	// device, regardless of how the container is addressed.
	s.addLUKS2Device("/dev/nvme0n1p3")
	s.addFile("/dev/nvme0n1p3", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(259, 3)})
	s.addSymlink("/dev/nvme0n1p3", "/dev/disk/by-path/pci-0000:00:0e.0-pci-10000:e1:00.0-nvme-1-part3")
	s.addDMDevice("/dev/dm-0", "/dev/nvme0n1p3")

	ctx := context.Background()
	container, err := s.backend.Probe(ctx, "/dev/nvme0n1p3")
	c.Assert(err, IsNil)
	c.Assert(container, NotNil)
	c.Check(container.Path(), Equals, "/dev/nvme0n1p3")

	container2, err := s.backend.Probe(ctx, "/dev/disk/by-path/pci-0000:00:0e.0-pci-10000:e1:00.0-nvme-1-part3")
	c.Assert(err, IsNil)
	c.Check(container2, Equals, container)

	container3, err := s.backend.Probe(ctx, "/dev/dm-0")
	c.Assert(err, IsNil)
	c.Check(container3, Equals, container)
}
