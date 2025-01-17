//go:build linux

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

package tpm2_device_test

import (
	"errors"

	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/ppi"
	. "github.com/snapcore/secboot/internal/tpm2_device"
	. "gopkg.in/check.v1"
)

type deviceLinuxSuite struct{}

var _ = Suite(&deviceLinuxSuite{})

func (s *deviceLinuxSuite) TestDefaultDeviceDefaultNotTPM2Device(c *C) {
	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return nil, linux.ErrDefaultNotTPM2Device
	})
	defer restore()

	_, err := DefaultDevice(DeviceModeDirect)
	c.Check(err, Equals, ErrNoTPM2Device)
}

func (s *deviceLinuxSuite) TestDefaultDeviceDefaultNoTPMDevices(c *C) {
	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return nil, linux.ErrNoTPMDevices
	})
	defer restore()

	_, err := DefaultDevice(DeviceModeDirect)
	c.Check(err, Equals, ErrNoTPM2Device)
}

func (s *deviceLinuxSuite) TestDefaultDeviceDefaultOtherError(c *C) {
	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return nil, errors.New("some error")
	})
	defer restore()

	_, err := DefaultDevice(DeviceModeDirect)
	c.Check(err, ErrorMatches, `some error`)
}

func (s *deviceLinuxSuite) TestDefaultDeviceDirect(c *C) {
	expectedRaw := new(linux.RawDevice)
	expectedPPI := new(mockPPI)

	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return expectedRaw, nil
	})
	defer restore()

	restore = MockLinuxRawDevicePhysicalPresenceInterface(func(raw *linux.RawDevice) (ppi.PPI, error) {
		c.Check(raw, Equals, expectedRaw)
		return expectedPPI, nil
	})
	defer restore()

	dev, err := DefaultDevice(DeviceModeDirect)
	c.Check(err, IsNil)
	c.Check(dev, DeepEquals, NewTPMDevice(expectedRaw, DeviceModeDirect, expectedPPI, nil))
}

func (s *deviceLinuxSuite) TestDefaultDeviceDirectNoPPI(c *C) {
	expectedRaw := new(linux.RawDevice)

	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return expectedRaw, nil
	})
	defer restore()

	restore = MockLinuxRawDevicePhysicalPresenceInterface(func(raw *linux.RawDevice) (ppi.PPI, error) {
		c.Check(raw, Equals, expectedRaw)
		return nil, linux.ErrNoPhysicalPresenceInterface
	})
	defer restore()

	dev, err := DefaultDevice(DeviceModeDirect)
	c.Check(err, IsNil)
	c.Check(dev, DeepEquals, NewTPMDevice(expectedRaw, DeviceModeDirect, nil, nil))
}

func (s *deviceLinuxSuite) TestDefaultDeviceDirectPPIError(c *C) {
	expectedRaw := new(linux.RawDevice)

	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return expectedRaw, nil
	})
	defer restore()

	restore = MockLinuxRawDevicePhysicalPresenceInterface(func(raw *linux.RawDevice) (ppi.PPI, error) {
		c.Check(raw, Equals, expectedRaw)
		return nil, errors.New("some error")
	})
	defer restore()

	dev, err := DefaultDevice(DeviceModeDirect)
	c.Check(err, IsNil)
	c.Check(dev, DeepEquals, NewTPMDevice(expectedRaw, DeviceModeDirect, nil, errors.New("some error")))
}

func (s *deviceLinuxSuite) TestDefaultDeviceTryResourceManaged(c *C) {
	expectedRaw := new(linux.RawDevice)
	expectedPPI := new(mockPPI)
	expectedRM := new(linux.RMDevice)

	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return expectedRaw, nil
	})
	defer restore()

	restore = MockLinuxRawDevicePhysicalPresenceInterface(func(raw *linux.RawDevice) (ppi.PPI, error) {
		c.Check(raw, Equals, expectedRaw)
		return expectedPPI, nil
	})
	defer restore()

	restore = MockLinuxRawDeviceResourceManagedDevice(func(raw *linux.RawDevice) (*linux.RMDevice, error) {
		c.Check(raw, Equals, expectedRaw)
		return expectedRM, nil
	})
	defer restore()

	restore = MockLinuxRMDeviceRawDevice(func(rm *linux.RMDevice) *linux.RawDevice {
		c.Check(rm, Equals, expectedRM)
		return expectedRaw
	})
	defer restore()

	dev, err := DefaultDevice(DeviceModeTryResourceManaged)
	c.Check(err, IsNil)
	c.Check(dev, DeepEquals, NewTPMDevice(expectedRM, DeviceModeResourceManaged, expectedPPI, nil))
}

func (s *deviceLinuxSuite) TestDefaultDeviceTryResourceManagedNoPPI(c *C) {
	expectedRaw := new(linux.RawDevice)
	expectedRM := new(linux.RMDevice)

	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return expectedRaw, nil
	})
	defer restore()

	restore = MockLinuxRawDevicePhysicalPresenceInterface(func(raw *linux.RawDevice) (ppi.PPI, error) {
		c.Check(raw, Equals, expectedRaw)
		return nil, linux.ErrNoPhysicalPresenceInterface
	})
	defer restore()

	restore = MockLinuxRawDeviceResourceManagedDevice(func(raw *linux.RawDevice) (*linux.RMDevice, error) {
		c.Check(raw, Equals, expectedRaw)
		return expectedRM, nil
	})
	defer restore()

	restore = MockLinuxRMDeviceRawDevice(func(rm *linux.RMDevice) *linux.RawDevice {
		c.Check(rm, Equals, expectedRM)
		return expectedRaw
	})
	defer restore()

	dev, err := DefaultDevice(DeviceModeTryResourceManaged)
	c.Check(err, IsNil)
	c.Check(dev, DeepEquals, NewTPMDevice(expectedRM, DeviceModeResourceManaged, nil, nil))
}

func (s *deviceLinuxSuite) TestDefaultDeviceTryResourceManagedPPIErr(c *C) {
	expectedRaw := new(linux.RawDevice)
	expectedRM := new(linux.RMDevice)

	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return expectedRaw, nil
	})
	defer restore()

	restore = MockLinuxRawDevicePhysicalPresenceInterface(func(raw *linux.RawDevice) (ppi.PPI, error) {
		c.Check(raw, Equals, expectedRaw)
		return nil, errors.New("some error")
	})
	defer restore()

	restore = MockLinuxRawDeviceResourceManagedDevice(func(raw *linux.RawDevice) (*linux.RMDevice, error) {
		c.Check(raw, Equals, expectedRaw)
		return expectedRM, nil
	})
	defer restore()

	restore = MockLinuxRMDeviceRawDevice(func(rm *linux.RMDevice) *linux.RawDevice {
		c.Check(rm, Equals, expectedRM)
		return expectedRaw
	})
	defer restore()

	dev, err := DefaultDevice(DeviceModeTryResourceManaged)
	c.Check(err, IsNil)
	c.Check(dev, DeepEquals, NewTPMDevice(expectedRM, DeviceModeResourceManaged, nil, errors.New("some error")))
}

func (s *deviceLinuxSuite) TestDefaultDeviceTryResourceManagedNoRM(c *C) {
	expectedRaw := new(linux.RawDevice)
	expectedPPI := new(mockPPI)

	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return expectedRaw, nil
	})
	defer restore()

	restore = MockLinuxRawDevicePhysicalPresenceInterface(func(raw *linux.RawDevice) (ppi.PPI, error) {
		c.Check(raw, Equals, expectedRaw)
		return expectedPPI, nil
	})
	defer restore()

	restore = MockLinuxRawDeviceResourceManagedDevice(func(raw *linux.RawDevice) (*linux.RMDevice, error) {
		c.Check(raw, Equals, expectedRaw)
		return nil, linux.ErrNoResourceManagedDevice
	})
	defer restore()

	restore = MockLinuxRMDeviceRawDevice(func(rm *linux.RMDevice) *linux.RawDevice {
		c.Errorf("unexpected call to linux.RMDevice.RawDevice()")
		return nil
	})
	defer restore()

	dev, err := DefaultDevice(DeviceModeTryResourceManaged)
	c.Check(err, IsNil)
	c.Check(dev, DeepEquals, NewTPMDevice(expectedRaw, DeviceModeDirect, expectedPPI, nil))
}

func (s *deviceLinuxSuite) TestDefaultDeviceTryResourceManagedErr(c *C) {
	expectedRaw := new(linux.RawDevice)

	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return expectedRaw, nil
	})
	defer restore()

	restore = MockLinuxRawDevicePhysicalPresenceInterface(func(raw *linux.RawDevice) (ppi.PPI, error) {
		c.Check(raw, Equals, expectedRaw)
		return nil, linux.ErrNoPhysicalPresenceInterface
	})
	defer restore()

	restore = MockLinuxRawDeviceResourceManagedDevice(func(raw *linux.RawDevice) (*linux.RMDevice, error) {
		c.Check(raw, Equals, expectedRaw)
		return nil, errors.New("some error")
	})
	defer restore()

	restore = MockLinuxRMDeviceRawDevice(func(rm *linux.RMDevice) *linux.RawDevice {
		c.Errorf("unexpected call to linux.RMDevice.RawDevice()")
		return nil
	})
	defer restore()

	_, err := DefaultDevice(DeviceModeTryResourceManaged)
	c.Check(err, ErrorMatches, `some error`)
}

func (s *deviceLinuxSuite) TestDefaultDeviceResourceManaged(c *C) {
	expectedRaw := new(linux.RawDevice)
	expectedPPI := new(mockPPI)
	expectedRM := new(linux.RMDevice)

	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return expectedRaw, nil
	})
	defer restore()

	restore = MockLinuxRawDevicePhysicalPresenceInterface(func(raw *linux.RawDevice) (ppi.PPI, error) {
		c.Check(raw, Equals, expectedRaw)
		return expectedPPI, nil
	})
	defer restore()

	restore = MockLinuxRawDeviceResourceManagedDevice(func(raw *linux.RawDevice) (*linux.RMDevice, error) {
		c.Check(raw, Equals, expectedRaw)
		return expectedRM, nil
	})
	defer restore()

	restore = MockLinuxRMDeviceRawDevice(func(rm *linux.RMDevice) *linux.RawDevice {
		c.Check(rm, Equals, expectedRM)
		return expectedRaw
	})
	defer restore()

	dev, err := DefaultDevice(DeviceModeResourceManaged)
	c.Check(err, IsNil)
	c.Check(dev, DeepEquals, NewTPMDevice(expectedRM, DeviceModeResourceManaged, expectedPPI, nil))
}

func (s *deviceLinuxSuite) TestDefaultDeviceResourceManagedNoRM(c *C) {
	expectedRaw := new(linux.RawDevice)

	restore := MockLinuxDefaultTPM2Device(func() (*linux.RawDevice, error) {
		return expectedRaw, nil
	})
	defer restore()

	restore = MockLinuxRawDevicePhysicalPresenceInterface(func(raw *linux.RawDevice) (ppi.PPI, error) {
		c.Errorf("unexpected call to linux.RawDevice.PhysicalPresenceInterface()")
		return nil, nil
	})
	defer restore()

	restore = MockLinuxRawDeviceResourceManagedDevice(func(raw *linux.RawDevice) (*linux.RMDevice, error) {
		c.Check(raw, Equals, expectedRaw)
		return nil, linux.ErrNoResourceManagedDevice
	})
	defer restore()

	restore = MockLinuxRMDeviceRawDevice(func(rm *linux.RMDevice) *linux.RawDevice {
		c.Errorf("unexpected call to linux.RMDevice.RawDevice()")
		return nil
	})
	defer restore()

	_, err := DefaultDevice(DeviceModeResourceManaged)
	c.Check(err, Equals, ErrNoResourceManagedTPM2Device)
}
