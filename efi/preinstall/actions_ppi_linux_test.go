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

package preinstall_test

import (
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/ppi"
	. "github.com/snapcore/secboot/efi/preinstall"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	. "gopkg.in/check.v1"
)

type actionsPpiLinuxSuite struct {
	snapd_testutil.BaseTest

	rmToRawMap  map[*linux.RMDevice]*linux.RawDevice
	rawToPPIMap map[*linux.RawDevice]ppi.PPI
	ppiErr      error
}

func (s *actionsPpiLinuxSuite) SetUpTest(c *C) {
	s.rmToRawMap = make(map[*linux.RMDevice]*linux.RawDevice)
	s.rawToPPIMap = make(map[*linux.RawDevice]ppi.PPI)
	s.ppiErr = nil

	restore := MockLinuxRawDevicePhysicalPresenceInterface(func(d *linux.RawDevice) (ppi.PPI, error) {
		if s.ppiErr != nil {
			return nil, s.ppiErr
		}
		p, exists := s.rawToPPIMap[d]
		if !exists {
			return nil, linux.ErrNoPhysicalPresenceInterface
		}
		return p, nil
	})
	s.AddCleanup(restore)

	restore = MockLinuxRMDeviceRawDevice(func(d *linux.RMDevice) *linux.RawDevice {
		return s.rmToRawMap[d]
	})
	s.AddCleanup(restore)
}

var _ = Suite(&actionsPpiLinuxSuite{})

func (s *actionsPpiLinuxSuite) TestObtainTPMDevicePPILinuxRawDevice(c *C) {
	expectedPPI := new(mockPPI)
	dev := new(linux.RawDevice)
	s.rawToPPIMap[dev] = expectedPPI

	p, err := ObtainTPMDevicePPILinux(dev)
	c.Assert(err, IsNil)
	c.Check(p, Equals, expectedPPI)
}

func (s *actionsPpiLinuxSuite) TestObtainTPMDevicePPILinuxRMDevice(c *C) {
	expectedPPI := new(mockPPI)
	rawDev := new(linux.RawDevice)
	s.rawToPPIMap[rawDev] = expectedPPI

	dev := new(linux.RMDevice)
	s.rmToRawMap[dev] = rawDev

	p, err := ObtainTPMDevicePPILinux(dev)
	c.Assert(err, IsNil)
	c.Check(p, Equals, expectedPPI)
}

func (s *actionsPpiLinuxSuite) TestObtainTPMDevicePPILinuxInvalidDevice(c *C) {
	expectedPPI := new(mockPPI)
	dev := new(linux.RawDevice)
	s.rawToPPIMap[dev] = expectedPPI

	_, err := ObtainTPMDevicePPILinux(tpm2.TPMDevice(nil))
	c.Assert(err, ErrorMatches, `not a linux tpm2.TPMDevice`)
}

func (s *actionsPpiLinuxSuite) TestObtainTPMDevicePPILinuxRawDeviceNoPPI(c *C) {
	p, err := ObtainTPMDevicePPILinux(new(linux.RawDevice))
	c.Check(err, IsNil)
	c.Check(p, IsNil)
}

func (s *actionsPpiLinuxSuite) TestObtainTPMDevicePPILinuxRMDeviceNoPPI(c *C) {
	dev := new(linux.RMDevice)
	s.rmToRawMap[dev] = new(linux.RawDevice)

	p, err := ObtainTPMDevicePPILinux(dev)
	c.Check(err, IsNil)
	c.Check(p, IsNil)
}

func (s *actionsPpiLinuxSuite) TestObtainTPMDevicePPILinuxRawDeviceErr(c *C) {
	s.ppiErr = errors.New("some error")

	_, err := ObtainTPMDevicePPILinux(new(linux.RawDevice))
	c.Check(err, ErrorMatches, `some error`)
}

func (s *actionsPpiLinuxSuite) TestObtainTPMDevicePPILinuxRMDeviceErr(c *C) {
	dev := new(linux.RMDevice)
	s.rmToRawMap[dev] = new(linux.RawDevice)
	s.ppiErr = errors.New("some error")

	_, err := ObtainTPMDevicePPILinux(dev)
	c.Check(err, ErrorMatches, `some error`)
}
