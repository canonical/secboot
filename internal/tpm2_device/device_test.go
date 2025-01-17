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
	"testing"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/ppi"
	. "github.com/snapcore/secboot/internal/tpm2_device"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type mockTpmDevice struct{}

func (mockTpmDevice) Open() (tpm2.Transport, error) {
	return nil, errors.New("cannot open mock transport")
}

func (mockTpmDevice) String() string {
	return "mock device"
}

type mockPPI struct {
	ppi.PPI
}

type deviceSuite struct{}

var _ = Suite(&deviceSuite{})

func (s *deviceSuite) TestTPMDeviceDevice(c *C) {
	dev := NewTPMDevice(new(mockTpmDevice), DeviceModeDirect, nil, ErrNoPPI)
	c.Check(dev.String(), Equals, "mock device")
	_, err := dev.Open()
	c.Check(err, ErrorMatches, `cannot open mock transport`)
}

func (s *deviceSuite) TestTPMDeviceMode(c *C) {
	dev := NewTPMDevice(new(mockTpmDevice), DeviceModeDirect, nil, ErrNoPPI)
	c.Check(dev.Mode(), Equals, DeviceModeDirect)

	dev = NewTPMDevice(new(mockTpmDevice), DeviceModeResourceManaged, nil, ErrNoPPI)
	c.Check(dev.Mode(), Equals, DeviceModeResourceManaged)
}

func (s *deviceSuite) TestTPMDevicePPINone(c *C) {
	dev := NewTPMDevice(new(mockTpmDevice), DeviceModeDirect, nil, nil)
	ppi, err := dev.PPI()
	c.Check(err, Equals, ErrNoPPI)
	c.Check(ppi, IsNil)
}

func (s *deviceSuite) TestTPMDevicePPIErr(c *C) {
	expected := errors.New("some error")
	dev := NewTPMDevice(new(mockTpmDevice), DeviceModeDirect, nil, expected)
	ppi, err := dev.PPI()
	c.Check(err, Equals, expected)
	c.Check(ppi, IsNil)
}

func (s *deviceSuite) TestTPMDevicePPI(c *C) {
	expected := new(mockPPI)
	dev := NewTPMDevice(new(mockTpmDevice), DeviceModeDirect, expected, nil)
	ppi, err := dev.PPI()
	c.Check(err, IsNil)
	c.Check(ppi, Equals, expected)
}
