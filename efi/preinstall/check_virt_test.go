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

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
)

type virtSuite struct{}

var _ = Suite(&virtSuite{})

func (s *virtSuite) TestDetectVirtualizationNone(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll))
	mode, err := DetectVirtualization(env)
	c.Check(err, IsNil)
	c.Check(mode, Equals, DetectVirtNone)
}

func (s *virtSuite) TestDetectVirtualizationContainer(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithVirtMode("lxc", internal_efi.DetectVirtModeContainer))
	_, err := DetectVirtualization(env)
	c.Check(err, ErrorMatches, `container environments are not supported`)
}

func (s *virtSuite) TestDetectVirtualizationVM(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithVirtMode("qemu", internal_efi.DetectVirtModeVM))
	mode, err := DetectVirtualization(env)
	c.Check(err, IsNil)
	c.Check(mode, Equals, DetectVirtVM)
}

func (s *virtSuite) TestDetectVirtualizationDetectVirtModeErr1(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithVirtModeError(errors.New("some error")))
	_, err := DetectVirtualization(env)
	c.Check(err, ErrorMatches, `cannot detect if environment is virtualized: some error`)
}

func (s *virtSuite) TestDetectVirtualizationDetectVirtModeErr2(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithDelayedVirtMode("lxc", internal_efi.DetectVirtModeContainer),
		efitest.WithDelayedVirtModeError(errors.New("some error")),
	)
	_, err := DetectVirtualization(env)
	c.Check(err, ErrorMatches, `cannot detect if environment is a container: some error`)
}

func (s *virtSuite) TestDetectVirtualizationDetectVirtModeErr3(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithDelayedVirtMode("qemu", internal_efi.DetectVirtModeVM),
		efitest.WithDelayedVirtMode("qemu", internal_efi.DetectVirtModeVM),
		efitest.WithDelayedVirtModeError(errors.New("some error")),
	)
	_, err := DetectVirtualization(env)
	c.Check(err, ErrorMatches, `cannot detect if environment is a VM: some error`)
}

func (s *virtSuite) TestDetectVirtualizationDetectVirtModeErr4(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithDelayedVirtMode("qemu", internal_efi.DetectVirtModeVM),
		efitest.WithDelayedVirtMode("qemu", internal_efi.DetectVirtModeVM),
		efitest.WithDelayedVirtMode("kvm", internal_efi.DetectVirtModeVM),
	)
	_, err := DetectVirtualization(env)
	c.Check(err, ErrorMatches, `unexpected return value from HostEnvironment.DetectVirtMode\(DetectVirtModeVM\) \(got:\"kvm\", expected:\"qemu\"\)`)
}
