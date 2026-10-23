// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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

	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

func (s *hostSecurityARM64Suite) TestCheckHostSecurityGoodDGXSparkVerified(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithARM64Environment("NVIDIA", "GB10"),
		efitest.WithSysfsDevices(makeArm64IOMMUDevices()...),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	integrity, err := CheckHostSecurity(env, log)
	c.Check(err, IsNil)
	c.Check(integrity, Equals, PlatformFirmwareIntegrityVerified)
}

func (s *hostSecurityARM64Suite) TestCheckHostSecurityGoodRTXSparkVerified(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithARM64Environment("NVIDIA", "NVIDIA RTX Spark N1X (5120-core GPU, 18-core CPU)"),
		efitest.WithSysfsDevices(makeArm64IOMMUDevices()...),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	integrity, err := CheckHostSecurity(env, log)
	c.Check(err, IsNil)
	c.Check(integrity, Equals, PlatformFirmwareIntegrityVerified)
}

func (s *hostSecurityARM64Suite) TestCheckHostSecurityGoodRTXSparkAlternativeSKUVerified(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithARM64Environment("NVIDIA", "NVIDIA RTX Spark N1X (4096-core GPU, 16-core CPU)"),
		efitest.WithSysfsDevices(makeArm64IOMMUDevices()...),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	integrity, err := CheckHostSecurity(env, log)
	c.Check(err, IsNil)
	c.Check(integrity, Equals, PlatformFirmwareIntegrityVerified)
}

func (s *hostSecurityARM64Suite) TestCheckHostSecurityErrUnsupportedNVIDIACPUVersion(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithARM64Environment("NVIDIA", "N2X"))

	_, err := CheckHostSecurity(env, nil)
	c.Check(err, ErrorMatches, `unsupported platform: unsupported NVIDIA CPU version: N2X`)
	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}
