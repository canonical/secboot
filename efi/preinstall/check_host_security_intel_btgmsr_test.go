//go:build amd64

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
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi/preinstall"
)

type hostSecurityIntelBtgMSRSuite struct{}

var _ = Suite(&hostSecurityIntelBtgMSRSuite{})

func (*hostSecurityIntelBtgMSRSuite) TestCheckHostSecurityIntelBootGuardMSRGoodFVMEProfile(c *C) {
	c.Check(CheckHostSecurityIntelBootGuardMSR(0x000000030000007d), IsNil)
}

func (*hostSecurityIntelBtgMSRSuite) TestCheckHostSecurityIntelBootGuardMSRGoodFVEProfile(c *C) {
	c.Check(CheckHostSecurityIntelBootGuardMSR(0x000000030000005d), IsNil)
}

func (*hostSecurityIntelBtgMSRSuite) TestCheckHostSecurityIntelBootGuardMSRErrInvalidProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardMSR(0x000000030000007c)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: cannot determine BootGuard profile: invalid profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelBtgMSRSuite) TestCheckHostSecurityIntelBootGuardMSRErrUnsupportedNoFVMEProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardMSR(0x000000030000000c)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: unsupported BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelBtgMSRSuite) TestCheckHostSecurityIntelBootGuardMSRErrUnsupportedVMProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardMSR(0x000000030000006d)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: unsupported BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelBtgMSRSuite) TestCheckHostSecurityIntelBootGuardMSRErrNoBtg(c *C) {
	err := CheckHostSecurityIntelBootGuardMSR(0)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard ACM is not active`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}
