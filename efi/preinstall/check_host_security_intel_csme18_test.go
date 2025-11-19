//go:build amd64

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
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi/preinstall"
)

type hostSecurityIntelCsme18Suite struct{}

var _ = Suite(&hostSecurityIntelCsme18Suite{})

func (*hostSecurityIntelCsme18Suite) TestCheckHostSecurityIntelBootGuardCSME18GoodFVMEProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME18(HfstsRegistersCsme18{Hfsts5: 0x02F61F03})
	c.Check(err, IsNil)
}

func (*hostSecurityIntelCsme18Suite) TestCheckHostSecurityIntelBootGuardCSME18GoodFVEProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME18(HfstsRegistersCsme18{Hfsts5: 0x02F21F03})
	c.Check(err, IsNil)
}

func (*hostSecurityIntelCsme18Suite) TestCheckHostSecurityIntelBootGuardCSME18ErrInvalidProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME18(HfstsRegistersCsme18{Hfsts5: 0x02F61F01})
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: invalid BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelCsme18Suite) TestCheckHostSecurityIntelBootGuardCSME18ErrUnsupportedNoFVMEProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME18(HfstsRegistersCsme18{Hfsts5: 0x02E21F03})
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: unsupported BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelCsme18Suite) TestCheckHostSecurityIntelBootGuardCSME18ErrUnsupportedVMProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME18(HfstsRegistersCsme18{Hfsts5: 0x02EE1F03})
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: unsupported BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}
