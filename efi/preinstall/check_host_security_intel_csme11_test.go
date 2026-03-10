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

type hostSecurityIntelCsme11Suite struct{}

var _ = Suite(&hostSecurityIntelCsme11Suite{})

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11GoodFVMEProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 16}, HfstsRegistersCsme11{
		Hfsts1: 0x94000245,
		Hfsts6: 0xC7E003CB,
	})
	c.Check(err, IsNil)
}

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11GoodFVEProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 16}, HfstsRegistersCsme11{
		Hfsts1: 0x94000245,
		Hfsts6: 0xC7E002CB,
	})
	c.Check(err, IsNil)
}

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11Good13(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 13}, HfstsRegistersCsme11{
		Hfsts1: 0x94000245,
		Hfsts6: 0x87C003CB,
	})
	c.Check(err, IsNil)
}

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11Good15(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 15}, HfstsRegistersCsme11{
		Hfsts1: 0x94000245,
		Hfsts6: 0xC7C003CB,
	})
	c.Check(err, IsNil)
}

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11ErrMfgMode(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 13}, HfstsRegistersCsme11{
		Hfsts1: 0x94000255,
		Hfsts6: 0x87C003CB,
	})
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: system is in manufacturing mode`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11ErrFPFsNotLocked(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 15}, HfstsRegistersCsme11{
		Hfsts1: 0x94000245,
		Hfsts6: 0x87C003CB,
	})
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: system is in manufacturing mode`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11ErrNoManufLock(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 16}, HfstsRegistersCsme11{
		Hfsts1: 0x94000245,
		Hfsts6: 0x87C003CB,
	})
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: system is in manufacturing mode`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11ErrBootGuardDisabled(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 16}, HfstsRegistersCsme11{
		Hfsts1: 0x94000245,
		Hfsts6: 0xD7E003CB,
	})
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard is disabled`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11ErrInvalidProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 16}, HfstsRegistersCsme11{
		Hfsts1: 0x94000245,
		Hfsts6: 0xC7E0024A,
	})
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: cannot determine BootGuard profile: invalid profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11ErrUnsupportedNoFVMEProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 16}, HfstsRegistersCsme11{
		Hfsts1: 0x94000245,
		Hfsts6: 0xC7E00002,
	})
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: unsupported BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (*hostSecurityIntelCsme11Suite) TestCheckHostSecurityIntelBootGuardCSME11ErrUnsupportedVMProfile(c *C) {
	err := CheckHostSecurityIntelBootGuardCSME11(MeVersion{Major: 16}, HfstsRegistersCsme11{
		Hfsts1: 0x94000245,
		Hfsts6: 0xC7E0030A,
	})
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: unsupported BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}
