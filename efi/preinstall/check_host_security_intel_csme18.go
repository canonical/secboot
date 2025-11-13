//go:build amd64

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

package preinstall

import "errors"

type (
	hfsts1Csme18 uint32
	hfsts2Csme18 uint32
	hfsts3Csme18 uint32
	hfsts4Csme18 uint32
	hfsts5Csme18 uint32
	hfsts6Csme18 uint32

	hfstsRegistersCsme18 struct {
		Hfsts1 hfsts1Csme18
		Hfsts2 hfsts2Csme18
		Hfsts3 hfsts3Csme18
		Hfsts4 hfsts4Csme18
		Hfsts5 hfsts5Csme18
		Hfsts6 hfsts6Csme18
	}
)

func (reg hfsts5Csme18) btgProfile() btgProfile {
	return btgProfile(reg & hfsts5Csme18BtgProfile >> 18)
}

const (
	hfsts5Csme18BtgProfileValid hfsts5Csme18 = 1 << 1

	// hfsts5Csme18BtgProfile is the bitmask for the BootGuard profile.
	// fwupd defines this as 0xe0000, but I think this is off by one bit.
	// I see a profile value of 5 on my XPS16 (which is what I expect) if
	// the field is shifted left by 1 bit. Fwupd's definition of HFSTS5
	// only has 31 bits, which suggests that there is a field missing from
	// its definition.
	hfsts5Csme18BtgProfile hfsts5Csme18 = 0x1c0000
)

func toHfstsRegistersCsme18(regs hfstsRegisters) hfstsRegistersCsme18 {
	return hfstsRegistersCsme18{
		Hfsts1: (hfsts1Csme18)(regs.Hfsts1),
		Hfsts2: (hfsts2Csme18)(regs.Hfsts2),
		Hfsts3: (hfsts3Csme18)(regs.Hfsts3),
		Hfsts4: (hfsts4Csme18)(regs.Hfsts4),
		Hfsts5: (hfsts5Csme18)(regs.Hfsts5),
		Hfsts6: (hfsts6Csme18)(regs.Hfsts6),
	}
}

func checkHostSecurityIntelBootGuardCSME18(regs hfstsRegistersCsme18) error {
	// These checks are based on the HSI checks performed in the pci-mei
	// plugin in fwupd.

	// Check that the BootGuard profile is valid. I think that's what this
	// is checking - fwupd's definition of this bit is just called "valid".
	// This bit does exist for CSME #11, but the definition in slimbootloader
	// suggests that it indicates that the error status code and result status
	// code in bits 7:2 are valid. This bit is set of my XPS16 with CSME #18
	// and unset on my older XPS15.
	if regs.Hfsts5&hfsts5Csme18BtgProfileValid == 0 {
		return &NoHardwareRootOfTrustError{errors.New("invalid BootGuard profile")}
	}

	// Check the BootGuard profile.
	switch regs.Hfsts5.btgProfile() {
	case btgProfileFVE, btgProfileFVME:
		// We require verified boot, so the 2 profiles with forced
		// verification are ok.
	default:
		return &NoHardwareRootOfTrustError{errors.New("unsupported BootGuard profile")}
	}

	// Everything is ok
	return nil
}
