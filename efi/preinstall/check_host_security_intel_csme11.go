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

package preinstall

import (
	"errors"
	"fmt"
)

type (
	hfsts1Csme11 uint32
	hfsts2Csme11 uint32
	hfsts3Csme11 uint32
	hfsts4Csme11 uint32
	hfsts5Csme11 uint32
	hfsts6Csme11 uint32

	errorEnforcementPolicyCsme11 uint8

	hfstsRegistersCsme11 struct {
		Hfsts1 hfsts1Csme11
		Hfsts2 hfsts2Csme11
		Hfsts3 hfsts3Csme11
		Hfsts4 hfsts4Csme11
		Hfsts5 hfsts5Csme11
		Hfsts6 hfsts6Csme11
	}
)

func (reg hfsts6Csme11) errorEnforcementPolicy() errorEnforcementPolicyCsme11 {
	return errorEnforcementPolicyCsme11(reg & hfsts6Csme11ErrorEnforcementPolicy >> 6)
}

func (reg hfsts6Csme11) btgProfile() (btgProfile, error) {
	f := reg&hfsts6Csme11ForceBootPolicy > 0
	v := reg&hfsts6Csme11VerifiedBoot > 0
	m := reg&hfsts6Csme11MeasuredBoot > 0
	e := reg.errorEnforcementPolicy()
	p := reg&hfsts6Csme11ProtectBIOSEnv > 0

	switch {
	case !f && !v && !m && e == errorEnforcementPolicyCsme11Nothing && !p:
		return btgProfileNoFVME, nil
	case !f && v && m && e == errorEnforcementPolicyCsme11Nothing && p:
		return btgProfileVM, nil
	case f && v && !m && e == errorEnforcementPolicyCsme11ShutdownNow && p:
		return btgProfileFVE, nil
	case f && v && m && e == errorEnforcementPolicyCsme11ShutdownNow && p:
		return btgProfileFVME, nil
	default:
		return 0, errors.New("invalid profile")
	}
}

func toHfstsRegistersCsme11(regs hfstsRegisters) hfstsRegistersCsme11 {
	return hfstsRegistersCsme11{
		Hfsts1: (hfsts1Csme11)(regs.Hfsts1),
		Hfsts2: (hfsts2Csme11)(regs.Hfsts2),
		Hfsts3: (hfsts3Csme11)(regs.Hfsts3),
		Hfsts4: (hfsts4Csme11)(regs.Hfsts4),
		Hfsts5: (hfsts5Csme11)(regs.Hfsts5),
		Hfsts6: (hfsts6Csme11)(regs.Hfsts6),
	}
}

const (
	// hfsts1Csme11MfgMode indicates that the system is in manufacturing mode. Note that
	// fwupd and coreboot refer to this bit as manufacturing mode whilst slimbootloader refers
	// to this as SPI protection mode. Based on this and the comments in coreboot, this bit
	// is set when the SPI flash descriptor is locked.
	hfsts1Csme11MfgMode hfsts1Csme11 = 1 << 4

	hfsts6Csme11ForceBootPolicy        hfsts6Csme11 = 1 << 0
	hfsts6Csme11CpuDebugDisable        hfsts6Csme11 = 1 << 1
	hfsts6Csme11ProtectBIOSEnv         hfsts6Csme11 = 1 << 3
	hfsts6Csme11ErrorEnforcementPolicy hfsts6Csme11 = 0xc0
	hfsts6Csme11MeasuredBoot           hfsts6Csme11 = 1 << 8
	hfsts6Csme11VerifiedBoot           hfsts6Csme11 = 1 << 9
	hfsts6Csme11MfgLock                hfsts6Csme11 = 1 << 21
	hfsts6Csme11BootGuardDisable       hfsts6Csme11 = 1 << 28
	hfsts6Csme11FPFSOCLock             hfsts6Csme11 = 1 << 30

	errorEnforcementPolicyCsme11Nothing        errorEnforcementPolicyCsme11 = 0
	errorEnforcementPolicyCsme11Shutdown30Mins errorEnforcementPolicyCsme11 = 1 // fwupd defines this as 3, which I think is wrong.
	errorEnforcementPolicyCsme11ShutdownNow    errorEnforcementPolicyCsme11 = 3 // fwupd defines this as 2, which I think is wrong.
)

func isInManufacturingModeCSME11(vers meVersion, regs hfstsRegistersCsme11) bool {
	// This is based on the checks from
	// https://github.com/coreboot/coreboot/blob/eb5bdf06b92534b6f66f612297a4ccb69008b4ac/src/soc/intel/common/block/cse/cse_spec.c#L15
	if regs.Hfsts1&hfsts1Csme11MfgMode > 0 {
		return true
	}
	if vers.Major > 13 {
		if regs.Hfsts6&hfsts6Csme11FPFSOCLock == 0 {
			return true
		}
	}
	if vers.Major > 15 {
		if regs.Hfsts6&hfsts6Csme11MfgLock == 0 {
			return true
		}
	}
	return false
}

// checkHostSecurityIntelBootGuardCSME11 checks the BootGuard configuration CSME versions 11 to 17.
func checkHostSecurityIntelBootGuardCSME11(vers meVersion, regs hfstsRegistersCsme11) error {
	// These checks are based on the HSI checks performed in the pci-mei
	// plugin in fwupd.

	// Make sure that the system is not in manufacturing mode.
	if isInManufacturingModeCSME11(vers, regs) {
		return &NoHardwareRootOfTrustError{errors.New("system is in manufacturing mode")}
	}

	// Check that BootGuard is enabled.
	if regs.Hfsts6&hfsts6Csme11BootGuardDisable > 0 {
		return &NoHardwareRootOfTrustError{errors.New("BootGuard is disabled")}
	}

	// Check the BootGuard profile.
	profile, err := regs.Hfsts6.btgProfile()
	if err != nil {
		return &NoHardwareRootOfTrustError{fmt.Errorf("cannot determine BootGuard profile: %w", err)}
	}
	switch profile {
	case btgProfileFVE, btgProfileFVME:
		// We require verified boot, so the 2 profiles with forced
		// verification are ok.
	default:
		return &NoHardwareRootOfTrustError{errors.New("unsupported BootGuard profile")}
	}

	// Everything is ok
	return nil
}
