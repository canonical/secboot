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

package preinstall

import (
	"errors"
	"fmt"
)

// checkHostSecurityIntelBootGuardMSR checks the BootGuard configuration using the BootGuard status
// MSR rather than the HFSTS registers. The MSR is mirrored by the startup ACM - it will contain
// all zeroes if this didn't execute, in which case, BootGuard is not active.
//
// This has some limitations compared with using the HFSTS registers. Eg, it's not possible to
// ensure that the system has properly transitioned out of manufacturing mode.
func checkHostSecurityIntelBootGuardMSR(status bootGuardStatus) error {
	if status&bootGuardCapability == 0 {
		return &NoHardwareRootOfTrustError{errors.New("BootGuard ACM is not active")}
	}

	// Check the BootGuard profile.
	profile, err := status.btgProfile()
	if err != nil {
		return &NoHardwareRootOfTrustError{fmt.Errorf("cannot determine BootGuard profile: %w", err)}
	}
	switch profile {
	case btgProfileFVE, btgProfileFVME:
		// We require verified boot, so the 2 profiles with forced
		// verification are ok.
		return nil
	default:
		return &NoHardwareRootOfTrustError{errors.New("unsupported BootGuard profile")}
	}
}
