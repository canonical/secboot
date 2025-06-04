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

	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// isTPMDiscrete determines whether the TPM is discrete
func isTPMDiscrete(env internal_efi.HostEnvironment) (bool, error) {
	amd64, err := env.AMD64()
	if err != nil {
		return false, err
	}

	cpuVendor, err := determineCPUVendor(env)
	if err != nil {
		return false, &UnsupportedPlatformError{fmt.Errorf("cannot determine CPU vendor: %w", err)}
	}

	switch cpuVendor {
	case cpuVendorIntel:
		discrete, err := isTPMDiscreteFromIntelBootGuard(amd64)
		if err != nil {
			return false, fmt.Errorf("cannot check TPM discreteness using Intel BootGuard status: %w", err)
		}
		return discrete, nil
	case cpuVendorAMD:
		return false, &UnsupportedPlatformError{errors.New("cannot check TPM discreteness on AMD systems")}
	default:
		panic("not reached")
	}
}
