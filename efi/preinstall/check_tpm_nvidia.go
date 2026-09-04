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
	"fmt"

	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// isTPMDiscreteNvidia determines whether the default TPM is discrete on NVIDIA systems
func isTPMDiscreteNvidia(env internal_efi.HostEnvironmentARM64) (bool, error) {
	cpuVersion, err := env.CPUVersion()
	if err != nil {
		return false, &UnsupportedPlatformError{fmt.Errorf("cannot determine CPU version: %w", err)}
	}

	switch {
	// We just happen to know that the NVIDIA DGX Spark and RTX Spark have a dTPM
	case isNvidiaSparkCPUVersion(cpuVersion):
		return true, nil
	default:
		return false, &UnsupportedPlatformError{fmt.Errorf("unsupported NVIDIA CPU version: %s", cpuVersion)}
	}
}
