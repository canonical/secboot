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
	"strings"

	internal_efi "github.com/snapcore/secboot/internal/efi"
)

const nvidiaDGXSparkCPUVersion = "GB10"
const nvidiaRTXSparkCPUVersionPrefix = "NVIDIA RTX Spark"

// isNvidiaSparkCPUVersion reports whether cpuVersion identifies a supported NVIDIA
// Spark platform: either the DGX Spark (exact match on "GB10") or any RTX Spark
// variant (prefix match on "NVIDIA RTX Spark").
func isNvidiaSparkCPUVersion(cpuVersion string) bool {
	return cpuVersion == nvidiaDGXSparkCPUVersion || strings.HasPrefix(cpuVersion, nvidiaRTXSparkCPUVersionPrefix)
}

func checkHostSecurityNVIDIA(env internal_efi.HostEnvironmentARM64) (platformFirmwareIntegrityConfig, error) {
	cpuVersion, err := env.CPUVersion()
	if err != nil {
		return platformFirmwareIntegrityNone, &UnsupportedPlatformError{fmt.Errorf("cannot determine CPU version: %w", err)}
	}

	switch {
	case isNvidiaSparkCPUVersion(cpuVersion):
		return checkHostSecurityNVIDIASpark(env)
	default:
		return platformFirmwareIntegrityNone, &UnsupportedPlatformError{fmt.Errorf("unsupported NVIDIA CPU version: %s", cpuVersion)}
	}
}

func checkHostSecurityNVIDIASpark(env internal_efi.HostEnvironmentARM64) (platformFirmwareIntegrityConfig, error) {
	// TODO: Implement proper HW ROT fusing checks, once we have the documentation
	// from NVIDIA to do so. This will involve checking fuses and will return
	// platformFirmwareIntegrityVerified if set correctly.

	// TODO: Implement proper debug authentication checks, once we have the documentation
	// from NVIDIA to do so.
	return platformFirmwareIntegrityVerified, nil
}
