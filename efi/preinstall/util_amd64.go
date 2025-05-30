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
	"fmt"

	internal_efi "github.com/snapcore/secboot/internal/efi"
)

type cpuVendor int

const (
	cpuVendorUnknown cpuVendor = iota
	cpuVendorIntel
	cpuVendorAMD
)

func determineCPUVendor(env internal_efi.HostEnvironment) (cpuVendor, error) {
	amd64, err := env.AMD64()
	if err != nil {
		return cpuVendorUnknown, err
	}

	switch amd64.CPUVendorIdentificator() {
	case "GenuineIntel":
		return cpuVendorIntel, nil
	case "AuthenticAMD":
		return cpuVendorAMD, nil
	default:
		return cpuVendorUnknown, fmt.Errorf("unknown CPU vendor: %s", amd64.CPUVendorIdentificator())
	}
}
