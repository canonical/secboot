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

	internal_efi "github.com/snapcore/secboot/internal/efi"
)

const bootGuardStatusMsr = 0x13a

type bootGuardStatus uint64

const (
	bootGuardStatusTPMShift                 = 1
	bootGuardStatusTPMMask  bootGuardStatus = (3 << bootGuardStatusTPMShift)
)

type bootGuardTPMStatus uint64

const (
	bootGuardTPMStatusNone bootGuardTPMStatus = 0
	bootGuardTPMStatus12   bootGuardTPMStatus = 1
	bootGuardTPMStatus2    bootGuardTPMStatus = 2
	bootGuardTPMStatusPTT  bootGuardTPMStatus = 3
)

func (s bootGuardStatus) tpmStatus() bootGuardTPMStatus {
	return bootGuardTPMStatus(s&bootGuardStatusTPMMask) >> bootGuardStatusTPMShift
}

func isTPMDiscreteFromIntelBootGuard(env internal_efi.HostEnvironmentAMD64) (bool, error) {
	msrValue, err := env.ReadMSRs(bootGuardStatusMsr)
	switch {
	case errors.Is(err, internal_efi.ErrNoKernelMSRSupport):
		return false, MissingKernelModuleError("msr")
	case err != nil:
		return false, fmt.Errorf("cannot read BootGuard status MSR: %w", err)
	}

	status := bootGuardStatus(msrValue[0])

	// NOTE: bootGuardStatus[0] is fine because BootGuard status MSR has the same value across all CPUs
	switch status.tpmStatus() {
	case bootGuardTPMStatusNone, bootGuardTPMStatus12:
		// System has no TPM or unsupported TPM 1.2 device
		return false, ErrNoTPM2Device
	case bootGuardTPMStatus2:
		// System has a discrete TPM 2.0 device
		return true, nil
	case bootGuardTPMStatusPTT:
		// System has a PTT firmware TPM
		return false, nil
	default:
		panic("executing unreachable code")
	}
}
