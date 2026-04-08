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

	internal_efi "github.com/snapcore/secboot/internal/efi"
)

const bootGuardStatusMsr = 0x13a

type bootGuardStatus uint64

const (
	bootGuardNEM          bootGuardStatus = 1 << 0
	bootGuardFACB         bootGuardStatus = 1 << 4
	bootGuardMeasuredBoot bootGuardStatus = 1 << 5
	bootGuardVerifiedBoot bootGuardStatus = 1 << 6
	bootGuardCapability   bootGuardStatus = 1 << 32

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

func (s bootGuardStatus) btgProfile() (btgProfile, error) {
	// We can't check the error enforcement policy here, either because it's
	// not mirrored into the MSR, or it is but we don't know which 2 bits to
	// use. We just interpret the other bits into one of the well known No_FVME,
	// VM, FVE and FVME profiles. This is ok because there are no known profiles
	// where these bits are reused with different error enforcement policies.
	f := s&bootGuardFACB > 0
	v := s&bootGuardVerifiedBoot > 0
	m := s&bootGuardMeasuredBoot > 0
	p := s&bootGuardNEM > 0

	switch {
	case !f && !v && !m && !p:
		return btgProfileNoFVME, nil
	case !f && v && m && p:
		return btgProfileVM, nil
	case f && v && !m && p:
		return btgProfileFVE, nil
	case f && v && m && p:
		return btgProfileFVME, nil
	default:
		return 0, errors.New("invalid profile")
	}
}

func readIntelBootGuardStatus(env internal_efi.HostEnvironmentAMD64) (bootGuardStatus, error) {
	msrValue, err := env.ReadMSRs(bootGuardStatusMsr)
	if err != nil {
		return 0, err
	}

	// NOTE: msrValue[0] is fine because BootGuard status MSR has the same value across all CPUs
	return bootGuardStatus(msrValue[0]), nil
}
