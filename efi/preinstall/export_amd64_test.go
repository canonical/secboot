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

type (
	CpuVendor            = cpuVendor
	HfstsRegisters       = hfstsRegisters
	HfstsRegistersCsme11 = hfstsRegistersCsme11
	HfstsRegistersCsme18 = hfstsRegistersCsme18
	MeVersion            = meVersion
)

const (
	CpuVendorIntel  = cpuVendorIntel
	CpuVendorAMD    = cpuVendorAMD
	MeFamilyUnknown = meFamilyUnknown
	MeFamilySps     = meFamilySps
	MeFamilyTxe     = meFamilyTxe
	MeFamilyMe      = meFamilyMe
	MeFamilyCsme    = meFamilyCsme
)

var (
	CalculateIntelMEFamily                   = calculateIntelMEFamily
	CheckHostSecurityAMDPSP                  = checkHostSecurityAMDPSP
	CheckHostSecurityIntelBootGuard          = checkHostSecurityIntelBootGuard
	CheckHostSecurityIntelBootGuardCSME11    = checkHostSecurityIntelBootGuardCSME11
	CheckHostSecurityIntelBootGuardCSME18    = checkHostSecurityIntelBootGuardCSME18
	CheckHostSecurityIntelCPUDebuggingLocked = checkHostSecurityIntelCPUDebuggingLocked
	DetermineCPUVendor                       = determineCPUVendor
	IsTPMDiscreteFromIntelBootGuard          = isTPMDiscreteFromIntelBootGuard
	ReadIntelHFSTSRegistersFromMEISysfs      = readIntelHFSTSRegistersFromMEISysfs
	ReadIntelMEVersionFromMEISysfs           = readIntelMEVersionFromMEISysfs
)
