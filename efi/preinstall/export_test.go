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
	CheckTPM2DeviceFlags      = checkTPM2DeviceFlags
	CpuVendor                 = cpuVendor
	DetectVirtResult          = detectVirtResult
	DriversAndAppsResultFlags = driversAndAppsResultFlags
	MeVersion                 = meVersion
)

const (
	CheckTPM2DeviceInVM          = checkTPM2DeviceInVM
	CheckTPM2DevicePostInstall   = checkTPM2DevicePostInstall
	CpuVendorIntel               = cpuVendorIntel
	CpuVendorAMD                 = cpuVendorAMD
	DetectVirtNone               = detectVirtNone
	DetectVirtVM                 = detectVirtVM
	DriversAndAppsDriversPresent = driversAndAppsDriversPresent
	MeFamilyUnknown              = meFamilyUnknown
	MeFamilySps                  = meFamilySps
	MeFamilyTxe                  = meFamilyTxe
	MeFamilyMe                   = meFamilyMe
	MeFamilyCsme                 = meFamilyCsme
)

var (
	CalculateIntelMEFamily                              = calculateIntelMEFamily
	CheckCPUDebuggingLockedMSR                          = checkCPUDebuggingLockedMSR
	CheckDriversAndAppsMeasurements                     = checkDriversAndAppsMeasurements
	CheckFirmwareLogAndChoosePCRBank                    = checkFirmwareLogAndChoosePCRBank
	CheckForKernelIOMMU                                 = checkForKernelIOMMU
	CheckPlatformFirmwareMeasurements                   = checkPlatformFirmwareMeasurements
	CheckPlatformFirmwareProtections                    = checkPlatformFirmwareProtections
	CheckPlatformFirmwareProtectionsIntelMEI            = checkPlatformFirmwareProtectionsIntelMEI
	CheckSecureBootPolicyPCRForDegradedFirmwareSettings = checkSecureBootPolicyPCRForDegradedFirmwareSettings
	DetectVirtualization                                = detectVirtualization
	DetermineCPUVendor                                  = determineCPUVendor
	OpenAndCheckTPM2Device                              = openAndCheckTPM2Device
	ReadIntelHFSTSRegistersFromMEISysfs                 = readIntelHFSTSRegistersFromMEISysfs
	ReadIntelMEVersionFromMEISysfs                      = readIntelMEVersionFromMEISysfs
)
