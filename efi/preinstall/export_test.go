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
	"crypto"
	"io"

	efi "github.com/canonical/go-efilib"
	pe "github.com/snapcore/secboot/internal/pe1.14"
)

type (
	AuthorityTrust                        = authorityTrust
	AuthorityTrustData                    = authorityTrustData
	AuthorityTrustDataSet                 = authorityTrustDataSet
	BootManagerCodeResultFlags            = bootManagerCodeResultFlags
	CheckDriversAndAppsMeasurementsResult = checkDriversAndAppsMeasurementsResult
	CheckTPM2DeviceFlags                  = checkTPM2DeviceFlags
	CpuVendor                             = cpuVendor
	DetectVirtResult                      = detectVirtResult
	MeVersion                             = meVersion
	SecureBootPolicyResult                = secureBootPolicyResult
	SecureBootPolicyResultFlags           = secureBootPolicyResultFlags
)

const (
	AuthorityTrustBootCode                     = authorityTrustBootCode
	AuthorityTrustDrivers                      = authorityTrustDrivers
	BootManagerCodeSysprepAppsPresent          = bootManagerCodeSysprepAppsPresent
	BootManagerCodeAbsoluteComputraceRunning   = bootManagerCodeAbsoluteComputraceRunning
	BootManagerCodeNotAllLaunchDigestsVerified = bootManagerCodeNotAllLaunchDigestsVerified
	CheckTPM2DeviceInVM                        = checkTPM2DeviceInVM
	CheckTPM2DevicePostInstall                 = checkTPM2DevicePostInstall
	CpuVendorIntel                             = cpuVendorIntel
	CpuVendorAMD                               = cpuVendorAMD
	DetectVirtNone                             = detectVirtNone
	DetectVirtVM                               = detectVirtVM
	DriversAndAppsPresent                      = driversAndAppsPresent
	MeFamilyUnknown                            = meFamilyUnknown
	MeFamilySps                                = meFamilySps
	MeFamilyTxe                                = meFamilyTxe
	MeFamilyMe                                 = meFamilyMe
	MeFamilyCsme                               = meFamilyCsme
	NoDriversAndAppsPresent                    = noDriversAndAppsPresent
	SecureBootIncludesWeakAlg                  = secureBootIncludesWeakAlg
	SecureBootPreOSVerificationIncludesDigest  = secureBootPreOSVerificationIncludesDigest
)

var (
	CalculateIntelMEFamily                                = calculateIntelMEFamily
	CheckBootManagerCodeMeasurements                      = checkBootManagerCodeMeasurements
	CheckCPUDebuggingLockedMSR                            = checkCPUDebuggingLockedMSR
	CheckDriversAndAppsMeasurements                       = checkDriversAndAppsMeasurements
	CheckFirmwareLogAndChoosePCRBank                      = checkFirmwareLogAndChoosePCRBank
	CheckForKernelIOMMU                                   = checkForKernelIOMMU
	CheckPlatformFirmwareProtections                      = checkPlatformFirmwareProtections
	CheckPlatformFirmwareProtectionsIntelMEI              = checkPlatformFirmwareProtectionsIntelMEI
	CheckSecureBootPolicyMeasurementsAndObtainAuthorities = checkSecureBootPolicyMeasurementsAndObtainAuthorities
	CheckSecureBootPolicyPCRForDegradedFirmwareSettings   = checkSecureBootPolicyPCRForDegradedFirmwareSettings
	DetectVirtualization                                  = detectVirtualization
	DetermineCPUVendor                                    = determineCPUVendor
	IsLaunchedFromLoadOption                              = isLaunchedFromLoadOption
	OpenAndCheckTPM2Device                                = openAndCheckTPM2Device
	ReadIntelHFSTSRegistersFromMEISysfs                   = readIntelHFSTSRegistersFromMEISysfs
	ReadIntelMEVersionFromMEISysfs                        = readIntelMEVersionFromMEISysfs
	ReadLoadOptionFromLog                                 = readLoadOptionFromLog
)

func MockEfiComputePeImageDigest(fn func(crypto.Hash, io.ReaderAt, int64) ([]byte, error)) (restore func()) {
	orig := efiComputePeImageDigest
	efiComputePeImageDigest = fn
	return func() {
		efiComputePeImageDigest = orig
	}
}

func MockInternalEfiSecureBootSignaturesFromPEFile(fn func(*pe.File, io.ReaderAt) ([]*efi.WinCertificateAuthenticode, error)) (restore func()) {
	orig := internal_efiSecureBootSignaturesFromPEFile
	internal_efiSecureBootSignaturesFromPEFile = fn
	return func() {
		internal_efiSecureBootSignaturesFromPEFile = orig
	}
}

func MockPeNewFile(fn func(io.ReaderAt) (*pe.File, error)) (restore func()) {
	orig := peNewFile
	peNewFile = fn
	return func() {
		peNewFile = orig
	}
}

func MockKnownCAs(set AuthorityTrustDataSet) (restore func()) {
	orig := knownCAs
	knownCAs = set
	return func() {
		knownCAs = orig
	}
}
