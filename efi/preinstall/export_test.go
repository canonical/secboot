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
	"encoding/json"
	"io"

	efi "github.com/canonical/go-efilib"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	pe "github.com/snapcore/secboot/internal/pe1.14"
)

type (
	AuthorityTrust                        = authorityTrust
	AuthorityTrustData                    = authorityTrustData
	AuthorityTrustDataSet                 = authorityTrustDataSet
	BootManagerCodeResultFlags            = bootManagerCodeResultFlags
	CheckDriversAndAppsMeasurementsResult = checkDriversAndAppsMeasurementsResult
	CheckFirmwareLogFlags                 = checkFirmwareLogFlags
	CheckTPM2DeviceFlags                  = checkTPM2DeviceFlags
	CpuVendor                             = cpuVendor
	DetectVirtResult                      = detectVirtResult
	JoinError                             = joinError
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
	CheckFirmwareLogPermitEmptyPCRBanks        = checkFirmwareLogPermitEmptyPCRBanks
	CheckFirmwareLogPermitWeakPCRBanks         = checkFirmwareLogPermitWeakPCRBanks
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
	CheckDriversAndAppsMeasurements                       = checkDriversAndAppsMeasurements
	CheckFirmwareLogAndChoosePCRBank                      = checkFirmwareLogAndChoosePCRBank
	CheckForKernelIOMMU                                   = checkForKernelIOMMU
	CheckHostSecurity                                     = checkHostSecurity
	CheckHostSecurityIntelBootGuard                       = checkHostSecurityIntelBootGuard
	CheckHostSecurityIntelCPUDebuggingLocked              = checkHostSecurityIntelCPUDebuggingLocked
	CheckSecureBootPolicyMeasurementsAndObtainAuthorities = checkSecureBootPolicyMeasurementsAndObtainAuthorities
	CheckSecureBootPolicyPCRForDegradedFirmwareSettings   = checkSecureBootPolicyPCRForDegradedFirmwareSettings
	CheckSystemIsEFI                                      = checkSystemIsEFI
	ClearTPM                                              = clearTPM
	DetectVirtualization                                  = detectVirtualization
	DetermineCPUVendor                                    = determineCPUVendor
	ErrInvalidLockoutAuthValueSupplied                    = errInvalidLockoutAuthValueSupplied
	IsLaunchedFromLoadOption                              = isLaunchedFromLoadOption
	IsPPIActionAvailable                                  = isPPIActionAvailable
	IsTPMDiscrete                                         = isTPMDiscrete
	IsTPMDiscreteFromIntelBootGuard                       = isTPMDiscreteFromIntelBootGuard
	JoinErrors                                            = joinErrors
	NewX509CertificateID                                  = newX509CertificateID
	OpenAndCheckTPM2Device                                = openAndCheckTPM2Device
	ReadCurrentBootLoadOptionFromLog                      = readCurrentBootLoadOptionFromLog
	ReadIntelHFSTSRegistersFromMEISysfs                   = readIntelHFSTSRegistersFromMEISysfs
	ReadIntelMEVersionFromMEISysfs                        = readIntelMEVersionFromMEISysfs
	ReadLoadOptionFromLog                                 = readLoadOptionFromLog
	RunPPIAction                                          = runPPIAction
	UnwrapCompoundError                                   = unwrapCompoundError
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

func MockKnownCAs(set AuthorityTrustDataSet) (restore func()) {
	orig := knownCAs
	knownCAs = set
	return func() {
		knownCAs = orig
	}
}

func MockPeNewFile(fn func(io.ReaderAt) (*pe.File, error)) (restore func()) {
	orig := peNewFile
	peNewFile = fn
	return func() {
		peNewFile = orig
	}
}

func MockRunChecksEnv(env internal_efi.HostEnvironment) (restore func()) {
	orig := runChecksEnv
	runChecksEnv = env
	return func() {
		runChecksEnv = orig
	}
}

func NewWithKindAndActionsErrorForTest(kind ErrorKind, args map[string]json.RawMessage, actions []Action, err error) *WithKindAndActionsError {
	return &WithKindAndActionsError{
		Kind:    kind,
		Args:    args,
		Actions: actions,
		err:     err,
	}
}
