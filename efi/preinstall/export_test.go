// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024-2026 Canonical Ltd
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
	"github.com/canonical/go-tpm2"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	pe "github.com/snapcore/secboot/internal/pe1.14"
)

type (
	AuthorityTrustFlags         = authorityTrustFlags
	AuthorityTrustData          = authorityTrustData
	AuthorityTrustDataSet       = authorityTrustDataSet
	BootManagerCodeResult       = bootManagerCodeResult
	CheckFirmwareLogFlags       = checkFirmwareLogFlags
	CheckTPM2DeviceFlags        = checkTPM2DeviceFlags
	CpuVendor                   = cpuVendor
	DetectVirtResult            = detectVirtResult
	HfstsRegisters              = hfstsRegisters
	HfstsRegistersCsme11        = hfstsRegistersCsme11
	HfstsRegistersCsme18        = hfstsRegistersCsme18
	JoinError                   = joinError
	MeVersion                   = meVersion
	PcrResults                  = pcrResults
	SecureBootPolicyResult      = secureBootPolicyResult
	SecureBootPolicyResultFlags = secureBootPolicyResultFlags
)

const (
	AuthorityTrustBootCode                      = authorityTrustBootCode
	AuthorityTrustDrivers                       = authorityTrustDrivers
	CheckFirmwareLogPermitWeakPCRBanks          = checkFirmwareLogPermitWeakPCRBanks
	CheckTPM2DevicePostInstall                  = checkTPM2DevicePostInstall
	CpuVendorAMD                                = cpuVendorAMD
	CpuVendorIntel                              = cpuVendorIntel
	DetectVirtNone                              = detectVirtNone
	DetectVirtVM                                = detectVirtVM
	DiscreteTPMDetected                         = discreteTPMDetected
	DtpmPartialResetAttackMitigationNotRequired = dtpmPartialResetAttackMitigationNotRequired
	DtpmPartialResetAttackMitigationPreferred   = dtpmPartialResetAttackMitigationPreferred
	DtpmPartialResetAttackMitigationUnavailable = dtpmPartialResetAttackMitigationUnavailable
	InsufficientDMAProtectionDetected           = insufficientDMAProtectionDetected
	MeFamilyCsme                                = meFamilyCsme
	MeFamilyMe                                  = meFamilyMe
	MeFamilySps                                 = meFamilySps
	MeFamilyTxe                                 = meFamilyTxe
	MeFamilyUnknown                             = meFamilyUnknown
	PlatformFirmwareIntegrityNone               = platformFirmwareIntegrityNone
	PlatformFirmwareIntegrityMeasured           = platformFirmwareIntegrityMeasured
	PlatformFirmwareIntegrityVerified           = platformFirmwareIntegrityVerified
	SecureBootIncludesWeakAlg                   = secureBootIncludesWeakAlg
	SecureBootPreOSVerificationIncludesDigest   = secureBootPreOSVerificationIncludesDigest
	SecureBootNoDeployedMode                    = secureBootNoDeployedMode
	StartupLocalityNotProtected                 = startupLocalityNotProtected
)

var (
	CalculateIntelMEFamily                                = calculateIntelMEFamily
	CheckBootManagerCodeMeasurements                      = checkBootManagerCodeMeasurements
	CheckHostSecurityAMDPSP                               = checkHostSecurityAMDPSP
	CheckHostSecurityIntelBootGuard                       = checkHostSecurityIntelBootGuard
	CheckHostSecurityIntelBootGuardCSME11                 = checkHostSecurityIntelBootGuardCSME11
	CheckHostSecurityIntelBootGuardCSME18                 = checkHostSecurityIntelBootGuardCSME18
	CheckHostSecurityIntelBootGuardMSR                    = checkHostSecurityIntelBootGuardMSR
	CheckHostSecurityIntelCPUDebuggingLocked              = checkHostSecurityIntelCPUDebuggingLocked
	CheckDiscreteTPMPartialResetAttackMitigationStatus    = checkDiscreteTPMPartialResetAttackMitigationStatus
	CheckDriversAndAppsMeasurements                       = checkDriversAndAppsMeasurements
	CheckFirmwareLogAndChoosePCRBank                      = checkFirmwareLogAndChoosePCRBank
	CheckForKernelIOMMU                                   = checkForKernelIOMMU
	CheckHostSecurity                                     = checkHostSecurity
	CheckSecureBootPolicyMeasurementsAndObtainAuthorities = checkSecureBootPolicyMeasurementsAndObtainAuthorities
	CheckSecureBootPolicyPCRForDegradedFirmwareSettings   = checkSecureBootPolicyPCRForDegradedFirmwareSettings
	CheckSystemIsEFI                                      = checkSystemIsEFI
	CheckTPM2ForRequiredPCClientFeatures                  = checkTPM2ForRequiredPCClientFeatures
	ClearTPM                                              = clearTPM
	DetermineCPUVendor                                    = determineCPUVendor
	DetectVirtualization                                  = detectVirtualization
	ErrInvalidLockoutAuthValueSupplied                    = errInvalidLockoutAuthValueSupplied
	InsertActionProceed                                   = insertActionProceed
	IsLaunchedFromLoadOption                              = isLaunchedFromLoadOption
	IsPPIActionAvailable                                  = isPPIActionAvailable
	IsTPMDiscrete                                         = isTPMDiscrete
	IsTPMDiscreteFromIntelBootGuard                       = isTPMDiscreteFromIntelBootGuard
	JoinErrors                                            = joinErrors
	MatchLaunchToLoadOption                               = matchLaunchToLoadOption
	NewX509CertificateID                                  = newX509CertificateID
	OpenAndCheckTPM2Device                                = openAndCheckTPM2Device
	ReadIntelHFSTSRegistersFromMEISysfs                   = readIntelHFSTSRegistersFromMEISysfs
	ReadIntelMEVersionFromMEISysfs                        = readIntelMEVersionFromMEISysfs
	ReadOrderedLoadOptionVariables                        = readOrderedLoadOptionVariables
	RestrictedTPMLocalitiesIntel                          = restrictedTPMLocalitiesIntel
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

func MakePCRResults(mandatory bool, initialVal, logVal, pcrVal tpm2.Digest, err error) pcrResults {
	return pcrResults{
		mandatory:    mandatory,
		initialValue: initialVal,
		logValue:     logVal,
		pcrValue:     pcrVal,
		err:          err,
	}
}

func NewPCRBankResults(alg tpm2.HashAlgorithmId, sl uint8, pcrs [8]PcrResults) *pcrBankResults {
	return &pcrBankResults{
		Alg:             alg,
		StartupLocality: sl,
		pcrs:            pcrs,
	}
}

func MockRuntimeGOARCH(arch string) (restore func()) {
	orig := runtimeGOARCH
	runtimeGOARCH = arch
	return func() { runtimeGOARCH = orig }
}
