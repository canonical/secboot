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
	DetectVirtResult            = detectVirtResult
	JoinError                   = joinError
	PcrResults                  = pcrResults
	SecureBootPolicyResult      = secureBootPolicyResult
	SecureBootPolicyResultFlags = secureBootPolicyResultFlags
)

const (
	AuthorityTrustBootCode                      = authorityTrustBootCode
	AuthorityTrustDrivers                       = authorityTrustDrivers
	CheckFirmwareLogPermitEmptyPCRBanks         = checkFirmwareLogPermitEmptyPCRBanks
	CheckFirmwareLogPermitWeakPCRBanks          = checkFirmwareLogPermitWeakPCRBanks
	CheckTPM2DevicePostInstall                  = checkTPM2DevicePostInstall
	DetectVirtNone                              = detectVirtNone
	DetectVirtVM                                = detectVirtVM
	DiscreteTPMDetected                         = discreteTPMDetected
	DtpmPartialResetAttackMitigationNotRequired = dtpmPartialResetAttackMitigationNotRequired
	DtpmPartialResetAttackMitigationPreferred   = dtpmPartialResetAttackMitigationPreferred
	DtpmPartialResetAttackMitigationUnavailable = dtpmPartialResetAttackMitigationUnavailable
	InsufficientDMAProtectionDetected           = insufficientDMAProtectionDetected
	SecureBootIncludesWeakAlg                   = secureBootIncludesWeakAlg
	SecureBootPreOSVerificationIncludesDigest   = secureBootPreOSVerificationIncludesDigest
	StartupLocalityNotProtected                 = startupLocalityNotProtected
)

var (
	CheckBootManagerCodeMeasurements                      = checkBootManagerCodeMeasurements
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
	DetectVirtualization                                  = detectVirtualization
	ErrInvalidLockoutAuthValueSupplied                    = errInvalidLockoutAuthValueSupplied
	InsertActionProceed                                   = insertActionProceed
	IsLaunchedFromFirmwareVolume                          = isLaunchedFromFirmwareVolume
	IsLaunchedFromLoadOption                              = isLaunchedFromLoadOption
	IsPPIActionAvailable                                  = isPPIActionAvailable
	IsTPMDiscrete                                         = isTPMDiscrete
	JoinErrors                                            = joinErrors
	MatchLaunchToLoadOption                               = matchLaunchToLoadOption
	NewX509CertificateID                                  = newX509CertificateID
	OpenAndCheckTPM2Device                                = openAndCheckTPM2Device
	ReadCurrentBootLoadOptionFromLog                      = readCurrentBootLoadOptionFromLog
	ReadLoadOptionFromLog                                 = readLoadOptionFromLog
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
