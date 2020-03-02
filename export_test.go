// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package secboot

import (
	"crypto/rsa"
	"io"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
)

// Export constants for testing
const (
	EkCertHandle        = ekCertHandle
	EkHandle            = ekHandle
	LockNVDataHandle    = lockNVDataHandle
	LockNVHandle        = lockNVHandle
	SanDirectoryNameTag = sanDirectoryNameTag
	SrkHandle           = srkHandle
)

// Export variables and unexported functions for testing
var (
	ComputeDbUpdate                          = computeDbUpdate
	ComputeDynamicPolicy                     = computeDynamicPolicy
	ComputeSecureBootPolicyDigests           = computeSecureBootPolicyDigests
	ComputeStaticPolicy                      = computeStaticPolicy
	CreatePinNVIndex                         = createPinNVIndex
	CreatePublicAreaForRSASigningKey         = createPublicAreaForRSASigningKey
	DecodeSecureBootDb                       = decodeSecureBootDb
	DecodeWinCertificate                     = decodeWinCertificate
	EkTemplate                               = ekTemplate
	EFICertTypePkcs7Guid                     = efiCertTypePkcs7Guid
	EFICertX509Guid                          = efiCertX509Guid
	EnsureLockNVIndex                        = ensureLockNVIndex
	ExecutePolicySession                     = executePolicySession
	IdentifyInitialOSLaunchVerificationEvent = identifyInitialOSLaunchVerificationEvent
	IncrementDynamicPolicyCounter            = incrementDynamicPolicyCounter
	LockAccessToSealedKeysUntilTPMReset      = lockAccessToSealedKeysUntilTPMReset
	LockNVIndexAttrs                         = lockNVIndexAttrs
	MakeDefaultEKTemplate                    = makeDefaultEKTemplate
	OidExtensionSubjectAltName               = oidExtensionSubjectAltName
	OidTcgAttributeTpmManufacturer           = oidTcgAttributeTpmManufacturer
	OidTcgAttributeTpmModel                  = oidTcgAttributeTpmModel
	OidTcgAttributeTpmVersion                = oidTcgAttributeTpmVersion
	OidTcgKpEkCertificate                    = oidTcgKpEkCertificate
	PerformPinChange                         = performPinChange
	ReadAndValidateLockNVIndexPublic         = readAndValidateLockNVIndexPublic
	ReadDynamicPolicyCounter                 = readDynamicPolicyCounter
	ReadShimVendorCert                       = readShimVendorCert
	SrkTemplate                              = srkTemplate
	WinCertTypePKCSSignedData                = winCertTypePKCSSignedData
	WinCertTypeEfiGuid                       = winCertTypeEfiGuid
)

// Export some types that wrap around unexported types, for testing. These are required in order to pass these between functions
// in tests, or to access unexported members of unexported types. Convert the unexported types to these with the corresponding
// As*() functions.
type DynamicPolicyData struct {
	*dynamicPolicyData
}

func AsDynamicPolicyData(in *dynamicPolicyData) *DynamicPolicyData {
	return &DynamicPolicyData{in}
}

type EFISignatureData struct {
	*efiSignatureData
}

func (s *EFISignatureData) SignatureType() *tcglog.EFIGUID {
	return &s.signatureType
}

func (s *EFISignatureData) Owner() *tcglog.EFIGUID {
	return &s.owner
}

func (s *EFISignatureData) Data() []byte {
	return s.data
}

func AsEFISignatureData(in *efiSignatureData) *EFISignatureData {
	return &EFISignatureData{in}
}

type SecureBootVerificationEvent struct {
	*secureBootVerificationEvent
}

func (e *SecureBootVerificationEvent) Event() *tcglog.Event {
	return e.event
}

func (e *SecureBootVerificationEvent) ImageLoadEvent() *tcglog.Event {
	return e.imageLoadEvent
}

func AsSecureBootVerificationEvent(in *secureBootVerificationEvent) *SecureBootVerificationEvent {
	return &SecureBootVerificationEvent{in}
}

type StaticPolicyData struct {
	*staticPolicyData
}

func AsStaticPolicyData(in *staticPolicyData) *StaticPolicyData {
	return &StaticPolicyData{in}
}

type WinCertificateAuthenticode struct {
	*winCertificateAuthenticode
}

func AsWinCertificateAuthenticode(in winCertificate) *WinCertificateAuthenticode {
	cert, ok := in.(*winCertificateAuthenticode)
	if !ok {
		return nil
	}
	return &WinCertificateAuthenticode{cert}
}

type WinCertificateUefiGuid struct {
	*winCertificateUefiGuid
}

func AsWinCertificateUefiGuid(in winCertificate) *WinCertificateUefiGuid {
	cert, ok := in.(*winCertificateUefiGuid)
	if !ok {
		return nil
	}
	return &WinCertificateUefiGuid{cert}
}

// Export some helpers for testing.
func AppendRootCAHash(h []byte) {
	rootCAHashes = append(rootCAHashes, h)
}

func GetWinCertificateType(cert winCertificate) uint16 {
	return cert.wCertificateType()
}

func InitTPMConnection(t *TPMConnection) error {
	return t.init()
}

func MockEfivarsPath(path string) (restore func()) {
	origPath := efivarsPath
	efivarsPath = path
	return func() {
		efivarsPath = origPath
	}
}

func MockEKTemplate(mock *tpm2.Public) (restore func()) {
	orig := ekTemplate
	ekTemplate = mock
	return func() {
		ekTemplate = orig
	}
}

func MockEventLogPath(path string) (restore func()) {
	origPath := eventLogPath
	eventLogPath = path
	return func() {
		eventLogPath = origPath
	}
}

type MockPolicyPCRParam struct {
	PCR     int
	Alg     tpm2.HashAlgorithmId
	Digests tpm2.DigestList
}

func NewDynamicPolicyComputeParams(key *rsa.PrivateKey, signAlg tpm2.HashAlgorithmId, mockPcrParams []MockPolicyPCRParam, policyCountIndexName tpm2.Name, policyCount uint64) *dynamicPolicyComputeParams {
	var pcrParams []policyPCRParam
	for _, p := range mockPcrParams {
		pcrParams = append(pcrParams, policyPCRParam{pcr: p.PCR, alg: p.Alg, digests: p.Digests})
	}
	return &dynamicPolicyComputeParams{
		key:                  key,
		signAlg:              signAlg,
		pcrParams:            pcrParams,
		policyCountIndexName: policyCountIndexName,
		policyCount:          policyCount}
}

func NewSecureBootProtectionParams(loadSequences []*EFIImageLoadEvent, signatureDbUpdateKeystores []string) *secureBootProtectionParams {
	return &secureBootProtectionParams{loadSequences: loadSequences, signatureDbUpdateKeystores: signatureDbUpdateKeystores}
}

func NewStaticPolicyComputeParams(key *rsa.PublicKey, pinIndexPub *tpm2.NVPublic, pinIndexAuthPolicies tpm2.DigestList, lockIndexName tpm2.Name) *staticPolicyComputeParams {
	return &staticPolicyComputeParams{key: key, pinIndexPub: pinIndexPub, pinIndexAuthPolicies: pinIndexAuthPolicies, lockIndexName: lockIndexName}
}

func SetOpenDefaultTctiFn(fn func() (io.ReadWriteCloser, error)) {
	openDefaultTcti = fn
}
