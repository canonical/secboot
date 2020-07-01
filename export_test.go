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
	"bytes"
	"crypto/rsa"
	"fmt"
	"io"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
)

// Export constants for testing
const (
	CurrentMetadataVersion = currentMetadataVersion
	EkCertHandle           = ekCertHandle
	EkHandle               = ekHandle
	LockNVDataHandle       = lockNVDataHandle
	LockNVHandle           = lockNVHandle
	SanDirectoryNameTag    = sanDirectoryNameTag
	SrkHandle              = srkHandle
)

// Export variables and unexported functions for testing
var (
	ComputeDbUpdate                          = computeDbUpdate
	ComputeDynamicPolicy                     = computeDynamicPolicy
	ComputePolicyORData                      = computePolicyORData
	ComputeSnapModelDigest                   = computeSnapModelDigest
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
	IsDynamicPolicyDataError                 = isDynamicPolicyDataError
	IsStaticPolicyDataError                  = isStaticPolicyDataError
	LockNVIndexAttrs                         = lockNVIndexAttrs
	MakeDefaultEKTemplate                    = makeDefaultEKTemplate
	MakeDefaultSRKTemplate                   = makeDefaultSRKTemplate
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

// Alias some unexported types for testing. These are required in order to pass these between functions in tests, or to access
// unexported members of some unexported types.
type DynamicPolicyData dynamicPolicyData

type EFISignatureData efiSignatureData

func (s *EFISignatureData) SignatureType() *tcglog.EFIGUID {
	return &s.signatureType
}

func (s *EFISignatureData) Owner() *tcglog.EFIGUID {
	return &s.owner
}

func (s *EFISignatureData) Data() []byte {
	return s.data
}

type SecureBootVerificationEvent secureBootVerificationEvent

func (e *SecureBootVerificationEvent) Event() *tcglog.Event {
	return e.event
}

func (e *SecureBootVerificationEvent) ImageLoadEvent() *tcglog.Event {
	return e.imageLoadEvent
}

type StaticPolicyData staticPolicyData

type WinCertificate interface {
	ToWinCertificateAuthenticode() *WinCertificateAuthenticode
	ToWinCertificateUefiGuid() *WinCertificateUefiGuid
}

type WinCertificateAuthenticode winCertificateAuthenticode

func (c *winCertificateAuthenticode) ToWinCertificateAuthenticode() *WinCertificateAuthenticode {
	return (*WinCertificateAuthenticode)(c)
}

func (c *winCertificateAuthenticode) ToWinCertificateUefiGuid() *WinCertificateUefiGuid {
	return nil
}

type WinCertificateUefiGuid winCertificateUefiGuid

func (c *winCertificateUefiGuid) ToWinCertificateAuthenticode() *WinCertificateAuthenticode {
	return nil
}

func (c *winCertificateUefiGuid) ToWinCertificateUefiGuid() *WinCertificateUefiGuid {
	return (*WinCertificateUefiGuid)(c)
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

type MockPolicyPCRParam struct {
	PCR     int
	Alg     tpm2.HashAlgorithmId
	Digests tpm2.DigestList
}

// MakeMockPolicyPCRValuesFull computes a slice of tpm2.PCRValues for every combination of supplied PCR values.
func MakeMockPolicyPCRValuesFull(params []MockPolicyPCRParam) (out []tpm2.PCRValues) {
	indices := make([]int, len(params))
	advanceIndices := func() bool {
		for i := range params {
			indices[i]++
			if indices[i] < len(params[i].Digests) {
				break
			}
			indices[i] = 0
			if i == len(params)-1 {
				return false
			}
		}
		return true
	}

	for {
		v := make(tpm2.PCRValues)
		for i := range params {
			v.SetValue(params[i].Alg, params[i].PCR, params[i].Digests[indices[i]])
		}
		out = append(out, v)

		if len(params) == 0 {
			break
		}

		if !advanceIndices() {
			break
		}
	}
	return
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

func MockRunDir(path string) (restore func()) {
	origRunDir := runDir
	runDir = path
	return func() {
		runDir = origRunDir
	}
}

func MockSystemdCryptsetupPath(path string) (restore func()) {
	origSystemdCryptsetupPath := systemdCryptsetupPath
	systemdCryptsetupPath = path
	return func() {
		systemdCryptsetupPath = origSystemdCryptsetupPath
	}
}

func NewDynamicPolicyComputeParams(key *rsa.PrivateKey, signAlg tpm2.HashAlgorithmId, pcrs tpm2.PCRSelectionList, pcrDigests tpm2.DigestList, policyCountIndexName tpm2.Name, policyCount uint64) *dynamicPolicyComputeParams {
	return &dynamicPolicyComputeParams{
		key:                  key,
		signAlg:              signAlg,
		pcrs:                 pcrs,
		pcrDigests:           pcrDigests,
		policyCountIndexName: policyCountIndexName,
		policyCount:          policyCount}
}

func NewStaticPolicyComputeParams(key *tpm2.Public, pinIndexPub *tpm2.NVPublic, pinIndexAuthPolicies tpm2.DigestList, lockIndexName tpm2.Name) *staticPolicyComputeParams {
	return &staticPolicyComputeParams{key: key, pinIndexPub: pinIndexPub, pinIndexAuthPolicies: pinIndexAuthPolicies, lockIndexName: lockIndexName}
}

func (p *PCRProtectionProfile) ComputePCRDigests(tpm *tpm2.TPMContext, alg tpm2.HashAlgorithmId) (tpm2.PCRSelectionList, tpm2.DigestList, error) {
	return p.computePCRDigests(tpm, alg)
}

func (p *PCRProtectionProfile) DumpValues(tpm *tpm2.TPMContext) string {
	values, err := p.computePCRValues(tpm)
	if err != nil {
		return ""
	}
	var s bytes.Buffer
	fmt.Fprintf(&s, "\n")
	for i, v := range values {
		fmt.Fprintf(&s, "Value %d:\n", i)
		for alg := range v {
			for pcr := range v[alg] {
				fmt.Fprintf(&s, " PCR%d,%v: %x\n", pcr, alg, v[alg][pcr])
			}
		}
	}
	return s.String()
}

func SetOpenDefaultTctiFn(fn func() (io.ReadWriteCloser, error)) {
	openDefaultTcti = fn
}

func ValidateKeyDataFile(tpm *tpm2.TPMContext, keyFile, privateFile string, session tpm2.SessionContext) error {
	kf, err := os.Open(keyFile)
	if err != nil {
		return err
	}
	defer kf.Close()

	var pf io.Reader
	if privateFile != "" {
		f, err := os.Open(privateFile)
		if err != nil {
			return err
		}
		defer f.Close()
		pf = f
	}

	_, _, _, err = decodeAndValidateKeyData(tpm, kf, pf, session)
	return err
}
