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
)

const (
	EkCertHandle        = ekCertHandle
	EkHandle            = ekHandle
	LockNVDataHandle    = lockNVDataHandle
	LockNVHandle        = lockNVHandle
	SanDirectoryNameTag = sanDirectoryNameTag
	SrkHandle           = srkHandle
)

var (
	EkTemplate                     = ekTemplate
	LockNVIndexAttrs               = lockNVIndexAttrs
	MakeDefaultEKTemplate	       = makeDefaultEKTemplate
	OidExtensionSubjectAltName     = oidExtensionSubjectAltName
	OidTcgAttributeTpmManufacturer = oidTcgAttributeTpmManufacturer
	OidTcgAttributeTpmModel        = oidTcgAttributeTpmModel
	OidTcgAttributeTpmVersion      = oidTcgAttributeTpmVersion
	OidTcgKpEkCertificate          = oidTcgKpEkCertificate
	SrkTemplate                    = srkTemplate
)

var ComputeDynamicPolicy = computeDynamicPolicy
var ComputeStaticPolicy = computeStaticPolicy
var CreatePinNVIndex = createPinNVIndex
var CreatePublicAreaForRSASigningKey = createPublicAreaForRSASigningKey
var EnsureLockNVIndex = ensureLockNVIndex
var ExecutePolicySession = executePolicySession
var IncrementDynamicPolicyCounter = incrementDynamicPolicyCounter
var LockAccessToSealedKeysUntilTPMReset = lockAccessToSealedKeysUntilTPMReset
var PerformPinChange = performPinChange
var ReadAndValidateLockNVIndexPublic = readAndValidateLockNVIndexPublic
var ReadDynamicPolicyCounter = readDynamicPolicyCounter

type DynamicPolicyData struct {
	*dynamicPolicyData
}

type MockPolicyPCRParam struct {
	PCR     int
	Alg     tpm2.HashAlgorithmId
	Digests tpm2.DigestList
}

type StaticPolicyData struct {
	*staticPolicyData
}

func AppendRootCAHash(h []byte) {
	rootCAHashes = append(rootCAHashes, h)
}

func AsDynamicPolicyData(in *dynamicPolicyData) *DynamicPolicyData {
	return &DynamicPolicyData{in}
}

func AsStaticPolicyData(in *staticPolicyData) *StaticPolicyData {
	return &StaticPolicyData{in}
}

func InitTPMConnection(t *TPMConnection) error {
	return t.init()
}

func MockEKTemplate(mock *tpm2.Public) (restore func()) {
	orig := ekTemplate
	ekTemplate = mock
	return func() {
		ekTemplate = orig
	}
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

func NewStaticPolicyComputeParams(key *rsa.PublicKey, pinIndexPub *tpm2.NVPublic, pinIndexAuthPolicies tpm2.DigestList, lockIndexName tpm2.Name) *staticPolicyComputeParams {
	return &staticPolicyComputeParams{key: key, pinIndexPub: pinIndexPub, pinIndexAuthPolicies: pinIndexAuthPolicies, lockIndexName: lockIndexName}
}

func SetOpenDefaultTctiFn(fn func() (io.ReadWriteCloser, error)) {
	openDefaultTcti = fn
}
