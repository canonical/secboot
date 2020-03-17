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
	MakeDefaultEKTemplate          = makeDefaultEKTemplate
	OidExtensionSubjectAltName     = oidExtensionSubjectAltName
	OidTcgAttributeTpmManufacturer = oidTcgAttributeTpmManufacturer
	OidTcgAttributeTpmModel        = oidTcgAttributeTpmModel
	OidTcgAttributeTpmVersion      = oidTcgAttributeTpmVersion
	OidTcgKpEkCertificate          = oidTcgKpEkCertificate
	SrkTemplate                    = srkTemplate
)

var ComputeDynamicPolicy = computeDynamicPolicy
var ComputePolicyORData = computePolicyORData
var ComputeStaticPolicy = computeStaticPolicy
var CreatePinNVIndex = createPinNVIndex
var CreatePublicAreaForRSASigningKey = createPublicAreaForRSASigningKey
var EnsureLockNVIndex = ensureLockNVIndex
var ExecutePolicyORAssertions = executePolicyORAssertions
var ExecutePolicySession = executePolicySession
var IncrementDynamicPolicyCounter = incrementDynamicPolicyCounter
var LockAccessToSealedKeysUntilTPMReset = lockAccessToSealedKeysUntilTPMReset
var PerformPinChange = performPinChange
var ReadAndValidateLockNVIndexPublic = readAndValidateLockNVIndexPublic
var ReadDynamicPolicyCounter = readDynamicPolicyCounter

type DynamicPolicyData dynamicPolicyData

type MockPolicyPCRParam struct {
	PCR     int
	Alg     tpm2.HashAlgorithmId
	Digests tpm2.DigestList
}

type StaticPolicyData staticPolicyData

func AppendRootCAHash(h []byte) {
	rootCAHashes = append(rootCAHashes, h)
}

func InitTPMConnection(t *TPMConnection) error {
	return t.init()
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
			v.SetValue(params[i].PCR, params[i].Alg, params[i].Digests[indices[i]])
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

func MockEKTemplate(mock *tpm2.Public) (restore func()) {
	orig := ekTemplate
	ekTemplate = mock
	return func() {
		ekTemplate = orig
	}
}

func NewDynamicPolicyComputeParams(key *rsa.PrivateKey, signAlg tpm2.HashAlgorithmId, pcrValues []tpm2.PCRValues, policyCountIndexName tpm2.Name, policyCount uint64) *dynamicPolicyComputeParams {
	return &dynamicPolicyComputeParams{
		key:                  key,
		signAlg:              signAlg,
		pcrValues:            pcrValues,
		policyCountIndexName: policyCountIndexName,
		policyCount:          policyCount}
}

func NewStaticPolicyComputeParams(key *rsa.PublicKey, pinIndexPub *tpm2.NVPublic, pinIndexAuthPolicies tpm2.DigestList, lockIndexName tpm2.Name) *staticPolicyComputeParams {
	return &staticPolicyComputeParams{key: key, pinIndexPub: pinIndexPub, pinIndexAuthPolicies: pinIndexAuthPolicies, lockIndexName: lockIndexName}
}

func SetOpenDefaultTctiFn(fn func() (io.ReadWriteCloser, error)) {
	openDefaultTcti = fn
}
