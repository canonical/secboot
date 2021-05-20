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
	"crypto/ecdsa"
	"os"

	"github.com/canonical/go-tpm2"
)

// Export constants for testing
const (
	CurrentMetadataVersion = currentMetadataVersion
	LockNVHandle           = lockNVHandle
	SrkTemplateHandle      = srkTemplateHandle
)

// Export variables and unexported functions for testing
var (
	ComputeDynamicPolicy                  = computeDynamicPolicy
	CreatePcrPolicyCounter                = createPcrPolicyCounter
	ComputePcrPolicyCounterAuthPolicies   = computePcrPolicyCounterAuthPolicies
	ComputePcrPolicyRefFromCounterContext = computePcrPolicyRefFromCounterContext
	ComputePcrPolicyRefFromCounterName    = computePcrPolicyRefFromCounterName
	ComputePolicyORData                   = computePolicyORData
	ComputeSnapModelDigest                = computeSnapModelDigest
	ComputeStaticPolicy                   = computeStaticPolicy
	CreateTPMPublicAreaForECDSAKey        = createTPMPublicAreaForECDSAKey
	ExecutePolicySession                  = executePolicySession
	IncrementPcrPolicyCounter             = incrementPcrPolicyCounter
	IsDynamicPolicyDataError              = isDynamicPolicyDataError
	IsStaticPolicyDataError               = isStaticPolicyDataError
	LockNVIndex1Attrs                     = lockNVIndex1Attrs
	PerformPinChange                      = performPinChange
	ReadPcrPolicyCounter                  = readPcrPolicyCounter
)

// Alias some unexported types for testing. These are required in order to pass these between functions in tests, or to access
// unexported members of some unexported types.
type DynamicPolicyData = dynamicPolicyData

func (d *DynamicPolicyData) PCRSelection() tpm2.PCRSelectionList {
	return d.pcrSelection
}

func (d *DynamicPolicyData) PCROrData() policyOrDataTree {
	return d.pcrOrData
}

func (d *DynamicPolicyData) PolicyCount() uint64 {
	return d.policyCount
}

func (d *DynamicPolicyData) SetPolicyCount(c uint64) {
	d.policyCount = c
}

func (d *DynamicPolicyData) AuthorizedPolicy() tpm2.Digest {
	return d.authorizedPolicy
}

func (d *DynamicPolicyData) AuthorizedPolicySignature() *tpm2.Signature {
	return d.authorizedPolicySignature
}

type StaticPolicyData = staticPolicyData

func (d *StaticPolicyData) AuthPublicKey() *tpm2.Public {
	return d.authPublicKey
}

func (d *StaticPolicyData) PcrPolicyCounterHandle() tpm2.Handle {
	return d.pcrPolicyCounterHandle
}

func (d *StaticPolicyData) SetPcrPolicyCounterHandle(h tpm2.Handle) {
	d.pcrPolicyCounterHandle = h
}

func (d *StaticPolicyData) V0PinIndexAuthPolicies() tpm2.DigestList {
	return d.v0PinIndexAuthPolicies
}

// Export some helpers for testing.
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

func MockLUKS2Activate(fn func(string, string, []byte) error) (restore func()) {
	origActivate := luks2Activate
	luks2Activate = fn
	return func() {
		luks2Activate = origActivate
	}
}

func MockLUKS2Deactivate(fn func(string) error) (restore func()) {
	origDeactivate := luks2Deactivate
	luks2Deactivate = fn
	return func() {
		luks2Deactivate = origDeactivate
	}
}

func MockRunDir(path string) (restore func()) {
	origRunDir := runDir
	runDir = path
	return func() {
		runDir = origRunDir
	}
}

func NewDynamicPolicyComputeParams(key *ecdsa.PrivateKey, signAlg tpm2.HashAlgorithmId, pcrs tpm2.PCRSelectionList,
	pcrDigests tpm2.DigestList, policyCounterName tpm2.Name, policyCount uint64) *dynamicPolicyComputeParams {
	return &dynamicPolicyComputeParams{
		key:               key,
		signAlg:           signAlg,
		pcrs:              pcrs,
		pcrDigests:        pcrDigests,
		policyCounterName: policyCounterName,
		policyCount:       policyCount}
}

func NewStaticPolicyComputeParams(key *tpm2.Public, pcrPolicyCounterPub *tpm2.NVPublic) *staticPolicyComputeParams {
	return &staticPolicyComputeParams{key: key, pcrPolicyCounterPub: pcrPolicyCounterPub}
}

func ValidateKeyDataFile(tpm *tpm2.TPMContext, keyFile string, authPrivateKey TPMPolicyAuthKey, session tpm2.SessionContext) error {
	kf, err := os.Open(keyFile)
	if err != nil {
		return err
	}
	defer kf.Close()

	_, _, _, err = decodeAndValidateKeyData(tpm, kf, authPrivateKey, session)
	return err
}
