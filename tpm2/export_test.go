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

package tpm2

import (
	"errors"

	"github.com/canonical/go-tpm2"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/snapcore/secboot"
)

// Export constants for testing
const (
	LockNVHandle          = lockNVHandle
	ResetPcrPolicyVersion = resetPcrPolicyVersion
	SrkTemplateHandle     = srkTemplateHandle
)

// Export variables and unexported functions for testing
var (
	ComputeV0PinNVIndexPostInitAuthPolicies = computeV0PinNVIndexPostInitAuthPolicies
	CreatePcrPolicyCounter                  = createPcrPolicyCounterLegacy
	EnsurePcrPolicyCounter                  = ensurePcrPolicyCounter
	ComputeV1PcrPolicyRefFromCounterName    = computeV1PcrPolicyRefFromCounterName
	ComputeV3PcrPolicyCounterAuthPolicies   = computeV3PcrPolicyCounterAuthPolicies
	ComputeV3PcrPolicyRef                   = computeV3PcrPolicyRef
	ComputeSnapModelDigest                  = computeSnapModelDigest
	DeriveV3PolicyAuthKey                   = deriveV3PolicyAuthKey
	ErrSessionDigestNotFound                = errSessionDigestNotFound
	IsPolicyDataError                       = isPolicyDataError
	MakeSealedKeyData                       = makeSealedKeyData
	MakeKeyDataNoAuth                       = makeKeyDataNoAuth
	MakeKeyDataWithPassphraseConstructor    = makeKeyDataWithPassphraseConstructor
	NewKeyData                              = newKeyData
	NewKeyDataPolicy                        = newKeyDataPolicy
	NewKeyDataPolicyLegacy                  = newKeyDataPolicyLegacy
	NewPolicyAuthPublicKey                  = newPolicyAuthPublicKey
	NewPolicyOrDataV0                       = newPolicyOrDataV0
	NewPolicyOrTree                         = newPolicyOrTree
	ReadKeyDataV0                           = readKeyDataV0
	ReadKeyDataV1                           = readKeyDataV1
	ReadKeyDataV2                           = readKeyDataV2
	ReadKeyDataV3                           = readKeyDataV3
)

// Alias some unexported types for testing. These are required in order to pass these between functions in tests, or to access
// unexported members of some unexported types.
type GoSnapModelHasher = goSnapModelHasher
type KeyData = keyData
type KeyData_v0 = keyData_v0
type KeyData_v1 = keyData_v1
type KeyData_v2 = keyData_v2
type KeyData_v3 = keyData_v3
type AdditionalData_v3 = additionalData_v3
type KeyDataError = keyDataError
type SealedKeyDataParams = makeSealedKeyDataParams
type KeyDataPolicy = keyDataPolicy
type KeyDataPolicy_v0 = keyDataPolicy_v0
type KeyDataPolicy_v1 = keyDataPolicy_v1
type KeyDataPolicy_v2 = keyDataPolicy_v2
type KeyDataPolicy_v3 = keyDataPolicy_v3

func NewImportableObjectKeySealer(key *tpm2.Public) keySealer {
	return &importableObjectKeySealer{key}
}

func NewSealedObjectKeySealer(tpm *Connection) keySealer {
	return &sealedObjectKeySealer{tpm}
}

type PcrPolicyVersionOption = pcrPolicyVersionOption
type PolicyDataError = policyDataError
type PolicyOrData_v0 = policyOrData_v0

func (t PolicyOrData_v0) Resolve() (out *PolicyOrTree, err error) {
	return t.resolve()
}

type PolicyOrDataNode_v0 = policyOrDataNode_v0

type PolicyOrNode = policyOrNode

func (n *PolicyOrNode) Parent() *PolicyOrNode {
	return n.parent
}

func (n *PolicyOrNode) Digests() tpm2.DigestList {
	return n.digests
}

func (n *PolicyOrNode) Contains(digest tpm2.Digest) bool {
	return n.contains(digest)
}

type PolicyOrTree = policyOrTree

func (t *PolicyOrTree) LeafNodes() []*PolicyOrNode {
	return t.leafNodes
}

func (t *PolicyOrTree) ExecuteAssertions(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	return t.executeAssertions(tpm, session)
}

type PcrPolicyData_v0 = pcrPolicyData_v0
type PcrPolicyData_v1 = pcrPolicyData_v1
type PcrPolicyData_v2 = pcrPolicyData_v2
type PcrPolicyData_v3 = pcrPolicyData_v3

type PcrPolicyParams = pcrPolicyParams

func NewPcrPolicyParams(key secboot.PrimaryKey, pcrs tpm2.PCRSelectionList, pcrDigests tpm2.DigestList, policyCounterName tpm2.Name, policySequence uint64) *PcrPolicyParams {
	return &PcrPolicyParams{
		key:               key,
		pcrs:              pcrs,
		pcrDigests:        pcrDigests,
		policyCounterName: policyCounterName,
		policySequence:    policySequence,
	}
}

type PlatformKeyDataHandler = platformKeyDataHandler
type SealedKeyDataBase = sealedKeyDataBase
type SnapModelHasher = snapModelHasher
type StaticPolicyData_v0 = staticPolicyData_v0
type StaticPolicyData_v1 = staticPolicyData_v1
type StaticPolicyData_v3 = staticPolicyData_v3

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

func MockEnsurePcrPolicyCounter(fn func(*tpm2.TPMContext, tpm2.Handle, *tpm2.Public, tpm2.SessionContext) (*tpm2.NVPublic, error)) (restore func()) {
	orig := ensurePcrPolicyCounter
	ensurePcrPolicyCounter = fn
	return func() {
		ensurePcrPolicyCounter = orig
	}
}

func MockNewKeyDataPolicy(fn func(tpm2.HashAlgorithmId, *tpm2.Public, string, *tpm2.NVPublic, bool) (KeyDataPolicy, tpm2.Digest, error)) (restore func()) {
	orig := newKeyDataPolicy
	newKeyDataPolicy = fn
	return func() {
		newKeyDataPolicy = orig
	}
}

func MockNewPolicyAuthPublicKey(fn func(authKey secboot.PrimaryKey) (*tpm2.Public, error)) (restore func()) {
	orig := newPolicyAuthPublicKey
	newPolicyAuthPublicKey = fn
	return func() {
		newPolicyAuthPublicKey = orig
	}
}

func MockSecbootNewKeyData(fn func(*secboot.KeyParams) (*secboot.KeyData, error)) (restore func()) {
	orig := secbootNewKeyData
	secbootNewKeyData = fn
	return func() {
		secbootNewKeyData = orig
	}
}

func MockSecbootNewKeyDataWithPassphrase(fn func(*secboot.KeyWithPassphraseParams, string, secboot.KDF) (*secboot.KeyData, error)) (restore func()) {
	orig := secbootNewKeyDataWithPassphrase
	secbootNewKeyDataWithPassphrase = fn
	return func() {
		secbootNewKeyDataWithPassphrase = orig
	}
}

func MockSkdbUpdatePCRProtectionPolicyNoValidate(fn func(*sealedKeyDataBase, *tpm2.TPMContext, secboot.PrimaryKey, *tpm2.NVPublic, *PCRProtectionProfile, PcrPolicyVersionOption, tpm2.SessionContext) error) (restore func()) {
	orig := skdbUpdatePCRProtectionPolicyNoValidate
	skdbUpdatePCRProtectionPolicyNoValidate = fn
	return func() {
		skdbUpdatePCRProtectionPolicyNoValidate = orig
	}
}

func (k *SealedKeyData) Data() KeyData {
	return k.data
}

func (k *SealedKeyObject) Data() KeyData {
	return k.data
}

func (k *SealedKeyObject) Validate(tpm *tpm2.TPMContext, authKey secboot.PrimaryKey, session tpm2.SessionContext) error {
	if _, err := k.validateData(tpm, "", session); err != nil {
		return err
	}

	return k.data.Policy().ValidateAuthKey(authKey)
}

func (k *SealedKeyData) Validate(tpm *tpm2.TPMContext, authKey secboot.PrimaryKey, session tpm2.SessionContext) error {
	if _, err := k.validateData(tpm, "", session); err != nil {
		return err
	}

	return k.data.Policy().ValidateAuthKey(authKey)
}

func ValidateKeyDataFile(tpm *tpm2.TPMContext, keyFile string, authKey secboot.PrimaryKey, session tpm2.SessionContext) error {
	k, err := ReadSealedKeyObjectFromFile(keyFile)
	if err != nil {
		return err
	}

	return k.Validate(tpm, authKey, session)
}

type protectedKeys struct {
	Primary secboot.PrimaryKey
	Unique  []byte
}

func UnmarshalProtectedKeys(data []byte) (*protectedKeys, error) {
	s := cryptobyte.String(data)
	if !s.ReadASN1(&s, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("malformed input")
	}

	pk := new(protectedKeys)

	if !s.ReadASN1Bytes((*[]byte)(&pk.Primary), cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("malformed primary key")
	}
	if !s.ReadASN1Bytes(&pk.Unique, cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("malformed unique key")
	}

	return pk, nil
}
