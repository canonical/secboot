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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"
)

var (
	// lockNVIndex1Attrs are the attributes for the first global lock NV index.
	lockNVIndex1Attrs = tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVReadStClear)
)

// dynamicPolicyComputeParams provides the parameters to computeDynamicPolicy.
type dynamicPolicyComputeParams struct {
	key crypto.PrivateKey // Key used to authorize the generated dynamic authorization policy

	// signAlg is the digest algorithm for the signature used to authorize the generated dynamic authorization policy. It must
	// match the name algorithm of the public part of key that will be loaded in to the TPM for verification.
	signAlg           tpm2.HashAlgorithmId
	pcrs              tpm2.PCRSelectionList // PCR selection
	pcrDigests        tpm2.DigestList       // Approved PCR digests
	policyCounterName tpm2.Name             // Name of the NV index used for revoking authorization policies
	policyCount       uint64                // Count for this policy, used for revocation
}

// policyOrDataNode represents a collection of up to 8 digests used in a single TPM2_PolicyOR invocation, and forms part of a tree
// of nodes in order to support authorization policies with more than 8 conditions.
type policyOrDataNode struct {
	Next    uint32 // Index of the parent node in the containing slice, relative to this node. Zero indicates that this is the root node
	Digests tpm2.DigestList
}

type policyOrDataTree []policyOrDataNode

// dynamicPolicyData is an output of computeDynamicPolicy and provides metadata for executing a policy session.
type dynamicPolicyData struct {
	pcrSelection              tpm2.PCRSelectionList
	pcrOrData                 policyOrDataTree
	policyCount               uint64
	authorizedPolicy          tpm2.Digest
	authorizedPolicySignature *tpm2.Signature
}

// dynamicPolicyDataRaw_v0 is version 0 of the on-disk format of dynamicPolicyData.
type dynamicPolicyDataRaw_v0 struct {
	PCRSelection              tpm2.PCRSelectionList
	PCROrData                 policyOrDataTree
	PolicyCount               uint64
	AuthorizedPolicy          tpm2.Digest
	AuthorizedPolicySignature *tpm2.Signature
}

func (d *dynamicPolicyDataRaw_v0) data() *dynamicPolicyData {
	return &dynamicPolicyData{
		pcrSelection:              d.PCRSelection,
		pcrOrData:                 d.PCROrData,
		policyCount:               d.PolicyCount,
		authorizedPolicy:          d.AuthorizedPolicy,
		authorizedPolicySignature: d.AuthorizedPolicySignature}
}

// makeDynamicPolicyDataRaw_v0 converts dynamicPolicyData to version 0 of the on-disk format.
func makeDynamicPolicyDataRaw_v0(data *dynamicPolicyData) *dynamicPolicyDataRaw_v0 {
	return &dynamicPolicyDataRaw_v0{
		PCRSelection:              data.pcrSelection,
		PCROrData:                 data.pcrOrData,
		PolicyCount:               data.policyCount,
		AuthorizedPolicy:          data.authorizedPolicy,
		AuthorizedPolicySignature: data.authorizedPolicySignature}
}

// staticPolicyComputeParams provides the parameters to computeStaticPolicy.
type staticPolicyComputeParams struct {
	key                 *tpm2.Public   // Public part of key used to authorize a dynamic authorization policy
	pcrPolicyCounterPub *tpm2.NVPublic // Public area of the NV counter used for revoking PCR policies
	legacyLockIndexName tpm2.Name      // Name of the legacy global NV index for locking access to sealed key objects
}

// staticPolicyData is an output of computeStaticPolicy and provides metadata for executing a policy session.
type staticPolicyData struct {
	authPublicKey          *tpm2.Public
	pcrPolicyCounterHandle tpm2.Handle
	v0PinIndexAuthPolicies tpm2.DigestList
}

// staticPolicyDataRaw_v0 is version 0 of the on-disk format of staticPolicyData.
type staticPolicyDataRaw_v0 struct {
	AuthPublicKey        *tpm2.Public
	PinIndexHandle       tpm2.Handle
	PinIndexAuthPolicies tpm2.DigestList
}

func (d *staticPolicyDataRaw_v0) data() *staticPolicyData {
	return &staticPolicyData{
		authPublicKey:          d.AuthPublicKey,
		pcrPolicyCounterHandle: d.PinIndexHandle,
		v0PinIndexAuthPolicies: d.PinIndexAuthPolicies}
}

// makeStaticPolicyDataRaw_v0 converts staticPolicyData to version 0 of the on-disk format.
func makeStaticPolicyDataRaw_v0(data *staticPolicyData) *staticPolicyDataRaw_v0 {
	return &staticPolicyDataRaw_v0{
		AuthPublicKey:        data.authPublicKey,
		PinIndexHandle:       data.pcrPolicyCounterHandle,
		PinIndexAuthPolicies: data.v0PinIndexAuthPolicies}
}

// staticPolicyDataRaw_v1 is version 1 of the on-disk format of staticPolicyData.
type staticPolicyDataRaw_v1 struct {
	AuthPublicKey          *tpm2.Public
	PCRPolicyCounterHandle tpm2.Handle
	PCRPolicyRef           tpm2.Nonce
}

func (d *staticPolicyDataRaw_v1) data() *staticPolicyData {
	return &staticPolicyData{
		authPublicKey:          d.AuthPublicKey,
		pcrPolicyCounterHandle: d.PCRPolicyCounterHandle}
}

// makeStaticPolicyDataRaw_v1 converts staticPolicyData to version 1 of the on-disk format.
func makeStaticPolicyDataRaw_v1(data *staticPolicyData) *staticPolicyDataRaw_v1 {
	return &staticPolicyDataRaw_v1{
		AuthPublicKey:          data.authPublicKey,
		PCRPolicyCounterHandle: data.pcrPolicyCounterHandle}
}

// computePcrPolicyCounterAuthPolicies computes the authorization policy digests passed to TPM2_PolicyOR for a PCR
// policy counter that can be updated with the key associated with updateKeyName.
func computePcrPolicyCounterAuthPolicies(alg tpm2.HashAlgorithmId, updateKeyName tpm2.Name) (tpm2.DigestList, error) {
	// The NV index requires 2 policies:
	// - A policy to initialize the index with no authorization
	// - A policy for updating the index to revoke old PCR policies using a signed assertion. This isn't done for security
	//   reasons, but just to make it harder to accidentally increment the counter for anyone interacting with the TPM.
	// This is simpler than the policy required for the v0 PIN NV index because it doesn't require additional authorization
	// policy branches to allow its authorization value to be changed, or to be able to read the counter value or use it in
	// a policy assertion without knowing the authorization value (reading the value of this counter does require the
	// authorization value, but it is always empty and this policy doesn't allow it to be changed).
	var authPolicies tpm2.DigestList

	trial, err := tpm2.ComputeAuthPolicy(alg)
	if err != nil {
		return nil, err
	}
	trial.PolicyNvWritten(false)
	authPolicies = append(authPolicies, trial.GetDigest())

	trial, _ = tpm2.ComputeAuthPolicy(alg)
	trial.PolicySigned(updateKeyName, nil)
	authPolicies = append(authPolicies, trial.GetDigest())

	return authPolicies, nil
}

// incrementPcrPolicyCounter will increment the NV counter index associated with nvPublic. This is designed to operate on a
// NV index created by createPcrPolicyCounter (for current key files) or on a NV index created by (the now deleted)
// createPinNVINdex for version 0 key files.
//
// This requires a signed authorization. For current key files, the keyPublic argument must correspond to the updateKeyName argument
// originally passed to createPcrPolicyCounter. For version 0 key files, this must correspond to the key originally passed to
// createPinNVIndex. The private part of that key must be supplied via the key argument. For version 0 key files, the authorization
// policy digests returned from createPinNVIndex must be supplied via the nvAuthPolicies argument.
func incrementPcrPolicyCounter(tpm *tpm2.TPMContext, version uint32, nvPublic *tpm2.NVPublic, nvAuthPolicies tpm2.DigestList, key crypto.PrivateKey, keyPublic *tpm2.Public, hmacSession tpm2.SessionContext) error {
	index, err := tpm2.CreateNVIndexResourceContextFromPublic(nvPublic)
	if err != nil {
		return xerrors.Errorf("cannot create context for NV index: %w", err)
	}

	// Begin a policy session to increment the index.
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nvPublic.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot begin policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	// Compute a digest for signing with the update key
	signDigest := tpm2.HashAlgorithmNull
	keyScheme := keyPublic.Params.AsymDetail().Scheme
	if keyScheme.Scheme != tpm2.AsymSchemeNull {
		signDigest = keyScheme.Details.Any().HashAlg
	}
	if signDigest == tpm2.HashAlgorithmNull {
		signDigest = tpm2.HashAlgorithmSHA256
	}
	h := signDigest.NewHash()
	h.Write(policySession.NonceTPM())
	binary.Write(h, binary.BigEndian, int32(0)) // expiration

	// Sign the digest
	var signature tpm2.Signature
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPSS(rand.Reader, k, signDigest.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return xerrors.Errorf("cannot sign authorization: %w", err)
		}
		signature = tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgRSAPSS,
			Signature: tpm2.SignatureU{
				Data: &tpm2.SignatureRSAPSS{
					Hash: signDigest,
					Sig:  tpm2.PublicKeyRSA(sig)}}}
	case *ecdsa.PrivateKey:
		sigR, sigS, err := ecdsa.Sign(rand.Reader, k, h.Sum(nil))
		if err != nil {
			return xerrors.Errorf("cannot sign authorization: %w", err)
		}
		signature = tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: tpm2.SignatureU{
				Data: &tpm2.SignatureECDSA{
					Hash:       signDigest,
					SignatureR: sigR.Bytes(),
					SignatureS: sigS.Bytes()}}}
	default:
		panic("invalid private key type")
	}

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, err := tpm.LoadExternal(nil, keyPublic, tpm2.HandleEndorsement)
	if err != nil {
		return xerrors.Errorf("cannot load public part of key used to verify authorization signature: %w", err)
	}
	defer tpm.FlushContext(keyLoaded)

	// Execute the policy assertions
	if version == 0 {
		// See the comment for computeV0PinNVIndexPostInitAuthPolicies for a description of the authorization policy
		// for the v0 NV index.
		if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVIncrement); err != nil {
			return xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
		}
		if err := tpm.PolicyNvWritten(policySession, true); err != nil {
			return xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
		}
	} else {
		nvAuthPolicies, err = computePcrPolicyCounterAuthPolicies(nvPublic.NameAlg, keyLoaded.Name())
		if err != nil {
			return xerrors.Errorf("cannot compute auth policies for counter: %w", err)
		}
	}

	if _, _, err := tpm.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, &signature); err != nil {
		return xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
	}
	if err := tpm.PolicyOR(policySession, nvAuthPolicies); err != nil {
		return xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
	}

	// Increment the index.
	if err := tpm.NVIncrement(index, index, policySession, hmacSession.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return xerrors.Errorf("cannot increment NV index: %w", err)
	}

	return nil
}

// readPcrPolicyCounter will read the value of the counter NV index associated with nvPublic. This is designed to operate on a
// NV index created by createPcrPolicyCounter (for current key files) or on a NV index created by (the now deleted)
// createPinNVINdex for version 0 key files. For version 0 key files, the authorization policy digests returned from createPinNVIndex
// must be supplied via the nvAuthPolicies argument.
func readPcrPolicyCounter(tpm *tpm2.TPMContext, version uint32, nvPublic *tpm2.NVPublic, nvAuthPolicies tpm2.DigestList, hmacSession tpm2.SessionContext) (uint64, error) {
	index, err := tpm2.CreateNVIndexResourceContextFromPublic(nvPublic)
	if err != nil {
		return 0, xerrors.Errorf("cannot create context for NV index: %w", err)
	}

	var authSession tpm2.SessionContext
	var extraSession tpm2.SessionContext
	if version == 0 {
		authSession, err = tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nvPublic.NameAlg)
		if err != nil {
			return 0, xerrors.Errorf("cannot begin policy session: %w", err)
		}
		defer tpm.FlushContext(authSession)

		// See the comment for computeV0PinNVIndexPostInitAuthPolicies for a description of the authorization policy
		// for the v0 NV index. Because the v0 NV index was also used for the PIN, it needed an authorization policy
		// to permit reading the counter value without knowing the authorization value of the index.
		if err := tpm.PolicyCommandCode(authSession, tpm2.CommandNVRead); err != nil {
			return 0, xerrors.Errorf("cannot execute assertion to read counter: %w", err)
		}
		if err := tpm.PolicyOR(authSession, nvAuthPolicies); err != nil {
			return 0, xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
		}

		extraSession = hmacSession.IncludeAttrs(tpm2.AttrAudit)
	} else {
		authSession = hmacSession
	}

	c, err := tpm.NVReadCounter(index, index, authSession, extraSession)
	if err != nil {
		return 0, xerrors.Errorf("cannot read counter: %w", err)
	}

	return c, nil
}

// createPcrPolicyCounter creates and initializes a NV counter that is associated with a sealed key object and is used for
// implementing dynamic authorization policy revocation.
//
// The NV index will be created with attributes that allow anyone to read the index, and an authorization policy that permits
// TPM2_NV_Increment with a signed authorization policy.
func createPcrPolicyCounter(tpm *tpm2.TPMContext, handle tpm2.Handle, updateKeyName tpm2.Name, hmacSession tpm2.SessionContext) (*tpm2.NVPublic, error) {
	nameAlg := tpm2.HashAlgorithmSHA256

	authPolicies, _ := computePcrPolicyCounterAuthPolicies(nameAlg, updateKeyName)

	trial, _ := tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyOR(authPolicies)

	// Define the NV index
	public := &tpm2.NVPublic{
		Index:      handle,
		NameAlg:    nameAlg,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		AuthPolicy: trial.GetDigest(),
		Size:       8}

	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, public, hmacSession)
	if err != nil {
		return nil, xerrors.Errorf("cannot define NV space: %w", err)
	}

	// NVDefineSpace was integrity protected, so we know that we have an index with the expected public area at the handle we specified
	// at this point.

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, hmacSession)
	}()

	// Begin a session to initialize the index.
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nameAlg)
	if err != nil {
		return nil, xerrors.Errorf("cannot begin policy session to initialize NV index: %w", err)
	}
	defer tpm.FlushContext(policySession)

	// Execute the policy assertions
	if err := tpm.PolicyNvWritten(policySession, false); err != nil {
		return nil, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyOR(policySession, authPolicies); err != nil {
		return nil, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}

	// Initialize the index
	if err := tpm.NVIncrement(index, index, policySession, hmacSession.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return nil, xerrors.Errorf("cannot initialize NV index: %w", err)
	}

	// The index has a different name now that it has been written, so update the public area we return so that it can be used
	// to construct an authorization policy.
	public.Attrs |= tpm2.AttrNVWritten

	succeeded = true
	return public, nil
}

// computeLockNVIndexPublicAreas computes the public areas used to define the NV indices used for locking access to sealed keys. It
// returns 3 public areas - the first one is for a bootstrap index, which is required to initialize the first index. See the
// description of ensureLockNVIndices to see the sequence for initializing these indices.
func computeLockNVIndexPublicAreas() (bootstrap *tpm2.NVPublic, index1 *tpm2.NVPublic, index2 *tpm2.NVPublic, err error) {
	bootstrap = &tpm2.NVPublic{
		Index:   lockNVHandle2,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		Size:    0}
	bootstrap.Attrs |= tpm2.AttrNVWritten
	bootstrapName, err := bootstrap.Name()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot compute name of bootstrap index: %w", err)
	}
	bootstrap.Attrs &^= tpm2.AttrNVWritten

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicySecret(bootstrapName, nil)

	index1 = &tpm2.NVPublic{
		Index:      lockNVHandle1,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      lockNVIndex1Attrs,
		AuthPolicy: trial.GetDigest(),
		Size:       0}
	index1.Attrs |= tpm2.AttrNVReadLocked | tpm2.AttrNVWritten
	index1LockedName, err := index1.Name()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot compute name of index 1: %w", err)
	}
	index1.Attrs &^= tpm2.AttrNVReadLocked | tpm2.AttrNVWritten

	trial, _ = tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicySecret(index1LockedName, nil)

	index2 = &tpm2.NVPublic{
		Index:      lockNVHandle2,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		AuthPolicy: trial.GetDigest(),
		Size:       0}

	return
}

// computeLockNVIndexNames computes the names of the 2 NV indices at well-known locations that are used for locking access to
// sealed keys. These names are not unique, and the presence of indices with these names should be asserted in any authorization
// policy that wants to benefit from locking.
func computeLockNVIndexNames() (tpm2.Name, tpm2.Name, error) {
	_, index1, index2, err := computeLockNVIndexPublicAreas()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute public areas for indices: %w", err)
	}

	index1.Attrs |= tpm2.AttrNVWritten
	index2.Attrs |= tpm2.AttrNVWritten

	index1Name, err := index1.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of index 1: %w", err)
	}
	index2Name, err := index2.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of index 2: %w", err)
	}

	return index1Name, index2Name, nil
}

// ensureLockNVIndices creates a pair of NV indices at well known handles for locking access to sealed keys with
// LockAccessToSealedKeys if they don't exist already, and the TPM doesn't contain a valid legacy lock NV index.
//
// These indices are used for locking access to any sealed key objects we create until the next TPM restart or reset. The same
// handles are used for all keys, regardless of individual key policy.
//
// The traditional way of achieving this is by extending another value to a PCR that is included in the PCR selection for a
// sealed key's authorization policy after the key has been unsealed, which makes its authorization policy non-satisfiable until
// the next reset or restart. The issue with this is that it makes the feature dependent on the PCR profile.
//
// The implementation here uses a pair of NV indices at well known handles and takes advantage of a couple of properties of NV
// index read locks:
// - Once enabled, they can only be disabled by a TPM reset or restart.
// - Enabling a read lock sets the index's TPMA_NV_READLOCKED attribute which changes its name.
// Sealed keys created by this package have an authorization policy that asserts that these NV indices exists at their well known
// handles. Calling LockAccessToSealedKeys enables the read lock for one of them, which changes its name and makes this assertion
// fail.
//
// The problem with this approach though is that the TPM owner (ie, anyone who knows the authorization value for the storage hierarchy,
// which is empty by default) can undefine and redefine a NV index in order to clear the read lock attribute, thus re-enabling access
// to sealed keys. One approach to prevent this from happening relies on the fact that writing to a NV index for the first time sets
// the TPMA_NV_WRITTEN attribute which also changes its name. If the index is defined with the TPMA_NV_POLICY_WRITE attribute and an
// authorization policy that can only be satisfied by an assertion signed with an ephemeral key (using TPM2_PolicySigned), and sealed
// keys have authorization policies that can only be satisfied by the presence of the initialized index, then it is not possible for
// an adversary without the private part of the ephemeral key to undefine and redefine an identical NV index in order to remove the
// TPMA_NV_READLOCKED attribute and reenable access to sealed keys. This was the approach previously taken by secboot, but this had
// its own problem - if the NV index is accidentally undefined, then this would make all sealed keys permanently unrecoverable.
// Ideally, provisioning the TPM without clearing it should be able to remedy any accidental changes and restore access to valid
// sealed keys in all cases except where the storage primary seed has been changed (ie, the TPM has been cleared).
//
// The current approach used for protecting the NV index used by LockAccessToSealedKeys makes use of 2 NV indices and has the property
// that the NV indices have names that are common to all devices and can always be recreated, but they have authorization policies
// that enforce a creation sequence that means that they can only be created in the locked state. The way this works is as follows:
// - A bootstrap index is created at handle 2 with TPMA_NV_AUTHREAD and TPMA_NV_AUTHWRITE attributes and an empty authorization
//   policy.
// - An empty write is performed to initialize the bootstrap index.
// - An index is created at handle 1 with TPMA_NV_AUTHREAD, TPMA_NV_POLICY_WRITE and TPMA_NV_READ_STCLEAR attributes, and an
//   authorization policy that can only be satisfied by the presence of the initialized bootstrap index.
// - An empty write is performed to initialize index 1 using a policy session.
// - The bootstrap index is undefined and another index is created at handle 2 with TPMA_NV_AUTHREAD and TPMA_NV_POLICY_WRITE
//   attributes, and an authorization policy that can only be satisfied by the presence of the initialized index at handle 1 with
//   its read lock enabled.
// - The read lock for the index at handle 1 is enabled.
// - An empty write is performed to initialize index 2 using a policy session.
//
// Authorization policies for sealed keys must assert the presence of both of these NV indices using the names of the initialized
// indices without the read lock enabled. Enabling the read lock on index 1 by calling LockAccessToSealedKeys will disable access to
// these keys.
// 
// It isn't possible to recreate these indices in their unlocked state. Although they can be recovered if they are undefined
// accidentally, they will not return to their unlocked state until the next TPM reset or restart.
//
// An adversary can't undefine and redefine either index in order to reenable access to sealed keys. Eg, say an adversary performs the
// following actions:
// - They undefine and redefine index 1. The new index isn't read locked, but sealed keys can't be unsealed until the new index has
//   been written to. But it has an authorization policy that requires index 2 to be undefined and replaced with the bootstrap index.
// - They undefine index 2 and create the boostrap index in its place.
// - They perform an empty write to index 1 to initialize it. Index 1 now has the expected name, but sealed keys still can't be
//   accessed because index 2 no longer exists.
// - They undefine the bootstrap index again and redefine index 2. However, sealed keys still can't be unsealed until the new index
//   has been written to. But it has an authorization policy that requires the read lock to be enabled on index 1.
// - They enable the read lock on index 1.
// - They perform an empty write to index 2 to initialize it. Index 2 now has the expected name, but sealed keys still can't be
//   accessed because index 1 is read locked. This can ony be undone by performing a TPM reset or restart.
//
// If this device has been provisioned with the legacy index, or has valid new-style indices, then this function does nothing.
func ensureLockNVIndices(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	if _, err := validateLockNVIndices(tpm, session); err == nil {
		// Nothing to do
		return nil
	}

	bootstrapPub, index1Pub, index2Pub, err := computeLockNVIndexPublicAreas()
	if err != nil {
		return xerrors.Errorf("cannot compute public areas for indices: %w", err)
	}

	for _, h := range []tpm2.Handle{index1Pub.Index, index2Pub.Index} {
		index, err := tpm.CreateResourceContextFromTPM(h)
		switch {
		case err != nil && !tpm2.IsResourceUnavailableError(err, h):
			// Unexpected error
			return xerrors.Errorf("cannot create context to determine if index is already defined: %w", err)
		case tpm2.IsResourceUnavailableError(err, h):
			// No existing index defined
		default:
			// Undefine the current index
			if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, session); err != nil {
				return xerrors.Errorf("cannot undefine existing index: %w", err)
			}
		}
	}

	succeeded := false

	bootstrap, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, bootstrapPub, session)
	if err != nil {
		return xerrors.Errorf("cannot create bootstrap index: %w", err)
	}
	defer func() {
		if succeeded || bootstrap.Handle() == tpm2.HandleUnassigned {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), bootstrap, session)
	}()

	if err := tpm.NVWrite(bootstrap, bootstrap, nil, 0, session); err != nil {
		return xerrors.Errorf("cannot initialize bootstrap index: %w", err)
	}

	index1, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, index1Pub, session)
	if err != nil {
		return xerrors.Errorf("cannot create index 1: %w", err)
	}
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index1, session)
	}()

	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, index1Pub.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot begin policy session to initialize indices: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if _, _, err := tpm.PolicySecret(bootstrap, policySession, nil, nil, 0, session); err != nil {
		return xerrors.Errorf("cannot execute assertion to initialize index 1: %w", err)
	}

	if err := tpm.NVWrite(index1, index1, nil, 0, policySession.IncludeAttrs(tpm2.AttrContinueSession), session.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return xerrors.Errorf("cannot initialize index 1: %w", err)
	}
	if err := tpm.NVReadLock(index1, index1, session); err != nil {
		return xerrors.Errorf("cannot enable read lock for index 1: %w", err)
	}

	if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), bootstrap, session); err != nil {
		return xerrors.Errorf("cannot undefine bootstrap index: %w", err)
	}

	index2, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, index2Pub, session)
	if err != nil {
		return xerrors.Errorf("cannot create index 2: %w", err)
	}
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index2, session)
	}()

	if _, _, err := tpm.PolicySecret(index1, policySession, nil, nil, 0, session); err != nil {
		return xerrors.Errorf("cannot execute assertion to initialize index 2: %w", err)
	}

	if err := tpm.NVWrite(index2, index2, nil, 0, policySession, session.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return xerrors.Errorf("cannot initialize index 2: %w", err)
	}

	succeeded = true

	return nil
}

// validateLegacyLockNVIndex validates that the supplied NV index is a valid legacy lock index and is safe to protect a new key against,
// and then returns the validated public area if it is. The name of the public area can then be used in an authorization policy.
func validateLegacyLockNVIndex(tpm *tpm2.TPMContext, index, dataIndex tpm2.ResourceContext, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	var s tpm2.SessionContext
	if session != nil {
		s = session.IncludeAttrs(tpm2.AttrAudit)
	}

	dataPub, _, err := tpm.NVReadPublic(dataIndex)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of policy data index: %w", err)
	}
	data, err := tpm.NVRead(dataIndex, dataIndex, dataPub.Size, 0, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot read policy data: %w", err)
	}

	// Unmarshal the data
	var version uint8
	var keyName tpm2.Name
	var clock uint64
	if _, err := tpm2.UnmarshalFromBytes(data, &version, &keyName, &clock); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal policy data: %w", err)
	}

	// Allow for future changes to the public attributes or auth policy configuration.
	if version != 0 {
		return nil, errors.New("unrecognized version for policy data")
	}

	// Read the TPM clock (no session here because some Infineon devices don't allow them, despite being permitted in the spec
	// and reference implementation)
	time, err := tpm.ReadClock()
	if err != nil {
		return nil, xerrors.Errorf("cannot read current time: %w", err)
	}

	// Make sure the window beyond which this index can be written has passed or about to pass.
	if time.ClockInfo.Clock+5000 < clock {
		return nil, errors.New("unexpected clock value in policy data")
	}

	// Read the public area of the lock NV index.
	pub, _, err := tpm.NVReadPublic(index, s)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of index: %w", err)
	}

	pub.Attrs &^= tpm2.AttrNVReadLocked
	// Validate its attributes
	if pub.Attrs != lockNVIndex1Attrs|tpm2.AttrNVWritten {
		return nil, errors.New("unexpected index attributes")
	}

	clockBytes := make([]byte, binary.Size(clock))
	binary.BigEndian.PutUint64(clockBytes, clock)

	// Compute the expected authorization policy from the contents of the data index, and make sure that this matches the public area.
	// This verifies that the lock NV index has a valid authorization policy.
	trial, err := tpm2.ComputeAuthPolicy(pub.NameAlg)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute expected policy for index: %w", err)
	}
	trial.PolicyCommandCode(tpm2.CommandNVWrite)
	trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
	trial.PolicySigned(keyName, nil)

	if !bytes.Equal(trial.GetDigest(), pub.AuthPolicy) {
		return nil, errors.New("incorrect policy for index")
	}

	// pub corresponds to a valid legacy global lock NV index that cannot be recreated!
	return pub, nil
}

// validateCurrentLockNVIndices validates that the supplied NV indices correspond to valid new-style lock NV indices.
func validateCurrentLockNVIndices(tpm *tpm2.TPMContext, index1, index2 tpm2.ResourceContext, session tpm2.SessionContext) error {
	var s tpm2.SessionContext
	if session != nil {
		s = session.IncludeAttrs(tpm2.AttrAudit)
	}

	index1Pub, _, err := tpm.NVReadPublic(index1, s)
	if err != nil {
		return xerrors.Errorf("cannot read public area of index 1: %w", err)
	}
	index1Pub.Attrs &^= tpm2.AttrNVReadLocked
	index1Name, err := index1Pub.Name()
	if err != nil {
		return xerrors.Errorf("cannot compute name of index 1: %w", err)
	}

	index1ExpectedName, index2ExpectedName, err := computeLockNVIndexNames()
	if err != nil {
		return xerrors.Errorf("cannot compute expected names: %w", err)
	}

	if !bytes.Equal(index1Name, index1ExpectedName) || !bytes.Equal(index2.Name(), index2ExpectedName) {
		return errors.New("found indices with unexpected names")
	}

	return nil
}

// validateLockNVIndices checks that the NV indices at the global handles used for locking access to sealed keys are valid lock
// indices, and returns an error if they aren't. If the indices correspond to the legacy mechanism, the public area of the lock index
// is returned, else no public area is returned.
func validateLockNVIndices(tpm *tpm2.TPMContext, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	var s tpm2.SessionContext
	if session != nil {
		s = session.IncludeAttrs(tpm2.AttrAudit)
	}
	index1, err := tpm.CreateResourceContextFromTPM(lockNVHandle1, s)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for index 1: %w", err)
	}
	index2, err := tpm.CreateResourceContextFromTPM(lockNVHandle2, s)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for index 2: %w", err)
	}

	err1 := validateCurrentLockNVIndices(tpm, index1, index2, session)
	if err1 == nil {
		return nil, nil
	}

	legacyPub, err2 := validateLegacyLockNVIndex(tpm, index1, index2, session)
	if err2 != nil {
		return nil, fmt.Errorf("cannot detect new indices (%v) or legacy index (%v)", err1, err2)
	}

	return legacyPub, nil
}

// ensureSufficientORDigests turns a single digest in to a pair of identical digests. This is because TPM2_PolicyOR assertions
// require more than one digest. This avoids having a separate policy sequence when there is only a single digest, without having
// to store duplicate digests on disk.
func ensureSufficientORDigests(digests tpm2.DigestList) tpm2.DigestList {
	if len(digests) == 1 {
		return tpm2.DigestList{digests[0], digests[0]}
	}
	return digests
}

// computePcrPolicyRefFromCounterName computes the reference used for authorization of signed PCR policies from the supplied
// PCR policy counter name. If name is empty, then the name of the null handle is assumed. The policy ref serves 2 purposes:
// 1) It limits the scope of the signed policy to just PCR policies (the dynamic authorization policy key may be able to sign
//    different types of policy in the future, for example, to permit recovery with a signed assertion.
// 2) It binds the name of the PCR policy counter to the static authorization policy.
func computePcrPolicyRefFromCounterName(name tpm2.Name) tpm2.Nonce {
	if len(name) == 0 {
		name = make(tpm2.Name, binary.Size(tpm2.Handle(0)))
		binary.BigEndian.PutUint32(name, uint32(tpm2.HandleNull))
	}

	h := tpm2.HashAlgorithmSHA256.NewHash()
	h.Write([]byte("AUTH-PCR-POLICY"))
	h.Write(name)

	return h.Sum(nil)
}

// computePcrPolicyRefFromCounterContext computes the reference used for authorization of signed PCR policies from the supplied
// ResourceContext.
func computePcrPolicyRefFromCounterContext(context tpm2.ResourceContext) tpm2.Nonce {
	var name tpm2.Name
	if context != nil {
		name = context.Name()
	}

	return computePcrPolicyRefFromCounterName(name)
}

// computeStaticPolicy computes the part of an authorization policy that is bound to a sealed key object and never changes. The
// static policy asserts that the following are true:
// - The signed PCR policy created by computeDynamicPolicy is valid and has been satisfied (by way of a PolicyAuthorize assertion,
//   which allows the PCR policy to be updated without creating a new sealed key object).
// - Knowledge of the the authorization value for the entity on which the policy session is used has been demonstrated by the
//   caller (in SealedKeyObject.UnsealFromTPM where the policy session is used for authorizing unsealing the sealed key object,
//   this means that the PIN / passhphrase has been provided).
// - That access to sealed keys created by this package is currently permitted (by way of a PolicyNV assertion against a NV index
//   at a well-known handle) because LockAccessToSealedKeys hasn't been called yet.
func computeStaticPolicy(alg tpm2.HashAlgorithmId, input *staticPolicyComputeParams) (*staticPolicyData, tpm2.Digest, error) {
	keyName, err := input.key.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of signing key for dynamic policy authorization: %w", err)
	}

	pcrPolicyCounterHandle := tpm2.HandleNull
	var pcrPolicyCounterName tpm2.Name
	if input.pcrPolicyCounterPub != nil {
		pcrPolicyCounterHandle = input.pcrPolicyCounterPub.Index
		pcrPolicyCounterName, err = input.pcrPolicyCounterPub.Name()
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot compute name of PCR policy counter: %w", err)
		}
	}

	trial, _ := tpm2.ComputeAuthPolicy(alg)
	trial.PolicyAuthorize(computePcrPolicyRefFromCounterName(pcrPolicyCounterName), keyName)
	trial.PolicyAuthValue()
	if len(input.legacyLockIndexName) > 0 {
		trial.PolicyNV(input.legacyLockIndexName, nil, 0, tpm2.OpEq)
	} else {
		lockIndex1Name, lockIndex2Name, err := computeLockNVIndexNames()
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot compute names of lock NV indices: %w", err)
		}
		trial.PolicyNV(lockIndex1Name, nil, 0, tpm2.OpEq)
		trial.PolicyNV(lockIndex2Name, nil, 0, tpm2.OpEq)
	}

	return &staticPolicyData{
		authPublicKey:          input.key,
		pcrPolicyCounterHandle: pcrPolicyCounterHandle}, trial.GetDigest(), nil
}

// computePolicyORData computes data required to perform a sequence of TPM2_PolicyOR assertions in order to support compound
// authorization policies with more than 8 conditions (which is the limit of the TPM). Its main purpose is to support PCR policies
// with more than 8 conditions. It works by turning a list of digests (or, conditions) in to a tree of nodes, with each node
// containing no more than 8 digests that can be used in a single TPM2_PolicyOR assertion, the root of the tree containing digests
// for the final TPM2_PolicyOR assertion, and leaf nodes containing digests for each OR condition. Whilst the returned data is
// conceptually a tree, the layout in memory is just a slice of tables of up to 8 digests, each with an index that enables the code
// executing the assertions to traverse upwards through the tree by just advancing to another entry in the slice. This format is
// easily serialized. After the computations are completed, the provided *tpm2.TrialAuthPolicy will be updated.
//
// The returned data is used by firstly finding the leaf node which contains the current session digest. Once this is found, a
// TPM2_PolicyOR assertion is executed on the digests in that node, and then the tree is traversed upwards to the root node, executing
// TPM2_PolicyOR assertions along the way - see executePolicyORAssertions.
func computePolicyORData(alg tpm2.HashAlgorithmId, trial *tpm2.TrialAuthPolicy, digests tpm2.DigestList) policyOrDataTree {
	var data policyOrDataTree
	curNode := 0
	var nextDigests tpm2.DigestList

	for {
		n := len(digests)
		if n > 8 {
			// The TPM only supports 8 conditions in TPM2_PolicyOR.
			n = 8
		}

		data = append(data, policyOrDataNode{Digests: digests[:n]})
		if n == len(digests) && len(nextDigests) == 0 {
			// All of the digests at this level fit in to a single TPM2_PolicyOR command, so this becomes the root node.
			break
		}

		// Consume the next n digests to fit in to this node and produce a single digest that will go in to the parent node.
		trial, _ := tpm2.ComputeAuthPolicy(alg)
		trial.PolicyOR(ensureSufficientORDigests(digests[:n]))
		nextDigests = append(nextDigests, trial.GetDigest())

		// We've consumed n digests, so adjust the slice to point to the next ones to consume to produce a sibling node.
		digests = digests[n:]

		if len(digests) == 0 {
			// There are no digests left to produce sibling nodes, and we have a collection of digests to produce parent nodes. Update the
			// nodes produced at this level to point to the parent nodes we're going to produce on the subsequent iterations.
			for i := range nextDigests {
				// At this point, len(nextDigests) == (len(data) - curNode).
				// 'len(nextDigests) - i' initializes Next to point to the end of data (ie, data[len(data)]), and the '+ (i / 8)' advances it to
				// point to the parent node that will be created on subsequent iterations, taking in to account that each node will have up to
				// 8 child nodes.
				data[curNode+i].Next = uint32(len(nextDigests) - i + (i / 8))
			}
			// Grab the digests produced for the nodes at this level to produce the parent nodes.
			curNode += len(nextDigests)
			digests = nextDigests
			nextDigests = nil
		}
	}

	trial.PolicyOR(ensureSufficientORDigests(digests))
	return data
}

// computeDynamicPolicy computes the PCR policy associated with a sealed key object, and can be updated without having to create a
// new sealed key object as it takes advantage of the PolicyAuthorize assertion. The PCR policy asserts that the following are true:
// - The selected PCRs contain expected values - ie, one of the sets of permitted values specified by the caller to this function,
//   indicating that the device is in an expected state. This is done by a single PolicyPCR assertion and then one or more PolicyOR
//   assertions (depending on how many sets of permitted PCR values there are).
// - The PCR policy hasn't been revoked. This is done using a PolicyNV assertion to assert that the value of an optional NV counter
//   is not greater than the expected value.
// The computed PCR policy digest is signed with the supplied asymmetric key, and the signature of this is validated before executing
// the corresponding PolicyAuthorize assertion as part of the static policy.
func computeDynamicPolicy(version uint32, alg tpm2.HashAlgorithmId, input *dynamicPolicyComputeParams) (*dynamicPolicyData, error) {
	if len(input.pcrDigests) == 0 {
		return nil, errors.New("no PCR digests specified")
	}

	// Compute the policy digest that would result from a TPM2_PolicyPCR assertion for each condition
	var pcrOrDigests tpm2.DigestList
	for _, d := range input.pcrDigests {
		trial, _ := tpm2.ComputeAuthPolicy(alg)
		trial.PolicyPCR(d, input.pcrs)
		pcrOrDigests = append(pcrOrDigests, trial.GetDigest())
	}

	trial, _ := tpm2.ComputeAuthPolicy(alg)
	pcrOrData := computePolicyORData(alg, trial, pcrOrDigests)

	if len(input.policyCounterName) > 0 {
		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, input.policyCount)
		trial.PolicyNV(input.policyCounterName, operandB, 0, tpm2.OpUnsignedLE)
	}

	authorizedPolicy := trial.GetDigest()

	// Create a digest to sign
	h := input.signAlg.NewHash()
	h.Write(authorizedPolicy)
	if version > 0 {
		h.Write(computePcrPolicyRefFromCounterName(input.policyCounterName))
	}

	// Sign the digest
	var signature tpm2.Signature
	if version == 0 {
		sig, err := rsa.SignPSS(rand.Reader, input.key.(*rsa.PrivateKey), input.signAlg.GetHash(), h.Sum(nil),
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
		}

		signature = tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgRSAPSS,
			Signature: tpm2.SignatureU{
				Data: &tpm2.SignatureRSAPSS{
					Hash: input.signAlg,
					Sig:  tpm2.PublicKeyRSA(sig)}}}
	} else {
		sigR, sigS, err := ecdsa.Sign(rand.Reader, input.key.(*ecdsa.PrivateKey), h.Sum(nil))
		if err != nil {
			return nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
		}

		signature = tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: tpm2.SignatureU{
				Data: &tpm2.SignatureECDSA{
					Hash:       input.signAlg,
					SignatureR: sigR.Bytes(),
					SignatureS: sigS.Bytes()}}}
	}

	return &dynamicPolicyData{
		pcrSelection:              input.pcrs,
		pcrOrData:                 pcrOrData,
		policyCount:               input.policyCount,
		authorizedPolicy:          authorizedPolicy,
		authorizedPolicySignature: &signature}, nil
}

type staticPolicyDataError struct {
	err error
}

func (e staticPolicyDataError) Error() string {
	return e.err.Error()
}

func (e staticPolicyDataError) Unwrap() error {
	return e.err
}

func isStaticPolicyDataError(err error) bool {
	var e staticPolicyDataError
	return xerrors.As(err, &e)
}

type dynamicPolicyDataError struct {
	err error
}

func (e dynamicPolicyDataError) Error() string {
	return e.err.Error()
}

func (e dynamicPolicyDataError) Unwrap() error {
	return e.err
}

func isDynamicPolicyDataError(err error) bool {
	var e dynamicPolicyDataError
	return xerrors.As(err, &e)
}

// executePolicyORAssertions takes the data produced by computePolicyORData and executes a sequence of TPM2_PolicyOR assertions, in
// order to support compound policies with more than 8 conditions.
func executePolicyORAssertions(tpm *tpm2.TPMContext, session tpm2.SessionContext, data policyOrDataTree) error {
	// First of all, obtain the current digest of the session.
	currentDigest, err := tpm.PolicyGetDigest(session)
	if err != nil {
		return xerrors.Errorf("cannot obtain current session digest: %w", err)
	}

	if len(data) == 0 {
		return errors.New("no policy data")
	}

	// Find the leaf node that contains the current digest of the session.
	index := -1
	end := data[0].Next
	if end == 0 {
		end = 1
	}

	for i := 0; i < len(data) && i < int(end); i++ {
		if digestListContains(data[i].Digests, currentDigest) {
			// We've got a match!
			index = i
			break
		}
	}
	if index == -1 {
		return errors.New("current session digest not found in policy data")
	}

	// Execute a TPM2_PolicyOR assertion on the digests in the leaf node and then traverse up the tree to the root node, executing
	// TPM2_PolicyOR assertions along the way.
	for lastIndex := -1; index > lastIndex && index < len(data); index += int(data[index].Next) {
		lastIndex = index
		if err := tpm.PolicyOR(session, ensureSufficientORDigests(data[index].Digests)); err != nil {
			return err
		}
		if data[index].Next == 0 {
			// This is the root node, so we're finished.
			break
		}
	}
	return nil
}

// executePolicySession executes an authorization policy session using the supplied metadata. On success, the supplied policy
// session can be used for authorization.
func executePolicySession(tpm *tpm2.TPMContext, policySession tpm2.SessionContext, version uint32, staticInput *staticPolicyData,
	dynamicInput *dynamicPolicyData, pin string, hmacSession tpm2.SessionContext) error {
	if err := tpm.PolicyPCR(policySession, nil, dynamicInput.pcrSelection); err != nil {
		return xerrors.Errorf("cannot execute PCR assertion: %w", err)
	}

	if err := executePolicyORAssertions(tpm, policySession, dynamicInput.pcrOrData); err != nil {
		switch {
		case tpm2.IsTPMError(err, tpm2.AnyErrorCode, tpm2.CommandPolicyGetDigest):
			return xerrors.Errorf("cannot execute OR assertions: %w", err)
		case tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyOR, 1):
			// The dynamic authorization policy data is invalid.
			return dynamicPolicyDataError{errors.New("cannot complete OR assertions: invalid data")}
		}
		return dynamicPolicyDataError{xerrors.Errorf("cannot complete OR assertions: %w", err)}
	}

	pcrPolicyCounterHandle := staticInput.pcrPolicyCounterHandle
	if (pcrPolicyCounterHandle != tpm2.HandleNull || version == 0) && pcrPolicyCounterHandle.Type() != tpm2.HandleTypeNVIndex {
		return staticPolicyDataError{errors.New("invalid handle for PCR policy counter")}
	}

	var policyCounter tpm2.ResourceContext
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		var err error
		policyCounter, err = tpm.CreateResourceContextFromTPM(pcrPolicyCounterHandle)
		switch {
		case tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle):
			// If there is no NV index at the expected handle then the key file is invalid and must be recreated.
			return staticPolicyDataError{errors.New("no PCR policy counter found")}
		case err != nil:
			return xerrors.Errorf("cannot obtain context for PCR policy counter: %w", err)
		}

		var revocationCheckSession tpm2.SessionContext
		if version == 0 {
			policyCounterPub, _, err := tpm.NVReadPublic(policyCounter)
			if err != nil {
				return xerrors.Errorf("cannot read public area for PCR policy counter: %w", err)
			}
			if !policyCounterPub.NameAlg.Supported() {
				//If the NV index has an unsupported name algorithm, then this key file is invalid and must be recreated.
				return staticPolicyDataError{errors.New("PCR policy counter has an unsupported name algorithm")}
			}

			revocationCheckSession, err = tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, policyCounterPub.NameAlg)
			if err != nil {
				return xerrors.Errorf("cannot create session for PCR policy revocation check: %w", err)
			}
			defer tpm.FlushContext(revocationCheckSession)

			// See the comment for computeV0PinNVIndexPostInitAuthPolicies for a description of the authorization policy
			// for the v0 NV index. Because the v0 NV index was also used for the PIN, it needed an authorization policy to
			// permit using the counter value in an assertion without knowing the authorization value of the index.
			if err := tpm.PolicyCommandCode(revocationCheckSession, tpm2.CommandPolicyNV); err != nil {
				return xerrors.Errorf("cannot execute assertion for PCR policy revocation check: %w", err)
			}
			if err := tpm.PolicyOR(revocationCheckSession, staticInput.v0PinIndexAuthPolicies); err != nil {
				if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyOR, 1) {
					// staticInput.v0PinIndexAuthPolicies is invalid.
					return staticPolicyDataError{errors.New("authorization policy metadata for PCR policy counter is invalid")}
				}
				return xerrors.Errorf("cannot execute assertion for PCR policy revocation check: %w", err)
			}
		}

		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, dynamicInput.policyCount)
		if err := tpm.PolicyNV(policyCounter, policyCounter, policySession, operandB, 0, tpm2.OpUnsignedLE, revocationCheckSession); err != nil {
			switch {
			case tpm2.IsTPMError(err, tpm2.ErrorPolicy, tpm2.CommandPolicyNV):
				// The PCR policy has been revoked.
				return dynamicPolicyDataError{errors.New("the PCR policy has been revoked")}
			case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandPolicyNV, 1):
				// Either staticInput.v0PinIndexAuthPolicies is invalid or the NV index isn't what's expected, so the key file is invalid.
				return staticPolicyDataError{errors.New("invalid PCR policy counter or associated authorization policy metadata")}
			}
			return xerrors.Errorf("PCR policy revocation check failed: %w", err)
		}
	}

	authPublicKey := staticInput.authPublicKey
	if !authPublicKey.NameAlg.Supported() {
		return staticPolicyDataError{errors.New("public area of dynamic authorization policy signing key has an unsupported name algorithm")}
	}
	authorizeKey, err := tpm.LoadExternal(nil, authPublicKey, tpm2.HandleOwner)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandLoadExternal, 2) {
			// staticInput.AuthPublicKey is invalid
			return staticPolicyDataError{errors.New("public area of dynamic authorization policy signing key is invalid")}
		}
		return xerrors.Errorf("cannot load public area for dynamic authorization policy signing key: %w", err)
	}
	defer tpm.FlushContext(authorizeKey)

	var pcrPolicyRef tpm2.Nonce
	if version > 0 {
		// The authorized PCR policy signature contains a reference for > v0 metadata, which limits the scope of it for authorizing
		// PCR policy. In future, the key that authorizes this policy may be used to authorize other policy digests for the purposes of,
		// eg, recovery with a signed assertion.
		pcrPolicyRef = computePcrPolicyRefFromCounterContext(policyCounter)
	}

	h := authPublicKey.NameAlg.NewHash()
	h.Write(dynamicInput.authorizedPolicy)
	h.Write(pcrPolicyRef)

	authorizeTicket, err := tpm.VerifySignature(authorizeKey, h.Sum(nil), dynamicInput.authorizedPolicySignature)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandVerifySignature, 2) {
			// dynamicInput.AuthorizedPolicySignature or the computed policy ref is invalid.
			// XXX: It's not possible to determine whether this is broken dynamic or static metadata -
			//  we should just do away with the distinction here tbh
			return dynamicPolicyDataError{errors.New("cannot verify PCR policy signature")}
		}
		return xerrors.Errorf("cannot verify PCR policy signature: %w", err)
	}

	if err := tpm.PolicyAuthorize(policySession, dynamicInput.authorizedPolicy, pcrPolicyRef, authorizeKey.Name(), authorizeTicket); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyAuthorize, 1) {
			// dynamicInput.AuthorizedPolicy is invalid.
			return dynamicPolicyDataError{errors.New("the PCR policy is invalid")}
		}
		return xerrors.Errorf("PCR policy check failed: %w", err)
	}

	if version == 0 {
		// For metadata version 0, PIN support is implemented by asserting knowlege of the authorization value
		// for the PCR policy counter.
		policyCounter.SetAuthValue([]byte(pin))
		if _, _, err := tpm.PolicySecret(policyCounter, policySession, nil, nil, 0, hmacSession); err != nil {
			return xerrors.Errorf("cannot execute PolicySecret assertion: %w", err)
		}
	} else {
		// For metadata versions > 0, PIN support is implemented by requiring knowlege of the authorization value for
		// the sealed key object when this policy session is used to unseal it.
		if err := tpm.PolicyAuthValue(policySession); err != nil {
			return xerrors.Errorf("cannot execute PolicyAuthValue assertion: %w", err)
		}
	}

	lockNVHandles := []tpm2.Handle{lockNVHandle1}
	if legacyPub, err := validateLockNVIndices(tpm, hmacSession); legacyPub == nil && err == nil {
		// The TPM is provisioned with new style lock NV indices.
		lockNVHandles = append(lockNVHandles, lockNVHandle2)
	}

	for _, h := range lockNVHandles {
		index, err := tpm.CreateResourceContextFromTPM(h)
		if err != nil {
			return xerrors.Errorf("cannot obtain context for lock NV index: %w", err)
		}
		if err := tpm.PolicyNV(index, index, policySession, nil, 0, tpm2.OpEq, nil); err != nil {
			return xerrors.Errorf("policy lock check failed: %w", err)
		}
	}

	return nil
}

// LockAccessToSealedKeys locks access to keys sealed by this package until the next TPM restart (equivalent to eg, system resume
// from suspend-to-disk) or TPM reset (equivalent to booting after a system restart). This works for all keys sealed by this package
// regardless of their PCR protection profile.
//
// On success, subsequent calls to SealedKeyObject.UnsealFromTPM will fail with a ErrSealedKeyAccessLocked error until the next TPM
// restart or TPM reset.
func LockAccessToSealedKeys(tpm *TPMConnection) error {
	session := tpm.HmacSession()

	handles, err := tpm.GetCapabilityHandles(lockNVHandle1, 1, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot obtain handles from TPM: %w", err)
	}
	if len(handles) == 0 || handles[0] != lockNVHandle1 {
		// Not provisioned, so no keys created by this package can be unsealed by this TPM
		return nil
	}
	lock, err := tpm.CreateResourceContextFromTPM(lockNVHandle1)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for lock NV index: %w", err)
	}
	lockPublic, _, err := tpm.NVReadPublic(lock, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area of lock NV index: %w", err)
	}
	if lockPublic.Attrs != lockNVIndex1Attrs|tpm2.AttrNVWritten {
		// Definitely not an index created by us, so no keys created by this package can be unsealed by this TPM.
		return nil
	}
	if err := tpm.NVReadLock(lock, lock, session); err != nil {
		if isAuthFailError(err, tpm2.CommandNVReadLock, 1) {
			// The index has an authorization value, so it wasn't created by this package and no keys created by this package can be unsealed
			// by this TPM.
			return nil
		}
		return xerrors.Errorf("cannot lock NV index for reading: %w", err)
	}
	return nil
}
