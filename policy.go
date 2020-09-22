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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"
)

const (
	lockNVIndexVersion   uint8 = 0    // Policy data version for lockNVHandle, to support backwards compatible changes
	lockNVIndexGraceTime       = 5000 // Time window in milliseconds in which lockNVHandle can be initialized after creation
)

var (
	// lockNVIndexAttrs are the attributes for the global lock NV index.
	lockNVIndexAttrs = tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVReadStClear)
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
	lockIndexName       tpm2.Name      // Name of the global NV index for locking access to sealed key objects
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

// ensureLockNVIndex creates a NV index at lockNVHandle if one doesn't exist already. This is used for locking access to any sealed
// key objects we create until the next TPM restart or reset. The same handle is used for all keys, regardless of individual key
// policy.
//
// Locking works by enabling the read lock bit for the NV index. As this changes the name of the index until the next TPM reset or
// restart, it makes any authorization policy that depends on it un-satisfiable. We do this rather than extending an extra value to a
// PCR, as it decouples the PCR policy from the locking feature and allows for the option of having more flexible, owner-customizable
// and maybe device-specific PCR policies in the future.
//
// To prevent someone with knowledge of the owner authorization (which is empty unless someone has taken ownership of the TPM) from
// clearing the read lock bit by just undefining and redifining a new NV index with the same properties, we need a way to prevent
// someone from being able to create an identical index. One option for this would be to use a NV counter, which has the property
// that they can only increment and are initialized with a value larger than the largest count value seen on the TPM. Whilst it
// would be possible to recreate a counter with the same name, it wouldn't be possible to recreate one with the same value. Keys
// sealed by this package can then execute an assertion that the counter is equal to a certain value. One problem with this is that
// the current value needs to be known at key sealing time (as it forms part of the authorization policy), and the read lock bit will
// prevent the count value from being read from the TPM. Also, the number of counters available is extremely limited, and we already
// use one per sealed key.
//
// Another approach is to use an ordinary NV index that can't be recreated with the same name. To do this, we require the NV index
// to have been written to and only allow writes with a signed authorization policy. Once initialized, the signing key is discarded.
// This works because the name of the signing key is included in the authorization policy digest for the NV index, and the
// authorization policy digest and attributes are included in the name of the NV index. Without the private part of the signing key,
// it is impossible to create a new NV index with the same name, and so, if this NV index is undefined then it becomes impossible to
// satisfy the authorization policy for any sealed key objects we've created already.
//
// The issue here though is that the globally defined NV index is created at provisioning time, and it may be possible to seal a new
// key to the TPM at any point in the future without provisioning a new global NV index here. In the time between provisioning and
// sealing a key to the TPM, an adversary may have created a new NV index with a policy that only allows writes with a signed
// authorization, initialized it, but then retained the private part of the key. This allows them to undefine and redefine a new NV
// index with the same name in the future in order to remove the read lock bit. To mitigate this, we include another assertion in
// the authorization policy that only allows writes during a small time window (sufficient to initialize the index after it is
// created), and disallows writes once the TPM's clock has advanced past that window. As the parameters of this assertion are
// included in the authorization policy digest, it becomes impossible even for someone with the private part of the key to create
// and initialize a NV index with the same name once the TPM's clock has advanced past that point, without performing a clear of the
// TPM. Clearing the TPM changes the SPS anyway, and makes it impossible to recover any keys previously sealed.
//
// The signing key name and the time window during which the index can be initialized are recorded in another NV index so that it is
// possible to use those to determine whether the lock NV index has an authorization policy that can never be satisfied, in order to
// verify that the index can not be recreated and is therefore safe to use.
func ensureLockNVIndex(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	if existing, err := tpm.CreateResourceContextFromTPM(lockNVHandle); err == nil {
		if _, err := readAndValidateLockNVIndexPublic(tpm, existing, session); err == nil {
			return nil
		}
	}

	// Create signing key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return xerrors.Errorf("cannot create signing key for initializing NV index: %w", err)
	}

	keyPublic := createTPMPublicAreaForECDSAKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		return xerrors.Errorf("cannot compute name of signing key for initializing NV index: %w", err)
	}

	// Read the TPM clock (no session here because some Infineon devices don't allow them, despite being permitted in the spec
	// and reference implementation)
	time, err := tpm.ReadClock()
	if err != nil {
		return xerrors.Errorf("cannot read current time: %w", err)
	}
	// Give us a small window in which to initialize the index, beyond which the index cannot be written to without a change in TPM owner.
	time.ClockInfo.Clock += lockNVIndexGraceTime
	clockBytes := make(tpm2.Operand, binary.Size(time.ClockInfo.Clock))
	binary.BigEndian.PutUint64(clockBytes, time.ClockInfo.Clock)

	nameAlg := tpm2.HashAlgorithmSHA256

	// Compute the authorization policy.
	trial, _ := tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyCommandCode(tpm2.CommandNVWrite)
	trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
	trial.PolicySigned(keyName, nil)

	// Create the index.
	public := &tpm2.NVPublic{
		Index:      lockNVHandle,
		NameAlg:    nameAlg,
		Attrs:      lockNVIndexAttrs,
		AuthPolicy: trial.GetDigest(),
		Size:       0}
	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, public, session)
	if err != nil {
		var e *tpm2.TPMError
		if tpm2.AsTPMError(err, tpm2.ErrorNVDefined, tpm2.CommandNVDefineSpace, &e) {
			return &tpmErrorWithHandle{err: e, handle: public.Index}
		}
		return xerrors.Errorf("cannot create NV index: %w", err)
	}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, session)
	}()

	// Begin a session to initialize the index.
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nameAlg)
	if err != nil {
		return xerrors.Errorf("cannot begin policy session to initialize NV index: %w", err)
	}
	defer tpm.FlushContext(policySession)

	// Compute a digest for signing with our key
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
	binary.Write(h, binary.BigEndian, int32(0))

	// Sign the digest
	sigR, sigS, err := ecdsa.Sign(rand.Reader, key, h.Sum(nil))
	if err != nil {
		return xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
	}

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, err := tpm.LoadExternal(nil, keyPublic, tpm2.HandleEndorsement)
	if err != nil {
		return xerrors.Errorf("cannot load public part of key used to initialize NV index to the TPM: %w", err)
	}
	defer tpm.FlushContext(keyLoaded)

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgECDSA,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureECDSA{
				Hash:       signDigest,
				SignatureR: sigR.Bytes(),
				SignatureS: sigS.Bytes()}}}

	// Execute the policy assertions
	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVWrite); err != nil {
		return xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyCounterTimer(policySession, clockBytes, 8, tpm2.OpUnsignedLT); err != nil {
		return xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}
	if _, _, err := tpm.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, &signature); err != nil {
		return xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}

	// Initialize the index
	if err := tpm.NVWrite(index, index, nil, 0, policySession, session.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return xerrors.Errorf("cannot initialize NV index: %w", err)
	}

	// Marshal key name and cut-off time for writing to the NV index so that they can be used for verification in the future.
	data, err := tpm2.MarshalToBytes(lockNVIndexVersion, keyName, time.ClockInfo.Clock)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal contents for policy data NV index: %v", err))
	}

	// Create the data index.
	dataPublic := tpm2.NVPublic{
		Index:   lockNVDataHandle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		Size:    uint16(len(data))}
	dataIndex, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &dataPublic, session)
	if err != nil {
		var e *tpm2.TPMError
		if tpm2.AsTPMError(err, tpm2.ErrorNVDefined, tpm2.CommandNVDefineSpace, &e) {
			return &tpmErrorWithHandle{err: e, handle: dataPublic.Index}
		}
		return xerrors.Errorf("cannot create policy data NV index: %w", err)
	}

	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), dataIndex, session)
	}()

	// Initialize the index
	if err := tpm.NVWrite(dataIndex, dataIndex, data, 0, session); err != nil {
		return xerrors.Errorf("cannot initialize policy data NV index: %w", err)
	}
	if err := tpm.NVWriteLock(dataIndex, dataIndex, session); err != nil {
		return xerrors.Errorf("cannot write lock policy data NV index: %w", err)
	}

	succeeded = true
	return nil
}

// readAndValidateLockNVIndexPublic validates that the NV index at the global lock handle is safe to protect a new key against, and
// then returns the public area if it is. The name of the public area can then be used in an authorization policy.
func readAndValidateLockNVIndexPublic(tpm *tpm2.TPMContext, index tpm2.ResourceContext, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	// Obtain the data recorded alongside the lock NV index for validating that it has a valid authorization policy.
	dataIndex, err := tpm.CreateResourceContextFromTPM(lockNVDataHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain context for policy data NV index: %w", err)
	}
	dataPub, _, err := tpm.NVReadPublic(dataIndex)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of policy data NV index: %w", err)
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
	if version != lockNVIndexVersion {
		return nil, errors.New("unrecognized version for policy data")
	}

	// Read the TPM clock (no session here because some Infineon devices don't allow them, despite being permitted in the spec
	// and reference implementation)
	time, err := tpm.ReadClock()
	if err != nil {
		return nil, xerrors.Errorf("cannot read current time: %w", err)
	}

	// Make sure the window beyond which this index can be written has passed or about to pass.
	if time.ClockInfo.Clock+lockNVIndexGraceTime < clock {
		return nil, errors.New("unexpected clock value in policy data")
	}

	// Read the public area of the lock NV index.
	pub, _, err := tpm.NVReadPublic(index, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of NV index: %w", err)
	}

	pub.Attrs &^= tpm2.AttrNVReadLocked
	// Validate its attributes
	if pub.Attrs != lockNVIndexAttrs|tpm2.AttrNVWritten {
		return nil, errors.New("unexpected NV index attributes")
	}

	clockBytes := make([]byte, binary.Size(clock))
	binary.BigEndian.PutUint64(clockBytes, clock)

	// Compute the expected authorization policy from the contents of the data index, and make sure this matches the public area.
	// This verifies that the lock NV index has a valid authorization policy.
	trial, err := tpm2.ComputeAuthPolicy(pub.NameAlg)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute expected policy for NV index: %w", err)
	}
	trial.PolicyCommandCode(tpm2.CommandNVWrite)
	trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
	trial.PolicySigned(keyName, nil)

	if !bytes.Equal(trial.GetDigest(), pub.AuthPolicy) {
		return nil, errors.New("incorrect policy for NV index")
	}

	// This is a valid global lock NV index that cannot be recreated!
	return pub, nil
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
	trial.PolicyNV(input.lockIndexName, nil, 0, tpm2.OpEq)

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

type policyDataError struct {
	err error
}

func (e policyDataError) Error() string {
	return e.err.Error()
}

func (e policyDataError) Unwrap() error {
	return e.err
}

func isPolicyDataError(err error) bool {
	var e policyDataError
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
			// The tree of policy digests is invalid
			return policyDataError{errors.New("cannot complete OR assertions for PCR policy: invalid metadata")}
		}
		// The tree of policy digests doesn't contain an entry for the current digest
		return policyDataError{xerrors.Errorf("cannot complete OR assertions for PCR policy: %w", err)}
	}

	pcrPolicyCounterHandle := staticInput.pcrPolicyCounterHandle
	if (pcrPolicyCounterHandle != tpm2.HandleNull || version == 0) && pcrPolicyCounterHandle.Type() != tpm2.HandleTypeNVIndex {
		return keyDataError{errors.New("invalid handle type for PCR policy counter")}
	}

	var policyCounter tpm2.ResourceContext
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		var err error
		policyCounter, err = tpm.CreateResourceContextFromTPM(pcrPolicyCounterHandle)
		switch {
		case tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle):
			// If there is no NV index at the expected handle then the key data is invalid.
			return keyDataError{errors.New("no PCR policy counter found")}
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
				// If the NV index has an unsupported name algorithm, then the key data is invalid.
				return keyDataError{errors.New("PCR policy counter has an unsupported name algorithm")}
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
					return keyDataError{errors.New("authorization policy metadata for PCR policy counter is invalid")}
				}
				return xerrors.Errorf("cannot execute assertion for PCR policy revocation check: %w", err)
			}
		}

		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, dynamicInput.policyCount)
		if err := tpm.PolicyNV(policyCounter, policyCounter, policySession, operandB, 0, tpm2.OpUnsignedLE, revocationCheckSession); err != nil {
			switch {
			case tpm2.IsTPMError(err, tpm2.ErrorPolicy, tpm2.CommandPolicyNV):
				// The PCR policy has been revoked. Note that this could happen if the keydata / NV index is invalid, but it's worth
				// not assuming that for now (SealedKeyObject.Validate can detect this)
				return policyDataError{errors.New("the PCR policy has been revoked")}
			case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandPolicyNV, 1):
				// Either staticInput.v0PinIndexAuthPolicies is invalid or the NV index isn't what's expected, so the key data is invalid.
				return keyDataError{errors.New("invalid PCR policy counter or associated authorization policy metadata")}
			}
			return xerrors.Errorf("PCR policy revocation check failed: %w", err)
		}
	}

	authPublicKey := staticInput.authPublicKey
	if !authPublicKey.NameAlg.Supported() {
		return keyDataError{errors.New("public area of dynamic authorization policy signing key has an unsupported name algorithm")}
	}
	authorizeKey, err := tpm.LoadExternal(nil, authPublicKey, tpm2.HandleOwner)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandLoadExternal, 2) {
			// staticInput.AuthPublicKey is invalid
			return keyDataError{errors.New("public area of dynamic authorization policy signing key is invalid")}
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
			// dynamicInput.AuthorizedPolicySignature, the signing key, or the PCR policy counter is invalid. Assume it is the former
			// for now (SealedKeyObject.Validate can detect the others).
			return policyDataError{errors.New("cannot verify PCR policy signature")}
		}
		return xerrors.Errorf("cannot verify PCR policy signature: %w", err)
	}

	if err := tpm.PolicyAuthorize(policySession, dynamicInput.authorizedPolicy, pcrPolicyRef, authorizeKey.Name(), authorizeTicket); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyAuthorize, 1) {
			// dynamicInput.AuthorizedPolicy is invalid.
			return policyDataError{errors.New("the PCR policy is invalid")}
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

	lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for lock NV index: %w", err)
	}
	if err := tpm.PolicyNV(lockIndex, lockIndex, policySession, nil, 0, tpm2.OpEq, hmacSession); err != nil {
		return xerrors.Errorf("policy lock check failed: %w", err)
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

	handles, err := tpm.GetCapabilityHandles(lockNVHandle, 1, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot obtain handles from TPM: %w", err)
	}
	if len(handles) == 0 || handles[0] != lockNVHandle {
		// Not provisioned, so no keys created by this package can be unsealed by this TPM
		return nil
	}
	lock, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for lock NV index: %w", err)
	}
	lockPublic, _, err := tpm.NVReadPublic(lock, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area of lock NV index: %w", err)
	}
	if lockPublic.Attrs != lockNVIndexAttrs|tpm2.AttrNVWritten {
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
