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
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/chrisccoulson/go-tpm2"

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

// policyPCRParam details a set of approved digests for a given PCR.
type policyPCRParam struct {
	pcr     int
	alg     tpm2.HashAlgorithmId
	digests tpm2.DigestList
}

// dynamicPolicyComputeParams provides the parameters to computeDynamicPolicy.
type dynamicPolicyComputeParams struct {
	key *rsa.PrivateKey // Key used to authorize the generated dynamic authorization policy

	// signAlg is the digest algorithm for the signature used to authorize the generated dynamic authorization policy. It must
	// match the name algorithm of the public part of key that will be loaded in to the TPM for verification.
	signAlg              tpm2.HashAlgorithmId
	pcrParams            []policyPCRParam // Approved PCR digests
	policyCountIndexName tpm2.Name        // Name of the NV index used for revoking authorization policies

	// policyCount is the maximum permitted value of the NV index associated with policyCountIndexName, beyond which, this authorization
	// policy will not be satisfied.
	policyCount uint64
}

type policyPCRData struct {
	PCR       int
	Alg       tpm2.HashAlgorithmId
	OrDigests tpm2.DigestList
}

type dynamicPolicyData struct {
	PCRData                   []policyPCRData
	PolicyCount               uint64
	AuthorizedPolicy          tpm2.Digest
	AuthorizedPolicySignature *tpm2.Signature
}

// staticPolicyComputeParams provides the parameters to computeStaticPolicy.
type staticPolicyComputeParams struct {
	key                  *rsa.PublicKey  // Public part of key used to authorize a dynamic authorization policy
	pinIndexPub          *tpm2.NVPublic  // Public area of the NV index used for the PIN
	pinIndexAuthPolicies tpm2.DigestList // Metadata for executing policy sessions to interact with the PIN NV index
	lockIndexName        tpm2.Name       // Name of the global NV index for locking access to sealed key objects
}

// staticPolicyData is an output of computeStaticPolicy and provides metadata for executing a policy session.
type staticPolicyData struct {
	AuthorizeKeyPublic   *tpm2.Public
	PinIndexHandle       tpm2.Handle
	PinIndexAuthPolicies tpm2.DigestList
}

// incrementDynamicPolicyCounter will increment the NV counter index associated with nvPublic. This is designed to operate on a
// NV index created by createPinNVIndex. The authorization policy digests returned from createPinNVIndex must be supplied via the
// nvAuthPolicies argument.
//
// This requires a signed authorization. The keyPublic argument must correspond to the updateKeyName argument originally passed to
// createPinNVIndex. The private part of that key must be supplied via the key argument.
func incrementDynamicPolicyCounter(tpm *tpm2.TPMContext, nvPublic *tpm2.NVPublic, nvAuthPolicies tpm2.DigestList, key *rsa.PrivateKey, keyPublic *tpm2.Public, hmacSession tpm2.SessionContext) error {
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
	signDigest := tpm2.HashAlgorithmSHA256
	h := signDigest.NewHash()
	h.Write(policySession.NonceTPM())
	binary.Write(h, binary.BigEndian, int32(0)) // expiration

	// Sign the digest
	sig, err := rsa.SignPSS(rand.Reader, key, signDigest.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return xerrors.Errorf("cannot sign authorization: %w", err)
	}

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, err := tpm.LoadExternal(nil, keyPublic, tpm2.HandleEndorsement)
	if err != nil {
		return xerrors.Errorf("cannot load public part of key used to verify authorization signature: %w", err)
	}
	defer tpm.FlushContext(keyLoaded)

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSAPSS,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureRSAPSS{
				Hash: signDigest,
				Sig:  tpm2.PublicKeyRSA(sig)}}}

	// Execute the policy assertions
	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVIncrement); err != nil {
		return xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
	}
	if err := tpm.PolicyNvWritten(policySession, true); err != nil {
		return xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
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

// readDynamicPolicyCounter will read the value of the counter NV index associated with nvPublic. This is designed to operate on a
// NV index created by createPinNVIndex. The authorization policy digests returned from createPinNVIndex must be supplied via the
// nvAuthPolicies argument.
func readDynamicPolicyCounter(tpm *tpm2.TPMContext, nvPublic *tpm2.NVPublic, nvAuthPolicies tpm2.DigestList, hmacSession tpm2.SessionContext) (uint64, error) {
	index, err := tpm2.CreateNVIndexResourceContextFromPublic(nvPublic)
	if err != nil {
		return 0, xerrors.Errorf("cannot create context for NV index: %w", err)
	}

	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nvPublic.NameAlg)
	if err != nil {
		return 0, xerrors.Errorf("cannot begin policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVRead); err != nil {
		return 0, xerrors.Errorf("cannot execute assertion to read counter: %w", err)
	}
	if err := tpm.PolicyOR(policySession, nvAuthPolicies); err != nil {
		return 0, xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
	}

	c, err := tpm.NVReadCounter(index, index, policySession, hmacSession.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return 0, xerrors.Errorf("cannot read counter: %w", err)
	}

	return c, nil
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return xerrors.Errorf("cannot create signing key for initializing NV index: %w", err)
	}

	keyPublic := createPublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		return xerrors.Errorf("cannot compute name of signing key for initializing NV index: %w", err)
	}

	// Read the TPM clock
	time, err := tpm.ReadClock(session.IncludeAttrs(tpm2.AttrAudit))
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
		if isNVIndexDefinedError(err) {
			return &nvIndexDefinedError{public.Index}
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
	signDigest := tpm2.HashAlgorithmSHA256
	h := signDigest.NewHash()
	h.Write(policySession.NonceTPM())
	binary.Write(h, binary.BigEndian, int32(0))

	// Sign the digest
	sig, err := rsa.SignPSS(rand.Reader, key, signDigest.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
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
		SigAlg: tpm2.SigSchemeAlgRSAPSS,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureRSAPSS{
				Hash: signDigest,
				Sig:  tpm2.PublicKeyRSA(sig)}}}

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
		if isNVIndexDefinedError(err) {
			return &nvIndexDefinedError{dataPublic.Index}
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

	// Read the current TPM clock.
	time, err := tpm.ReadClock(session.IncludeAttrs(tpm2.AttrAudit))
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

func makePCRSelectionList(alg tpm2.HashAlgorithmId, index int) tpm2.PCRSelectionList {
	return tpm2.PCRSelectionList{tpm2.PCRSelection{Hash: alg, Select: []int{index}}}
}

func computePolicyPCRParams(policyAlg, pcrAlg tpm2.HashAlgorithmId, digest tpm2.Digest, index int) (tpm2.Digest, tpm2.PCRSelectionList) {
	pcrs := makePCRSelectionList(pcrAlg, index)

	pcrValues := make(tpm2.PCRValues)
	pcrValues.EnsureBank(pcrAlg)
	pcrValues[pcrAlg][index] = digest
	pcrDigest, _ := tpm2.ComputePCRDigest(policyAlg, pcrs, pcrValues)

	return pcrDigest, pcrs
}

// computeStaticPolicy computes the part of an authorization policy that is bound to a sealed key object and never changes.
func computeStaticPolicy(alg tpm2.HashAlgorithmId, input *staticPolicyComputeParams) (*staticPolicyData, tpm2.Digest, error) {
	trial, _ := tpm2.ComputeAuthPolicy(alg)

	keyPublic := createPublicAreaForRSASigningKey(input.key)
	keyName, err := keyPublic.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of signing key for dynamic policy authorization: %w", err)
	}

	pinIndexName, err := input.pinIndexPub.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of PIN NV index: %w", err)
	}

	trial.PolicyAuthorize(nil, keyName)
	trial.PolicySecret(pinIndexName, nil)
	trial.PolicyNV(input.lockIndexName, nil, 0, tpm2.OpEq)

	return &staticPolicyData{
		AuthorizeKeyPublic:   keyPublic,
		PinIndexHandle:       input.pinIndexPub.Index,
		PinIndexAuthPolicies: input.pinIndexAuthPolicies}, trial.GetDigest(), nil
}

// computeDynamicPolicy computes the part of an authorization policy associated with a sealed key object that can change and be
// updated.
func computeDynamicPolicy(alg tpm2.HashAlgorithmId, input *dynamicPolicyComputeParams) (*dynamicPolicyData, error) {
	var pcrData []policyPCRData
	for _, p := range input.pcrParams {
		if len(p.digests) == 0 {
			return nil, fmt.Errorf("no digests provided for PCR%d", p.pcr)
		}
		var orDigests tpm2.DigestList
		for _, d := range p.digests {
			trial, _ := tpm2.ComputeAuthPolicy(alg)
			if len(pcrData) > 0 {
				trial.PolicyOR(ensureSufficientORDigests(pcrData[len(pcrData)-1].OrDigests))
			}
			pcrDigest, pcrs := computePolicyPCRParams(alg, p.alg, d, p.pcr)
			trial.PolicyPCR(pcrDigest, pcrs)
			orDigests = append(orDigests, trial.GetDigest())
		}
		pcrData = append(pcrData, policyPCRData{PCR: p.pcr, Alg: p.alg, OrDigests: orDigests})
	}

	trial, _ := tpm2.ComputeAuthPolicy(alg)
	if len(pcrData) > 0 {
		trial.PolicyOR(ensureSufficientORDigests(pcrData[len(pcrData)-1].OrDigests))
	}

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, input.policyCount)
	trial.PolicyNV(input.policyCountIndexName, operandB, 0, tpm2.OpUnsignedLE)

	authorizedPolicy := trial.GetDigest()

	// Create a digest to sign
	h := input.signAlg.NewHash()
	h.Write(authorizedPolicy)

	// Sign the digest
	sig, err := rsa.SignPSS(rand.Reader, input.key, input.signAlg.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
	}

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSAPSS,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureRSAPSS{
				Hash: input.signAlg,
				Sig:  tpm2.PublicKeyRSA(sig)}}}

	return &dynamicPolicyData{
		PCRData:                   pcrData,
		PolicyCount:               input.policyCount,
		AuthorizedPolicy:          authorizedPolicy,
		AuthorizedPolicySignature: &signature}, nil
}

func executePolicySessionPCRAssertions(tpm *tpm2.TPMContext, session tpm2.SessionContext, input []policyPCRData) error {
	for _, i := range input {
		if err := tpm.PolicyPCR(session, nil, makePCRSelectionList(i.Alg, i.PCR)); err != nil {
			return err
		}
		if err := tpm.PolicyOR(session, ensureSufficientORDigests(i.OrDigests)); err != nil {
			var e *tpm2.TPMParameterError
			if xerrors.As(err, &e) && e.Code() == tpm2.ErrorValue {
				return xerrors.Errorf("unexpected session digest after executing TPM2_PolicyPCR assertion for PCR%d: %w", i.PCR, err)
			}
			return err
		}
	}
	return nil
}

// executePolicySession executes an authorization policy session using the supplied metadata. On success, the supplied policy
// session can be used for authorization.
func executePolicySession(tpm *tpm2.TPMContext, policySession tpm2.SessionContext, staticInput *staticPolicyData,
	dynamicInput *dynamicPolicyData, pin string, hmacSession tpm2.SessionContext) error {
	if err := executePolicySessionPCRAssertions(tpm, policySession, dynamicInput.PCRData); err != nil {
		return xerrors.Errorf("cannot complete PCR assertions: %w", err)
	}

	if staticInput.PinIndexHandle.Type() != tpm2.HandleTypeNVIndex {
		return errors.New("invalid handle type for PIN NV index")
	}
	pinIndex, err := tpm.CreateResourceContextFromTPM(staticInput.PinIndexHandle)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for PIN NV index: %w", err)
	}
	pinIndexPub, _, err := tpm.NVReadPublic(pinIndex)
	if err != nil {
		return xerrors.Errorf("cannot read public area for PIN NV index: %w", err)
	}

	revocationCheckSession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, pinIndexPub.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot create session for dynamic authorization policy revocation check: %w", err)
	}
	defer tpm.FlushContext(revocationCheckSession)

	if err := tpm.PolicyCommandCode(revocationCheckSession, tpm2.CommandPolicyNV); err != nil {
		return xerrors.Errorf("cannot execute assertion for dynamic authorization policy revocation check: %w", err)
	}
	if err := tpm.PolicyOR(revocationCheckSession, staticInput.PinIndexAuthPolicies); err != nil {
		return xerrors.Errorf("cannot execute assertion for dynamic authorization policy revocation check: %w", err)
	}

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, dynamicInput.PolicyCount)
	if err := tpm.PolicyNV(pinIndex, pinIndex, policySession, operandB, 0, tpm2.OpUnsignedLE, revocationCheckSession); err != nil {
		return xerrors.Errorf("dynamic authorization policy revocation check failed: %w", err)
	}

	if !staticInput.AuthorizeKeyPublic.NameAlg.Supported() {
		return errors.New("public area of dynamic authorization policy signature verification key has an unsupported name algorithm")
	}
	authorizeKey, err := tpm.LoadExternal(nil, staticInput.AuthorizeKeyPublic, tpm2.HandleOwner)
	if err != nil {
		return xerrors.Errorf("cannot load public area for dynamic authorization policy signature verification key: %w", err)
	}
	defer tpm.FlushContext(authorizeKey)

	h := staticInput.AuthorizeKeyPublic.NameAlg.NewHash()
	h.Write(dynamicInput.AuthorizedPolicy)

	authorizeTicket, err := tpm.VerifySignature(authorizeKey, h.Sum(nil), dynamicInput.AuthorizedPolicySignature)
	if err != nil {
		return xerrors.Errorf("dynamic authorization policy signature verification failed: %w", err)
	}

	if err := tpm.PolicyAuthorize(policySession, dynamicInput.AuthorizedPolicy, nil, authorizeKey.Name(), authorizeTicket); err != nil {
		return xerrors.Errorf("dynamic authorization policy check failed: %w", err)
	}

	pinIndex.SetAuthValue([]byte(pin))
	if _, _, err := tpm.PolicySecret(pinIndex, policySession, nil, nil, 0, hmacSession); err != nil {
		return xerrors.Errorf("cannot execute PolicySecret assertion: %w", err)
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

// lockAccessToSealedKeysUntilTPMReset locks access to sealed key objects created by this package until the next TPM restart
// or TPM reset (aka, Startup(CLEAR)). This works by enabling the read lock bit for a well-known NV index. The static authorization
// policy of sealed key objects created by this package contain a TPM2_PolicyNV assertion on this index, which will fail once the
// read lock bit has been enabled.
func lockAccessToSealedKeysUntilTPMReset(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	handles, err := tpm.GetCapabilityHandles(lockNVHandle, 1, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot obtain handles from TPM: %w", err)
	}
	if len(handles) == 0 || handles[0] != lockNVHandle {
		// Not provisioned, so no keys to protect.
		return nil
	}
	lock, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for lock NV index: %w", err)
	}
	if err := tpm.NVReadLock(lock, lock, session); err != nil {
		var hErr *tpm2.TPMHandleError
		if xerrors.As(err, &hErr) && hErr.Index == 2 && hErr.Code() == tpm2.ErrorAttributes {
			// Not provisioned with a valid lock NV index, so no keys created by this package can
			// be unsealed on this TPM anyway.
			return nil
		}
		return xerrors.Errorf("cannot readlock pin NV index: %w", err)
	}
	return nil
}
