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
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"
)

const (
	policyOrMaxDepth = 4

	// policyOrMaxDigests sets a reasonable limit on the maximum number of or
	// digests.
	policyOrMaxDigests = 4096 // equivalent to a depth of 4
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

// policyOrNode represents a collection of up to 8 digests used in a single
// TPM2_PolicyOR invocation, and forms part of a tree of nodes in order to support
// authorization policies with more than 8 conditions.
type policyOrNode struct {
	parent  *policyOrNode
	digests tpm2.DigestList
}

// contains determines if this node contains the supplied digest.
func (n *policyOrNode) contains(digest tpm2.Digest) bool {
	for _, d := range n.digests {
		if bytes.Equal(d, digest) {
			return true
		}
	}
	return false
}

// executeAssertion executes a PolicyOR assertion for this node.
func (n *policyOrNode) executeAssertion(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	return tpm.PolicyOR(session, ensureSufficientORDigests(n.digests))
}

// policyOrTree represents a tree of nodes that facilitates nesting of
// TPM2_PolicyOR assertions in order to support policies with more than 8
// branches.
//
// During execution, the leaf node with the current session digest is found.
// A PolicyOR assertion is then executed with the digests from this node,
// and then a PolicyOR assertion is executed with the digests from each of
// the ancestor nodes.
type policyOrTree struct {
	leafNodes []*policyOrNode // the leaf nodes
}

// dynamicPolicyData is an output of computeDynamicPolicy and provides metadata for executing a policy session.
type dynamicPolicyData struct {
	pcrSelection tpm2.PCRSelectionList

	// XXX: The _v0 here is a bit of a hack, but this entire structure goes away in
	// the next PR.
	pcrOrData                 policyOrData_v0
	policyCount               uint64
	authorizedPolicy          tpm2.Digest
	authorizedPolicySignature *tpm2.Signature
}

// staticPolicyComputeParams provides the parameters to computeStaticPolicy.
type staticPolicyComputeParams struct {
	key                 *tpm2.Public   // Public part of key used to authorize a dynamic authorization policy
	pcrPolicyCounterPub *tpm2.NVPublic // Public area of the NV counter used for revoking PCR policies
}

// staticPolicyData is an output of computeStaticPolicy and provides metadata for executing a policy session.
type staticPolicyData struct {
	authPublicKey          *tpm2.Public
	pcrPolicyCounterHandle tpm2.Handle
	v0PinIndexAuthPolicies tpm2.DigestList
}

// pcrPolicyCounterHandle abstracts access to the PCR policy counter in order to
// support the current style of index created with createPcrPolicyCounter, and the
// legacy PIN index originally created by (the now deleted) createPinNVINdex.
type pcrPolicyCounterHandle interface {
	// Get returns the current value of the associated NV counter index.
	Get(tpm *tpm2.TPMContext, session tpm2.SessionContext) (uint64, error)

	// Incremement will increment the associated NV counter index by one.
	// This requires a signed authorization.
	Increment(tpm *tpm2.TPMContext, key crypto.PrivateKey, session tpm2.SessionContext) error
}

func incrementPcrPolicyCounterTo(tpm *tpm2.TPMContext, handle pcrPolicyCounterHandle, value uint64,
	key crypto.PrivateKey, session tpm2.SessionContext) error {
	for {
		current, err := handle.Get(tpm, session)
		switch {
		case err != nil:
			return xerrors.Errorf("cannot read current value: %w", err)
		case current > value:
			return errors.New("cannot set counter to a lower value")
		}

		if current == value {
			return nil
		}

		if err := handle.Increment(tpm, key, session); err != nil {
			return xerrors.Errorf("cannot increment counter: %w", err)
		}
	}
}

type pcrPolicyCounterCommon struct {
	pub          *tpm2.NVPublic
	updateKey    *tpm2.Public
	authPolicies tpm2.DigestList
}

// createPcrPolicyCounter creates and initializes a NV counter that is associated with a sealed key object and is used for
// implementing dynamic authorization policy revocation.
//
// The NV index will be created with attributes that allow anyone to read the index, and an authorization policy that permits
// TPM2_NV_Increment with a signed authorization policy.
func createPcrPolicyCounter(tpm *tpm2.TPMContext, handle tpm2.Handle, updateKey *tpm2.Public, hmacSession tpm2.SessionContext) (*tpm2.NVPublic, uint64, error) {
	nameAlg := tpm2.HashAlgorithmSHA256

	updateKeyName, err := updateKey.Name()
	if err != nil {
		return nil, 0, xerrors.Errorf("cannot compute name of update key: %w", err)
	}

	authPolicies := computeV1PcrPolicyCounterAuthPolicies(nameAlg, updateKeyName)

	trial := util.ComputeAuthPolicy(nameAlg)
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
		return nil, 0, xerrors.Errorf("cannot define NV space: %w", err)
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
		return nil, 0, xerrors.Errorf("cannot begin policy session to initialize NV index: %w", err)
	}
	defer tpm.FlushContext(policySession)

	// Execute the policy assertions
	if err := tpm.PolicyNvWritten(policySession, false); err != nil {
		return nil, 0, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyOR(policySession, authPolicies); err != nil {
		return nil, 0, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}

	// Initialize the index
	if err := tpm.NVIncrement(index, index, policySession, hmacSession.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return nil, 0, xerrors.Errorf("cannot initialize NV index: %w", err)
	}

	// The index has a different name now that it has been written, so update the public area we return so that it can be used
	// to construct an authorization policy.
	public.Attrs |= tpm2.AttrNVWritten

	h, err := newPcrPolicyCounterHandleV1(public, updateKey)
	if err != nil {
		panic(fmt.Sprintf("cannot create handle to read counter value: %v", err))
	}

	value, err := h.Get(tpm, hmacSession)
	if err != nil {
		return nil, 0, xerrors.Errorf("cannot read current counter value: %w", err)
	}

	succeeded = true
	return public, value, nil
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

// computeStaticPolicy computes the part of an authorization policy that is bound to a sealed key object and never changes. The
// static policy asserts that the following are true:
// - The signed PCR policy created by computeDynamicPolicy is valid and has been satisfied (by way of a PolicyAuthorize assertion,
//   which allows the PCR policy to be updated without creating a new sealed key object).
// - Knowledge of the the authorization value for the entity on which the policy session is used has been demonstrated by the
//   caller - this will be used in the future as part of the passphrase integration.
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

	trial := util.ComputeAuthPolicy(alg)
	trial.PolicyAuthorize(computeV1PcrPolicyRefFromCounterName(pcrPolicyCounterName), keyName)
	trial.PolicyAuthValue()

	return &staticPolicyData{
		authPublicKey:          input.key,
		pcrPolicyCounterHandle: pcrPolicyCounterHandle}, trial.GetDigest(), nil
}

// newPolicyOrTree creates a new policyOrTree from the supplied digests
// for creating a policy that can be satisified by multiple conditions. It also
// extends the supplied trial policy.
//
// It works by turning the supplied list of digests (each corresponding to some
// condition) into a tree of nodes, with each node containing no more than 8 digests
// that can be used in a single PolicyOR assertion. The leaf nodes contain the
// supplied digests, and correspond to the first PolicyOR assertion. The root node
// contains the digests for the final PolicyOR execution, and the policy is executed
// by finding the leaf node with the current session digest and then walking up the
// tree to the root node, executing a PolicyOR assertion at each step.
//
// It returns an error if no digests are supplied or if too many digests are
// supplied. The returned tree won't have a depth of more than 4.
func newPolicyOrTree(alg tpm2.HashAlgorithmId, trial *util.TrialAuthPolicy, digests tpm2.DigestList) (out *policyOrTree, err error) {
	if len(digests) == 0 {
		return nil, errors.New("no digests supplied")
	}
	if len(digests) > policyOrMaxDigests {
		return nil, errors.New("too many digests")
	}

	var prev []*policyOrNode

	for len(prev) != 1 {
		// The outer loop runs on each level of the tree. If
		// len(prev) == 1, then we have produced the root node
		// and the loop should not continue.

		var current []*policyOrNode
		var nextDigests tpm2.DigestList

		for len(digests) > 0 {
			// The inner loop runs on each sibling node within a level.

			n := len(digests)
			if n > 8 {
				// The TPM only supports 8 conditions in TPM2_PolicyOR.
				n = 8
			}

			// Create a new node with the next n digests and save it.
			current = append(current, &policyOrNode{digests: digests[:n]})

			// Consume the next n digests to fit in to this node and produce a single digest
			// that will go in to the parent node.
			trial := util.ComputeAuthPolicy(alg)
			trial.PolicyOR(ensureSufficientORDigests(digests[:n]))
			nextDigests = append(nextDigests, trial.GetDigest())

			// We've consumed n digests, so adjust the slice to point to the next ones to consume to
			// produce a sibling node.
			digests = digests[n:]
		}

		// There are no digests left to produce sibling nodes.
		// Link child nodes to parents.
		for i, child := range prev {
			child.parent = current[i/8]
		}

		// Grab the digests for the nodes we've just produced to create the parent nodes.
		prev = current
		digests = nextDigests

		if out == nil {
			// Save the leaf nodes to return.
			out = &policyOrTree{leafNodes: current}
		}
	}

	trial.PolicyOR(ensureSufficientORDigests(prev[0].digests))
	return out, nil
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
	if version == 0 {
		return computeDynamicPolicyV0(alg, input)
	}
	return computeDynamicPolicyV1(alg, input)
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

var errSessionDigestNotFound = errors.New("current session digest not found in policy data")

// executeAssertions executes one or more PolicyOR assertions in order to support
// compound policies with more than 8 conditions. It starts by searching for the
// current session digest in one of the leaf nodes. If found, it executes a PolicyOR
// assertion with the digests associated with that node, and then walks up through
// its ancestors all the way to the root node, executing a PolicyOR assertion at each
// node.
func (t *policyOrTree) executeAssertions(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	// First of all, obtain the current digest of the session.
	currentDigest, err := tpm.PolicyGetDigest(session)
	if err != nil {
		return err
	}

	// Find the leaf node that contains the current digest of the session.
	var node *policyOrNode
	for _, n := range t.leafNodes {
		if n.contains(currentDigest) {
			// We've got a match!
			node = n
			break
		}
	}

	if node == nil {
		return errSessionDigestNotFound
	}

	// Execute a TPM2_PolicyOR assertion on the digests in the leaf node and then traverse up the tree to the root node, executing
	// TPM2_PolicyOR assertions along the way.
	for node != nil {
		if err := node.executeAssertion(tpm, session); err != nil {
			return err
		}
		node = node.parent
	}
	return nil
}

// executePolicySession executes an authorization policy session using the supplied metadata. On success, the supplied policy
// session can be used for authorization.
func executePolicySession(tpm *tpm2.TPMContext, policySession tpm2.SessionContext, version uint32, staticInput *staticPolicyData,
	dynamicInput *dynamicPolicyData, hmacSession tpm2.SessionContext) error {
	if version == 0 {
		return executePolicySessionV0(tpm, policySession, staticInput, dynamicInput, hmacSession)
	}

	return executePolicySessionV1(tpm, policySession, staticInput, dynamicInput, hmacSession)
}

// BlockPCRProtectionPolicies inserts a fence in to the specific PCRs for all active PCR banks, in order to
// make PCR policies that depend on the specified PCRs and are satisfiable by the current PCR values invalid
// until the next TPM restart (equivalent to eg, system resume from suspend-to-disk) or TPM reset
// (equivalent to booting after a system reset).
//
// This acts as a barrier between the environment in which a sealed key should be permitted to be unsealed
// (eg, the initramfs), and the environment in which a sealed key should not be permitted to be unsealed
// (eg, the OS runtime).
func BlockPCRProtectionPolicies(tpm *Connection, pcrs []int) error {
	session := tpm.HmacSession()

	// The fence is a hash of uint32(0), which is the same as EV_SEPARATOR (which can be uint32(0) or uint32(-1))
	fence := make([]byte, 4)

	// Insert PCR fence
	for _, pcr := range pcrs {
		seq, err := tpm.HashSequenceStart(nil, tpm2.HashAlgorithmNull)
		if err != nil {
			return xerrors.Errorf("cannot being hash sequence: %w", err)
		}
		if _, err := tpm.EventSequenceExecute(tpm.PCRHandleContext(pcr), seq, fence, session, nil); err != nil {
			return xerrors.Errorf("cannot execute hash sequence: %w", err)
		}
	}

	return nil
}
