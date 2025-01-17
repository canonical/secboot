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
	_ "crypto/sha256"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/policyutil"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
)

const (
	policyOrMaxDepth = 4

	// policyOrMaxDigests sets a reasonable limit on the maximum number of or
	// digests.
	policyOrMaxDigests = 4096 // equivalent to a depth of 4
)

// pcrPolicyParams provides the parameters to keyDataPolicy.updatePcrPolicy.
type pcrPolicyParams struct {
	key  secboot.PrimaryKey // Key used to authorize the generated dynamic authorization policy
	role []byte

	pcrs       tpm2.PCRSelectionList // PCR selection
	pcrDigests tpm2.DigestList       // Approved PCR digests

	// policyCounter is the public area of the NV index used for revoking authorization
	// policies. It must be associated with the handle in the keyDataPolicy, else the
	// policy will not work.
	policyCounter *tpm2.NVPublic

	policySequence uint64 // the PCR policy sequence
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

// pcrPolicyCounterContext corresponds to a PCR policy counter.
type pcrPolicyCounterContext interface {
	Get() (uint64, error)                   // Return the current counter value
	Increment(key secboot.PrimaryKey) error // Increment the counter value using the supplied key for authorization
}

// keyDataPolicy corresponds to the authorization policy for keyData.
type keyDataPolicy interface {
	PCRPolicyCounterHandle() tpm2.Handle // Handle of PCR policy counter, or HandleNull

	PCRPolicySequence() uint64 // Current sequence of PCR policy for revocation

	// UpdatePCRPolicy updates the PCR policy associated with this keyDataPolicy.
	UpdatePCRPolicy(alg tpm2.HashAlgorithmId, params *pcrPolicyParams) error

	// SetPCRPolicy updates the PCR policy to match that associated with the
	// supplied keyDataPolicy. The caller is responsible for ensuring that
	// the 2 keyDataPolicies are the same type and have the same underlying
	// static policy.
	SetPCRPolicyFrom(src keyDataPolicy)

	// ExecutePCRPolicy executes the PCR policy using the supplied authorization policy
	// session using the supplied metadata. On success, the supplied policy session can
	// be used for authorization.
	ExecutePCRPolicy(tpm *tpm2.TPMContext, policySession, hmacSession tpm2.SessionContext) error

	// PCRPolicyCounterContext returns a context for the PCR policy counter
	// associated with this keyDataPolicy. The supplied public area must match
	// the public area of the counter associated with this policy.
	PCRPolicyCounterContext(tpm *tpm2.TPMContext, pub *tpm2.NVPublic) (pcrPolicyCounterContext, error)

	// RequireUserAuth returns true if the object has an authorization value that is needed
	// from the user.
	RequireUserAuth() bool

	// ValidateAuthKey verifies that the supplied key is associated with this
	// keyDataPolicy.
	ValidateAuthKey(key secboot.PrimaryKey) error
}

// createPcrPolicyCounterLegacy creates and initializes a NV counter that is associated with a sealed key object
// and is used for implementing PCR policy revocation.
//
// The NV index will be created with attributes that allow anyone to read the index, and an authorization
// policy that permits TPM2_NV_Increment with a signed authorization policy.
//
// If hmacSession is supplied, it is used for authenticating with the storage hierarchy, in order to avoid
// transmitting the cleartext auth value, and must have the AttrContinueSession attribute set
func createPcrPolicyCounterLegacy(tpm *tpm2.TPMContext, handle tpm2.Handle, updateKey *tpm2.Public, hmacSession tpm2.SessionContext) (public *tpm2.NVPublic, value uint64, err error) {
	nameAlg := tpm2.HashAlgorithmSHA256

	authPolicies, err := computeV2PcrPolicyCounterAuthPolicies(nameAlg, updateKey)
	if err != nil {
		return nil, 0, err
	}

	builder := policyutil.NewPolicyBuilder(nameAlg)
	builder.RootBranch().PolicyOR(authPolicies...)
	policyDigest, err := builder.Digest()
	if err != nil {
		return nil, 0, err
	}

	public = &tpm2.NVPublic{
		Index:      handle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}

	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, public, hmacSession)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		if err == nil {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, hmacSession)
	}()

	// Begin a session to initialize the index.
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, public.NameAlg)
	if err != nil {
		return nil, 0, err
	}
	defer tpm.FlushContext(policySession)

	// Execute the policy assertions
	if err := tpm.PolicyNvWritten(policySession, false); err != nil {
		return nil, 0, err
	}
	if err := tpm.PolicyOR(policySession, authPolicies); err != nil {
		return nil, 0, err
	}

	// Initialize the index
	if err := tpm.NVIncrement(index, index, policySession); err != nil {
		return nil, 0, err
	}

	// The index has a different name now that it has been written, so update the public area
	// we return so that it can be used to construct an authorization policy.
	public.Attrs |= tpm2.AttrNVWritten

	// Read the current value
	value, err = tpm.NVReadCounter(index, index, nil)
	if err != nil {
		return nil, 0, err
	}

	return public, value, nil
}

// ensurePcrPolicyCounter creates and initializes a NV counter that is associated with a sealed key object
// and is used for implementing PCR policy revocation.
//
// The NV index will be created with attributes that allow anyone to read the index, and an authorization
// policy that permits TPM2_NV_Increment with a signed authorization policy.
//
// If hmacSession is supplied, it is used for authenticating with the storage hierarchy, in order to avoid
// transmitting the cleartext auth value, and must have the AttrContinueSession attribute set
var ensurePcrPolicyCounter = func(tpm *tpm2.TPMContext, handle tpm2.Handle, updateKey *tpm2.Public, hmacSession tpm2.SessionContext) (public *tpm2.NVPublic, err error) {
	nameAlg := tpm2.HashAlgorithmSHA256

	authPolicies, err := computeV3PcrPolicyCounterAuthPolicies(nameAlg, updateKey)
	if err != nil {
		return nil, err
	}

	builder := policyutil.NewPolicyBuilder(nameAlg)
	builder.RootBranch().PolicyOR(authPolicies...)
	policyDigest, err := builder.Digest()
	if err != nil {
		return nil, err
	}

	public = &tpm2.NVPublic{
		Index:      handle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}

	index, err := tpm.NewResourceContext(handle)
	switch {
	case tpm2.IsResourceUnavailableError(err, handle):
		// ok, need to create
		index, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, public, hmacSession)
		if err != nil {
			return nil, err
		}
		defer func() {
			if err == nil {
				return
			}
			tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, hmacSession)
		}()

		// Begin a session to initialize the index.
		policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, public.NameAlg)
		if err != nil {
			return nil, err
		}
		defer tpm.FlushContext(policySession)

		// Execute the policy assertions
		if err := tpm.PolicyNvWritten(policySession, false); err != nil {
			return nil, err
		}
		if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVIncrement); err != nil {
			return nil, err
		}
		if err := tpm.PolicyOR(policySession, authPolicies); err != nil {
			return nil, err
		}

		// Initialize the index
		if err := tpm.NVIncrement(index, index, policySession); err != nil {
			return nil, err
		}
	case err != nil:
		// unexpected error
		return nil, err
	}

	// The index has a different name once it has been written, so update the public area
	// we return so that it can be used to construct an authorization policy.
	public.Attrs |= tpm2.AttrNVWritten

	// Make sure the name matches that returned from the TPM - this catches the case
	// where an index already exists but it has the wrong public area.
	if !bytes.Equal(public.Name(), index.Name()) {
		return nil, TPMResourceExistsError{handle}
	}

	return public, nil
}

var newPolicyAuthPublicKey = func(key secboot.PrimaryKey) (*tpm2.Public, error) {
	ecdsaKey, err := deriveV3PolicyAuthKey(crypto.SHA256, key)
	if err != nil {
		return nil, err
	}

	return objectutil.NewECCPublicKey(&ecdsaKey.PublicKey)
}

// ensureSufficientORDigests turns a single digest in to a pair of identical digests.
// This is because TPM2_PolicyOR assertions require more than one digest. This avoids
// having a separate policy sequence when there is only a single digest, without having
// to store duplicate digests on disk.
func ensureSufficientORDigests(digests tpm2.DigestList) tpm2.DigestList {
	if len(digests) == 1 {
		return tpm2.DigestList{digests[0], digests[0]}
	}
	return digests
}

// newKeyDataPolicy creates a keyDataPolicy containing a static authorization policy that asserts:
//   - The PCR policy created by updatePcrPolicy and authorized by key is valid and has been satisfied (by way
//     of a PolicyAuthorize assertion, which allows the PCR policy to be updated without creating a new sealed
//     key object).
//   - Knowledge of the the authorization value for the entity on which the policy session is used has been
//     demonstrated by the caller - this will be used in the future as part of the passphrase integration.
//
// PCR policies support revocation by way of a NV counter. The revocation check is part of the PCR policy,
// but the counter is bound to the static policy by including it in the policyRef for the PolicyAuthorize
// assertion, which can be used verify that a NV index is associated with this policy. The caller must ensure
// that the pcrPolicyCounterPub argument is valid if supplied.
//
// The key argument must be created with newPolicyAuthPublicKey.
//
// This returns some policy metadata and a policy digest which is used as the auth policy field of the
// protected object.
var newKeyDataPolicy = func(alg tpm2.HashAlgorithmId, key *tpm2.Public, role string, pcrPolicyCounterPub *tpm2.NVPublic, requireAuthValue bool) (keyDataPolicy, tpm2.Digest, error) {
	if len(role) > 1024 {
		// We serialize this in the TPM wire format in computeV3PcrPolicyRef and define the
		// type as TPM2B_MAX_BUFFER in the SE041, and this has a maximum size of 1024 bytes,
		// although the real ceiling for us is MaxUint16. Let's be consistent though, and
		// 1024 bytes is more than enough.
		return nil, nil, errors.New("invalid role: too large")
	}

	pcrPolicyCounterHandle := tpm2.HandleNull
	var pcrPolicyCounterName tpm2.Name
	if pcrPolicyCounterPub != nil {
		pcrPolicyCounterHandle = pcrPolicyCounterPub.Index
		pcrPolicyCounterName = pcrPolicyCounterPub.Name()
	}

	pcrPolicyRef := computeV3PcrPolicyRef(key.NameAlg, []byte(role), pcrPolicyCounterName)

	builder := policyutil.NewPolicyBuilder(alg)
	builder.RootBranch().PolicyAuthorize(pcrPolicyRef, key)
	if requireAuthValue {
		builder.RootBranch().PolicyAuthValue()
	}
	policyDigest, err := builder.Digest()
	if err != nil {
		return nil, nil, err
	}

	return &keyDataPolicy_v3{
		StaticData: &staticPolicyData_v3{
			AuthPublicKey:          key,
			PCRPolicyRef:           pcrPolicyRef,
			PCRPolicyCounterHandle: pcrPolicyCounterHandle,
			RequireAuthValue:       requireAuthValue},
		PCRData: &pcrPolicyData_v3{
			// Set AuthorizedPolicySignature here because this object needs to be
			// serializable before the initial signature is created.
			AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgNull}}}, policyDigest, nil
}

// newKeyDataPolicyLegacy creates a keyDataPolicy for legacy sealed key files containing a static
// authorization policy that asserts:
//   - The PCR policy created by updatePcrPolicy and authorized by key is valid and has been satisfied (by way
//     of a PolicyAuthorize assertion, which allows the PCR policy to be updated without creating a new sealed
//     key object).
//   - Knowledge of the the authorization value for the entity on which the policy session is used has been
//     demonstrated by the caller - this will be used in the future as part of the passphrase integration.
//
// PCR policies support revocation by way of a NV counter. The revocation check is part of the PCR policy,
// but the counter is bound to the static policy by including it in the policyRef for the PolicyAuthorize
// assertion, which can be used verify that a NV index is associated with this policy. The caller must ensure
// that the pcrPolicyCounterPub argument is valid if supplied.
func newKeyDataPolicyLegacy(alg tpm2.HashAlgorithmId, key *tpm2.Public, pcrPolicyCounterPub *tpm2.NVPublic, pcrPolicySequence uint64) (keyDataPolicy, tpm2.Digest, error) {
	pcrPolicyCounterHandle := tpm2.HandleNull
	var pcrPolicyCounterName tpm2.Name
	if pcrPolicyCounterPub != nil {
		pcrPolicyCounterHandle = pcrPolicyCounterPub.Index
		pcrPolicyCounterName = pcrPolicyCounterPub.Name()
	}

	builder := policyutil.NewPolicyBuilder(alg)
	builder.RootBranch().PolicyAuthorize(computeV2PcrPolicyRefFromCounterName(pcrPolicyCounterName), key)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, err := builder.Digest()
	if err != nil {
		return nil, nil, err
	}

	return &keyDataPolicy_v2{
		StaticData: &staticPolicyData_v2{
			AuthPublicKey:          key,
			PCRPolicyCounterHandle: pcrPolicyCounterHandle},
		PCRData: &pcrPolicyData_v2{
			PolicySequence: pcrPolicySequence}}, policyDigest, nil
}

// newPolicyOrTree creates a new policyOrTree from the supplied digests
// for creating a policy that can be satisified by multiple conditions. It also
// returns a list of digests to use in the root PolicyOR assertion.
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
func newPolicyOrTree(alg tpm2.HashAlgorithmId, digests tpm2.DigestList) (out *policyOrTree, rootDigest tpm2.DigestList, err error) {
	if len(digests) == 0 {
		return nil, nil, errors.New("no digests supplied")
	}
	if len(digests) > policyOrMaxDigests {
		return nil, nil, errors.New("too many digests")
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
			builder := policyutil.NewPolicyBuilder(alg)
			builder.RootBranch().PolicyOR(ensureSufficientORDigests(digests[:n])...)
			digest, err := builder.Digest()
			if err != nil {
				return nil, nil, err
			}
			nextDigests = append(nextDigests, digest)

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

	return out, ensureSufficientORDigests(prev[0].digests), nil
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

// BlockPCRProtectionPolicies inserts a fence in to the specific PCRs for all active PCR banks, in order to
// make PCR policies that depend on the specified PCRs and are satisfiable by the current PCR values invalid
// until the next TPM restart (equivalent to eg, system resume from suspend-to-disk) or TPM reset
// (equivalent to booting after a system reset).
//
// This acts as a barrier between the environment in which a sealed key should be permitted to be unsealed
// (eg, the initramfs), and the environment in which a sealed key should not be permitted to be unsealed
// (eg, the OS runtime).
func BlockPCRProtectionPolicies(tpm *Connection, pcrs []int) error {
	// The fence is a hash of uint32(0), which is the same as EV_SEPARATOR (which can be uint32(0) or uint32(-1))
	fence := make([]byte, 4)

	// Insert PCR fence
	for _, pcr := range pcrs {
		seq, err := tpm.HashSequenceStart(nil, tpm2.HashAlgorithmNull)
		if err != nil {
			return xerrors.Errorf("cannot being hash sequence: %w", err)
		}
		if _, err := tpm.EventSequenceExecute(tpm.PCRHandleContext(pcr), seq, fence, nil, nil); err != nil {
			return xerrors.Errorf("cannot execute hash sequence: %w", err)
		}
	}

	return nil
}
