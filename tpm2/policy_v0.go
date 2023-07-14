// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2021 Canonical Ltd
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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
)

type policyOrDataNode_v0 struct {
	Next    uint32 // Index of the parent node in the containing slice, relative to this node. Zero indicates that this is the root node
	Digests tpm2.DigestList
}

// policyOrData_v0 is the version 0 on-disk representation of policyOrTree.
// It is a flattened tree which suitable for serializing - the tree is just
// a slice of nodes, with each node specifying an offset to its parent node.
type policyOrData_v0 []*policyOrDataNode_v0

type policyOrDataResolver_v0 struct {
	src         []*policyOrDataNode_v0
	all         []*policyOrNode
	numResolved int
	depth       int
}

func (r *policyOrDataResolver_v0) resolveOne(n uint32) (*policyOrNode, error) {
	// newPolicyOrTree limits the depth by limiting the
	// number of digests. Limit the depth when constructing
	// a tree from its serialized format too.
	r.depth += 1
	defer func() { r.depth -= 1 }()
	if r.depth > policyOrMaxDepth {
		return nil, errors.New("too deep")
	}

	if int(n) >= len(r.all) {
		// A node is indexing its parent from outside of the tree.
		return nil, fmt.Errorf("index %d out of range", n)
	}

	node := r.all[n]
	if node == nil {
		// This is a node we haven't resolved yet.
		// Create the resolved node and copy the digests across.
		node = new(policyOrNode)
		node.digests = make(tpm2.DigestList, len(r.src[n].Digests))
		copy(node.digests, r.src[n].Digests)

		// Bounds check the offset to the parent node.
		if r.src[n].Next > policyOrMaxDigests/8 {
			return nil, fmt.Errorf("next value too large (%d)", r.src[n].Next)
		}

		if r.src[n].Next != 0 {
			// This is not the root node. Resolve the parent node.
			parent, err := r.resolveOne(n + r.src[n].Next)
			if err != nil {
				return nil, err
			}
			node.parent = parent
		}

		// Save the resolved node so we can return the same one for
		// other children.
		r.numResolved += 1
		r.all[n] = node
	}
	return node, nil
}

// resolve converts the flattened tree in to an actual tree, suitable for
// executing assertions on.
func (t policyOrData_v0) resolve() (out *policyOrTree, err error) {
	if len(t) == 0 {
		return nil, errors.New("no nodes")
	}

	// The offset to the first non-leaf node tells us how many leaf
	// nodes we have.
	numLeafNodes := t[0].Next
	if numLeafNodes == 0 {
		// This is a tree containing a single node.
		numLeafNodes = 1
	}

	if numLeafNodes > policyOrMaxDigests/8 {
		return nil, fmt.Errorf("too many leaf nodes (%d)", numLeafNodes)
	}

	resolver := &policyOrDataResolver_v0{
		src: t,
		all: make([]*policyOrNode, len(t))}

	out = new(policyOrTree)

	// Resolve each leaf node.
	for i := uint32(0); i < numLeafNodes; i++ {
		leaf, err := resolver.resolveOne(i)
		if err != nil {
			return nil, err
		}
		out.leafNodes = append(out.leafNodes, leaf)
	}

	if resolver.numResolved < len(t) {
		// The data contains nodes that aren't reachable, so consider it to
		// be invalid.
		return nil, errors.New("unreachable nodes")
	}

	return out, nil
}

// newPolicyOrDataV0 creates a new flattened tree suitable for serialization
// from the supplied policyOrTree. The returned data is just a list of nodes,
// with each node containing an offset in order to index its parent node.
func newPolicyOrDataV0(tree *policyOrTree) (out policyOrData_v0) {
	// Track source nodes to index in the flattened tree.
	srcNodesToIndex := make(map[*policyOrNode]int)

	// Start with leaf nodes
	current := tree.leafNodes

	for current != nil {
		// The outer loop runs on each level of the tree.

		// Keep an ordered list of parent nodes collected from the
		// current nodes.
		var next []*policyOrNode
		seen := make(map[*policyOrNode]struct{})

		// Process the nodes in the current level.
		for _, node := range current {
			// Append the node to the flattened tree.
			srcNodesToIndex[node] = len(out)
			out = append(out, &policyOrDataNode_v0{Digests: node.digests})

			if node.parent == nil {
				// This is the root node
				if len(current) != 1 {
					panic("node without parent")
				}
				break
			}

			// Record the parent node for processing the next
			// level of the tree.
			if _, ok := seen[node.parent]; !ok {
				seen[node.parent] = struct{}{}
				next = append(next, node.parent)
			}
		}

		// Move to the parent nodes.
		current = next
	}

	// Link each node to its parent by setting the offset values.
	for node, index := range srcNodesToIndex {
		if node.parent == nil {
			// This is the root
			continue
		}

		parentIndex := srcNodesToIndex[node.parent]
		out[index].Next = uint32(parentIndex - index)
	}

	return out
}

// computeV0PinNVIndexPostInitAuthPolicies computes the authorization policy digests associated with the post-initialization
// actions on a NV index created with the removed createPinNVIndex for version 0 key files. These are:
//   - A policy for updating the index to revoke old dynamic authorization policies, requiring an assertion signed by the key
//     associated with updateKeyName.
//   - A policy for updating the authorization value (PIN / passphrase), requiring knowledge of the current authorization value.
//   - A policy for reading the counter value without knowing the authorization value, as the value isn't secret.
//   - A policy for using the counter value in a TPM2_PolicyNV assertion without knowing the authorization value.
func computeV0PinNVIndexPostInitAuthPolicies(alg tpm2.HashAlgorithmId, updateKeyName tpm2.Name) tpm2.DigestList {
	var out tpm2.DigestList
	// Compute a policy for incrementing the index to revoke dynamic authorization policies, requiring an assertion signed by the
	// key associated with updateKeyName.
	trial := util.ComputeAuthPolicy(alg)
	trial.PolicyCommandCode(tpm2.CommandNVIncrement)
	trial.PolicyNvWritten(true)
	trial.PolicySigned(updateKeyName, nil)
	out = append(out, trial.GetDigest())

	// Compute a policy for updating the authorization value of the index, requiring knowledge of the current authorization value.
	trial = util.ComputeAuthPolicy(alg)
	trial.PolicyCommandCode(tpm2.CommandNVChangeAuth)
	trial.PolicyAuthValue()
	out = append(out, trial.GetDigest())

	// Compute a policy for reading the counter value without knowing the authorization value.
	trial = util.ComputeAuthPolicy(alg)
	trial.PolicyCommandCode(tpm2.CommandNVRead)
	out = append(out, trial.GetDigest())

	// Compute a policy for using the counter value in a TPM2_PolicyNV assertion without knowing the authorization value.
	trial = util.ComputeAuthPolicy(alg)
	trial.PolicyCommandCode(tpm2.CommandPolicyNV)
	out = append(out, trial.GetDigest())

	return out
}

// staticPolicyData_v0 represents version 0 of the metadata for executing a
// policy session that never changes for the life of a key.
type staticPolicyData_v0 struct {
	AuthPublicKey                *tpm2.Public
	PCRPolicyCounterHandle       tpm2.Handle
	PCRPolicyCounterAuthPolicies tpm2.DigestList
}

// pcrPolicyData_v0 represents version 0 of the PCR policy metadata for
// executing a policy session, and can be updated.
type pcrPolicyData_v0 struct {
	Selection                 tpm2.PCRSelectionList
	OrData                    policyOrData_v0
	PolicySequence            uint64
	AuthorizedPolicy          tpm2.Digest
	AuthorizedPolicySignature *tpm2.Signature
}

func (d *pcrPolicyData_v0) new(params *pcrPolicyParams) *pcrPolicyData_v0 {
	return &pcrPolicyData_v0{
		Selection:      params.pcrs,
		PolicySequence: d.PolicySequence + 1}
}

func (d *pcrPolicyData_v0) addPcrAssertions(alg tpm2.HashAlgorithmId, trial *util.TrialAuthPolicy, digests tpm2.DigestList) error {
	// Compute the policy digest that would result from a TPM2_PolicyPCR assertion for each condition
	var orDigests tpm2.DigestList
	for _, digest := range digests {
		trial2 := util.ComputeAuthPolicy(alg)
		trial2.SetDigest(trial.GetDigest())
		trial2.PolicyPCR(digest, d.Selection)
		orDigests = append(orDigests, trial2.GetDigest())
	}

	orTree, err := newPolicyOrTree(alg, trial, orDigests)
	if err != nil {
		return xerrors.Errorf("cannot create tree for PolicyOR digests: %w", err)
	}
	d.OrData = newPolicyOrDataV0(orTree)
	return nil
}

func (d *pcrPolicyData_v0) addRevocationCheck(trial *util.TrialAuthPolicy, policyCounterName tpm2.Name) {
	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, d.PolicySequence)
	trial.PolicyNV(policyCounterName, operandB, 0, tpm2.OpUnsignedLE)
}

func (d *pcrPolicyData_v0) authorizePolicy(key crypto.PrivateKey, scheme *tpm2.SigScheme, approvedPolicy tpm2.Digest, policyRef tpm2.Nonce) error {
	d.AuthorizedPolicy = approvedPolicy

	_, signature, err := util.PolicyAuthorize(key, scheme, approvedPolicy, policyRef)
	if err != nil {
		return err
	}
	d.AuthorizedPolicySignature = signature
	return nil
}

func (d *pcrPolicyData_v0) executePcrAssertions(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	if err := tpm.PolicyPCR(session, nil, d.Selection); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyPCR, 2) {
			return policyDataError{errors.New("invalid PCR selection")}
		}
		return err
	}

	tree, err := d.OrData.resolve()
	if err != nil {
		return policyDataError{xerrors.Errorf("cannot resolve PolicyOR tree: %w", err)}
	}
	if err := tree.executeAssertions(tpm, session); err != nil {
		err = xerrors.Errorf("cannot execute PolicyOR assertions: %w", err)
		switch {
		case tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyOR, 1):
			// A digest list in the tree is invalid.
			return policyDataError{errors.New("cannot execute PolicyOR assertions: invalid data")}
		case xerrors.Is(err, errSessionDigestNotFound):
			// Current session digest does not appear in any leaf node.
			return policyDataError{err}
		default:
			// Unexpected error
			return err
		}
	}

	return nil
}

func (d *pcrPolicyData_v0) executeRevocationCheck(tpm *tpm2.TPMContext, counter tpm2.ResourceContext, policySession, revocationCheckSession tpm2.SessionContext) error {
	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, d.PolicySequence)
	if err := tpm.PolicyNV(counter, counter, policySession, operandB, 0, tpm2.OpUnsignedLE, revocationCheckSession); err != nil {
		switch {
		case tpm2.IsTPMError(err, tpm2.ErrorPolicy, tpm2.CommandPolicyNV):
			// The PCR policy has been revoked.
			return policyDataError{errors.New("the PCR policy has been revoked")}
		case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandPolicyNV, 1):
			// Either StaticData.PCRPolicyCounterAuthPolicies is invalid or the NV index isn't what's expected, so the key file is invalid.
			return policyDataError{errors.New("invalid PCR policy counter or associated authorization policy metadata")}
		}
		return xerrors.Errorf("cannot complete PCR policy revocation check: %w", err)
	}

	return nil
}

// keyDataPolicy_v0 represents version 0 of the metadata for executing a
// policy session.
type keyDataPolicy_v0 struct {
	StaticData *staticPolicyData_v0
	PCRData    *pcrPolicyData_v0
}

func (p *keyDataPolicy_v0) PCRPolicyCounterHandle() tpm2.Handle {
	return p.StaticData.PCRPolicyCounterHandle
}

func (p *keyDataPolicy_v0) PCRPolicySequence() uint64 {
	return p.PCRData.PolicySequence
}

// UpdatePCRPolicy updates the PCR policy associated with this keyDataPolicy. The PCR policy asserts
// that the following are true:
//   - The selected PCRs contain expected values - ie, one of the sets of permitted values specified by
//     the caller to this function, indicating that the device is in an expected state. This is done by a
//     single PolicyPCR assertion and then one or more PolicyOR assertions (depending on how many sets of
//     permitted PCR values there are).
//   - The PCR policy hasn't been revoked. This is done using a PolicyNV assertion to assert that the
//     value of an optional NV counter is not greater than the PCR policy sequence.
//
// The computed PCR policy digest is authorized with the supplied key. The signature of this is
// validated during execution before executing the corresponding PolicyAuthorize assertion as part of the
// static policy.
func (p *keyDataPolicy_v0) UpdatePCRPolicy(alg tpm2.HashAlgorithmId, params *pcrPolicyParams) error {
	pcrData := p.PCRData.new(params)

	trial := util.ComputeAuthPolicy(alg)
	if err := pcrData.addPcrAssertions(alg, trial, params.pcrDigests); err != nil {
		return xerrors.Errorf("cannot compute base PCR policy: %w", err)
	}

	pcrData.addRevocationCheck(trial, params.policyCounterName)

	key, err := x509.ParsePKCS1PrivateKey(params.key)
	if err != nil {
		return xerrors.Errorf("cannot parse auth key: %w", err)
	}

	scheme := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSAPSS,
		Details: &tpm2.SigSchemeU{
			RSAPSS: &tpm2.SigSchemeRSAPSS{
				HashAlg: p.StaticData.AuthPublicKey.NameAlg}}}
	if err := pcrData.authorizePolicy(key, scheme, trial.GetDigest(), nil); err != nil {
		return xerrors.Errorf("cannot authorize policy: %w", err)
	}

	p.PCRData = pcrData
	return nil
}

func (p *keyDataPolicy_v0) SetPCRPolicyFrom(src keyDataPolicy) {
	p.PCRData = src.(*keyDataPolicy_v0).PCRData
}

func (p *keyDataPolicy_v0) ExecutePCRPolicy(tpm *tpm2.TPMContext, policySession, hmacSession tpm2.SessionContext) error {
	if err := p.PCRData.executePcrAssertions(tpm, policySession); err != nil {
		return xerrors.Errorf("cannot execute PCR assertions: %w", err)
	}

	pcrPolicyCounterHandle := p.StaticData.PCRPolicyCounterHandle
	if pcrPolicyCounterHandle.Type() != tpm2.HandleTypeNVIndex {
		return policyDataError{fmt.Errorf("invalid handle %v for PCR policy counter", pcrPolicyCounterHandle)}
	}

	pcrPolicyCounter, err := tpm.CreateResourceContextFromTPM(pcrPolicyCounterHandle)
	switch {
	case tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle):
		// If there is no NV index at the expected handle then the key file is invalid and must be recreated.
		return policyDataError{errors.New("no PCR policy counter found")}
	case err != nil:
		return err
	}

	pcrPolicyCounterPub, _, err := tpm.NVReadPublic(pcrPolicyCounter)
	if err != nil {
		return err
	}
	if !pcrPolicyCounterPub.NameAlg.Available() {
		//If the NV index has an unsupported name algorithm, then this key file is invalid and must be recreated.
		return policyDataError{errors.New("PCR policy counter has an unsupported name algorithm")}
	}

	revocationCheckSession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, pcrPolicyCounterPub.NameAlg)
	if err != nil {
		return err
	}
	defer tpm.FlushContext(revocationCheckSession)

	// See the comment for computeV0PinNVIndexPostInitAuthPolicies for a description of the authorization policy
	// for the v0 NV index. Because the v0 NV index was also used for the PIN, it needed an authorization policy to
	// permit using the counter value in an assertion without knowing the authorization value of the index.
	if err := tpm.PolicyCommandCode(revocationCheckSession, tpm2.CommandPolicyNV); err != nil {
		return xerrors.Errorf("cannot execute assertion for PCR policy revocation check: %w", err)
	}
	if err := tpm.PolicyOR(revocationCheckSession, p.StaticData.PCRPolicyCounterAuthPolicies); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyOR, 1) {
			// StaticData.PCRPolicyCounterAuthPolicies is invalid.
			return policyDataError{errors.New("authorization policy metadata for PCR policy counter is invalid")}
		}
		return xerrors.Errorf("cannot execute assertion for PCR policy revocation check: %w", err)
	}

	if err := p.PCRData.executeRevocationCheck(tpm, pcrPolicyCounter, policySession, revocationCheckSession); err != nil {
		return err
	}

	authPublicKey := p.StaticData.AuthPublicKey
	authorizeKey, err := tpm.LoadExternal(nil, authPublicKey, tpm2.HandleOwner)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandLoadExternal, 2) {
			// StaticData.AuthPublicKey is invalid
			return policyDataError{xerrors.Errorf("public area of dynamic authorization policy signing key is invalid: %w", err)}
		}
		return err
	}
	defer tpm.FlushContext(authorizeKey)

	pcrPolicyDigest, err := util.ComputePolicyAuthorizeDigest(authPublicKey.NameAlg, p.PCRData.AuthorizedPolicy, nil)
	if err != nil {
		return policyDataError{xerrors.Errorf("cannot compute PCR policy digest: %w", err)}
	}

	authorizeTicket, err := tpm.VerifySignature(authorizeKey, pcrPolicyDigest, p.PCRData.AuthorizedPolicySignature)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandVerifySignature, 2) {
			// PCRData.AuthorizedPolicySignature is invalid.
			return policyDataError{xerrors.Errorf("cannot verify PCR policy signature: %w", err)}
		}
		return err
	}

	if err := tpm.PolicyAuthorize(policySession, p.PCRData.AuthorizedPolicy, nil, authorizeKey.Name(), authorizeTicket); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyAuthorize, 1) {
			// d.PCRData.AuthorizedPolicy is invalid or the auth key isn't associated with
			// this object.
			return policyDataError{errors.New("the PCR policy is invalid")}
		}
		return err
	}

	// For metadata version 0, PIN support was implemented by asserting knowlege of the authorization value
	// for the PCR policy counter, although this support was never used and has been removed.
	if _, _, err := tpm.PolicySecret(pcrPolicyCounter, policySession, nil, nil, 0, hmacSession); err != nil {
		return err
	}

	// Execute required TPM2_PolicyNV assertion that was used for legacy locking with v0 files -
	// this is only here because the existing policy for v0 files requires it. It is not expected that
	// this will fail unless the NV index has been removed or altered, at which point the key is
	// non-recoverable anyway.
	lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	switch {
	case tpm2.IsResourceUnavailableError(err, lockNVHandle):
		// If there is no NV index at the expected handle then the key file is invalid and must be recreated.
		return policyDataError{errors.New("no lock NV index found")}
	case err != nil:
		return err
	}
	if err := tpm.PolicyNV(lockIndex, lockIndex, policySession, nil, 0, tpm2.OpEq, nil); err != nil {
		return xerrors.Errorf("policy lock check failed: %w", err)
	}

	return nil
}

type pcrPolicyCounterContext_v0 struct {
	tpm          *tpm2.TPMContext
	index        tpm2.ResourceContext
	session      tpm2.SessionContext
	updateKey    *tpm2.Public
	authPolicies tpm2.DigestList
}

func (c *pcrPolicyCounterContext_v0) Get() (uint64, error) {
	authSession, err := c.tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, c.index.Name().Algorithm())
	if err != nil {
		return 0, err
	}
	defer c.tpm.FlushContext(authSession)

	// See the comment for computeV0PinNVIndexPostInitAuthPolicies for a description of the authorization policy
	// for the v0 NV index. Because the v0 NV index was also used for the PIN, it needed an authorization policy
	// to permit reading the counter value without knowing the authorization value of the index.
	if err := c.tpm.PolicyCommandCode(authSession, tpm2.CommandNVRead); err != nil {
		return 0, err
	}
	if err := c.tpm.PolicyOR(authSession, c.authPolicies); err != nil {
		return 0, err
	}

	return c.tpm.NVReadCounter(c.index, c.index, authSession, c.session.IncludeAttrs(tpm2.AttrAudit))
}

func (c *pcrPolicyCounterContext_v0) Increment(key secboot.PrimaryKey) error {
	rsaKey, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		return xerrors.Errorf("cannot parse auth key: %w", err)
	}

	// Begin a policy session to increment the index.
	policySession, err := c.tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, c.index.Name().Algorithm())
	if err != nil {
		return err
	}
	defer c.tpm.FlushContext(policySession)

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, err := c.tpm.LoadExternal(nil, c.updateKey, tpm2.HandleEndorsement)
	if err != nil {
		return err
	}
	defer c.tpm.FlushContext(keyLoaded)

	// Create a signed authorization. keyData.validate checks that this scheme is compatible with the key
	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSAPSS,
		Details: &tpm2.SigSchemeU{
			RSAPSS: &tpm2.SigSchemeRSAPSS{
				HashAlg: c.updateKey.NameAlg}}}
	signature, err := util.SignPolicyAuthorization(rsaKey, &scheme, policySession.NonceTPM(), nil, nil, 0)
	if err != nil {
		return xerrors.Errorf("cannot sign authorization: %w", err)
	}

	// See the comment for computeV0PinNVIndexPostInitAuthPolicies for a description of the authorization policy
	// for the v0 NV index.
	if err := c.tpm.PolicyCommandCode(policySession, tpm2.CommandNVIncrement); err != nil {
		return err
	}
	if err := c.tpm.PolicyNvWritten(policySession, true); err != nil {
		return err
	}
	if _, _, err := c.tpm.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, signature); err != nil {
		return err
	}
	if err := c.tpm.PolicyOR(policySession, c.authPolicies); err != nil {
		return err
	}

	// Increment the index.
	return c.tpm.NVIncrement(c.index, c.index, policySession, c.session.IncludeAttrs(tpm2.AttrAudit))
}

func (p *keyDataPolicy_v0) PCRPolicyCounterContext(tpm *tpm2.TPMContext, pub *tpm2.NVPublic, session tpm2.SessionContext) (pcrPolicyCounterContext, error) {
	if pub.Index != p.StaticData.PCRPolicyCounterHandle {
		return nil, errors.New("NV index public area is inconsistent with metadata")
	}

	index, err := tpm2.CreateNVIndexResourceContextFromPublic(pub)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for NV index: %w", err)
	}

	return &pcrPolicyCounterContext_v0{
		tpm:          tpm,
		index:        index,
		session:      session,
		updateKey:    p.StaticData.AuthPublicKey,
		authPolicies: p.StaticData.PCRPolicyCounterAuthPolicies}, nil
}

func (p *keyDataPolicy_v0) ValidateAuthKey(key secboot.PrimaryKey) error {
	rsaKey, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		return xerrors.Errorf("cannot parse auth key: %w", err)
	}

	pub, ok := p.StaticData.AuthPublicKey.Public().(*rsa.PublicKey)
	if !ok {
		return policyDataError{errors.New("unexpected dynamic authorization policy public key type")}
	}

	if rsaKey.E != pub.E || rsaKey.N.Cmp(pub.N) != 0 {
		return policyDataError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
	}

	return nil
}
