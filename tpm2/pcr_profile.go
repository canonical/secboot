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
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"
)

// maxPCR is the maximum PCR index representable by a selection. A selection is a
// bitmap with a size field of 1 byte, so up to 256 bytes long.
const maxPCR = ((math.MaxUint8 + 1) * 8) - 1

// pcrValuesList is a list of PCR value combinations computed from PCRProtectionProfile.
type pcrValuesList []tpm2.PCRValues

// setValue sets the specified PCR to the supplied value for all branches.
func (l pcrValuesList) setValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	for _, v := range l {
		v.SetValue(alg, pcr, value)
	}
}

// extendValue extends the specified PCR with the supplied value for all branches.
func (l pcrValuesList) extendValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	for _, v := range l {
		if _, ok := v[alg]; !ok {
			v[alg] = make(map[int]tpm2.Digest)
		}
		if _, ok := v[alg][pcr]; !ok {
			v[alg][pcr] = make(tpm2.Digest, alg.Size())
		}
		h := alg.NewHash()
		h.Write(v[alg][pcr])
		h.Write(value)
		v[alg][pcr] = h.Sum(nil)
	}
}

func (l pcrValuesList) copy() (out pcrValuesList) {
	for _, v := range l {
		ov := make(tpm2.PCRValues)
		for alg := range v {
			ov[alg] = make(map[int]tpm2.Digest)
			for pcr := range v[alg] {
				ov[alg][pcr] = v[alg][pcr]
			}
		}
		out = append(out, ov)
	}
	return
}

type pcrProtectionProfileAddPCRValueInstr struct {
	alg   tpm2.HashAlgorithmId
	pcr   int
	value tpm2.Digest
}

type pcrProtectionProfileAddPCRValueFromTPMInstr struct {
	alg tpm2.HashAlgorithmId
	pcr int
}

type pcrProtectionProfileExtendPCRInstr struct {
	alg   tpm2.HashAlgorithmId
	pcr   int
	value tpm2.Digest
}

type pcrProtectionProfileBranchPointInstr struct {
	bp *PCRProtectionProfileBranchPoint
}

// pcrProtectionProfileEndBranchInstr is a pseudo instruction to mark the end of a branch.
type pcrProtectionProfileEndBranchInstr struct{}

// pcrProtectionProfileInstr is a building block of PCRProtectionProfile.
type pcrProtectionProfileInstr interface{}

type pcrProtectionProfileInstrList []pcrProtectionProfileInstr

// PCRProtectionProfileBranchPoint represents a point in a parent branch
// in which sub-branches can be inserted and populated, in order to create
// compound policies that correspond to multiple conditions.
type PCRProtectionProfileBranchPoint struct {
	profile       *PCRProtectionProfile         // the profile associated with this branch point
	parentBranch  *PCRProtectionProfileBranch   // the branch that this branch point was added to
	childBranches []*PCRProtectionProfileBranch // sub-branches added to this point

	done bool
}

func (p *PCRProtectionProfileBranchPoint) removeBranch(b *PCRProtectionProfileBranch) {
	for i, c := range p.childBranches {
		if c == b {
			if i < len(p.childBranches)-1 {
				copy(p.childBranches[i:], p.childBranches[i+1:])
			}
			p.childBranches = p.childBranches[:len(p.childBranches)-1]
			break
		}
	}
}

// AddBranch creates and returns a PCRProtectionProfileBranch corresponding to a
// new sub-branch in the associated profile.
//
// Note that each branch created from this branch point must explicitly define
// values for the same set of PCRs. It is not possible to generate policies where
// each branch defines values for a different set of PCRs.
//
// Calling this after the branch point has been terminated with EndBranchPoint
// either explicitly or by terminating the branch from which it originates will
// mark the associated profile as failed.
func (p *PCRProtectionProfileBranchPoint) AddBranch() *PCRProtectionProfileBranch {
	b := &PCRProtectionProfileBranch{profile: p.profile, parentBranchPoint: p}

	if p.done {
		p.profile.fail("cannot add a branch to a branch point that has already been terminated")
	}

	p.childBranches = append(p.childBranches, b)
	return b
}

// EndBranchPoint can be called when the caller is finished adding branches to
// this branch point. It will implicitly terminate any in-progress sub-branches
// with PCRProtectionProfileBranch.EndBranch.
//
// Once this has been called, further attempts to create additional sub-branches
// or modify existing ones will mark the profile as failed.
//
// This returns a pointer to the parent branch.
func (p *PCRProtectionProfileBranchPoint) EndBranchPoint() *PCRProtectionProfileBranch {
	if p.done {
		p.profile.fail("cannot terminate a branch point more than once")
	}

	var branchesToEnd []*PCRProtectionProfileBranch
	branchPoints := []*PCRProtectionProfileBranchPoint{p}

	for len(branchPoints) > 0 {
		bp := branchPoints[0]
		branchPoints = branchPoints[1:]

		for _, b := range bp.childBranches {
			if b.done {
				continue
			}
			branchesToEnd = append(branchesToEnd, b)
			if b.currentBranchPoint != nil {
				branchPoints = append(branchPoints, b.currentBranchPoint)
			}
		}
	}

	for i := len(branchesToEnd) - 1; i >= 0; i-- {
		branchesToEnd[i].EndBranch()
	}

	p.parentBranch.doneBranchPoint(p)
	p.done = true
	return p.parentBranch
}

// PCRProtectionProfileBranch represents a branch in a PCR profile. It
// contains a sequence of instructions that are used to compute PCR values.
//
// Note that there isn't a one-to-one association between a branch in a
// profile and a branch in the computed policy - a branch in a profile
// may correspond to multiple branches in the computed policy.
type PCRProtectionProfileBranch struct {
	profile *PCRProtectionProfile // the profile associated with this branch

	// parentBranchPoint is the branch point that this branch was added to. This
	// is nil for the root branch
	parentBranchPoint *PCRProtectionProfileBranchPoint

	instrs             pcrProtectionProfileInstrList
	currentBranchPoint *PCRProtectionProfileBranchPoint // currently active branch point

	done bool
}

func (b *PCRProtectionProfileBranch) prepareToModifyBranch() {
	if b.done {
		b.profile.fail("cannot modify branch that has already been terminated")
	}
	if b.currentBranchPoint != nil {
		b.currentBranchPoint.EndBranchPoint()
	}
}

func (b *PCRProtectionProfileBranch) checkArguments(alg tpm2.HashAlgorithmId, pcr int) {
	if !alg.IsValid() {
		b.profile.fail("invalid digest algorithm")
	}
	if pcr < 0 || pcr > maxPCR {
		b.profile.fail("invalid PCR index")
	}
}

func (b *PCRProtectionProfileBranch) doneBranchPoint(p *PCRProtectionProfileBranchPoint) {
	if p != b.currentBranchPoint {
		// This shouldn't happen when the API is used correctly. Do nothing
		// there though - the caller will have already marked this profile
		// as failed.
		return
	}

	b.currentBranchPoint = nil
}

// AddPCRValue adds the supplied value to this branch for the specified PCR.
// This action replaces any value set previously for this PCR in this branch.
// The function returns the same PCRProtectionProfileBranch so that calls may
// be chained.
//
// Specifying an invalid algorithm or PCR index, or a digest with a size that
// doesn't match the algorithm will mark the associated profile as failed.
func (b *PCRProtectionProfileBranch) AddPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) *PCRProtectionProfileBranch {
	b.prepareToModifyBranch()
	b.checkArguments(alg, pcr)

	if alg.IsValid() && len(value) != alg.Size() {
		b.profile.fail("digest length is inconsistent with specified algorithm")
		return b
	}

	b.instrs = append(b.instrs, &pcrProtectionProfileAddPCRValueInstr{alg: alg, pcr: pcr, value: value})
	return b
}

// AddPCRValueFromTPM adds the current value of the specified PCR to this
// branch. This action replaces any value set previously for this PCR in
// this branch. The current value is read back from the TPM when the PCR
// values generated by the associated profile are computed. The function
// returns the same PCRProtectionProfileBranch so that calls may be chained.
//
// Specifying an invalid algorithm or PCR index will mark the associated
// profile as failed.
func (b *PCRProtectionProfileBranch) AddPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) *PCRProtectionProfileBranch {
	b.prepareToModifyBranch()
	b.checkArguments(alg, pcr)

	b.instrs = append(b.instrs, &pcrProtectionProfileAddPCRValueFromTPMInstr{alg: alg, pcr: pcr})
	return b
}

// ExtendPCR extends the value of the specified PCR in this branch with the
// supplied value. If this branch doesn't yet have a value for the specified
// PCR, an initial value of all zeroes will be added first. The function
// returns the same PCRProtectionProfileBranch so that calls may be chained.
//
// Specifying an invalid algorithm or PCR index, or a digest with a size that
// doesn't match the algorithm will mark the associated profile as failed.
func (b *PCRProtectionProfileBranch) ExtendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) *PCRProtectionProfileBranch {
	b.prepareToModifyBranch()
	b.checkArguments(alg, pcr)

	if alg.IsValid() && len(value) != alg.Size() {
		b.profile.fail("digest length is inconsistent with specified algorithm")
		return b
	}

	b.instrs = append(b.instrs, &pcrProtectionProfileExtendPCRInstr{alg: alg, pcr: pcr, value: value})
	return b
}

// AddBranchPoint adds a branch point to this branch from which multiple
// sub-branches can be added in order to define PCR policies for multiple
// conditions. When a branch point is encountered whilst computing PCR values
// for a profile, instructions from sub-branches are executed before continuing
// with instructions in the current branch - ie, sub-branches make changes to
// the state of this branch before processing subsequent instructions in this
// branch.
//
// Instructions added to this branch after this point will apply to all of the
// sub-branches created at this branch point.
//
// Further modifications to this branch after calling this function will implicitly
// terminate the returned branch point by calling
// PCRProtectionProfileBranchPoint.EndBranchPoint.
func (b *PCRProtectionProfileBranch) AddBranchPoint() *PCRProtectionProfileBranchPoint {
	b.prepareToModifyBranch()

	p := &PCRProtectionProfileBranchPoint{
		profile:      b.profile,
		parentBranch: b}

	b.instrs = append(b.instrs, &pcrProtectionProfileBranchPointInstr{bp: p})
	b.currentBranchPoint = p
	return p
}

// EndBranch can be called when the caller is finished with this branch. If
// there is an in-progress branch point (ie, the last call on this branch was
// AddBranchPoint and the returned branch point has not been terminated with
// PCRProtectionProfileBranchPoint.EndBranchPoint, then this will be terminated
// implicitly.
//
// Once this has been called, attempts to modify this branch or any sub-branch
// will result in the associated profile being marked as failed.
//
// This should not be called on the root branch associated with a profile, and
// doing so will mark the profile as failed.
//
// It returns a pointer to the branch point to which this branch was added.
func (b *PCRProtectionProfileBranch) EndBranch() *PCRProtectionProfileBranchPoint {
	b.prepareToModifyBranch()

	if b.parentBranchPoint == nil {
		b.profile.fail("cannot terminate the root branch")
		// Always return something to avoid having to check for nil
		return &PCRProtectionProfileBranchPoint{
			profile:      b.profile,
			parentBranch: &PCRProtectionProfileBranch{profile: b.profile}}
	}

	b.done = true
	return b.parentBranchPoint
}

// AbortBranch can be called to remove this branch and all of its sub-branches
// from the profile.
//
// Once this has been called, attempts to modify this branch or any sub-branch
// will result in the associated profile being marked as failed.
//
// This should not be called on the root branch associated with a profile, and
// doing so will mark the profile as failed.
//
// It returns a pointer to the branch point to which this branch was originally
// added.
func (b *PCRProtectionProfileBranch) AbortBranch() *PCRProtectionProfileBranchPoint {
	b.prepareToModifyBranch()

	if b.parentBranchPoint == nil {
		b.profile.fail("cannot abort the root branch")
		// Always return something to avoid having to check for nil
		return &PCRProtectionProfileBranchPoint{
			profile:      b.profile,
			parentBranch: &PCRProtectionProfileBranch{profile: b.profile}}
	}

	b.done = true
	b.parentBranchPoint.removeBranch(b)
	return b.parentBranchPoint
}

// PCRProtectionProfile provides a way to create the PCR policy used to
// protect a key sealed with SealKeyToTPM. It can generate compound PCR
// policies for multiple conditions by making use of sub-branches.
//
// The API can be used to assemble profiles without any error checking.
// Errors that occur when assembling the profile or misuse of the API will
// mark a profile as failed and the error will subsequently be returned
// when calling ComputePCRDigests or ComputePCRValues.
//
// Every profile starts with a root PCRProtectionProfileBranch. If no
// sub-branches are created then the computed policy (the PCR selection and
// composite PCR digests returned from ComputePCRDigests) will have a single
// branch.
//
// When computing policy from a profile, a profile branch corresponds to one or
// more branches in the computed policy. Instructions in the profile branch are
// applied to each of the associated policy branches. The profile's root branch
// initially corresponds to one branch in the computed policy.
//
// When encountering a branch point and sub-branches whilst computing the PCR
// policy for a profile, instructions from each sub-branch are executed in turn
// before resuming execution of the parent branch. Each sub-branch inherits a
// copy of the current state of the PCR policy branches associated with the
// parent branch. Upon completion of a branch point, the state of the parent
// branch is replaced by the modified state associated with all of the
// sub-branches before instructions from the parent branch are resumed.
// Effectively, if a profile branch is associated with n branches in the
// computed PCR policy and a branch point with m sub-branches is encountered,
// the profile branch will be associated with n x m branches in the computed
// PCR policy upon completion of the sub-branches.
type PCRProtectionProfile struct {
	root *PCRProtectionProfileBranch
	err  error
}

// NewPCRProtectionProfile creates an empty PCR profile.
func NewPCRProtectionProfile() *PCRProtectionProfile {
	profile := &PCRProtectionProfile{root: new(PCRProtectionProfileBranch)}
	profile.root.profile = profile
	return profile
}

func (p *PCRProtectionProfile) fail(msg string) {
	if p.err != nil {
		return
	}

	var pc [10]uintptr
	n := runtime.Callers(1, pc[:])
	frames := runtime.CallersFrames(pc[:n])

	for {
		frame, more := frames.Next()
		if !strings.HasPrefix(frame.Function, "github.com/snapcore/secboot/tpm2.(*PCRProtectionProfile") {
			p.err = fmt.Errorf("%s (occurred at %s:%d)", msg, frame.File, frame.Line)
			break
		}
		if !more {
			p.err = fmt.Errorf("%s (cannot determine call site)", msg)
			break
		}
	}
}

// RootBranch returns the root branch associated with this PCR profile.
func (p *PCRProtectionProfile) RootBranch() *PCRProtectionProfileBranch {
	return p.root
}

// AddPCRValue adds the supplied value to the root branch of this profile
// for the specified PCR. This action replaces any value set previously for
// this PCR. The function returns the same PCRProtectionProfile so that calls
// may be chained.
//
// Deprecated: Use PCRProtectionProfileBranch.AddPCRValue instead.
func (p *PCRProtectionProfile) AddPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) *PCRProtectionProfile {
	p.root.AddPCRValue(alg, pcr, value)
	return p
}

// AddPCRValueFromTPM adds the current value of the specified PCR to the
// root branch of this profile This action replaces any value set previously
// for this PCR. The current value is read back from the TPM when the PCR
// values generated by this profile are computed. The function returns the
// same PCRProtectionProfile so that calls may be chained.
//
// Deprecated: Use PCRProtectionProfileBranch.AddPCRValueFromTPM instead.
func (p *PCRProtectionProfile) AddPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) *PCRProtectionProfile {
	p.root.AddPCRValueFromTPM(alg, pcr)
	return p
}

// ExtendPCR extends the value of the specified PCR in the root profile of
// this branch with the supplied value. If this branch doesn't yet have a
// value for the specified PCR, an initial value of all zeroes will be added
// first. The function returns the same PCRProtectionProfile so that calls
// may be chained.
//
// Deprecated: Use PCRProtectionProfileBranch.ExtendPCR instead.
func (p *PCRProtectionProfile) ExtendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) *PCRProtectionProfile {
	p.root.ExtendPCR(alg, pcr, value)
	return p
}

// AddProfileOR adds a branch point to this branch containing the supplied
// root branches associated with the supplied sub-profiles as branches, in order
// to define PCR policies for multiple conditions.
//
// Deprecated: Use PCRProtectionProfileBranch.AddBranchPoint instead.
func (p *PCRProtectionProfile) AddProfileOR(profiles ...*PCRProtectionProfile) *PCRProtectionProfile {
	bp := p.root.AddBranchPoint()

	for _, sub := range profiles {
		branch := sub.root
		branch.parentBranchPoint = bp
		branch.profile = p

		if sub.err != nil {
			if p.err == nil {
				p.err = sub.err
			}
			return p
		}

		bp.childBranches = append(bp.childBranches, branch)
	}

	bp.EndBranchPoint()
	return p
}

// pcrProtectionProfileIterator provides a mechanism to perform a depth first
// traversal of instructions in a PCRProtectionProfile.
type pcrProtectionProfileIterator struct {
	instrs []pcrProtectionProfileInstrList
}

// descendInToProfiles adds instructions from the supplied profiles to the front
// of the iterator, so that subsequent calls to next will return instructions from
// each of these profiles in turn.
func (iter *pcrProtectionProfileIterator) descendInToBranches(branches ...*PCRProtectionProfileBranch) {
	var instrs []pcrProtectionProfileInstrList
	for _, b := range branches {
		instrs = append(instrs, b.instrs)
	}
	instrs = append(instrs, iter.instrs...)
	iter.instrs = instrs
}

// next returns the next instruction from this iterator. When encountering a
// branch point, a *pcrProtectionProfileBranchPointInstr will be returned, which
// indicates the number of branches from the branch point. Subsequent calls to
// next will return instructions from each of these branches in turn, with each
// branch terminating with *pcrProtectionProfileEndBranchInstr. Once all branches
// have been processed, subsequent calls to next will resume returning instructions
// from the parent branch.
func (iter *pcrProtectionProfileIterator) next() pcrProtectionProfileInstr {
	if len(iter.instrs) == 0 {
		panic("no more instructions")
	}

	for {
		if len(iter.instrs[0]) == 0 {
			iter.instrs = iter.instrs[1:]
			return &pcrProtectionProfileEndBranchInstr{}
		}

		instr := iter.instrs[0][0]
		iter.instrs[0] = iter.instrs[0][1:]

		switch i := instr.(type) {
		case *pcrProtectionProfileBranchPointInstr:
			if len(i.bp.childBranches) == 0 {
				// If this is an empty branch point, don't return this instruction because there
				// won't be a corresponding *EndBranchInstr
				continue
			}
			iter.descendInToBranches(i.bp.childBranches...)
			return instr
		default:
			return instr
		}
	}
}

// traverseInstructions returns an iterator that performs a depth first traversal
// through the instructions in this profile.
func (p *PCRProtectionProfile) traverseInstructions() *pcrProtectionProfileIterator {
	i := &pcrProtectionProfileIterator{}
	i.descendInToBranches(p.root)
	return i
}

type pcrProtectionProfileStringifyBranchContext struct {
	index int
	total int
}

func (p *PCRProtectionProfile) String() string {
	var b bytes.Buffer

	contexts := []*pcrProtectionProfileStringifyBranchContext{{index: 0, total: 1}}
	branchStart := false

	iter := p.traverseInstructions()
	for len(contexts) > 0 {
		fmt.Fprintf(&b, "\n")
		depth := len(contexts) - 1
		if branchStart {
			branchStart = false
			fmt.Fprintf(&b, "%*sBranch %d {\n", depth*3, "", contexts[0].index)
		}

		switch i := iter.next().(type) {
		case *pcrProtectionProfileAddPCRValueInstr:
			fmt.Fprintf(&b, "%*s AddPCRValue(%v, %d, %x)", depth*3, "", i.alg, i.pcr, i.value)
		case *pcrProtectionProfileAddPCRValueFromTPMInstr:
			fmt.Fprintf(&b, "%*s AddPCRValueFromTPM(%v, %d)", depth*3, "", i.alg, i.pcr)
		case *pcrProtectionProfileExtendPCRInstr:
			fmt.Fprintf(&b, "%*s ExtendPCR(%v, %d, %x)", depth*3, "", i.alg, i.pcr, i.value)
		case *pcrProtectionProfileBranchPointInstr:
			contexts = append([]*pcrProtectionProfileStringifyBranchContext{{index: 0, total: len(i.bp.childBranches)}}, contexts...)
			fmt.Fprintf(&b, "%*s BranchPoint(", depth*3, "")
			branchStart = true
		case *pcrProtectionProfileEndBranchInstr:
			contexts[0].index++
			if len(contexts) > 1 {
				// This is the end of a sub-branch rather than the root profile.
				fmt.Fprintf(&b, "%*s}", depth*3, "")
			}
			switch {
			case contexts[0].index < contexts[0].total:
				// There are sibling branches to print.
				branchStart = true
			case len(contexts) > 1:
				// This is the end of a branch point. Printing will continue with the parent branch.
				fmt.Fprintf(&b, "\n%*s )", (depth-1)*3, "")
				fallthrough
			default:
				// Return to the parent branch's context.
				contexts = contexts[1:]
			}
		}
	}

	return b.String()
}

// pcrProtectionProfileComputeContext records state used when computing PCR
// values for a PCRProtectionProfile
type pcrProtectionProfileComputeContext struct {
	parent *pcrProtectionProfileComputeContext
	values pcrValuesList
}

// handleBranches is called when encountering a branch in a profile, and
// returns a slice of new *pcrProtectionProfileComputeContext instances (one
// for each sub-branch). At the end of each sub-branch, finishBranch must be
// called on the associated *pcrProtectionProfileComputeContext.
func (c *pcrProtectionProfileComputeContext) handleBranches(n int) (out []*pcrProtectionProfileComputeContext) {
	out = make([]*pcrProtectionProfileComputeContext, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &pcrProtectionProfileComputeContext{parent: c, values: c.values.copy()})
	}
	c.values = nil
	return
}

// finishBranch is called when encountering the end of a branch. This propagates the computed PCR values to the
// *pcrProtectionProfileComputeContext associated with the parent branch. Calling this will panic on a
// *pcrProtectionProfileComputeContext associated with the root branch.
func (c *pcrProtectionProfileComputeContext) finishBranch() {
	c.parent.values = append(c.parent.values, c.values...)
}

// isRoot returns true if this *pcrProtectionProfileComputeContext is associated with a root branch.
func (c *pcrProtectionProfileComputeContext) isRoot() bool {
	return c.parent == nil
}

// pcrProtectionProfileComputeContextStack is a stack of *pcrProtectionProfileComputeContext, with the top of the stack associated
// with the profile branch from which instructions are currently being processed.
type pcrProtectionProfileComputeContextStack []*pcrProtectionProfileComputeContext

// handleBranches is called when encountering a branch in a profile, and returns a new pcrProtectionProfileComputeContextStack with
// the top of the stack associated with the first sub-branch, from which subsequent instructions will be processed from. At the
// end of each sub-branch, finishBranch must be called.
func (s pcrProtectionProfileComputeContextStack) handleBranches(n int) pcrProtectionProfileComputeContextStack {
	newContexts := s.top().handleBranches(n)
	return pcrProtectionProfileComputeContextStack(append(newContexts, s...))
}

// finishBranch is called when encountering the end of a branch. This propagates the computed PCR values from the
// *pcrProtectionProfileComputeContext at the top of the stack to the *pcrProtectionProfileComputeContext associated with the parent
// branch, and then pops the context from the top of the stack. The new top of the stack corresponds to either a sibling branch or
// the parent branch, from which subsequent instructions will be processed from.
func (s pcrProtectionProfileComputeContextStack) finishBranch() pcrProtectionProfileComputeContextStack {
	s.top().finishBranch()
	return s[1:]
}

// top returns the *pcrProtectionProfileComputeContext at the top of the stack, which is associated with the branch that instructions
// are currently being processed from.
func (s pcrProtectionProfileComputeContextStack) top() *pcrProtectionProfileComputeContext {
	return s[0]
}

// ComputePCRValues computes PCR values for this PCRProtectionProfile, and is
// an intermediate step in computing a PCR policy from this profile
// (ComputePCRDigests performs this entire process). There is one set of PCR
// values for each branch in the computed PCR policy. Note that there isn't a
// one-to-one association between a branch in the computed policy and a branch
// in the profile.
//
// The returned list of PCR values is not de-duplicated.
func (p *PCRProtectionProfile) ComputePCRValues(tpm *tpm2.TPMContext) ([]tpm2.PCRValues, error) {
	if p.err != nil {
		return nil, fmt.Errorf("cannot compute PCR values because of an error when constructing the profile: %v", p.err)
	}

	contexts := pcrProtectionProfileComputeContextStack{{values: pcrValuesList{make(tpm2.PCRValues)}}}

	iter := p.traverseInstructions()
	for {
		switch i := iter.next().(type) {
		case *pcrProtectionProfileAddPCRValueInstr:
			contexts.top().values.setValue(i.alg, i.pcr, i.value)
		case *pcrProtectionProfileAddPCRValueFromTPMInstr:
			if tpm == nil {
				return nil, fmt.Errorf("cannot read current value of PCR %d from bank %v: no TPM context", i.pcr, i.alg)
			}
			_, v, err := tpm.PCRRead(tpm2.PCRSelectionList{{Hash: i.alg, Select: []int{i.pcr}}})
			if err != nil {
				return nil, xerrors.Errorf("cannot read current value of PCR %d from bank %v: %w", i.pcr, i.alg, err)
			}
			contexts.top().values.setValue(i.alg, i.pcr, v[i.alg][i.pcr])
		case *pcrProtectionProfileExtendPCRInstr:
			contexts.top().values.extendValue(i.alg, i.pcr, i.value)
		case *pcrProtectionProfileBranchPointInstr:
			// As this is a depth-first traversal, processing of this branch is parked when a BranchPoint instruction is encountered.
			// Subsequent instructions will be from each of the branches from this branch point in turn.
			contexts = contexts.handleBranches(len(i.bp.childBranches))
		case *pcrProtectionProfileEndBranchInstr:
			if contexts.top().isRoot() {
				// This is the end of the profile
				return []tpm2.PCRValues(contexts.top().values), nil
			}
			contexts = contexts.finishBranch()
		}
	}
}

// ComputePCRDigests computes a PCR policy consisting of a PCR selection and
// a list of composite PCR digests from this PCRProtectionProfile (one
// composite digest per branch). Note that there isn't a one-to-one association
// between a branch in the computed policy and a branch in the profile.
//
// The returned list of composite PCR digests is de-duplicated.
func (p *PCRProtectionProfile) ComputePCRDigests(tpm *tpm2.TPMContext, alg tpm2.HashAlgorithmId) (tpm2.PCRSelectionList, tpm2.DigestList, error) {
	// Compute the sets of PCR values for all branches
	values, err := p.ComputePCRValues(tpm)
	if err != nil {
		return nil, nil, err
	}

	// Compute the PCR selection for this profile from the first branch.
	pcrs := values[0].SelectionList()

	// Compute the PCR digests for all branches, making sure that they all contain values for the same sets of PCRs.
	var pcrDigests tpm2.DigestList
	for _, v := range values {
		p, digest, err := util.ComputePCRDigestFromAllValues(alg, v)
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot compute PCR digest: %w", err)
		}
		if !p.Equal(pcrs) {
			return nil, nil, errors.New("not all branches contain values for the same sets of PCRs")
		}
		pcrDigests = append(pcrDigests, digest)
	}

	var uniquePcrDigests tpm2.DigestList
	for _, d := range pcrDigests {
		found := false
		for _, f := range uniquePcrDigests {
			if bytes.Equal(d, f) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		uniquePcrDigests = append(uniquePcrDigests, d)
	}

	return pcrs, uniquePcrDigests, nil
}
