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
	"io"
	"math"
	"math/bits"
	"reflect"
	"runtime"
	"strings"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/util"
)

// maxPCR is the maximum PCR index representable by a selection. A selection is a
// bitmap with a size field of 1 byte, so up to 256 bytes long.
const maxPCR = ((math.MaxUint8 + 1) * 8) - 1

// pcrValuesList is a list of PCR value combinations computed from PCRProtectionProfile.
// It has one entry for each branch created by a profile.
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

// pcrProtectionProfileInstr is a building block of PCRProtectionProfile.
type pcrProtectionProfileInstr interface {
	run(context *pcrProtectionProfileExecContext)
}

type pcrProtectionProfileInstrList []pcrProtectionProfileInstr

// pcrProtectionProfileInstrHandler is an interface to receive instructions associated
// with a profile.
type pcrProtectionProfileInstrHandler interface {
	// beginBranch is called to signal the start of a new branch.
	beginBranch(index int)

	// addPCRValue is called to add the supplied PCR value to the
	// current branch.
	addPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest)

	// addPCRValueFromTPM is called to add the value of the specified
	// PCR to the current branch,
	addPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int)

	// extendPCR is called to extend the specified PCR with the supplied
	// value for the current branch.
	extendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest)

	// beginBranchPoint signals the start of a branch point in the
	// current branch.
	beginBranchPoint()

	// endBranchPoint signals the end of a branch point.
	endBranchPoint()

	// endBranch signals the end of the current branch. The next branch
	// is selected, which will either be for a sibling branch (in which case,
	// the next call will be beginBranch with the sub-branch index) or the
	// parent branch (in which case, the next call will be endBranchPoint)
	endBranch()
}

// pcrProtectionProfileExecContext contains the context associated with the
// pcrProtectionProfileBranchExecContext maintains context associated with a single
// branch when executing a profile.
type pcrProtectionProfileBranchExecContext struct {
	index              int
	instrs             pcrProtectionProfileInstrList
	pendingSubBranches []*PCRProtectionProfileBranch
	nextSubBranchIndex int
}

func newPcrProtectionProfileBranchExecContext(index int, branch *PCRProtectionProfileBranch) *pcrProtectionProfileBranchExecContext {
	instrs := append(pcrProtectionProfileInstrList{}, branch.instrs...)
	if branch.currentBranchPoint != nil {
		// Implicitly add an EndBranchPoint if needed and one doesn't exist
		instrs = append(instrs, new(pcrProtectionProfileEndBranchPointInstr))
	}
	if !branch.done {
		// Implicitly add an EndBranch if one doesn't exist
		instrs = append(instrs, new(pcrProtectionProfileEndBranchInstr))
	}
	return &pcrProtectionProfileBranchExecContext{index: index, instrs: instrs}
}

// execution of PCRProtectionProfile.
type pcrProtectionProfileExecContext struct {
	handler     pcrProtectionProfileInstrHandler
	branchStack []*pcrProtectionProfileBranchExecContext
}

func newPcrProtectionProfileExecContext(profile *PCRProtectionProfile, handler pcrProtectionProfileInstrHandler) *pcrProtectionProfileExecContext {
	return &pcrProtectionProfileExecContext{
		handler: handler,
		branchStack: []*pcrProtectionProfileBranchExecContext{
			newPcrProtectionProfileBranchExecContext(0, profile.root)}}
}

func (c *pcrProtectionProfileExecContext) currentBranchIndex() int {
	return c.branchStack[0].index
}

func (c *pcrProtectionProfileExecContext) queueSubBranches(branches ...*PCRProtectionProfileBranch) {
	branch := c.branchStack[0]
	if len(branch.pendingSubBranches) != 0 {
		panic("cannot begin a branch point whilst one is in progress")
	}
	branch.pendingSubBranches = branches
	branch.nextSubBranchIndex = 0
}

func (c *pcrProtectionProfileExecContext) endCurrentBranch() {
	c.branchStack = c.branchStack[1:]
}

func (c *pcrProtectionProfileExecContext) selectNextPendingSubBranch() {
	if len(c.branchStack) == 0 {
		// We're finished with the profile.
		return
	}

	branch := c.branchStack[0]
	if len(branch.pendingSubBranches) == 0 {
		// We don't have any pending sub branches, so continue with
		// this branch.
		return
	}

	// We're entering or continuing a branch point, so select the next
	// sub branch.
	subBranch := branch.pendingSubBranches[0]
	branch.pendingSubBranches = branch.pendingSubBranches[1:]

	// Push the new sub branch to the top of the stack.
	c.branchStack = append([]*pcrProtectionProfileBranchExecContext{
		newPcrProtectionProfileBranchExecContext(branch.nextSubBranchIndex, subBranch),
	}, c.branchStack...)
	branch.nextSubBranchIndex++
}

func (c *pcrProtectionProfileExecContext) popNextInstr() pcrProtectionProfileInstr {
	branch := c.branchStack[0]
	instr := branch.instrs[0]
	branch.instrs = branch.instrs[1:]
	return instr
}

func (c *pcrProtectionProfileExecContext) done() bool {
	return len(c.branchStack) == 0
}

// pcrProtectionProfileBeginBranchInstr is inserted at the start of every
// branch and calls pcrProtectionProfileInstrHandler.beginBranch when
// executed.
type pcrProtectionProfileBeginBranchInstr struct{}

func (*pcrProtectionProfileBeginBranchInstr) run(context *pcrProtectionProfileExecContext) {
	context.handler.beginBranch(context.currentBranchIndex())
}

// pcrProtectionProfileAddPCRValueInstr is inserted by
// PCRProtectionProfileBranch.AddPCRValue and calls
// pcrProtectionProfileInstrHandler.addPCRValue when executed.
type pcrProtectionProfileAddPCRValueInstr struct {
	alg   tpm2.HashAlgorithmId
	pcr   int
	value tpm2.Digest
}

func (i *pcrProtectionProfileAddPCRValueInstr) run(context *pcrProtectionProfileExecContext) {
	context.handler.addPCRValue(i.alg, i.pcr, i.value)
}

// pcrProtectionProfileAddPCRValueFromTPMInstr is inserted by
// PCRProtectionProfileBranch.AddPCRValueFromTPM and calls
// pcrProtectionProfileInstrHandler.addPCRValueFromTPM when executed.
type pcrProtectionProfileAddPCRValueFromTPMInstr struct {
	alg tpm2.HashAlgorithmId
	pcr int
}

func (i *pcrProtectionProfileAddPCRValueFromTPMInstr) run(context *pcrProtectionProfileExecContext) {
	context.handler.addPCRValueFromTPM(i.alg, i.pcr)
}

// pcrProtectionProfileExtendPCRInstr is inserted by
// PCRProtectionProfileBranch.ExtendPCR and calls
// pcrProtectionProfileInstrHandler.extendPCR when executed.
type pcrProtectionProfileExtendPCRInstr struct {
	alg   tpm2.HashAlgorithmId
	pcr   int
	value tpm2.Digest
}

func (i *pcrProtectionProfileExtendPCRInstr) run(context *pcrProtectionProfileExecContext) {
	context.handler.extendPCR(i.alg, i.pcr, i.value)
}

// pcrProtectionProfileBranchPointInstr is inserted by
// PCRProtectionProfileBranch.AddBranchPoint. When executed, it calls
// pcrProtectionProfileInstrHandler.beginBranchPoint, queues the associated
// sub-branches and selects the next branch to execute.
type pcrProtectionProfileBranchPointInstr struct {
	bp *PCRProtectionProfileBranchPoint
}

func (i *pcrProtectionProfileBranchPointInstr) run(context *pcrProtectionProfileExecContext) {
	context.handler.beginBranchPoint()
	context.queueSubBranches(i.bp.childBranches...)
	context.selectNextPendingSubBranch()
}

// pcrProtectionProfileEndBranchPointInstr is inserted in to the parent branch by
// PCRProtectionProfileBranchPoint.EndBranchPoint and calls
// pcrProtectionProfileInstrHandler.endBranchPoint when executed.
type pcrProtectionProfileEndBranchPointInstr struct{}

func (*pcrProtectionProfileEndBranchPointInstr) run(context *pcrProtectionProfileExecContext) {
	context.handler.endBranchPoint()
}

// pcrProtectionProfileEndBranchInstr is inserted implicitly to the end of a
// branch or explicitly by PCRProtectionProfileBranch.EndBranch. When executed,
// it calls pcrProtectionProfileInstrHandler.endBranch and selects the next
// branch to execute.
type pcrProtectionProfileEndBranchInstr struct{}

func (*pcrProtectionProfileEndBranchInstr) run(context *pcrProtectionProfileExecContext) {
	context.handler.endBranch()
	context.endCurrentBranch()
	context.selectNextPendingSubBranch()
}

// PCRProtectionProfileBranchPoint represents a point in a parent branch
// in which sub-branches can be inserted and populated, in order to create
// compound policies that correspond to multiple conditions.
type PCRProtectionProfileBranchPoint struct {
	profile       *PCRProtectionProfile         // the profile associated with this branch point
	parentBranch  *PCRProtectionProfileBranch   // the branch that this branch point was added to
	childBranches []*PCRProtectionProfileBranch // sub-branches added to this point

	done bool
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
	b := newPCRProtectionProfileBranch(p.profile, p)

	if p.done {
		p.profile.fail("cannot add a branch to a branch point that has already been terminated")
		return b
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

func newPCRProtectionProfileBranch(profile *PCRProtectionProfile, parent *PCRProtectionProfileBranchPoint) *PCRProtectionProfileBranch {
	return &PCRProtectionProfileBranch{
		profile:           profile,
		parentBranchPoint: parent,
		instrs:            pcrProtectionProfileInstrList{new(pcrProtectionProfileBeginBranchInstr)}}
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

	switch len(p.childBranches) {
	case 0:
		// Elide the empty branch point.
		b.instrs = b.instrs[:len(b.instrs)-1]
	case 1:
		// Elide the branch point that contains only a single sub-branch
		// and append the sub-branch to this branch.
		b.instrs = b.instrs[:len(b.instrs)-1]

		sb := p.childBranches[0]

		// Remove the BeginBranch instruction
		instrs := sb.instrs[1:]
		// Remove the EndBranch instruction
		instrs = instrs[:len(instrs)-1]
		b.instrs = append(b.instrs, instrs...)

	default:
		b.instrs = append(b.instrs, new(pcrProtectionProfileEndBranchPointInstr))
	}
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
	b.profile.addPCRToReadFromTPM(alg, pcr)
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
	b.instrs = append(b.instrs, new(pcrProtectionProfileEndBranchInstr))
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
//
// A PCRProtectionProfile can be serialized to and unserialized from the TPM
// wire format.
type PCRProtectionProfile struct {
	root              *PCRProtectionProfileBranch
	pcrsToReadFromTPM tpm2.PCRSelectionList
	err               error
}

// NewPCRProtectionProfile creates an empty PCR profile.
func NewPCRProtectionProfile() *PCRProtectionProfile {
	profile := new(PCRProtectionProfile)
	profile.root = newPCRProtectionProfileBranch(profile, nil)
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

func (p *PCRProtectionProfile) addPCRToReadFromTPM(alg tpm2.HashAlgorithmId, pcr int) {
	p.pcrsToReadFromTPM = p.pcrsToReadFromTPM.MustMerge(
		tpm2.PCRSelectionList{{Hash: alg, Select: []int{pcr}}})
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

		p.pcrsToReadFromTPM = p.pcrsToReadFromTPM.MustMerge(sub.pcrsToReadFromTPM)
		bp.childBranches = append(bp.childBranches, branch)
	}

	bp.EndBranchPoint()
	return p
}

// run executes this profile with the supplied handler.
func (p *PCRProtectionProfile) run(handler pcrProtectionProfileInstrHandler) {
	context := newPcrProtectionProfileExecContext(p, handler)

	for !context.done() {
		context.popNextInstr().run(context)
	}
}

type pcrProtectionProfileStringifier struct {
	w     io.Writer
	depth int
}

func (c *pcrProtectionProfileStringifier) beginBranch(index int) {
	c.depth++

	if c.depth == 0 {
		return
	}

	fmt.Fprintf(c.w, "\n%*sBranch %d {", c.depth*3, "", index)
}

func (c *pcrProtectionProfileStringifier) addPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	fmt.Fprintf(c.w, "\n%*s AddPCRValue(%v, %d, %x)", c.depth*3, "", alg, pcr, value)
}

func (c *pcrProtectionProfileStringifier) addPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) {
	fmt.Fprintf(c.w, "\n%*s AddPCRValueFromTPM(%v, %d)", c.depth*3, "", alg, pcr)
}

func (c *pcrProtectionProfileStringifier) extendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	fmt.Fprintf(c.w, "\n%*s ExtendPCR(%v, %d, %x)", c.depth*3, "", alg, pcr, value)
}

func (c *pcrProtectionProfileStringifier) beginBranchPoint() {
	fmt.Fprintf(c.w, "\n%*s BranchPoint(", c.depth*3, "")
}

func (c *pcrProtectionProfileStringifier) endBranchPoint() {
	fmt.Fprintf(c.w, "\n%*s )", c.depth*3, "")
}

func (c *pcrProtectionProfileStringifier) endBranch() {
	if c.depth > 0 {
		fmt.Fprintf(c.w, "\n%*s}", c.depth*3, "")
	}
	c.depth--
}

func (p *PCRProtectionProfile) String() string {
	s := new(bytes.Buffer)
	p.run(&pcrProtectionProfileStringifier{w: s, depth: -1})
	return s.String() + "\n"
}

var (
	savedPCRBits           = bits.Len16(uint16(maxPCR))
	savedDigestMask uint32 = (1 << (32 - savedPCRBits)) - 1
	savedPCRMask    uint16 = (1 << savedPCRBits) - 1
	maxSavedDigests int    = int(savedDigestMask)
)

// savedPCRProtectionProfilePCRAndDigest provides a way of storing a PCR
// index and digest index as a uint32 in a saved PCR profile, with the
// lower 11 bits used to store the PCR index and the upper 22 bits used
// to store a digest index, which references a digest in a list.
type savedPCRProtectionProfilePCRAndDigest uint32

func (i savedPCRProtectionProfilePCRAndDigest) PCR() uint16 {
	return uint16(i) & savedPCRMask
}

func (i savedPCRProtectionProfilePCRAndDigest) DigestIndex() uint32 {
	return (uint32(i) >> savedPCRBits) & savedDigestMask
}

func newSavedPCRProtectionProfilePCRAndDigest(pcr uint16, digestIndex uint32) savedPCRProtectionProfilePCRAndDigest {
	return savedPCRProtectionProfilePCRAndDigest(uint32(pcr&savedPCRMask) | ((digestIndex & savedDigestMask) << savedPCRBits))
}

type savedPCRProtectionProfilePCREventInstrData struct {
	Alg          tpm2.HashAlgorithmId
	PCRAndDigest savedPCRProtectionProfilePCRAndDigest
}

type savedPCRProtectionProfileAddPCRValueFromTPMInstrData struct {
	Alg tpm2.HashAlgorithmId
	PCR uint16
}

// savedPCRProtectionProfileInstrData represents the data associated with a
// single instruction in a saved PCR profile.
type savedPCRProtectionProfileInstrData struct {
	AddPCRValue        *savedPCRProtectionProfilePCREventInstrData
	AddPCRValueFromTPM *savedPCRProtectionProfileAddPCRValueFromTPMInstrData
	ExtendPCR          *savedPCRProtectionProfilePCREventInstrData
}

// Select implements the mu.Union interface.
func (d *savedPCRProtectionProfileInstrData) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(savedPCRProtectionProfileInstrType) {
	case beginBranch, beginBranchPoint, endBranchPoint, endBranch:
		return mu.NilUnionValue
	case addPCRValue:
		return &d.AddPCRValue
	case addPCRValueFromTPM:
		return &d.AddPCRValueFromTPM
	case extendPCR:
		return &d.ExtendPCR
	default:
		return nil
	}
}

type savedPCRProtectionProfileInstrType uint8

const (
	beginBranch savedPCRProtectionProfileInstrType = iota + 1
	addPCRValue
	addPCRValueFromTPM
	extendPCR
	beginBranchPoint
	endBranchPoint
	endBranch
)

// savedPCRProtectionProfileInstr represents a single instruction in a
// saved PCR profile.
type savedPCRProtectionProfileInstr struct {
	Type savedPCRProtectionProfileInstrType
	Data *savedPCRProtectionProfileInstrData
}

// savedPCRProtectionProfile represents a PCR profile in a form that can
// be serialized. It is constructed in a way that permits de-duplication of
// digests that appear multiple times in the profile in order to save space.
// It also has a fixed depth that is independent of the source profile depth.
type savedPCRProtectionProfile struct {
	Digests tpm2.DigestList                   // a de-duplicated list of all the digests in this profile
	Instrs  []*savedPCRProtectionProfileInstr // a list of instructions used to reconstruct this profile
}

type pcrProtectionProfileSerializer struct {
	digests   tpm2.DigestList
	digestMap map[[32]byte]uint32
	instrs    []*savedPCRProtectionProfileInstr
}

func newPcrProtectionProfileSerializer() *pcrProtectionProfileSerializer {
	return &pcrProtectionProfileSerializer{digestMap: make(map[[32]byte]uint32)}
}

func (c *pcrProtectionProfileSerializer) digestIndex(digest tpm2.Digest) uint32 {
	h := crypto.SHA256.New()
	h.Write(digest)

	var k [32]byte
	copy(k[:], h.Sum(nil))

	index, exists := c.digestMap[k]
	if !exists {
		// The length isn't guaranteed to fit into uint32, but this doesn't
		// matter - go-tpm2 won't serialize a list where the number of
		// elements exceeds math.MaxInt32 (so that the uint32 from the wire
		// always fits in an int) and we'll return an error from the call to
		// mu.MarshalToWriter. But if this profile has more than 2^^31 digests
		// then the creator of it has bigger problems.
		index = uint32(len(c.digests))
		c.digestMap[k] = index
		c.digests = append(c.digests, digest)
	}

	return index
}

func (c *pcrProtectionProfileSerializer) beginBranch(_ int) {
	c.instrs = append(c.instrs, &savedPCRProtectionProfileInstr{Type: beginBranch})
}

func (c *pcrProtectionProfileSerializer) addPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	c.instrs = append(c.instrs, &savedPCRProtectionProfileInstr{
		Type: addPCRValue,
		Data: &savedPCRProtectionProfileInstrData{
			AddPCRValue: &savedPCRProtectionProfilePCREventInstrData{
				Alg:          alg,
				PCRAndDigest: newSavedPCRProtectionProfilePCRAndDigest(uint16(pcr), c.digestIndex(value))}}})
}

func (c *pcrProtectionProfileSerializer) addPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) {
	c.instrs = append(c.instrs, &savedPCRProtectionProfileInstr{
		Type: addPCRValueFromTPM,
		Data: &savedPCRProtectionProfileInstrData{
			AddPCRValueFromTPM: &savedPCRProtectionProfileAddPCRValueFromTPMInstrData{
				Alg: alg,
				PCR: uint16(pcr), // checked against maxPCR
			}}})
}

func (c *pcrProtectionProfileSerializer) extendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	c.instrs = append(c.instrs, &savedPCRProtectionProfileInstr{
		Type: extendPCR,
		Data: &savedPCRProtectionProfileInstrData{
			ExtendPCR: &savedPCRProtectionProfilePCREventInstrData{
				Alg:          alg,
				PCRAndDigest: newSavedPCRProtectionProfilePCRAndDigest(uint16(pcr), c.digestIndex(value))}}})
}

func (c *pcrProtectionProfileSerializer) beginBranchPoint() {
	c.instrs = append(c.instrs, &savedPCRProtectionProfileInstr{Type: beginBranchPoint})
}

func (c *pcrProtectionProfileSerializer) endBranchPoint() {
	c.instrs = append(c.instrs, &savedPCRProtectionProfileInstr{Type: endBranchPoint})
}

func (c *pcrProtectionProfileSerializer) endBranch() {
	c.instrs = append(c.instrs, &savedPCRProtectionProfileInstr{Type: endBranch})
}

func (p PCRProtectionProfile) Marshal(w io.Writer) error {
	c := newPcrProtectionProfileSerializer()
	p.run(c)

	if len(c.digests) > maxSavedDigests {
		return errors.New("profile contains too many digests")
	}

	_, err := mu.MarshalToWriter(w, &savedPCRProtectionProfile{
		Digests: c.digests,
		Instrs:  c.instrs})
	return err
}

func (p *PCRProtectionProfile) Unmarshal(r io.Reader) error {
	var s *savedPCRProtectionProfile
	if _, err := mu.UnmarshalFromReader(r, &s); err != nil {
		return err
	}

	p.root = newPCRProtectionProfileBranch(p, nil)

	var b *PCRProtectionProfileBranch
	var bp *PCRProtectionProfileBranchPoint

	instrs := s.Instrs
	for i := 0; len(instrs) > 0; i++ {
		instr := instrs[0]
		instrs = instrs[1:]

		var digestIndex uint32
		requireDigest := true
		switch instr.Type {
		case addPCRValue:
			digestIndex = instr.Data.AddPCRValue.PCRAndDigest.DigestIndex()
		case extendPCR:
			digestIndex = instr.Data.ExtendPCR.PCRAndDigest.DigestIndex()
		default:
			requireDigest = false
		}

		var digest tpm2.Digest
		if requireDigest {
			if int(digestIndex) >= len(s.Digests) {
				return fmt.Errorf("digest index (%d) out of range for instruction %d", digestIndex, i)
			}
			digest = s.Digests[int(digestIndex)]
		}

		switch instr.Type {
		case beginBranch:
			switch {
			case bp == nil && b == nil:
				b = p.root
			case bp == nil:
				return fmt.Errorf("unexpected BeginBranch at instruction %d", i)
			default:
				b = bp.AddBranch()
				bp = nil
			}
		case addPCRValue:
			if b == nil {
				return fmt.Errorf("unexpected AddPCRValue at instruction %d", i)
			}
			b.AddPCRValue(instr.Data.AddPCRValue.Alg, int(instr.Data.AddPCRValue.PCRAndDigest.PCR()), digest)
		case addPCRValueFromTPM:
			if b == nil {
				return fmt.Errorf("unexpected AddPCRValueFromTPM at instruction %d", i)
			}
			b.AddPCRValueFromTPM(instr.Data.AddPCRValueFromTPM.Alg, int(instr.Data.AddPCRValueFromTPM.PCR))
		case extendPCR:
			if b == nil {
				return fmt.Errorf("unexpected ExtendPCR at instruction %d", i)
			}
			b.ExtendPCR(instr.Data.ExtendPCR.Alg, int(instr.Data.ExtendPCR.PCRAndDigest.PCR()), digest)
		case beginBranchPoint:
			if b == nil {
				return fmt.Errorf("unexpected BeginBranchPoint at instruction %d", i)
			}
			bp = b.AddBranchPoint()
			b = nil
		case endBranchPoint:
			if bp == nil {
				return fmt.Errorf("unexpected EndBranchPoint at instruction %d", i)
			}
			b = bp.EndBranchPoint()
			bp = nil
		case endBranch:
			switch {
			case b == p.root && len(instrs) != 0:
				return fmt.Errorf("unexpected EndBranch for root branch at instruction %d", i)
			case b == p.root:
				// done:
				return nil
			case b == nil:
				return fmt.Errorf("unexpected EndBranch at instruction %d", i)
			default:
				bp = b.EndBranch()
				b = nil
			}
		default:
			// this will be caught by go-tpm2/mu as an invalid selector value
			return fmt.Errorf("invalid instruction type %d at instruction %d", instr.Type, i)
		}
	}

	return errors.New("missing EndBranch for root branch")
}

type pcrProtectionProfileComputerBranchContext struct {
	values          pcrValuesList
	subBranchValues pcrValuesList
}

type pcrProtectionProfileComputer struct {
	tpmValues   tpm2.PCRValues
	branchStack []*pcrProtectionProfileComputerBranchContext
}

func (c *pcrProtectionProfileComputer) currentBranch() *pcrProtectionProfileComputerBranchContext {
	return c.branchStack[0]
}

func (c *pcrProtectionProfileComputer) beginBranch(_ int) {
	// A sub-branch inherits a copy of the PCR values from the parent branch
	c.branchStack = append([]*pcrProtectionProfileComputerBranchContext{
		&pcrProtectionProfileComputerBranchContext{values: c.currentBranch().values.copy()},
	}, c.branchStack...)
}

func (c *pcrProtectionProfileComputer) addPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	c.currentBranch().values.setValue(alg, pcr, value)
}

func (c *pcrProtectionProfileComputer) addPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) {
	c.currentBranch().values.setValue(alg, pcr, c.tpmValues[alg][pcr])
}

func (c *pcrProtectionProfileComputer) extendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	c.currentBranch().values.extendValue(alg, pcr, value)
}

func (*pcrProtectionProfileComputer) beginBranchPoint() {}

func (c *pcrProtectionProfileComputer) endBranchPoint() {
	// When a branch point is completed, the branch inherits the PCR values computed
	// by the sub-branches.
	if c.currentBranch().subBranchValues == nil {
		// There were no sub branches.
		return
	}

	c.currentBranch().values = c.currentBranch().subBranchValues
	c.currentBranch().subBranchValues = nil
}

func (c *pcrProtectionProfileComputer) endBranch() {
	values := c.currentBranch().values
	c.branchStack = c.branchStack[1:]
	c.currentBranch().subBranchValues = append(c.currentBranch().subBranchValues, values...)
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
		return nil, fmt.Errorf("cannot compute PCR values because an error occurred when constructing the profile: %v", p.err)
	}

	tpmValues := make(tpm2.PCRValues)
	if !p.pcrsToReadFromTPM.IsEmpty() {
		if tpm == nil {
			return nil, errors.New("cannot read current PCR values from TPM: no context")
		}
		var err error
		_, tpmValues, err = tpm.PCRRead(p.pcrsToReadFromTPM)
		if err != nil {
			return nil, fmt.Errorf("cannot read current PCR values from TPM: %w", err)
		}
	}
	context := &pcrProtectionProfileComputer{
		tpmValues: tpmValues,
		branchStack: []*pcrProtectionProfileComputerBranchContext{
			&pcrProtectionProfileComputerBranchContext{values: pcrValuesList{make(tpm2.PCRValues)}}}}
	p.run(context)
	return []tpm2.PCRValues(context.currentBranch().subBranchValues), nil
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
	pcrs, err := values[0].SelectionList()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot compute selection list: %w", err)
	}

	// Compute the PCR digests for all branches, making sure that they all contain values for the same sets of PCRs.
	var pcrDigests tpm2.DigestList
	for _, v := range values {
		p, digest, err := util.ComputePCRDigestFromAllValues(alg, v)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot compute PCR digest from values: %w", err)
		}
		if !mu.DeepEqual(p, pcrs) {
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
