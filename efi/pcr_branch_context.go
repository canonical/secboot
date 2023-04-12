// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package efi

import (
	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"

	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

// pcrBranchContext contains the context associated with a branch of a EFI PCR profile
// generation
type pcrBranchContext interface {
	pcrProfileContext
	Params() *loadParams       // access the externally supplied parameters for this branch
	Vars() varReadWriter       // access the variable state for this branch
	FwContext() *fwContext     // access the platform firmware state for this branch
	ShimContext() *shimContext // access the shim state for this branch

	ResetPCR(pcr int)                                                 // reset the specified PCR for this branch
	ExtendPCR(pcr int, digest tpm2.Digest)                            // extend the specified PCR for this branch
	MeasureVariable(pcr int, guid efi.GUID, name string, data []byte) // measure the specified variable for this branch
}

type pcrBranchContextImpl struct {
	pcrProfileContext
	branch *secboot_tpm2.PCRProtectionProfileBranch
	params loadParams
	vars   varBranch
	fc     fwContext
	sc     shimContext
}

// newPcrBranchContextImpl creates a new pcrBranchContextImpl from the supplied arguments.
// Note that this performs a copy of the varBranch, fwContext and shimContext
// arguments which is important so that they can be mutated without affecting the
// state of ancestor branch contexts.
func newPcrBranchContextImpl(pc pcrProfileContext, branch *secboot_tpm2.PCRProtectionProfileBranch, params *loadParams, vars *varBranch, fc *fwContext, sc *shimContext) *pcrBranchContextImpl {
	return &pcrBranchContextImpl{
		pcrProfileContext: pc,
		branch:            branch,
		params:            *params,
		vars:              *vars,
		fc:                *fc,
		sc:                *sc}
}

func (c *pcrBranchContextImpl) Params() *loadParams {
	return &c.params
}

func (c *pcrBranchContextImpl) Vars() varReadWriter {
	return &c.vars
}

func (c *pcrBranchContextImpl) FwContext() *fwContext {
	return &c.fc
}

func (c *pcrBranchContextImpl) ShimContext() *shimContext {
	return &c.sc
}

func (c *pcrBranchContextImpl) ResetPCR(pcr int) {
	c.branch.AddPCRValue(c.PCRAlg(), pcr, make(tpm2.Digest, c.PCRAlg().Size()))
}

func (c *pcrBranchContextImpl) ExtendPCR(pcr int, digest tpm2.Digest) {
	c.branch.ExtendPCR(c.PCRAlg(), pcr, digest)
}

func (c *pcrBranchContextImpl) MeasureVariable(pcr int, guid efi.GUID, name string, data []byte) {
	c.branch.ExtendPCR(
		c.PCRAlg(),
		pcr,
		tcglog.ComputeEFIVariableDataDigest(c.PCRAlg().GetHash(), name, guid, data))
}
