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
	"errors"
	"fmt"
	"sort"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"
)

// computePCRSelectionListFromValues builds a tpm2.PCRSelectionList from the provided map of PCR values.
func computePCRSelectionListFromValues(v tpm2.PCRValues) (out tpm2.PCRSelectionList) {
	for alg := range v {
		s := tpm2.PCRSelection{Hash: alg}
		for pcr := range v[alg] {
			s.Select = append(s.Select, pcr)
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return
}

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

func (i *pcrProtectionProfileAddPCRValueInstr) apply(_ *tpm2.TPMContext, values pcrValuesList) (pcrValuesList, error) {
	values.setValue(i.alg, i.pcr, i.value)
	return values, nil
}

type pcrProtectionProfileAddPCRValueFromTPMInstr struct {
	alg tpm2.HashAlgorithmId
	pcr int
}

func (i *pcrProtectionProfileAddPCRValueFromTPMInstr) apply(tpm *tpm2.TPMContext, values pcrValuesList) (pcrValuesList, error) {
	if tpm == nil {
		return nil, fmt.Errorf("cannot read current value of PCR %d from bank %v: no TPM context", i.pcr, i.alg)
	}
	_, v, err := tpm.PCRRead(tpm2.PCRSelectionList{{Hash: i.alg, Select: []int{i.pcr}}})
	if err != nil {
		return nil, xerrors.Errorf("cannot read current value of PCR %d from bank %v: %w", i.pcr, i.alg, err)
	}
	values.setValue(i.alg, i.pcr, v[i.alg][i.pcr])
	return values, nil
}

type pcrProtectionProfileExtendPCRInstr struct {
	alg   tpm2.HashAlgorithmId
	pcr   int
	value tpm2.Digest
}

func (i *pcrProtectionProfileExtendPCRInstr) apply(_ *tpm2.TPMContext, values pcrValuesList) (pcrValuesList, error) {
	values.extendValue(i.alg, i.pcr, i.value)
	return values, nil
}

type pcrProtectionProfileAddProfileORInstr struct {
	profiles []*PCRProtectionProfile
}

func (i *pcrProtectionProfileAddProfileORInstr) apply(tpm *tpm2.TPMContext, values pcrValuesList) (pcrValuesList, error) {
	var out []tpm2.PCRValues
	for _, p := range i.profiles {
		v, err := p.computePCRValues(tpm, values.copy())
		if err != nil {
			// TODO: More context
			return nil, err
		}
		out = append(out, v...)
	}
	return out, nil
}

// pcrProtectionProfileInstr is a building block of PCRProtectionProfile.
type pcrProtectionProfileInstr interface {
	apply(*tpm2.TPMContext, pcrValuesList) (pcrValuesList, error)
}

// PCRProtectionProfile defines the PCR profile used to protect a key sealed with SealKeyToTPM. It contains a sequence of instructions
// for computing combinations of PCR values that a key will be protected against. The profile is built using the methods of this type.
type PCRProtectionProfile struct {
	instrs []pcrProtectionProfileInstr
}

func NewPCRProtectionProfile() *PCRProtectionProfile {
	return &PCRProtectionProfile{}
}

// AddPCRValue adds the supplied value to this profile for the specified PCR. This action replaces any value set previously in this
// profile. The function returns the same PCRProtectionProfile so that calls may be chained.
func (p *PCRProtectionProfile) AddPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) *PCRProtectionProfile {
	if len(value) != alg.Size() {
		panic("invalid digest length")
	}
	p.instrs = append(p.instrs, &pcrProtectionProfileAddPCRValueInstr{alg: alg, pcr: pcr, value: value})
	return p
}

// AddPCRValueFromTPM adds the current value of the specified PCR to this profile. This action replaces any value set previously in
// this profile. The current value is read back from the TPM when the PCR values generated by this profile are computed. The function
// returns the same PCRProtectionProfile so that calls may be chained.
func (p *PCRProtectionProfile) AddPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) *PCRProtectionProfile {
	p.instrs = append(p.instrs, &pcrProtectionProfileAddPCRValueFromTPMInstr{alg: alg, pcr: pcr})
	return p
}

// ExtendPCR extends the value of the specified PCR in this profile with the supplied value. If this profile doesn't yet have a
// value for the specified PCR, an initial value of all zeroes will be added first. The function returns the same PCRProtectionProfile
// so that calls may be chained.
func (p *PCRProtectionProfile) ExtendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) *PCRProtectionProfile {
	if len(value) != alg.Size() {
		panic("invalid digest length")
	}
	p.instrs = append(p.instrs, &pcrProtectionProfileExtendPCRInstr{alg: alg, pcr: pcr, value: value})
	return p
}

// AddProfileOR adds one or more sub-profiles that can be used to define PCR policies for multiple conditions. Note that each
// branch must explicitly define values for the same set of PCRs. It is not possible to generate policies where each branch
// defines values for a different set of PCRs. When computing the PCR values for this profile, the sub-profiles added by this command
// will inherit the PCR values computed by this profile. The function returns the same PCRProtectionProfile so that calls may be
// chained.
func (p *PCRProtectionProfile) AddProfileOR(profiles ...*PCRProtectionProfile) *PCRProtectionProfile {
	p.instrs = append(p.instrs, &pcrProtectionProfileAddProfileORInstr{profiles: profiles})
	return p
}

// computePCRValues computes a list of different PCR value combinations from this PCRProtectionProfile.
func (p *PCRProtectionProfile) computePCRValues(tpm *tpm2.TPMContext, values pcrValuesList) (pcrValuesList, error) {
	if len(values) == 0 {
		values = append(values, make(tpm2.PCRValues))
	}

	for _, instr := range p.instrs {
		var err error
		values, err = instr.apply(tpm, values)
		if err != nil {
			return nil, err
		}
	}

	return values, nil
}

func (p *PCRProtectionProfile) computePCRDigests(tpm *tpm2.TPMContext, alg tpm2.HashAlgorithmId) (tpm2.PCRSelectionList, tpm2.DigestList, error) {
	// Compute the sets of PCR values for all branches
	values, err := p.computePCRValues(tpm, nil)
	if err != nil {
		return nil, nil, err
	}

	// Compute the PCR selections and PCR digest for the first branch.
	pcrs, firstDigest, err := tpm2.ComputePCRDigestSimple(alg, values[0])
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute PCR digest for first branch: %w", err)
	}

	pcrDigests := tpm2.DigestList{firstDigest}

	// Compute the PCR digests for the remaining branches, making sure that they contain values for the same sets of PCRs.
	for _, v := range values[1:] {
		p, digest, _ := tpm2.ComputePCRDigestSimple(alg, v)
		if !p.Equal(pcrs) {
			return nil, nil, errors.New("not all branches contain values for the same sets of PCRs")
		}
		pcrDigests = append(pcrDigests, digest)
	}

	var filteredPcrDigests tpm2.DigestList
	for _, d := range pcrDigests {
		found := false
		for _, f := range filteredPcrDigests {
			if bytes.Equal(d, f) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		filteredPcrDigests = append(filteredPcrDigests, d)
	}

	return pcrs, filteredPcrDigests, nil
}
