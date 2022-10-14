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

package tpm2test

import (
	"bytes"
	"fmt"

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

// MakePCREventDigest creates a digest for a single PCR event by
// hashing the supplied string with the specified algorithm.
func MakePCREventDigest(alg tpm2.HashAlgorithmId, event string) tpm2.Digest {
	h := alg.NewHash()
	h.Write([]byte(event))
	return h.Sum(nil)
}

// MakePCRValueFromEvents creates a PCR value by hashing the supplied
// events with the specified algorithm and then computing the PCR value
// that would result by extending these events.
func MakePCRValueFromEvents(alg tpm2.HashAlgorithmId, events ...string) tpm2.Digest {
	p := make(tpm2.Digest, alg.Size())
	for _, e := range events {
		h := alg.NewHash()
		h.Write(p)
		h.Write(MakePCREventDigest(alg, e))
		p = h.Sum(nil)
	}
	return p
}

// FormatPCRValuesFromPCRProtectionProfile returns a formatted string of PCR values
// contained within the supplied PCR profile.
func FormatPCRValuesFromPCRProtectionProfile(profile *secboot_tpm2.PCRProtectionProfile, tpm *tpm2.TPMContext) string {
	values, err := profile.ComputePCRValues(tpm)
	if err != nil {
		return ""
	}
	var s bytes.Buffer
	fmt.Fprintf(&s, "\n")
	for i, v := range values {
		fmt.Fprintf(&s, "Value %d:\n", i)
		for alg := range v {
			for pcr := range v[alg] {
				fmt.Fprintf(&s, " PCR%d,%v: %x\n", pcr, alg, v[alg][pcr])
			}
		}
	}
	return s.String()
}

func NewPCRProfileFromCurrentValues(alg tpm2.HashAlgorithmId, pcrs []int) *secboot_tpm2.PCRProtectionProfile {
	out := secboot_tpm2.NewPCRProtectionProfile()
	root := out.RootBranch()
	for _, pcr := range pcrs {
		root.AddPCRValueFromTPM(alg, pcr)
	}
	return out
}

func NewResolvedPCRProfileFromCurrentValues(c *C, tpm *tpm2.TPMContext, alg tpm2.HashAlgorithmId, pcrs []int) *secboot_tpm2.PCRProtectionProfile {
	_, values, err := tpm.PCRRead(tpm2.PCRSelectionList{{Hash: alg, Select: pcrs}})
	c.Assert(err, IsNil)

	out := secboot_tpm2.NewPCRProtectionProfile()
	root := out.RootBranch()
	for _, pcr := range pcrs {
		root.AddPCRValue(alg, pcr, values[alg][pcr])
	}
	return out
}
