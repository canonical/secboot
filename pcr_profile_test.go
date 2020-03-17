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

package secboot_test

import (
	"reflect"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	. "github.com/snapcore/secboot"
)

func TestPCRProtectionProfile(t *testing.T) {
	for _, data := range []struct {
		desc    string
		profile PCRProtectionProfile
		values  []tpm2.PCRValues
	}{
		{
			// Verify that AddPCRValues works as expected
			desc: "AddValues/1",
			profile: func() PCRProtectionProfile {
				return PCRProtectionProfile{}.
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 8, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
		},
		{
			// Verify that AddPCRValues overwrites previous values
			desc: "AddValues/2",
			profile: func() PCRProtectionProfile {
				return PCRProtectionProfile{}.
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
		},
		{
			// Verify that (A1 || A2) && (B1 || B2) produces 4 outcomes
			desc: "OR/1",
			profile: func() PCRProtectionProfile {
				return PCRProtectionProfile{}.
					AddProfileOR(
						PCRProtectionProfile{}.AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")),
						PCRProtectionProfile{}.AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo2"))).
					AddProfileOR(
						PCRProtectionProfile{}.AddPCRValue(tpm2.HashAlgorithmSHA256, 8, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
						PCRProtectionProfile{}.AddPCRValue(tpm2.HashAlgorithmSHA256, 8, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar2")))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
						8: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
						8: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
					},
				},
			},
		},
		{
			// Verify that (A1 && B1) || (A2 && B2) produces 2 outcomes
			desc: "OR/2",
			profile: func() PCRProtectionProfile {
				return PCRProtectionProfile{}.AddProfileOR(
					PCRProtectionProfile{}.
						AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
						AddPCRValue(tpm2.HashAlgorithmSHA256, 8, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
					PCRProtectionProfile{}.
						AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).
						AddPCRValue(tpm2.HashAlgorithmSHA256, 8, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar2")))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
						8: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
					},
				},
			},
		},
		{
			// Verify that ExtendPCR without an initial value works as expected
			desc: "Extend",
			profile: func() PCRProtectionProfile {
				return PCRProtectionProfile{}.
					ExtendPCR(tpm2.HashAlgorithmSHA256, 7, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 12, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event2")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 7, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event3")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 12, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event4"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "event1", "event3"),
						12: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "event2", "event4"),
					},
				},
			},
		},
		{
			// Verify that ExtendPCR after AddPCRValue works as expected
			desc: "AddAndExtend",
			profile: func() PCRProtectionProfile {
				return PCRProtectionProfile{}.
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 12, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 7, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 12, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event2"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1"),
						12: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event2"),
					},
				},
			},
		},
		{
			// Verify that ExtendPCR inside ProfileOR with initial PCR values works as expected
			desc: "OR/3",
			profile: func() PCRProtectionProfile {
				return PCRProtectionProfile{}.
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 12, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
					AddProfileOR(
						PCRProtectionProfile{}.
							ExtendPCR(tpm2.HashAlgorithmSHA256, 7, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
							ExtendPCR(tpm2.HashAlgorithmSHA256, 12, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event2")),
						PCRProtectionProfile{}.
							ExtendPCR(tpm2.HashAlgorithmSHA256, 7, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event3")).
							ExtendPCR(tpm2.HashAlgorithmSHA256, 12, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event4")))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1"),
						12: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event2"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7:  makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event3"),
						12: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event4"),
					},
				},
			},
		},
		{
			// Verify that AddPCRValue inside ProfileOR with initial PCR values works as expected
			desc: "OR/4",
			profile: func() PCRProtectionProfile {
				return PCRProtectionProfile{}.
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 12, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
					AddProfileOR(
						PCRProtectionProfile{}.
							ExtendPCR(tpm2.HashAlgorithmSHA256, 7, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
							AddPCRValue(tpm2.HashAlgorithmSHA256, 12, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")),
						PCRProtectionProfile{}.
							AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
							ExtendPCR(tpm2.HashAlgorithmSHA256, 12, makePCREventDigest(tpm2.HashAlgorithmSHA256, "event4")))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1"),
						12: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7:  makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
						12: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event4"),
					},
				},
			},
		},
		{
			// Verify that other PCR digest algorithms work
			desc: "SHA1",
			profile: func() PCRProtectionProfile {
				return PCRProtectionProfile{}.
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA1, 8, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA1, "bar"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA1: {
						8: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA1, "bar"),
					},
					tpm2.HashAlgorithmSHA256: {
						7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					},
				},
			},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			values, err := data.profile.ComputePCRValues(nil)
			if err != nil {
				t.Fatalf("ComputePCRValues failed: %v", err)
			}
			if !reflect.DeepEqual(values, data.values) {
				t.Errorf("ComputePCRValues returned unexpected values")
				for i, v := range values {
					t.Logf("Value %d:", i)
					for alg := range v {
						for pcr := range v[alg] {
							t.Logf(" PCR%d,%v: %x", pcr, alg, v[alg][pcr])
						}
					}
				}
			}
		})
	}
}

func TestPCRProtectionProfileAddValueFromTPM(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if _, err := tpm.PCREvent(tpm.PCRHandleContext(7), []byte("foo"), nil); err != nil {
		t.Fatalf("PCREvent failed: %v", err)
	}
	_, tpmValues, err := tpm.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
	if err != nil {
		t.Fatalf("PCRRead failed: %v", err)
	}

	p := PCRProtectionProfile{}.AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7)
	values, err := p.ComputePCRValues(tpm.TPMContext)
	if err != nil {
		t.Fatalf("ComputePCRValues failed: %v", err)
	}
	if len(values) != 1 {
		t.Fatalf("ComputePCRValues returned the wrong number of values")
	}
	if !reflect.DeepEqual(tpmValues, values[0]) {
		t.Errorf("ComputePCRValues returned unexpected values")
	}
}
