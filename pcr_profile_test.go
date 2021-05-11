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
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
)

func TestPCRProtectionProfile(t *testing.T) {
	for _, data := range []struct {
		desc    string
		alg     tpm2.HashAlgorithmId
		profile *PCRProtectionProfile
		pcrs    tpm2.PCRSelectionList
		values  []tpm2.PCRValues
	}{
		{
			// Verify that AddPCRValues works as expected
			desc: "AddValues/1",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
		},
		{
			// Verify that AddPCRValues overwrites previous values
			desc: "AddValues/2",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
		},
		{
			// Verify that (A1 || A2) && (B1 || B2) produces 4 outcomes
			desc: "OR/1",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddProfileOR(
						NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")),
						NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"))).
					AddProfileOR(
						NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
						NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
					},
				},
			},
		},
		{
			// Verify that (A1 && B1) || (A2 && B2) produces 2 outcomes
			desc: "OR/2",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().AddProfileOR(
					NewPCRProtectionProfile().
						AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
						AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
					NewPCRProtectionProfile().
						AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).
						AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
					},
				},
			},
		},
		{
			// Verify that ExtendPCR without an initial value works as expected
			desc: "Extend",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event2")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event3")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event4"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "event1", "event3"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "event2", "event4"),
					},
				},
			},
		},
		{
			// Verify that ExtendPCR after AddPCRValue works as expected
			desc: "AddAndExtend",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event2"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event2"),
					},
				},
			},
		},
		{
			// Verify that ExtendPCR inside ProfileOR with initial PCR values works as expected
			desc: "OR/3",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
					AddProfileOR(
						NewPCRProtectionProfile().
							ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
							ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event2")),
						NewPCRProtectionProfile().
							ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event3")).
							ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event4")))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event2"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event3"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event4"),
					},
				},
			},
		},
		{
			// Verify that AddPCRValue inside ProfileOR with initial PCR values works as expected
			desc: "OR/4",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
					AddProfileOR(
						NewPCRProtectionProfile().
							ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
							AddPCRValue(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")),
						NewPCRProtectionProfile().
							AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
							ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event4")))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event4"),
					},
				},
			},
		},
		{
			// Verify that other PCR algorithms work
			desc: "SHA1PCRs",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA1, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA1, "bar"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA1: {
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA1, "bar"),
					},
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					},
				},
			},
		},
		{
			// Verify that other PCR digest algorithms work
			desc: "SHA1",
			alg:  tpm2.HashAlgorithmSHA1,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
		},
		{
			// Verify that (A1 && B1) || (A1 && B1) is de-duplicated
			desc: "DeDuplicate",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().AddProfileOR(
					NewPCRProtectionProfile().
						AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
						AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
					NewPCRProtectionProfile().
						AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
						AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
		},
		{
			desc: "EmptyProfileOR",
			alg:  tpm2.HashAlgorithmSHA256,
			profile: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddProfileOR().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			}(),
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			expectedPcrs := data.values[0].SelectionList()
			var expectedDigests tpm2.DigestList
			for _, v := range data.values {
				d, _ := tpm2.ComputePCRDigest(data.alg, expectedPcrs, v)
				expectedDigests = append(expectedDigests, d)
			}

			pcrs, pcrDigests, err := data.profile.ComputePCRDigests(nil, data.alg)
			if err != nil {
				t.Fatalf("ComputePCRDigests failed: %v", err)
			}
			if !pcrs.Equal(expectedPcrs) {
				t.Errorf("Unexpected PCRSelectionList")
			}
			if !reflect.DeepEqual(pcrDigests, expectedDigests) {
				t.Errorf("ComputePCRDigests returned unexpected digests")
				t.Logf("Profile:\n%s", data.profile)
				t.Logf("Values:\n%s", testutil.FormatPCRValuesFromPCRProtectionProfile(data.profile, nil))
			}
		})
	}
}

func TestPCRProtectionProfileString(t *testing.T) {
	profile := NewPCRProtectionProfile().
		AddPCRValue(tpm2.HashAlgorithmSHA256, 7, make([]byte, tpm2.HashAlgorithmSHA256.Size())).
		AddPCRValue(tpm2.HashAlgorithmSHA256, 8, make([]byte, tpm2.HashAlgorithmSHA256.Size())).
		AddProfileOR(
			NewPCRProtectionProfile().
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo1")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar1")),
			NewPCRProtectionProfile().
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar1")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo1"))).
		ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "end"))
	expectedTpl := `
 AddPCRValue(TPM_ALG_SHA256, 7, %[1]x)
 AddPCRValue(TPM_ALG_SHA256, 8, %[1]x)
 AddProfileOR(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 7, %[2]x)
    ExtendPCR(TPM_ALG_SHA256, 8, %[3]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 7, %[3]x)
    ExtendPCR(TPM_ALG_SHA256, 8, %[2]x)
   }
 )
 ExtendPCR(TPM_ALG_SHA256, 7, %[4]x)
`

	expected := fmt.Sprintf(expectedTpl,
		make([]byte, tpm2.HashAlgorithmSHA256.Size()),
		testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo1"),
		testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar1"),
		testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "end"))
	if expected != profile.String() {
		t.Errorf("Unexpected string:\ngot:%s\nexpected:%s", profile, expected)
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

	p := NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7)
	pcrs, digests, err := p.ComputePCRDigests(tpm.TPMContext, tpm2.HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("ComputePCRDigests failed: %v", err)
	}

	if !pcrs.Equal(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}) {
		t.Errorf("ComputePCRDigests returned the wrong selection")
	}
	if len(digests) != 1 {
		t.Fatalf("ComputePCRDigests returned the wrong number of digests")
	}
	expectedDigest, _ := tpm2.ComputePCRDigest(tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}, tpmValues)
	if !bytes.Equal(digests[0], expectedDigest) {
		t.Errorf("ComputePCRDigests returned unexpected values")
	}
}
