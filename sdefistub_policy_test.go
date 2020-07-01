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

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
)

func TestAddSystemdEFIStubProfile(t *testing.T) {
	for _, data := range []struct {
		desc    string
		initial *PCRProtectionProfile
		params  SystemdEFIStubProfileParams
		values  []tpm2.PCRValues
	}{
		{
			desc: "UC20",
			params: SystemdEFIStubProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				PCRIndex:     12,
				KernelCmdlines: []string{
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover",
				},
			},
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						12: decodeHexStringT(t, "fc433eaf039c6261f496a2a5bf2addfd8ff1104b0fc98af3fe951517e3bde824"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						12: decodeHexStringT(t, "b3a29076eeeae197ae721c254da40480b76673038045305cfa78ec87421c4eea"),
					},
				},
			},
		},
		{
			desc: "SHA1",
			params: SystemdEFIStubProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA1,
				PCRIndex:     12,
				KernelCmdlines: []string{
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
					"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover",
				},
			},
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA1: {
						12: decodeHexStringT(t, "eb6312b7db70fe16206c162326e36b2fcda74b68"),
					},
				},
				{
					tpm2.HashAlgorithmSHA1: {
						12: decodeHexStringT(t, "bd612bea9efa582fcbfae97973c89b163756fe0b"),
					},
				},
			},
		},
		{
			desc: "Classic",
			params: SystemdEFIStubProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				PCRIndex:     8,
				KernelCmdlines: []string{
					"root=/dev/mapper/vgubuntu-root ro quiet splash vt.handoff=7",
				},
			},
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						8: decodeHexStringT(t, "74fe9080b798f9220c18d0fcdd0ccb82d50ce2a317bc6cdaa2d8715d02d0efbe"),
					},
				},
			},
		},
		{
			desc: "WithInitialProfile",
			initial: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 8, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			}(),
			params: SystemdEFIStubProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				PCRIndex:     8,
				KernelCmdlines: []string{
					"root=/dev/mapper/vgubuntu-root ro quiet splash vt.handoff=7",
				},
			},
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: decodeHexStringT(t, "3d39c0db757b47b484006003724d990403d533044ed06e8798ab374bd73f32dc"),
					},
				},
			},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			profile := data.initial
			if profile == nil {
				profile = NewPCRProtectionProfile()
			}
			expectedPcrs, _, _ := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
			expectedPcrs = expectedPcrs.Merge(tpm2.PCRSelectionList{{Hash: data.params.PCRAlgorithm, Select: []int{data.params.PCRIndex}}})
			var expectedDigests tpm2.DigestList
			for _, v := range data.values {
				d, _ := tpm2.ComputePCRDigest(tpm2.HashAlgorithmSHA256, expectedPcrs, v)
				expectedDigests = append(expectedDigests, d)
			}

			if err := AddSystemdEFIStubProfile(profile, &data.params); err != nil {
				t.Fatalf("AddSystemdEFIStubProfile failed: %v", err)
			}
			pcrs, digests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("ComputePCRDigests failed: %v", err)
			}
			if !pcrs.Equal(expectedPcrs) {
				t.Errorf("ComputePCRDigests returned the wrong PCR selection")
			}
			if !reflect.DeepEqual(digests, expectedDigests) {
				t.Errorf("ComputePCRDigests returned unexpected values")
				t.Logf("Profile:\n%s", profile)
				t.Logf("Values:\n%s", profile.DumpValues(nil))
			}
		})
	}
}
