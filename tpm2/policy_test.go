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

package tpm2_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sort"
	"testing"
	"unsafe"

	"github.com/canonical/go-tpm2"

	"github.com/snapcore/secboot/internal/testutil"
	. "github.com/snapcore/secboot/tpm2"
)

func TestPcrPolicyCounterHandleSet(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreateTPMPublicAreaForECDSAKey(&key.PublicKey)

	policyCounterPub, initialCount, err := CreatePcrPolicyCounter(tpm.TPMContext, 0x0181ff00, keyPublic, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreatePcrPolicyCounter failed: %v", err)
	}
	defer func() {
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(policyCounterPub)
		if err != nil {
			t.Errorf("CreateNVIndexResourceContextFromPublic failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}()

	h, err := NewPcrPolicyCounterHandleV1(policyCounterPub, keyPublic)
	if err != nil {
		t.Fatalf("NewPcrPolicyCounterHandleV1 failed: %v", err)
	}

	if err := h.Set(tpm.TPMContext, initialCount+1, key, tpm.HmacSession()); err != nil {
		t.Errorf("Set failed: %v", err)
	}

	count, err := h.Get(tpm.TPMContext, tpm.HmacSession())
	if err != nil {
		t.Errorf("Get failed: %v", err)
	}
	if count != initialCount+1 {
		t.Errorf("Get returned an unexpected count (got %d, expected %d)", count, initialCount+1)
	}
}

func TestCreatePcrPolicyCounterHandle(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	testPublic := tpm2.NVPublic{
		Index:   0x0181fe00,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead),
		Size:    8}
	testIndex, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &testPublic, nil)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, testIndex, tpm.OwnerHandleContext())
	if err := tpm.NVIncrement(testIndex, testIndex, nil); err != nil {
		t.Fatalf("NVIncrement failed: %v", err)
	}
	testCount, err := tpm.NVReadCounter(testIndex, testIndex, nil)
	if err != nil {
		t.Fatalf("NVReadCounter failed: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreateTPMPublicAreaForECDSAKey(&key.PublicKey)

	policyCounterPub, count, err := CreatePcrPolicyCounter(tpm.TPMContext, 0x0181ff00, keyPublic, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreatePcrPolicyCounter failed: %v", err)
	}
	defer func() {
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(policyCounterPub)
		if err != nil {
			t.Errorf("CreateNVIndexResourceContextFromPublic failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}()

	if count != testCount {
		t.Errorf("CreatePcrPolicyCounter returned an unexpected count (got %d, expected %d)", count, testCount)
	}
}

func TestComputeStaticPolicy(t *testing.T) {
	block, _ := pem.Decode([]byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIN0CY2/bCbM8ZRSVp5v/KAQKF110RFcA6TucTfUluWwcoAoGCCqGSM49
AwEHoUQDQgAEkxoOhf6oe3ZE91Kl97qMH/WndK1B0gD7nuqXzPnwtxBBWhTF6pbw
9Q+I3rhtL9V2WmOkOLIivB6zTO+dDmJi6w==
-----END EC PRIVATE KEY-----`))
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey failed: %v", err)
	}
	publicKey := CreateTPMPublicAreaForECDSAKey(&key.PublicKey)

	pcrPolicyCounterAuthPolicies, _ := ComputePcrPolicyCounterAuthPolicies(tpm2.HashAlgorithmSHA256, publicKey)
	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyOR(pcrPolicyCounterAuthPolicies)

	pcrPolicyCounterPub := &tpm2.NVPublic{
		Index:      0x0181fff0,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
		AuthPolicy: trial.GetDigest(),
		Size:       8}

	for _, data := range []struct {
		desc                string
		alg                 tpm2.HashAlgorithmId
		pcrPolicyCounterPub *tpm2.NVPublic
		policy              tpm2.Digest
	}{
		{
			desc:                "SHA256",
			alg:                 tpm2.HashAlgorithmSHA256,
			pcrPolicyCounterPub: pcrPolicyCounterPub,
			policy:              testutil.DecodeHexStringT(t, "8fe1ba2f9a6883bac310c9dcb86a0337cf065bba792dcb80c86a1e91056c353e"),
		},
		{
			desc:                "SHA1",
			alg:                 tpm2.HashAlgorithmSHA1,
			pcrPolicyCounterPub: pcrPolicyCounterPub,
			policy:              testutil.DecodeHexStringT(t, "71f93798419e42275cc3e54915f46d8734563803"),
		},
		{
			desc:   "NoPolicyCounter",
			alg:    tpm2.HashAlgorithmSHA256,
			policy: testutil.DecodeHexStringT(t, "375b8a3aca3df9c7fc34b4184f7d030625470d56e89480b81d2f98900f0152a3"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			dataout, policy, err := ComputeStaticPolicy(data.alg, NewStaticPolicyComputeParams(publicKey, data.pcrPolicyCounterPub))
			if err != nil {
				t.Fatalf("ComputeStaticPolicy failed: %v", err)
			}
			if dataout.AuthPublicKey().Params.ECCDetail.CurveID.GoCurve() != key.Curve {
				t.Errorf("Auth key public area has the wrong curve")
			}
			if (&big.Int{}).SetBytes(dataout.AuthPublicKey().Unique.ECC.X).Cmp(key.X) != 0 {
				t.Errorf("Auth key public area has the wrong point")
			}
			if (&big.Int{}).SetBytes(dataout.AuthPublicKey().Unique.ECC.Y).Cmp(key.Y) != 0 {
				t.Errorf("Auth key public area has the wrong point")
			}

			expectedPCRPolicyCounterHandle := tpm2.HandleNull
			if data.pcrPolicyCounterPub != nil {
				expectedPCRPolicyCounterHandle = pcrPolicyCounterPub.Index
			}
			if dataout.PcrPolicyCounterHandle() != expectedPCRPolicyCounterHandle {
				t.Errorf("Wrong policy counter index handle")
			}

			if len(dataout.V0PinIndexAuthPolicies()) != 0 {
				t.Errorf("Wrong number of legacy PIN NV index auth policies")
			}

			if !bytes.Equal(policy, data.policy) {
				t.Errorf("Wrong policy digest: %x", policy)
			}
		})
	}
}

type pcrDigestBuilder struct {
	t           *testing.T
	alg         tpm2.HashAlgorithmId
	pcrs        tpm2.PCRSelectionList
	pcrsCurrent tpm2.PCRSelectionList
	values      tpm2.PCRValues
}

func (b *pcrDigestBuilder) addDigest(digest tpm2.Digest) *pcrDigestBuilder {
	for {
		if len(b.pcrsCurrent) == 0 {
			b.t.Fatalf("No more digests required")
		}
		if len(b.pcrsCurrent[0].Select) > 0 {
			break
		}
		b.pcrsCurrent = b.pcrsCurrent[1:]
	}

	b.values.SetValue(b.pcrsCurrent[0].Hash, b.pcrsCurrent[0].Select[0], digest)

	b.pcrsCurrent[0].Select = b.pcrsCurrent[0].Select[1:]
	return b
}

func (b *pcrDigestBuilder) end() tpm2.Digest {
	digest, err := tpm2.ComputePCRDigest(b.alg, b.pcrs, b.values)
	if err != nil {
		b.t.Fatalf("ComputePCRDigest failed: %v", err)
	}
	return digest
}

func buildPCRDigest(t *testing.T, alg tpm2.HashAlgorithmId, pcrs tpm2.PCRSelectionList) *pcrDigestBuilder {
	var pcrs2 tpm2.PCRSelectionList
	for _, p := range pcrs {
		p2 := tpm2.PCRSelection{Hash: p.Hash}
		p2.Select = make([]int, len(p.Select))
		copy(p2.Select, p.Select)
		sort.Ints(p2.Select)
		pcrs2 = append(pcrs2, p2)
	}
	return &pcrDigestBuilder{t: t, alg: alg, pcrs: pcrs, pcrsCurrent: pcrs2, values: make(tpm2.PCRValues)}
}

func TestComputePolicyORData(t *testing.T) {
	for _, data := range []struct {
		desc         string
		alg          tpm2.HashAlgorithmId
		inputDigests tpm2.DigestList
		outputPolicy tpm2.Digest
	}{
		{
			desc: "SingleDigest",
			alg:  tpm2.HashAlgorithmSHA256,
			inputDigests: tpm2.DigestList{
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).end(),
			},
			outputPolicy: testutil.DecodeHexStringT(t, "fd7451c024bafe5f117cab2841c2dd81f5304350bd8b17ef1f667bceda1ffcf9"),
		},
		{
			desc: "MultipleDigests",
			alg:  tpm2.HashAlgorithmSHA256,
			inputDigests: tpm2.DigestList{
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "1234")).end(),
			},
			outputPolicy: testutil.DecodeHexStringT(t, "4088de0181ede03662fabce88ba4385b16448a981f6b399da861dfe6cc955b68"),
		},
		{
			desc: "2Rows",
			alg:  tpm2.HashAlgorithmSHA256,
			inputDigests: tpm2.DigestList{
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
			},
			outputPolicy: testutil.DecodeHexStringT(t, "0a023c5b9182d2456407c39bf0ab62f6b86f90a4cec61e594c026a087c43e84c"),
		},
		{
			desc: "3Rows",
			alg:  tpm2.HashAlgorithmSHA256,
			inputDigests: tpm2.DigestList{
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc1")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc2")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc3")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc4")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar3")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar4")).end(),
				buildPCRDigest(t, tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}}).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc5")).addDigest(testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar5")).end(),
			},
			outputPolicy: testutil.DecodeHexStringT(t, "447f411c3cedd453e53e9b95958774413bea32267a75db8545cd258ed4968575"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			trial, _ := tpm2.ComputeAuthPolicy(data.alg)
			orData := ComputePolicyORData(data.alg, trial, data.inputDigests)
			if !bytes.Equal(trial.GetDigest(), data.outputPolicy) {
				t.Errorf("Unexpected policy digest (got %x, expected %x)", trial.GetDigest(), data.outputPolicy)
			}

			// Verify we can walk the tree correctly from each input digest and that we get to the root node each time
			for i, d := range data.inputDigests {
				for n := i / 8; n < len(orData); n += int(orData[n].Next) {
					found := false
					for _, digest := range orData[n].Digests {
						if bytes.Equal(digest, d) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Digest %x not found in expected node %d", d, n)
						break
					}

					trial, _ := tpm2.ComputeAuthPolicy(data.alg)
					if len(orData[n].Digests) == 1 {
						trial.PolicyOR(tpm2.DigestList{orData[n].Digests[0], orData[n].Digests[0]})
					} else {
						trial.PolicyOR(orData[n].Digests)
					}
					d = trial.GetDigest()

					if orData[n].Next == 0 {
						break
					}
				}
				if !bytes.Equal(d, data.outputPolicy) {
					t.Errorf("Unexpected final digest after tree walk from digest %x, node %d (got %x, expected %x)", data.inputDigests[i], i/8, d, data.outputPolicy)
				}

			}
		})
	}
}

func TestComputeDynamicPolicy(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	policyCounterPub := &tpm2.NVPublic{
		Index:      0x0181fff0,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
		AuthPolicy: make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size()),
		Size:       8}
	policyCounterName, _ := policyCounterPub.Name()

	for _, data := range []struct {
		desc              string
		alg               tpm2.HashAlgorithmId
		signAlg           tpm2.HashAlgorithmId
		pcrs              tpm2.PCRSelectionList
		pcrValues         []tpm2.PCRValues
		policyCounterName tpm2.Name
		policyCount       uint64
		pcrSelection      tpm2.PCRSelectionList
		policy            tpm2.Digest
		err               string
	}{
		{
			desc:    "Single/1",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrs:    tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
			policyCounterName: policyCounterName,
			policyCount:       10,
			pcrSelection:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			policy:            testutil.DecodeHexStringT(t, "983c996e26d08cdd5a67f3fbdb98fe737e7c6f499e0fd5189ac99719a14c00db"),
		},
		{
			desc:    "Single/2",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrs:    tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
			policyCounterName: policyCounterName,
			policyCount:       10,
			pcrSelection:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8}}},
			policy:            testutil.DecodeHexStringT(t, "166168f87e22c01dc62b19adab299f4ad18f5b313c81696d70c8bf64ed314208"),
		},
		{
			desc:    "SHA1Session",
			alg:     tpm2.HashAlgorithmSHA1,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrs:    tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "ABC"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "1234"),
					},
				},
			},
			policyCounterName: policyCounterName,
			policyCount:       4551,
			pcrSelection:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			policy:            testutil.DecodeHexStringT(t, "66f29c63a88ce0d5046999b5067ced2c9e7d9a48"),
		},
		{
			desc:    "SHA256SessionWithSHA512PCRs",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrs:    tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA512, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA512: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA512, "foo"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA512, "bar"),
					},
				},
			},
			policyCounterName: policyCounterName,
			policyCount:       403,
			pcrSelection:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA512, Select: []int{7, 12}}},
			policy:            testutil.DecodeHexStringT(t, "151216fb8a020dbf181c936cb32e03606d5fd0073aa3b3999365e3d9a08d1f8a"),
		},
		{
			desc:    "MultiplePCRValues/1",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrs:    tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "ABC"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "1234"),
					},
				},
			},
			policyCounterName: policyCounterName,
			policyCount:       5,
			pcrSelection:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			policy:            testutil.DecodeHexStringT(t, "a218c6db035ac2a84b229f2eddd3064a79c3b7c9f48d7bb2f3c6f3f3dda8712b"),
		},
		{
			desc:    "MultiplePCRValues/2",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrs:    tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: MakeMockPolicyPCRValuesFull([]MockPolicyPCRParam{
				{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")},
				},
				{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "ABC"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "1234")},
				},
			}),
			policyCounterName: policyCounterName,
			policyCount:       5,
			pcrSelection:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			policy:            testutil.DecodeHexStringT(t, "e86c232ba03d8153fd1ebb8d248d64dd18d90acc7c0a3ddf6f0863af3f0c87f5"),
		},
		{
			desc:    "SHA512AuthKey",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA512,
			pcrs:    tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
			policyCounterName: policyCounterName,
			policyCount:       10,
			pcrSelection:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			policy:            testutil.DecodeHexStringT(t, "983c996e26d08cdd5a67f3fbdb98fe737e7c6f499e0fd5189ac99719a14c00db"),
		},
		{
			desc:    "MultiplePCRAlgorithms",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrs:    tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{8}}, {Hash: tpm2.HashAlgorithmSHA512, Select: []int{7}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
					tpm2.HashAlgorithmSHA512: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA512, "foo"),
					},
				},
			},
			policyCounterName: policyCounterName,
			policyCount:       10,
			pcrSelection:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{8}}, {Hash: tpm2.HashAlgorithmSHA512, Select: []int{7}}},
			policy:            testutil.DecodeHexStringT(t, "e516f77fbd8a055c472d0cea472828a825b20096655bc1f5264504794b63d400"),
		},
		{
			desc:    "LotsOfPCRValues",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrs:    tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}},
			pcrValues: MakeMockPolicyPCRValuesFull([]MockPolicyPCRParam{
				{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar2"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar3"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar4"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar5")},
				},
				{PCR: 8, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "bar"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "bar2"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "bar3"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "bar4"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "bar5")},
				},
				{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo2"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo3"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo4"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo5")},
				},
			}),
			policyCounterName: policyCounterName,
			policyCount:       15,
			pcrSelection:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}},
			policy:            testutil.DecodeHexStringT(t, "926f36ead779ff00e413bba00df3dd0428bd570c7fedb828a8ea2f0c12cc72ac"),
		},
		{
			desc:    "NoPolicyCounter",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrs:    tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					},
				},
			},
			pcrSelection: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			policy:       testutil.DecodeHexStringT(t, "2af7dc478be6b563113b150fa5c2cc844506ec2273c9aa69ff5a67b150b3c339"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			var pcrDigests tpm2.DigestList
			for _, v := range data.pcrValues {
				d, _ := tpm2.ComputePCRDigest(data.alg, data.pcrs, v)
				pcrDigests = append(pcrDigests, d)
			}
			dataout, err := ComputeDynamicPolicy(CurrentMetadataVersion, data.alg, NewDynamicPolicyComputeParams(key, data.signAlg, data.pcrs, pcrDigests, data.policyCounterName, data.policyCount))
			if data.err == "" {
				if err != nil {
					t.Fatalf("ComputeDynamicPolicy failed: %v", err)
				}
				if !dataout.PCRSelection().Equal(data.pcrSelection) {
					t.Errorf("Unexpected PCR selection")
				}
				// TODO: Test dataout.PCROrData

				if dataout.PolicyCount() != data.policyCount {
					t.Errorf("Unexpected policy revocation count")
				}

				if !bytes.Equal(data.policy, dataout.AuthorizedPolicy()) {
					t.Errorf("Unexpected policy digest returned (got %x, expected %x)", dataout.AuthorizedPolicy(), data.policy)
				}

				if dataout.AuthorizedPolicySignature().SigAlg != tpm2.SigSchemeAlgECDSA {
					t.Errorf("Unexpected authorized policy signature algorithm")
				}
				if dataout.AuthorizedPolicySignature().Signature.ECDSA.Hash != data.signAlg {
					t.Errorf("Unexpected authorized policy signature digest algorithm")
				}

				h := data.signAlg.NewHash()
				h.Write(dataout.AuthorizedPolicy())
				h.Write(ComputePcrPolicyRefFromCounterName(data.policyCounterName))

				if ok := ecdsa.Verify(&key.PublicKey, h.Sum(nil),
					(&big.Int{}).SetBytes(dataout.AuthorizedPolicySignature().Signature.ECDSA.SignatureR),
					(&big.Int{}).SetBytes(dataout.AuthorizedPolicySignature().Signature.ECDSA.SignatureS)); !ok {
					t.Errorf("Invalid authorized policy signature")
				}
			} else {
				if err == nil {
					t.Fatalf("ComputeDynamicPolicy should have failed")
				}
				if err.Error() != data.err {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestExecutePolicy(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer func() { closeTPM(t, tpm) }()

	key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreateTPMPublicAreaForECDSAKey(&key.PublicKey)

	policyCounterPub, policyCount, err := CreatePcrPolicyCounter(tpm.TPMContext, 0x0181ff00, keyPublic, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreatePcrPolicyCounter failed: %v", err)
	}
	policyCounter, err := tpm2.CreateNVIndexResourceContextFromPublic(policyCounterPub)
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	defer func() { undefineNVSpace(t, tpm, policyCounter, tpm.OwnerHandleContext()) }()

	type pcrEvent struct {
		index int
		data  string
	}
	type testData struct {
		alg              tpm2.HashAlgorithmId
		pcrs             tpm2.PCRSelectionList
		pcrValues        []tpm2.PCRValues
		policyCounterPub *tpm2.NVPublic
		policyCount      uint64
		pcrEvents        []pcrEvent
	}

	run := func(t *testing.T, data *testData, prepare func(*StaticPolicyData, *DynamicPolicyData)) (tpm2.Digest, tpm2.Digest, error) {
		tpm, tcti = resetTPMSimulator(t, tpm, tcti)

		var policyCounterName tpm2.Name
		if data.policyCounterPub != nil {
			policyCounterName, _ = data.policyCounterPub.Name()
		}

		staticPolicyData, policy, err := ComputeStaticPolicy(data.alg, NewStaticPolicyComputeParams(CreateTPMPublicAreaForECDSAKey(&key.PublicKey), data.policyCounterPub))
		if err != nil {
			t.Fatalf("ComputeStaticPolicy failed: %v", err)
		}
		signAlg := staticPolicyData.AuthPublicKey().NameAlg
		var pcrDigests tpm2.DigestList
		for _, v := range data.pcrValues {
			d, _ := tpm2.ComputePCRDigest(data.alg, data.pcrs, v)
			pcrDigests = append(pcrDigests, d)
		}
		dynamicPolicyData, err := ComputeDynamicPolicy(CurrentMetadataVersion, data.alg,
			NewDynamicPolicyComputeParams(key, signAlg, data.pcrs, pcrDigests, policyCounterName, data.policyCount))
		if err != nil {
			t.Fatalf("ComputeDynamicPolicy failed: %v", err)
		}

		for _, e := range data.pcrEvents {
			if _, err := tpm.PCREvent(tpm.PCRHandleContext(e.index), []byte(e.data), nil); err != nil {
				t.Fatalf("PCREvent failed: %v", err)
			}
		}

		if prepare != nil {
			prepare(staticPolicyData, dynamicPolicyData)
		}

		session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, data.alg)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, session)

		policyErr := ExecutePolicySession(tpm.TPMContext, session, CurrentMetadataVersion, staticPolicyData, dynamicPolicyData, "", tpm.HmacSession())
		digest, err := tpm.PolicyGetDigest(session)
		if err != nil {
			t.Errorf("PolicyGetDigest failed: %v", err)
		}

		return policy, digest, policyErr
	}

	t.Run("Single/1", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("Single/2", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						8: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 8,
					data:  "bar",
				},
				{
					index: 8,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("SHA1SessionWithSHA256PCRs", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs and where those PCRs are for an algorithm that doesn't match the
		// policy digest algorithm
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA1,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("SHA1", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs, using the SHA-1 algorithm
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA1,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA1: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA1, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA1, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("PCRMismatch/1", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs, where the PCR values during execution don't match the policy
		// (execution should fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "abc",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if !IsDynamicPolicyDataError(err) || err.Error() != "cannot complete OR assertions: current session digest not found in policy data" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("PCRMismatch/2", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs, where the PCR values during execution don't match the policy
		// (execution should fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "xxx",
				},
			}}, nil)
		if !IsDynamicPolicyDataError(err) || err.Error() != "cannot complete OR assertions: current session digest not found in policy data" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("MultiplePCRValues/1", func(t *testing.T) {
		// Test with a compound policy that includes a pair of digests for 2 PCRs
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "baz"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("MultiplePCRValues/2", func(t *testing.T) {
		// Test with a compound policy that includes a pair of digests for 2 PCRs
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "baz"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "baz",
				},
				{
					index: 12,
					data:  "abc",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("MultiplePCRValues/Mismatch", func(t *testing.T) {
		// Test with a compound policy that includes a pair of digests for 2 PCRs, where the PCR values during execution don't match the
		// policy (execution should fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "baz"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "baz",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if !IsDynamicPolicyDataError(err) || err.Error() != "cannot complete OR assertions: current session digest not found in policy data" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("LotsOfPCRValues", func(t *testing.T) {
		// Test with a compound PCR policy that has 125 combinations of conditions.
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8, 12}}},
			pcrValues: MakeMockPolicyPCRValuesFull([]MockPolicyPCRParam{
				{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar2"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar3"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar4"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar5")},
				},
				{PCR: 8, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "bar"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "bar2"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "bar3"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "bar4"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "abc", "bar5")},
				},
				{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo2"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo3"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo4"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo5")},
				},
			}),
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar4",
				},
				{
					index: 8,
					data:  "abc",
				},
				{
					index: 8,
					data:  "bar2",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo5",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("NoPCRs", func(t *testing.T) {
		// Test with a policy that includes no PCR assertions - probably fairly pointless, but should work nonetheless
		expected, digest, err := run(t, &testData{
			alg:              tpm2.HashAlgorithmSHA256,
			pcrValues:        []tpm2.PCRValues{{}},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
		}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("RevokedDynamicPolicy", func(t *testing.T) {
		// Test with a dynamic authorization policy that has been revoked (execution should fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount - 1,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if !IsDynamicPolicyDataError(err) || err.Error() != "the PCR policy has been revoked" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/PCRPolicyCounterHandle/1", func(t *testing.T) {
		// Test handling of an invalid handle for the policy counter in the static metadata (execution should fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			s.SetPcrPolicyCounterHandle(0x40ffffff)
		})
		if !IsStaticPolicyDataError(err) || err.Error() != "invalid handle for PCR policy counter" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/PCRPolicyCounterHandle/2", func(t *testing.T) {
		// Test handling of the policy counter handle in the static metadata pointing to a non-existant resource (execution should fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			s.SetPcrPolicyCounterHandle(s.PcrPolicyCounterHandle() + 1)
		})
		if !IsStaticPolicyDataError(err) || err.Error() != "no PCR policy counter found" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/AuthPublicKey/1", func(t *testing.T) {
		// Test handling of the public area of the dynamic policy authorization key having an unsupported name algorithm (execution should
		// fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			s.AuthPublicKey().NameAlg = tpm2.HashAlgorithmId(tpm2.AlgorithmSM4)
		})
		if !IsStaticPolicyDataError(err) || err.Error() != "public area of dynamic authorization policy signing key has an unsupported "+
			"name algorithm" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/AuthPublicKey/2", func(t *testing.T) {
		// Test handling of the public area of the dynamic policy authorization key being replaced by one corresponding to a different key
		// (execution should fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			s.AuthPublicKey().Unique.ECC = &tpm2.ECCPoint{X: key.X.Bytes(), Y: key.Y.Bytes()}
		})
		// Even though this error is caused by broken static metadata, we get a dynamicPolicyDataError error because the signature
		// verification fails. Validation with validateKeyData will detect the real issue though.
		if !IsDynamicPolicyDataError(err) || err.Error() != "cannot verify PCR policy signature" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidMetadata/DynamicPolicySignature/1", func(t *testing.T) {
		// Test handling of the dynamic authorization signature being replaced (execution should fail).
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			policyCounter, err := tpm.CreateResourceContextFromTPM(s.PcrPolicyCounterHandle())
			if err != nil {
				t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
			}

			alg := d.AuthorizedPolicySignature().Signature.ECDSA.Hash
			h := alg.NewHash()
			h.Write(d.AuthorizedPolicy())
			h.Write(ComputePcrPolicyRefFromCounterContext(policyCounter))

			sigR, sigS, err := ecdsa.Sign(testutil.RandReader, key, h.Sum(nil))
			if err != nil {
				t.Fatalf("SignPSS failed: %v", err)
			}
			d.AuthorizedPolicySignature().Signature.ECDSA.SignatureR = sigR.Bytes()
			d.AuthorizedPolicySignature().Signature.ECDSA.SignatureS = sigS.Bytes()
		})
		if !IsDynamicPolicyDataError(err) || err.Error() != "cannot verify PCR policy signature" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidMetadata/DynamicPolicySignature/2", func(t *testing.T) {
		// Test handling of the public area of the dynamic policy authorization key being replaced by one corresponding to a different key,
		// and the authorized policy signature being replaced with a signature signed by the new key (execution should succeed, but the
		// resulting session digest shouldn't match the computed policy digest)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			s.AuthPublicKey().Unique.ECC = &tpm2.ECCPoint{X: key.X.Bytes(), Y: key.Y.Bytes()}

			policyCounter, err := tpm.CreateResourceContextFromTPM(s.PcrPolicyCounterHandle())
			if err != nil {
				t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
			}

			alg := d.AuthorizedPolicySignature().Signature.ECDSA.Hash
			h := alg.NewHash()
			h.Write(d.AuthorizedPolicy())
			h.Write(ComputePcrPolicyRefFromCounterContext(policyCounter))

			sigR, sigS, err := ecdsa.Sign(testutil.RandReader, key, h.Sum(nil))
			if err != nil {
				t.Fatalf("SignPSS failed: %v", err)
			}
			d.AuthorizedPolicySignature().Signature.ECDSA.SignatureR = sigR.Bytes()
			d.AuthorizedPolicySignature().Signature.ECDSA.SignatureS = sigS.Bytes()
		})
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidDynamicMetadata/PolicyCount", func(t *testing.T) {
		// Test handling of the policy count in a revoked dynamic policy metadata being changed so that it is equal to the current policy
		// counter value (execution should fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount - 1,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			d.SetPolicyCount(d.PolicyCount() + 1)
		})
		if !IsDynamicPolicyDataError(err) || err.Error() != "the PCR policy is invalid" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidDynamicMetadata/PCROrDigests/1", func(t *testing.T) {
		// Test handling of a corrupted OR digest tree with a PCR policy that only has one condition (execution should succeed - the
		// corrupted value causes executeOrPolicyAssertions to bail at the right time but for the wrong reason, so the resulting
		// session digest ends up correct)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			d.PCROrData()[0].Next = 1000
		})
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("InvalidDynamicMetadata/PCROrDigests/2", func(t *testing.T) {
		// Test handling of a corrupted OR digest tree with a PCR policy that has lots of conditions (execution should fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: MakeMockPolicyPCRValuesFull([]MockPolicyPCRParam{
				{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar2"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar3"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar4"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar5")},
				},
				{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo2"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo3"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo4"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo5")},
				},
			}),
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			d.PCROrData()[0].Next = 1000
		})
		if !IsDynamicPolicyDataError(err) || err.Error() != "the PCR policy is invalid" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidDynamicMetadata/PCROrDigests/3", func(t *testing.T) {
		// Test handling of a corrupted OR digest tree with a PCR policy that has lots of conditions (execution should fail)
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: MakeMockPolicyPCRValuesFull([]MockPolicyPCRParam{
				{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar2"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar3"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar4"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar5")},
				},
				{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo2"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo3"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo4"),
					testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo5")},
				},
			}),
			policyCounterPub: policyCounterPub,
			policyCount:      policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			x := int32(-10)
			d.PCROrData()[0].Next = *(*uint32)(unsafe.Pointer(&x))
		})
		if !IsDynamicPolicyDataError(err) || err.Error() != "the PCR policy is invalid" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("NoPolicyCounter", func(t *testing.T) {
		// Test with a policy that doesn't include a dynamic authorization policy revocation counter.
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/PCRPolicyCounterHandle/3", func(t *testing.T) {
		// Test handling of the policy counter handle in the static metadata pointing to a NV index when the policy was created without
		// the counter (execution should fail).
		expected, digest, err := run(t, &testData{
			alg:  tpm2.HashAlgorithmSHA256,
			pcrs: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			pcrValues: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
						12: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					},
				},
			},
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			s.SetPcrPolicyCounterHandle(policyCounterPub.Index)
			d.SetPolicyCount(policyCount)
		})
		if !IsDynamicPolicyDataError(err) || err.Error() != "cannot verify PCR policy signature" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})
}

func TestBlockPCRProtectionPolicies(t *testing.T) {
	// This test only test the fence style locking - the old style is tested with v0
	// key files in internal/compattest/v0_test.go
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		pcrs []int
	}{
		{
			desc: "12",
			pcrs: []int{12},
		},
		{
			desc: "12,13",
			pcrs: []int{12, 13},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			pcrs := tpm2.PCRSelectionList{
				{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
				{Hash: tpm2.HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}}
			_, pcrValues, err := tpm.PCRRead(pcrs)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}

			if err := BlockPCRProtectionPolicies(tpm, data.pcrs); err != nil {
				t.Errorf("BlockPCRProtectionPolicies failed: %v", err)
			}

			for _, p := range pcrs {
				h := p.Hash.NewHash()
				h.Write(make([]byte, 4))
				fenceHash := h.Sum(nil)

				for _, s := range data.pcrs {
					h = p.Hash.NewHash()
					h.Write(pcrValues[p.Hash][s])
					h.Write(fenceHash)
					pcrValues[p.Hash][s] = h.Sum(nil)
				}
			}

			_, pcrValues2, err := tpm.PCRRead(pcrs)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}

			for _, p := range pcrs {
				for _, s := range p.Select {
					if !bytes.Equal(pcrValues2[p.Hash][s], pcrValues[p.Hash][s]) {
						t.Errorf("Unexpected PCR value")
					}
				}
			}
		})
	}

}
