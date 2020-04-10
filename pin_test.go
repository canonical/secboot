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
	"crypto/rsa"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	. "github.com/snapcore/secboot"
)

func TestCreatePinNVIndex(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	key, err := rsa.GenerateKey(testRandReader, 768)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		t.Fatalf("Cannot compute key name: %v", err)
	}

	for _, data := range []struct {
		desc   string
		handle tpm2.Handle
	}{
		{
			desc:   "0x01800000",
			handle: 0x01800000,
		},
		{
			desc:   "0x0181ff00",
			handle: 0x0181ff00,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			pub, authPolicies, err := CreatePinNVIndex(tpm.TPMContext, data.handle, keyName, tpm.HmacSession())
			if err != nil {
				t.Fatalf("CreatePinNVIndex failed: %v", err)
			}
			defer func() {
				index, err := tpm2.CreateNVIndexResourceContextFromPublic(pub)
				if err != nil {
					t.Errorf("CreateNVIndexResourceContextFromPublic failed: %v", err)
				}
				undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
			}()

			if pub.Index != data.handle {
				t.Errorf("Public area has wrong handle")
			}
			if pub.NameAlg != tpm2.HashAlgorithmSHA256 {
				t.Errorf("Public area has wrong name algorithm")
			}
			if pub.Attrs != tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead|tpm2.AttrNVPolicyRead|tpm2.AttrNVWritten) {
				t.Errorf("Public area has wrong attributes")
			}
			trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
			trial.PolicyOR(authPolicies)
			if !bytes.Equal(pub.AuthPolicy, trial.GetDigest()) {
				t.Errorf("Public area has wrong auth policy")
			}
			// Note, we test the individual components of the authorization policy during tests for
			// incrementDynamicPolicyCounter, readDynamicPolicyCounter, performPinChange and executePolicySession.

			pinIndexName, err := pub.Name()
			if err != nil {
				t.Errorf("NVPublic.Name failed: %v", err)
			}
			index, err := tpm.CreateResourceContextFromTPM(data.handle)
			if err != nil {
				t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
			}
			if !bytes.Equal(index.Name(), pinIndexName) {
				t.Errorf("Unexpected name read back from TPM")
			}
		})
	}
}

func TestPerformPinChange(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	key, err := rsa.GenerateKey(testRandReader, 768)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		t.Fatalf("Cannot compute key name: %v", err)
	}
	pinIndexPub, pinIndexAuthPolicies, err := CreatePinNVIndex(tpm.TPMContext, 0x01810000, keyName, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreatePinNVIndex failed: %v", err)
	}
	defer func() {
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
		if err != nil {
			t.Errorf("CreateNVIndexResourceContextFromPublic failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}()

	pin := "1234"

	if err := PerformPinChange(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, "", pin, tpm.HmacSession()); err != nil {
		t.Fatalf("PerformPinChange failed: %v", err)
	}

	// Verify that the PIN change succeeded by executing a PolicySecret assertion, which is immediate and will fail if it
	// didn't work.
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, policySession)

	pinIndex, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	pinIndex.SetAuthValue([]byte(pin))

	if _, _, err := tpm.PolicySecret(pinIndex, policySession, nil, nil, 0, nil); err != nil {
		t.Errorf("PolicySecret assertion failed: %v", err)
	}
}
