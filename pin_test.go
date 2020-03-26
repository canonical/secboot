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
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"os"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	. "github.com/snapcore/secboot"
)

func TestCreatePinNVIndex(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	key, err := rsa.GenerateKey(rand.Reader, 768)
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

	key, err := rsa.GenerateKey(rand.Reader, 768)
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

func TestChangePIN(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestChangePIN_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyFile := tmpDir + "/keydata"

	if err := SealKeyToTPM(tpm, key, keyFile, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PINHandle: 0x0181fff0}); err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	defer undefineKeyNVSpace(t, tpm, keyFile)

	testPIN := "1234"

	if err := ChangePIN(tpm, keyFile, "", testPIN); err != nil {
		t.Fatalf("ChangePIN failed: %v", err)
	}

	// Verify that the PIN change succeeded by executing a PolicySecret assertion, which is immediate and will fail if it
	// didn't work.
	k, err := ReadSealedKeyObject(keyFile)
	if err != nil {
		t.Fatalf("ReadSealedKeyObject failed: %v", err)
	}
	if k.AuthMode2F() != AuthModePIN {
		t.Errorf("Wrong auth mode")
	}

	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, policySession)

	pinIndex, err := tpm.CreateResourceContextFromTPM(k.PINIndexHandle())
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	pinIndex.SetAuthValue([]byte(testPIN))

	if _, _, err := tpm.PolicySecret(pinIndex, policySession, nil, nil, 0, nil); err != nil {
		t.Errorf("PolicySecret assertion failed: %v", err)
	}

	// Try clearing the PIN
	if err := ChangePIN(tpm, keyFile, testPIN, ""); err != nil {
		t.Fatalf("ChangePIN failed: %v", err)
	}

	// Verify that the PIN change succeeded by executing a PolicySecret assertion, which is immediate and will fail if it
	// didn't work.
	k, err = ReadSealedKeyObject(keyFile)
	if err != nil {
		t.Fatalf("ReadSealedKeyObject failed: %v", err)
	}
	if k.AuthMode2F() != AuthModeNone {
		t.Errorf("Wrong auth mode")
	}

	pinIndex.SetAuthValue(nil)

	if _, _, err := tpm.PolicySecret(pinIndex, policySession, nil, nil, 0, nil); err != nil {
		t.Errorf("PolicySecret assertion failed: %v", err)
	}
}

func TestChangePINErrorHandling(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Fatalf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	run := func(t *testing.T, oldPIN string) error {
		tmpDir, err := ioutil.TempDir("", "_TestChangePINErrorHandling_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		keyFile := tmpDir + "/keydata"

		if err := SealKeyToTPM(tpm, key, keyFile, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PINHandle: 0x0181fff0}); err != nil {
			t.Fatalf("SealKeyToTPM failed: %v", err)
		}
		defer undefineKeyNVSpace(t, tpm, keyFile)

		return ChangePIN(tpm, keyFile, oldPIN, "")
	}

	t.Run("TPMLockout", func(t *testing.T) {
		// Put the TPM in DA lockout mode
		if err := tpm.DictionaryAttackParameters(tpm.LockoutHandleContext(), 0, 7200, 86400, nil); err != nil {
			t.Errorf("DictionaryAttackParameters failed: %v", err)
		}
		defer func() {
			if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
				t.Errorf("ProvisionTPM failed: %v", err)
			}
		}()
		if err := run(t, ""); err != ErrTPMLockout {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("PINFail", func(t *testing.T) {
		if err := run(t, "1234"); err != ErrPINFail {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}
