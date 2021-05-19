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
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/xerrors"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
)

func getTestPCRProfile() *PCRProtectionProfile {
	return NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7)
}

func TestSealKeyToTPM(t *testing.T) {
	func() {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)

		if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
			t.Errorf("Failed to provision TPM for test: %v", err)
		}
	}()

	key := make([]byte, 64)
	rand.Read(key)

	run := func(t *testing.T, tpm *TPMConnection, params *KeyCreationParams) (authKeyBytes []byte) {
		tmpDir, err := ioutil.TempDir("", "_TestSealKeyToTPM_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		keyFile := tmpDir + "/keydata"

		authPrivateKey, err := SealKeyToTPM(tpm, key, keyFile, params)
		if err != nil {
			t.Errorf("SealKeyToTPM failed: %v", err)
		}
		defer undefineKeyNVSpace(t, tpm, keyFile)

		if err := ValidateKeyDataFile(tpm.TPMContext, keyFile, authPrivateKey, tpm.HmacSession()); err != nil {
			t.Errorf("ValidateKeyDataFile failed: %v", err)
		}

		return authPrivateKey
	}

	t.Run("Standard", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("DifferentPCRPolicyCounterHandle", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x0181fff0})
	})

	t.Run("SealAfterProvision", func(t *testing.T) {
		// SealKeyToTPM behaves slightly different if called immediately after EnsureProvisioned with the same TPMConnection
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
			t.Errorf("Failed to provision TPM for test: %v", err)
		}
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("NoSRK", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)

		srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
		if err != nil {
			t.Fatalf("No SRK: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srk, srk.Handle(), nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("NilPCRProfile", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, &KeyCreationParams{PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("NoPCRPolicyCounterHandle", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	})

	t.Run("WithProvidedAuthKey", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		pkb := run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000, AuthKey: authKey})
		if !bytes.Equal(pkb, authKey.D.Bytes()) {
			t.Fatalf("AuthKey private part bytes do not match provided one")
		}
	})
}

func TestSealKeyToTPMMultiple(t *testing.T) {
	func() {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)

		if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
			t.Errorf("Failed to provision TPM for test: %v", err)
		}
	}()

	key := make([]byte, 64)
	rand.Read(key)

	run := func(t *testing.T, tpm *TPMConnection, n int, params *KeyCreationParams) (authKeyBytes TPMPolicyAuthKey) {
		tmpDir, err := ioutil.TempDir("", "_TestSealKeyToTPM_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		var keys []*SealKeyRequest
		for i := 0; i < n; i++ {
			keys = append(keys, &SealKeyRequest{Key: key, Path: filepath.Join(tmpDir, fmt.Sprintf("keydata%d", i))})
		}

		authPrivateKey, err := SealKeyToTPMMultiple(tpm, keys, params)
		if err != nil {
			t.Errorf("SealKeyToTPMMultiple failed: %v", err)
		}
		defer undefineKeyNVSpace(t, tpm, keys[0].Path)

		for _, k := range keys {
			if err := ValidateKeyDataFile(tpm.TPMContext, k.Path, authPrivateKey, tpm.HmacSession()); err != nil {
				t.Errorf("ValidateKeyDataFile failed: %v", err)
			}
		}

		return authPrivateKey
	}

	t.Run("Single", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, 1, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("2Keys", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("DifferentPCRPolicyCounterHandle", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x0181fff0})
	})

	t.Run("SealAfterProvision", func(t *testing.T) {
		// SealKeyToTPM behaves slightly different if called immediately after EnsureProvisioned with the same TPMConnection
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
			t.Errorf("Failed to provision TPM for test: %v", err)
		}
		run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("NoSRK", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)

		srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
		if err != nil {
			t.Fatalf("No SRK: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srk, srk.Handle(), nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("NilPCRProfile", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, 2, &KeyCreationParams{PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("NoPCRPolicyCounterHandle", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	})

	t.Run("WithProvidedAuthKey", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		pkb := run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000, AuthKey: authKey})
		if !bytes.Equal(pkb, authKey.D.Bytes()) {
			t.Fatalf("AuthKey private part bytes do not match provided one")
		}
	})
}

func TestSealKeyToTPMErrorHandling(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
		t.Errorf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	run := func(t *testing.T, tmpDir string, params *KeyCreationParams) error {
		if tmpDir == "" {
			var err error
			tmpDir, err = ioutil.TempDir("", "_TestSealKeyToTPMErrors_")
			if err != nil {
				t.Fatalf("Creating temporary directory failed: %v", err)
			}
		}
		defer os.RemoveAll(tmpDir)

		keyFile := tmpDir + "/keydata"

		origKeyFileInfo, _ := os.Stat(keyFile)
		var policyCounter tpm2.ResourceContext
		if params != nil {
			policyCounter, _ = tpm.CreateResourceContextFromTPM(params.PCRPolicyCounterHandle)
		}

		_, err := SealKeyToTPM(tpm, key, keyFile, params)

		if fi, err := os.Stat(keyFile); err == nil && (origKeyFileInfo == nil || origKeyFileInfo.ModTime() != fi.ModTime()) {
			t.Errorf("SealKeyToTPM created a key file")
		}
		if params != nil {
			if index, err := tpm.CreateResourceContextFromTPM(params.PCRPolicyCounterHandle); err == nil && (policyCounter == nil || !bytes.Equal(policyCounter.Name(), index.Name())) {
				t.Errorf("SealKeyToTPM created a dynamic policy counter")
			}
		}
		return err
	}

	t.Run("NilParams", func(t *testing.T) {
		err := run(t, "", nil)
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "no KeyCreationParams provided" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("OwnerAuthFail", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		tpm.OwnerHandleContext().SetAuthValue(nil)

		defer func() {
			tpm.OwnerHandleContext().SetAuthValue(testAuth)
			resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())
		}()

		err := run(t, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
		if e, ok := err.(AuthFailError); !ok || e.Handle != tpm2.HandleOwner {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("FileExists", func(t *testing.T) {
		tmpDir, err := ioutil.TempDir("", "_TestSealKeyToTPMErrors_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		f, err := os.OpenFile(tmpDir+"/keydata", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		defer f.Close()
		err = run(t, tmpDir, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
		var e *os.PathError
		if !xerrors.As(err, &e) || e.Path != tmpDir+"/keydata" || e.Err != syscall.EEXIST {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("PinNVIndexExists", func(t *testing.T) {
		public := tpm2.NVPublic{
			Index:   0x0181ffff,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead),
			Size:    0}
		index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &public, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
		err = run(t, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: public.Index})
		if e, ok := err.(TPMResourceExistsError); !ok || e.Handle != public.Index {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("InvalidPCRProfile", func(t *testing.T) {
		pcrProfile := NewPCRProtectionProfile().
			AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).
			AddProfileOR(
				NewPCRProtectionProfile(),
				NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 8))
		err := run(t, "", &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: 0x01810000})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "cannot compute dynamic authorization policy: cannot compute PCR digests from protection profile: not all "+
			"branches contain values for the same sets of PCRs" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("InvalidPCRProfileSelection", func(t *testing.T) {
		pcrProfile := NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 50, make([]byte, tpm2.HashAlgorithmSHA256.Size()))
		err := run(t, "", &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: 0x01810000})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "cannot compute dynamic authorization policy: PCR protection profile contains digests for unsupported PCRs" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("WrongCurve", func(t *testing.T) {
		authKey, err := ecdsa.GenerateKey(elliptic.P384(), testutil.RandReader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		err = run(t, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000, AuthKey: authKey})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "provided AuthKey must be from elliptic.P256, no other curve is supported" {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestSealKeyToExternalTPMStorageKey(t *testing.T) {
	var srkPub *tpm2.Public

	func() {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)

		if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
			t.Errorf("Failed to provision TPM for test: %v", err)
		}

		srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
		if err != nil {
			t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
		}

		srkPub, _, _, err = tpm.ReadPublic(srk)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}
	}()

	pcrProfile := func() *PCRProtectionProfile {
		return NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, make([]byte, 32))
	}

	key := make([]byte, 32)
	rand.Read(key)

	run := func(t *testing.T, params *KeyCreationParams) (authKeyBytes []byte) {
		tmpDir, err := ioutil.TempDir("", "_TestSealKeyToExternalTPMStorageKey_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		keyFile := tmpDir + "/keydata"

		authPrivateKey, err := SealKeyToExternalTPMStorageKey(srkPub, key, keyFile, params)
		if err != nil {
			t.Errorf("SealKeyToExternalTPMStorageKey failed: %v", err)
		}

		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)

		if err := ValidateKeyDataFile(tpm.TPMContext, keyFile, authPrivateKey, tpm.HmacSession()); err != nil {
			t.Errorf("ValidateKeyDataFile failed: %v", err)
		}

		return authPrivateKey
	}

	t.Run("Standard", func(t *testing.T) {
		run(t, &KeyCreationParams{PCRProfile: pcrProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	})

	t.Run("NilPCRProfile", func(t *testing.T) {
		run(t, &KeyCreationParams{PCRPolicyCounterHandle: tpm2.HandleNull})
	})

	t.Run("WithProvidedAuthKey", func(t *testing.T) {
		authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		pkb := run(t, &KeyCreationParams{PCRProfile: pcrProfile(), PCRPolicyCounterHandle: tpm2.HandleNull, AuthKey: authKey})
		if !bytes.Equal(pkb, authKey.D.Bytes()) {
			t.Fatalf("AuthKey private part bytes do not match provided one")
		}
	})
}

func TestSealKeyToExternalTPMStorageKeyErrorHandling(t *testing.T) {
	var srkPub *tpm2.Public

	func() {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)

		if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
			t.Errorf("Failed to provision TPM for test: %v", err)
		}

		srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
		if err != nil {
			t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
		}

		srkPub, _, _, err = tpm.ReadPublic(srk)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}
	}()

	key := make([]byte, 32)
	rand.Read(key)

	run := func(t *testing.T, tmpDir string, params *KeyCreationParams) error {
		if tmpDir == "" {
			var err error
			tmpDir, err = ioutil.TempDir("", "_TestSealKeyToExternalTPMStorageKeyErrorHandling_")
			if err != nil {
				t.Fatalf("Creating temporary directory failed: %v", err)
			}
		}
		defer os.RemoveAll(tmpDir)

		keyFile := tmpDir + "/keydata"
		origKeyFileInfo, _ := os.Stat(keyFile)

		_, err := SealKeyToExternalTPMStorageKey(srkPub, key, keyFile, params)

		if fi, err := os.Stat(keyFile); err == nil && (origKeyFileInfo == nil || origKeyFileInfo.ModTime() != fi.ModTime()) {
			t.Errorf("SealKeyToTPM created a key file")
		}

		return err
	}

	t.Run("NilParams", func(t *testing.T) {
		err := run(t, "", nil)
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "no KeyCreationParams provided" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("FileExists", func(t *testing.T) {
		tmpDir, err := ioutil.TempDir("", "_TestSealKeyToTPMErrors_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		f, err := os.OpenFile(tmpDir+"/keydata", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		defer f.Close()
		err = run(t, tmpDir, &KeyCreationParams{PCRPolicyCounterHandle: tpm2.HandleNull})
		var e *os.PathError
		if !xerrors.As(err, &e) || e.Path != tmpDir+"/keydata" || e.Err != syscall.EEXIST {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("InvalidPCRProfile", func(t *testing.T) {
		pcrProfile := NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7)
		err := run(t, "", &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: tpm2.HandleNull})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "cannot compute dynamic authorization policy: cannot compute PCR digests from protection profile: cannot read "+
			"current value of PCR 7 from bank TPM_ALG_SHA256: no TPM context" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("InvalidPCRProfileSelection", func(t *testing.T) {
		pcrProfile := NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 50, make([]byte, tpm2.HashAlgorithmSHA256.Size()))
		err := run(t, "", &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: tpm2.HandleNull})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "cannot compute dynamic authorization policy: PCR protection profile contains digests for unsupported PCRs" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("WrongCurve", func(t *testing.T) {
		authKey, err := ecdsa.GenerateKey(elliptic.P384(), testutil.RandReader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		err = run(t, "", &KeyCreationParams{PCRPolicyCounterHandle: tpm2.HandleNull, AuthKey: authKey})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "provided AuthKey must be from elliptic.P256, no other curve is supported" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("WithPCRPolicyCounter", func(t *testing.T) {
		err := run(t, "", &KeyCreationParams{PCRPolicyCounterHandle: 0x01810000})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "PCRPolicyCounter must be tpm2.HandleNull when creating an importable sealed key" {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestUpdateKeyPCRProtectionPolicy(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
		t.Errorf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	prepare := func(t *testing.T, params *KeyCreationParams) (path string, authKey TPMPolicyAuthKey, cleanup func()) {
		tmpDir, err := ioutil.TempDir("", "_TestUpdateKeyPCRProtectionPolicy_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}

		keyFile := filepath.Join(tmpDir, "keydata")

		authPrivateKey, err := SealKeyToTPM(tpm, key, keyFile, params)
		if err != nil {
			t.Errorf("SealKeyToTPM failed: %v", err)
		}
		return keyFile, authPrivateKey, func() {
			undefineKeyNVSpace(t, tpm, keyFile)
			os.RemoveAll(tmpDir)
		}
	}
	update := func(t *testing.T, keyFile string, authKey TPMPolicyAuthKey, profile *PCRProtectionProfile) {
		if err := UpdateKeyPCRProtectionPolicy(tpm, keyFile, authKey, profile); err != nil {
			t.Errorf("UpdateKeyPCRProtectionPolicy failed: %v", err)
		}
	}

	checkUnseal := func(t *testing.T, keyFile string) {
		k, err := ReadSealedKeyObject(keyFile)
		if err != nil {
			t.Fatalf("ReadSealedKeyObject failed: %v", err)
		}

		unsealedKey, _, err := k.UnsealFromTPM(tpm, "")
		if err != nil {
			t.Errorf("Unseal failed: %v", err)
		}

		if !bytes.Equal(unsealedKey, key) {
			t.Errorf("Unexpected key")
		}
	}

	t.Run("WithPCRPolicyCounter", func(t *testing.T) {
		// Create initial keyfile
		keyFile, authKey, cleanup := prepare(t, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
		defer cleanup()

		// Create a copy of initial file
		keyFile2 := filepath.Join(filepath.Dir(keyFile), "keydata2")
		if err := testutil.CopyFile(keyFile2, keyFile, 0600); err != nil {
			t.Errorf("CopyFile failed: %v", err)
		}

		// Update policy with 2 branches
		newProfile := NewPCRProtectionProfile().AddProfileOR(
			NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7),
			NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo")))
		update(t, keyFile, authKey, newProfile)

		// Check that unseal fails with the backup file
		k, err := ReadSealedKeyObject(keyFile2)
		if err != nil {
			t.Fatalf("ReadSealedKeyObject failed: %v", err)
		}

		if _, _, err := k.UnsealFromTPM(tpm, ""); err == nil ||
			err.Error() != "invalid key data file: cannot complete authorization policy assertions: the PCR policy has been revoked" {
			t.Errorf("Unexpected error: %v", err)
		}

		// Check it unseals with the first branch
		checkUnseal(t, keyFile)

		// Modify the PCR state to match the second branch
		if _, err := tpm.PCREvent(tpm.PCRHandleContext(7), []byte("foo"), nil); err != nil {
			t.Errorf("PCREvent failed: %v", err)
		}

		// Check it unseals with the second branch
		checkUnseal(t, keyFile)
	})

	t.Run("WithoutPCRPolicyCounter", func(t *testing.T) {
		// Create initial keyfile
		keyFile, authKey, cleanup := prepare(t, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
		defer cleanup()

		// Create a copy of initial file
		keyFile2 := filepath.Join(filepath.Dir(keyFile), "keydata2")
		if err := testutil.CopyFile(keyFile2, keyFile, 0600); err != nil {
			t.Errorf("CopyFile failed: %v", err)
		}

		// Update policy with 2 branches
		newProfile := NewPCRProtectionProfile().AddProfileOR(
			NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7),
			NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo")))
		update(t, keyFile, authKey, newProfile)

		// Check that the backup file still works
		checkUnseal(t, keyFile2)

		// Check it unseals with the first branch
		checkUnseal(t, keyFile)

		// Modify the PCR state to match the second branch
		if _, err := tpm.PCREvent(tpm.PCRHandleContext(7), []byte("foo"), nil); err != nil {
			t.Errorf("PCREvent failed: %v", err)
		}

		// Check it unseals with the second branch
		checkUnseal(t, keyFile)
	})
}

func TestUpdateKeyPCRProtectionPolicyMultiple(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
		t.Errorf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	prepare := func(t *testing.T, n int, params *KeyCreationParams) (paths []string, authKey TPMPolicyAuthKey, cleanup func()) {
		tmpDir, err := ioutil.TempDir("", "_TestUpdateKeyPCRProtectionPolicyMultiple_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}

		var keys []*SealKeyRequest
		for i := 0; i < n; i++ {
			keys = append(keys, &SealKeyRequest{Key: key, Path: filepath.Join(tmpDir, fmt.Sprintf("keydata%d", i))})
		}

		authPrivateKey, err := SealKeyToTPMMultiple(tpm, keys, params)
		if err != nil {
			t.Errorf("SealKeyToTPMMultiple failed: %v", err)
		}

		for _, k := range keys {
			paths = append(paths, k.Path)
		}

		return paths, authPrivateKey, func() {
			undefineKeyNVSpace(t, tpm, keys[0].Path)
			os.RemoveAll(tmpDir)
		}
	}

	update := func(t *testing.T, keyFiles []string, authKey TPMPolicyAuthKey, profile *PCRProtectionProfile) {
		if err := UpdateKeyPCRProtectionPolicyMultiple(tpm, keyFiles, authKey, profile); err != nil {
			t.Errorf("UpdateKeyPCRProtectionPolicy failed: %v", err)
		}
	}

	checkUnseal := func(t *testing.T, keyFile string) {
		k, err := ReadSealedKeyObject(keyFile)
		if err != nil {
			t.Fatalf("ReadSealedKeyObject failed: %v", err)
		}

		unsealedKey, _, err := k.UnsealFromTPM(tpm, "")
		if err != nil {
			t.Errorf("Unseal failed: %v", err)
		}

		if !bytes.Equal(unsealedKey, key) {
			t.Errorf("Unexpected key")
		}
	}

	t.Run("WithPCRPolicyCounter", func(t *testing.T) {
		// Create initial keyfiles
		keyFiles, authKey, cleanup := prepare(t, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
		defer cleanup()

		// Create a copy of initial files
		var backups []string
		for _, kf := range keyFiles {
			bf := kf + ".bak"
			if err := testutil.CopyFile(bf, kf, 0600); err != nil {
				t.Errorf("CopyFile failed: %v", err)
			}
			backups = append(backups, bf)
		}

		// Update policy with 2 branches
		newProfile := NewPCRProtectionProfile().AddProfileOR(
			NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7),
			NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo")))
		update(t, keyFiles, authKey, newProfile)

		// Check that unseal fails with the backup files
		for _, bf := range backups {
			k, err := ReadSealedKeyObject(bf)
			if err != nil {
				t.Fatalf("ReadSealedKeyObject failed: %v", err)
			}

			if _, _, err := k.UnsealFromTPM(tpm, ""); err == nil ||
				err.Error() != "invalid key data file: cannot complete authorization policy assertions: the PCR policy has been revoked" {
				t.Errorf("Unexpected error: %v", err)
			}
		}

		// Check that the keys unseal with the first branch
		for _, k := range keyFiles {
			checkUnseal(t, k)
		}

		// Modify the PCR state to match the second branch
		if _, err := tpm.PCREvent(tpm.PCRHandleContext(7), []byte("foo"), nil); err != nil {
			t.Errorf("PCREvent failed: %v", err)
		}

		// Check that the keys unseal with the second branch
		for _, k := range keyFiles {
			checkUnseal(t, k)
		}
	})

	t.Run("WithoutPCRPolicyCounter", func(t *testing.T) {
		// Create initial keyfile
		keyFiles, authKey, cleanup := prepare(t, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
		defer cleanup()

		// Create a copy of initial files
		var backups []string
		for _, kf := range keyFiles {
			bf := kf + ".bak"
			if err := testutil.CopyFile(bf, kf, 0600); err != nil {
				t.Errorf("CopyFile failed: %v", err)
			}
			backups = append(backups, bf)
		}

		// Update policy with 2 branches
		newProfile := NewPCRProtectionProfile().AddProfileOR(
			NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7),
			NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo")))
		update(t, keyFiles, authKey, newProfile)

		// Check that unseal still succeeds with the backup files
		for _, bf := range backups {
			checkUnseal(t, bf)
		}

		// Check that the keys unseal with the first branch
		for _, k := range keyFiles {
			checkUnseal(t, k)
		}

		// Modify the PCR state to match the second branch
		if _, err := tpm.PCREvent(tpm.PCRHandleContext(7), []byte("foo"), nil); err != nil {
			t.Errorf("PCREvent failed: %v", err)
		}

		// Check that the keys unseal with the second branch
		for _, k := range keyFiles {
			checkUnseal(t, k)
		}
	})
}

func TestUpdateKeyPCRProtectionPolicyMultipleUnrelated1(t *testing.T) {
	// Test that UpdateKeyPCRProtectionPolicyMultiple rejects keys that have the
	// same auth key, but different policies because they use independent PCR policy
	// counters.
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
		t.Errorf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUpdateKeyPCRProtectionPolicyMultiple1_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	var keyFiles []string
	for i := 0; i < 3; i++ {
		keyFile := filepath.Join(tmpDir, fmt.Sprintf("keydata%d", i))
		if _, err := SealKeyToTPM(tpm, key, keyFile, &KeyCreationParams{
			PCRProfile:             getTestPCRProfile(),
			PCRPolicyCounterHandle: 0x01810000 + tpm2.Handle(i),
			AuthKey:                authKey}); err != nil {
			t.Fatalf("SealKeyToTPM failed: %v", err)
		}
		defer undefineKeyNVSpace(t, tpm, keyFile)
		keyFiles = append(keyFiles, keyFile)
	}

	if err := UpdateKeyPCRProtectionPolicyMultiple(tpm, keyFiles, authKey.D.Bytes(), nil); err == nil ||
		!strings.HasSuffix(err.Error(), "keydata1 is not a related key file") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestUpdateKeyPCRProtectionPolicyMultipleUnrelated2(t *testing.T) {
	// Test that UpdateKeyPCRProtectionPolicyMultiple rejects keys that use different
	// auth keys.
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
		t.Errorf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUpdateKeyPCRProtectionPolicyMultiple12_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	var keyFiles []string

	keyFile := filepath.Join(tmpDir, "keyfile0")
	authKey, err := SealKeyToTPM(tpm, key, keyFile, &KeyCreationParams{
		PCRProfile:             getTestPCRProfile(),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	if err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	keyFiles = append(keyFiles, keyFile)

	for i := 1; i < 3; i++ {
		keyFile := filepath.Join(tmpDir, fmt.Sprintf("keydata%d", i))
		if _, err := SealKeyToTPM(tpm, key, keyFile, &KeyCreationParams{
			PCRProfile:             getTestPCRProfile(),
			PCRPolicyCounterHandle: tpm2.HandleNull}); err != nil {
			t.Fatalf("SealKeyToTPM failed: %v", err)
		}
		keyFiles = append(keyFiles, keyFile)
	}

	if err := UpdateKeyPCRProtectionPolicyMultiple(tpm, keyFiles, authKey, nil); err == nil ||
		!strings.HasSuffix(err.Error(), "keydata1 is not a related key file") {
		t.Errorf("Unexpected error: %v", err)
	}
}
