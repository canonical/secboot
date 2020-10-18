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
	"io/ioutil"
	"math/rand"
	"os"
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

	runNoCleanup := func(t *testing.T, tpm *TPMConnection, params *KeyCreationParams) (authKeyBytes []byte, path string, cleanup func()) {
		tmpDir, err := ioutil.TempDir("", "_TestSealKeyToTPM_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}

		keyFile := tmpDir + "/keydata"

		authPrivateKey, err := SealKeyToTPM(tpm, key, keyFile, params)
		if err != nil {
			t.Errorf("SealKeyToTPM failed: %v", err)
		}

		if err := ValidateKeyDataFile(tpm.TPMContext, keyFile, authPrivateKey, tpm.HmacSession()); err != nil {
			t.Errorf("ValidateKeyDataFile failed: %v", err)
		}

		return authPrivateKey, keyFile, func() {
			undefineKeyNVSpace(t, tpm, keyFile)
			os.RemoveAll(tmpDir)
		}
	}

	run := func(t *testing.T, tpm *TPMConnection, params *KeyCreationParams) (authKeyBytes []byte) {
		authKeyBytes, _, cleanup := runNoCleanup(t, tpm, params)
		cleanup()
		return
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

	t.Run("WithRelatedKey", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		authKey, keyFile, cleanup := runNoCleanup(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
		defer cleanup()

		k, err := ReadSealedKeyObject(keyFile)
		if err != nil {
			t.Fatalf("ReadSealedKeyObject failed: %v", err)
		}

		authKey2 := run(t, tpm, &KeyCreationParams{PCRPolicyCounterHandle: tpm2.HandleNull, RelatedSealedKey: k, RelatedAuthKey: authKey})
		if !bytes.Equal(authKey2, authKey) {
			t.Errorf("Auth key private parts don't match")
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
