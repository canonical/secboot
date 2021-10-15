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
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

func getTestPCRProfile() *PCRProtectionProfile {
	return NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7)
}

func TestSealKeyToTPM(t *testing.T) {
	key := make([]byte, 64)
	rand.Read(key)

	provision := func(t *testing.T) (*Connection, *tpm2test.TCTI, func()) {
		tpm, tcti, closeTPM := tpm2test.OpenTPMConnectionT(t,
			tpm2test.TPMFeatureOwnerHierarchy|
				tpm2test.TPMFeatureEndorsementHierarchy|
				tpm2test.TPMFeatureNV)

		if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
			t.Fatalf("EnsureProvisioned failed: %v", err)
		}

		return tpm, tcti, closeTPM
	}

	run := func(t *testing.T, tpm *Connection, params *KeyCreationParams) (authKeyBytes []byte) {
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

		if err := ValidateKeyDataFile(tpm.TPMContext, keyFile, authPrivateKey, tpm.HmacSession()); err != nil {
			t.Errorf("ValidateKeyDataFile failed: %v", err)
		}

		return authPrivateKey
	}

	t.Run("Standard", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("DifferentPCRPolicyCounterHandle", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x0181fff0})
	})

	t.Run("SealWithNewConnection", func(t *testing.T) {
		// SealKeyToTPM behaves slightly different if called immediately after EnsureProvisioned with the same Connection
		tpm, tcti, _ := provision(t)
		defer func() {
			if err := tpm.Close(); err != nil {
				t.Errorf("close failed: %v", err)
			}
		}()

		tpm, _, _ = tpm2test.NewTPMConnectionFromExistingT(t, tpm, tcti)
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("MissingSRK", func(t *testing.T) {
		// Ensure that calling SealKeyToTPM recreates the SRK with the standard template
		tpm, tcti, _ := provision(t)
		defer func() {
			if err := tpm.Close(); err != nil {
				t.Errorf("close failed: %v", err)
			}
		}()

		srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
		if err != nil {
			t.Fatalf("No SRK: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srk, srk.Handle(), nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		tpm, _, _ = tpm2test.NewTPMConnectionFromExistingT(t, tpm, tcti)
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})

		validateSRK(t, tpm.TPMContext)
	})

	t.Run("MissingCustomSRK", func(t *testing.T) {
		// Ensure that calling SealKeyToTPM recreates the SRK with the custom
		// template originally supplied during provisioning
		tpm, tcti, _ := provision(t)
		defer func() {
			if err := tpm.Close(); err != nil {
				t.Errorf("close failed: %v", err)
			}
		}()

		srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
		if err != nil {
			t.Fatalf("No SRK: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srk, srk.Handle(), nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		template := tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
				tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}

		tmplB, err := mu.MarshalToBytes(template)
		if err != nil {
			t.Errorf("MarshalToBytes failed: %v", err)
		}

		nvPub := tpm2.NVPublic{
			Index:   SrkTemplateHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVOwnerRead | tpm2.AttrNVNoDA),
			Size:    uint16(len(tmplB))}
		nv, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPub, nil)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		if err := tpm.NVWrite(nv, nv, tmplB, 0, nil); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}

		tpm, _, _ = tpm2test.NewTPMConnectionFromExistingT(t, tpm, tcti)
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})

		validatePrimaryKeyAgainstTemplate(t, tpm.TPMContext, tpm2.HandleOwner, tcg.SRKHandle, &template)
	})

	t.Run("MissingSRKWithInvalidCustomTemplate", func(t *testing.T) {
		// Ensure that calling SealKeyToTPM recreates the SRK with the standard
		// template if the NV index we use to store custom templates has invalid
		// contents - if the contents are invalid then we didn't create it.
		tpm, tcti, _ := provision(t)
		defer func() {
			if err := tpm.Close(); err != nil {
				t.Errorf("close failed: %v", err)
			}
		}()

		srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
		if err != nil {
			t.Fatalf("No SRK: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srk, srk.Handle(), nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		template := tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
				tpm2.AttrRestricted | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.RSAScheme{
						Scheme: tpm2.RSASchemeRSAPSS,
						Details: &tpm2.AsymSchemeU{
							RSAPSS: &tpm2.SigSchemeRSAPSS{HashAlg: tpm2.HashAlgorithmSHA256},
						},
					},
					KeyBits:  2048,
					Exponent: 0}}}

		tmplB, err := mu.MarshalToBytes(template)
		if err != nil {
			t.Errorf("MarshalToBytes failed: %v", err)
		}

		nvPub := tpm2.NVPublic{
			Index:   SrkTemplateHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVOwnerRead | tpm2.AttrNVNoDA),
			Size:    uint16(len(tmplB))}
		nv, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPub, nil)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		if err := tpm.NVWrite(nv, nv, tmplB, 0, nil); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}

		tpm, _, _ = tpm2test.NewTPMConnectionFromExistingT(t, tpm, tcti)
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})

		validateSRK(t, tpm.TPMContext)
	})

	t.Run("NilPCRProfile", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
		run(t, tpm, &KeyCreationParams{PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("NoPCRPolicyCounterHandle", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
		run(t, tpm, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	})

	t.Run("WithProvidedAuthKey", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
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
	key := make([]byte, 64)
	rand.Read(key)

	provision := func(t *testing.T) (*Connection, *tpm2test.TCTI, func()) {
		tpm, tcti, closeTPM := tpm2test.OpenTPMConnectionT(t,
			tpm2test.TPMFeatureOwnerHierarchy|
				tpm2test.TPMFeatureEndorsementHierarchy|
				tpm2test.TPMFeatureNV)

		if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
			t.Fatalf("EnsureProvisioned failed: %v", err)
		}

		return tpm, tcti, closeTPM
	}

	run := func(t *testing.T, tpm *Connection, n int, params *KeyCreationParams) (authKeyBytes PolicyAuthKey) {
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

		for _, k := range keys {
			if err := ValidateKeyDataFile(tpm.TPMContext, k.Path, authPrivateKey, tpm.HmacSession()); err != nil {
				t.Errorf("ValidateKeyDataFile failed: %v", err)
			}
		}

		return authPrivateKey
	}

	t.Run("Single", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
		run(t, tpm, 1, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("2Keys", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
		run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("DifferentPCRPolicyCounterHandle", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
		run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x0181fff0})
	})

	t.Run("SealWithNewConnection", func(t *testing.T) {
		// SealKeyToTPM behaves slightly different if called immediately after EnsureProvisioned with the same Connection
		tpm, tcti, _ := provision(t)
		defer func() {
			if err := tpm.Close(); err != nil {
				t.Errorf("close failed: %v", err)
			}
		}()

		tpm, _, _ = tpm2test.NewTPMConnectionFromExistingT(t, tpm, tcti)
		run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("NoSRK", func(t *testing.T) {
		tpm, tcti, _ := provision(t)
		defer func() {
			if err := tpm.Close(); err != nil {
				t.Errorf("close failed: %v", err)
			}
		}()

		srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
		if err != nil {
			t.Fatalf("No SRK: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srk, srk.Handle(), nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		tpm, _, _ = tpm2test.NewTPMConnectionFromExistingT(t, tpm, tcti)
		run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("NilPCRProfile", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
		run(t, tpm, 2, &KeyCreationParams{PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("NoPCRPolicyCounterHandle", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
		run(t, tpm, 2, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	})

	t.Run("WithProvidedAuthKey", func(t *testing.T) {
		tpm, _, closeTPM := provision(t)
		defer closeTPM()
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
	key := make([]byte, 64)
	rand.Read(key)

	provision := func(t *testing.T) (*Connection, func()) {
		tpm, _, closeTPM := tpm2test.OpenTPMConnectionT(t,
			tpm2test.TPMFeatureOwnerHierarchy|
				tpm2test.TPMFeatureEndorsementHierarchy|
				tpm2test.TPMFeatureNV)

		if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
			t.Fatalf("EnsureProvisioned failed: %v", err)
		}

		return tpm, closeTPM
	}

	run := func(t *testing.T, tpm *Connection, tmpDir string, params *KeyCreationParams) error {
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
		tpm, closeTPM := provision(t)
		defer closeTPM()

		err := run(t, tpm, "", nil)
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "no KeyCreationParams provided" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("OwnerAuthFail", func(t *testing.T) {
		tpm, closeTPM := provision(t)
		defer closeTPM()

		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		tpm.OwnerHandleContext().SetAuthValue(nil)

		err := run(t, tpm, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
		if e, ok := err.(AuthFailError); !ok || e.Handle != tpm2.HandleOwner {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("PinNVIndexExists", func(t *testing.T) {
		tpm, closeTPM := provision(t)
		defer closeTPM()

		public := tpm2.NVPublic{
			Index:   0x0181ffff,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead),
			Size:    0}
		if _, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &public, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		err := run(t, tpm, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: public.Index})
		if e, ok := err.(TPMResourceExistsError); !ok || e.Handle != public.Index {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("InvalidPCRProfile", func(t *testing.T) {
		tpm, closeTPM := provision(t)
		defer closeTPM()

		pcrProfile := NewPCRProtectionProfile().
			AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).
			AddProfileOR(
				NewPCRProtectionProfile(),
				NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 8))
		err := run(t, tpm, "", &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: 0x01810000})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "cannot compute dynamic authorization policy: cannot compute PCR digests from protection profile: not all "+
			"branches contain values for the same sets of PCRs" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("InvalidPCRProfileSelection", func(t *testing.T) {
		tpm, closeTPM := provision(t)
		defer closeTPM()

		pcrProfile := NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 50, make([]byte, tpm2.HashAlgorithmSHA256.Size()))
		err := run(t, tpm, "", &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: 0x01810000})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "cannot compute dynamic authorization policy: PCR protection profile contains digests for unsupported PCRs" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("WrongCurve", func(t *testing.T) {
		tpm, closeTPM := provision(t)
		defer closeTPM()

		authKey, err := ecdsa.GenerateKey(elliptic.P384(), testutil.RandReader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		err = run(t, tpm, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000, AuthKey: authKey})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "provided AuthKey must be from elliptic.P256, no other curve is supported" {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestSealKeyToExternalTPMStorageKey(t *testing.T) {
	pcrProfile := func() *PCRProtectionProfile {
		return NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, make([]byte, 32))
	}

	key := make([]byte, 32)
	rand.Read(key)

	run := func(t *testing.T, params *KeyCreationParams) (authKeyBytes []byte) {
		tpm, _, closeTPM := tpm2test.OpenTPMConnectionT(t,
			tpm2test.TPMFeatureOwnerHierarchy|
				tpm2test.TPMFeatureEndorsementHierarchy|
				tpm2test.TPMFeatureNV)
		defer closeTPM()

		if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
			t.Errorf("Failed to provision TPM for test: %v", err)
		}

		srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
		if err != nil {
			t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
		}

		srkPub, _, _, err := tpm.ReadPublic(srk)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}

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
		tpm, _, closeTPM := tpm2test.OpenTPMConnectionT(t,
			tpm2test.TPMFeatureOwnerHierarchy|
				tpm2test.TPMFeatureEndorsementHierarchy|
				tpm2test.TPMFeatureNV)
		defer closeTPM()

		if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
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
	key := make([]byte, 64)
	rand.Read(key)

	run := func(t *testing.T, params *KeyCreationParams) {
		tpm, _, closeTPM := tpm2test.OpenTPMConnectionT(t,
			tpm2test.TPMFeatureOwnerHierarchy|
				tpm2test.TPMFeatureEndorsementHierarchy|
				tpm2test.TPMFeatureLockoutHierarchy|
				tpm2test.TPMFeaturePCR|
				tpm2test.TPMFeatureNV)
		defer closeTPM()

		if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
			t.Fatalf("EnsureProvisioned failed: %v", err)
		}

		tmpDir, err := ioutil.TempDir("", "_TestUpdateKeyPCRProtectionPolicy_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		keyFile := filepath.Join(tmpDir, "keydata")

		authKey, err := SealKeyToTPM(tpm, key, keyFile, params)
		if err != nil {
			t.Errorf("SealKeyToTPM failed: %v", err)
		}

		profile := NewPCRProtectionProfile().AddProfileOR(
			NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7),
			NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo")))

		k, err := ReadSealedKeyObjectFromFile(keyFile)
		if err != nil {
			t.Fatalf("ReadSealedKeyObject failed: %v", err)
		}
		if err := k.UpdatePCRProtectionPolicy(tpm, authKey, profile); err != nil {
			t.Errorf("UpdatePCRProtectionPolicy failed: %v", err)
		}

		checkUnseal := func() {
			unsealedKey, _, err := k.UnsealFromTPM(tpm)
			if err != nil {
				t.Errorf("Unseal failed: %v", err)
			}

			if !bytes.Equal(unsealedKey, key) {
				t.Errorf("Unexpected key")
			}
		}

		// Check it unseals with the first branch
		checkUnseal()

		// Modify the PCR state to match the second branch
		if _, err := tpm.PCREvent(tpm.PCRHandleContext(7), []byte("foo"), nil); err != nil {
			t.Errorf("PCREvent failed: %v", err)
		}

		// Check it unseals with the second branch
		checkUnseal()
	}

	t.Run("WithPCRPolicyCounter", func(t *testing.T) {
		run(t, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	})

	t.Run("WithoutPCRPolicyCounter", func(t *testing.T) {
		run(t, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	})
}

func TestRevokeOldPCRProtectionPolicies(t *testing.T) {
	key := make([]byte, 64)
	rand.Read(key)

	checkUnseal := func(t *testing.T, tpm *Connection, k *SealedKeyObject) {
		unsealedKey, _, err := k.UnsealFromTPM(tpm)
		if err != nil {
			t.Errorf("Unseal failed: %v", err)
		}

		if !bytes.Equal(unsealedKey, key) {
			t.Errorf("Unexpected key")
		}
	}

	run := func(t *testing.T, params *KeyCreationParams, fn func(*Connection, *SealedKeyObject)) {
		tpm, _, closeTPM := tpm2test.OpenTPMConnectionT(t,
			tpm2test.TPMFeatureOwnerHierarchy|
				tpm2test.TPMFeatureEndorsementHierarchy|
				tpm2test.TPMFeatureLockoutHierarchy|
				tpm2test.TPMFeaturePCR|
				tpm2test.TPMFeatureNV)
		defer closeTPM()

		if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
			t.Fatalf("Failed to provision TPM for test: %v", err)
		}

		tmpDir, err := ioutil.TempDir("", "_TestUpdateKeyPCRProtectionPolicy_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		keyFile := filepath.Join(tmpDir, "keydata")

		authKey, err := SealKeyToTPM(tpm, key, keyFile, params)
		if err != nil {
			t.Errorf("SealKeyToTPM failed: %v", err)
		}

		k, err := ReadSealedKeyObjectFromFile(keyFile)
		if err != nil {
			t.Fatalf("ReadSealedKeyObject failed: %v", err)
		}
		if err := k.UpdatePCRProtectionPolicy(tpm, authKey, params.PCRProfile); err != nil {
			t.Errorf("UpdatePCRProtectionPolicy failed: %v", err)
		}

		k2, err := ReadSealedKeyObjectFromFile(keyFile)
		if err != nil {
			t.Fatalf("ReadSealedKeyObject failed: %v", err)
		}

		// Check that both files unseal
		checkUnseal(t, tpm, k)
		checkUnseal(t, tpm, k2)

		// Revoke old policies
		if err := k.RevokeOldPCRProtectionPolicies(tpm, authKey); err != nil {
			t.Errorf("RevokeOldPCRProtectionPolicies failed: %v", err)
		}

		// Check current file unseals ok
		checkUnseal(t, tpm, k)
		fn(tpm, k2)
	}

	t.Run("WithPCRPolicyCounter", func(t *testing.T) {
		run(t, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000}, func(tpm *Connection, k *SealedKeyObject) {
			_, _, err := k.UnsealFromTPM(tpm)
			if _, ok := err.(InvalidKeyDataError); !ok ||
				err.Error() != "invalid key data: cannot complete authorization policy assertions: the PCR policy has been revoked" {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	})

	t.Run("WithoutPCRPolicyCounter", func(t *testing.T) {
		run(t, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull}, func(tpm *Connection, k *SealedKeyObject) {
			checkUnseal(t, tpm, k)
		})
	})
}
func TestUpdateKeyPCRProtectionPolicyMultiple(t *testing.T) {
	tpm, _, closeTPM := tpm2test.OpenTPMConnectionT(t,
		tpm2test.TPMFeatureOwnerHierarchy|
			tpm2test.TPMFeatureEndorsementHierarchy|
			tpm2test.TPMFeatureLockoutHierarchy|
			tpm2test.TPMFeaturePCR|
			tpm2test.TPMFeatureNV)
	defer closeTPM()

	if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
		t.Errorf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUpdateKeyPCRProtectionPolicyMultiple_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create initial keyfiles
	var keys []*SealKeyRequest
	for i := 0; i < 2; i++ {
		keys = append(keys, &SealKeyRequest{Key: key, Path: filepath.Join(tmpDir, fmt.Sprintf("keydata%d", i))})
	}

	authKey, err := SealKeyToTPMMultiple(tpm, keys, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: 0x01810000})
	if err != nil {
		t.Errorf("SealKeyToTPMMultiple failed: %v", err)
	}

	// Update policy with 2 branches
	profile := NewPCRProtectionProfile().AddProfileOR(
		NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7),
		NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).
			ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo")))

	var ks []*SealedKeyObject
	for _, key := range keys {
		k, err := ReadSealedKeyObjectFromFile(key.Path)
		if err != nil {
			t.Fatalf("ReadSealedKeyObject failed: %v", err)
		}
		ks = append(ks, k)
	}

	if err := UpdateKeyPCRProtectionPolicyMultiple(tpm, ks, authKey, profile); err != nil {
		t.Errorf("UpdateKeyPCRProtectionPolicy failed: %v", err)
	}

	checkUnseal := func(t *testing.T, k *SealedKeyObject) {
		unsealedKey, _, err := k.UnsealFromTPM(tpm)
		if err != nil {
			t.Errorf("Unseal failed: %v", err)
		}

		if !bytes.Equal(unsealedKey, key) {
			t.Errorf("Unexpected key")
		}
	}

	// Check that the keys unseal with the first branch
	for _, k := range ks {
		checkUnseal(t, k)
	}

	// Modify the PCR state to match the second branch
	if _, err := tpm.PCREvent(tpm.PCRHandleContext(7), []byte("foo"), nil); err != nil {
		t.Errorf("PCREvent failed: %v", err)
	}

	// Check that the keys unseal with the second branch
	for _, k := range ks {
		checkUnseal(t, k)
	}
}

func TestUpdateKeyPCRProtectionPolicyMultipleUnrelated1(t *testing.T) {
	// Test that UpdateKeyPCRProtectionPolicyMultiple rejects keys that have the
	// same auth key, but different policies because they use independent PCR policy
	// counters.
	tpm, _, closeTPM := tpm2test.OpenTPMConnectionT(t,
		tpm2test.TPMFeatureOwnerHierarchy|
			tpm2test.TPMFeatureEndorsementHierarchy|
			tpm2test.TPMFeatureLockoutHierarchy|
			tpm2test.TPMFeatureNV)
	defer closeTPM()

	if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
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

	var keys []*SealedKeyObject
	for i := 0; i < 3; i++ {
		keyFile := filepath.Join(tmpDir, fmt.Sprintf("keydata%d", i))
		if _, err := SealKeyToTPM(tpm, key, keyFile, &KeyCreationParams{
			PCRProfile:             getTestPCRProfile(),
			PCRPolicyCounterHandle: 0x01810000 + tpm2.Handle(i),
			AuthKey:                authKey}); err != nil {
			t.Fatalf("SealKeyToTPM failed: %v", err)
		}

		k, err := ReadSealedKeyObjectFromFile(keyFile)
		if err != nil {
			t.Fatalf("ReadSealedKeyObject failed: %v", err)
		}
		keys = append(keys, k)
	}

	if err := UpdateKeyPCRProtectionPolicyMultiple(tpm, keys, authKey.D.Bytes(), nil); err == nil ||
		!strings.HasSuffix(err.Error(), "key data at index 0 is not related to the primary key data") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestUpdateKeyPCRProtectionPolicyMultipleUnrelated2(t *testing.T) {
	// Test that UpdateKeyPCRProtectionPolicyMultiple rejects keys that use different
	// auth keys.
	tpm, _, closeTPM := tpm2test.OpenTPMConnectionT(t,
		tpm2test.TPMFeatureOwnerHierarchy|
			tpm2test.TPMFeatureEndorsementHierarchy|
			tpm2test.TPMFeatureLockoutHierarchy|
			tpm2test.TPMFeatureNV)
	defer closeTPM()

	if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
		t.Errorf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 64)
	rand.Read(key)

	tmpDir, err := ioutil.TempDir("", "_TestUpdateKeyPCRProtectionPolicyMultiple12_")
	if err != nil {
		t.Fatalf("Creating temporary directory failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	var keys []*SealedKeyObject

	keyFile := filepath.Join(tmpDir, "keyfile0")
	authKey, err := SealKeyToTPM(tpm, key, keyFile, &KeyCreationParams{
		PCRProfile:             getTestPCRProfile(),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	if err != nil {
		t.Fatalf("SealKeyToTPM failed: %v", err)
	}
	k, err := ReadSealedKeyObjectFromFile(keyFile)
	if err != nil {
		t.Fatalf("ReadSealedKeyObject failed: %v", err)
	}
	keys = append(keys, k)

	for i := 1; i < 3; i++ {
		keyFile := filepath.Join(tmpDir, fmt.Sprintf("keydata%d", i))
		if _, err := SealKeyToTPM(tpm, key, keyFile, &KeyCreationParams{
			PCRProfile:             getTestPCRProfile(),
			PCRPolicyCounterHandle: tpm2.HandleNull}); err != nil {
			t.Fatalf("SealKeyToTPM failed: %v", err)
		}

		k, err := ReadSealedKeyObjectFromFile(keyFile)
		if err != nil {
			t.Fatalf("ReadSealedKeyObject failed: %v", err)
		}
		keys = append(keys, k)
	}

	if err := UpdateKeyPCRProtectionPolicyMultiple(tpm, keys, authKey, nil); err == nil ||
		!strings.HasSuffix(err.Error(), "key data at index 0 is not related to the primary key data") {
		t.Errorf("Unexpected error: %v", err)
	}
}
