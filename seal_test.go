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
	"io/ioutil"
	"os"
	"syscall"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	. "github.com/snapcore/secboot"

	"golang.org/x/xerrors"
)

func getTestPCRProfile() *PCRProtectionProfile {
	return NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7)
}

func TestSealKeyToTPM(t *testing.T) {
	func() {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)

		if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
			t.Errorf("Failed to provision TPM for test: %v", err)
		}
	}()

	key := make([]byte, 32)
	rand.Read(key)

	run := func(t *testing.T, tpm *TPMConnection, withPolicyUpdateFile bool, params *KeyCreationParams) {
		tmpDir, err := ioutil.TempDir("", "_TestSealKeyToTPM_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		keyFile := tmpDir + "/keydata"
		policyUpdateFile := ""
		if withPolicyUpdateFile {
			policyUpdateFile = tmpDir + "/keypolicyupdatedata"
		}

		if err := SealKeyToTPM(tpm, keyFile, policyUpdateFile, params, getTestPCRProfile(), key); err != nil {
			t.Errorf("SealKeyToTPM failed: %v", err)
		}
		defer undefineKeyNVSpace(t, tpm, keyFile)

		if err := ValidateKeyDataFile(tpm.TPMContext, keyFile, policyUpdateFile, tpm.HmacSession()); err != nil {
			t.Errorf("ValidateKeyDataFile failed: %v", err)
		}
	}

	t.Run("BothFiles", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, true, &KeyCreationParams{PinHandle: 0x01810000})
	})

	t.Run("NoPrivFile", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, false, &KeyCreationParams{PinHandle: 0x01810000})
	})

	t.Run("DifferentPINHandle", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		run(t, tpm, true, &KeyCreationParams{PinHandle: 0x0181fff0})
	})

	t.Run("SealAfterProvision", func(t *testing.T) {
		// SealKeyToTPM behaves slightly different if called immediately after ProvisionTPM with the same TPMConnection
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)
		if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
			t.Errorf("Failed to provision TPM for test: %v", err)
		}
		run(t, tpm, true, &KeyCreationParams{PinHandle: 0x01810000})
	})

	t.Run("NoSRK", func(t *testing.T) {
		tpm := openTPMForTesting(t)
		defer closeTPM(t, tpm)

		srk, err := tpm.CreateResourceContextFromTPM(SrkHandle)
		if err != nil {
			t.Fatalf("No SRK: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srk, srk.Handle(), nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		run(t, tpm, true, &KeyCreationParams{PinHandle: 0x01810000})
	})
}

func TestSealKeyToTPMErrorHandling(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Errorf("Failed to provision TPM for test: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	run := func(t *testing.T, tmpDir string, params *KeyCreationParams, pcrProfile *PCRProtectionProfile, key []byte) error {
		if tmpDir == "" {
			var err error
			tmpDir, err = ioutil.TempDir("", "_TestSealKeyToTPMErrors_")
			if err != nil {
				t.Fatalf("Creating temporary directory failed: %v", err)
			}
		}
		defer os.RemoveAll(tmpDir)

		keyFile := tmpDir + "/keydata"
		policyUpdateFile := tmpDir + "/keypolicyupdatedata"

		origKeyFileInfo, _ := os.Stat(keyFile)
		origPolicyUpdateFileInfo, _ := os.Stat(policyUpdateFile)
		pinIndex, _ := tpm.CreateResourceContextFromTPM(params.PinHandle)

		err := SealKeyToTPM(tpm, keyFile, policyUpdateFile, params, pcrProfile, key)

		if fi, err := os.Stat(keyFile); err == nil && (origKeyFileInfo == nil || origKeyFileInfo.ModTime() != fi.ModTime()) {
			t.Errorf("SealKeyToTPM created a key file")
		}
		if fi, err := os.Stat(policyUpdateFile); err == nil && (origPolicyUpdateFileInfo == nil || origPolicyUpdateFileInfo.ModTime() != fi.ModTime()) {
			t.Errorf("SealKeyToTPM created a key file")
		}
		if index, err := tpm.CreateResourceContextFromTPM(params.PinHandle); err == nil && (pinIndex == nil || !bytes.Equal(pinIndex.Name(), index.Name())) {
			t.Errorf("SealKeyToTPM created a PIN NV index")
		}

		return err
	}

	t.Run("InvalidKeyLength", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		err := run(t, "", &KeyCreationParams{PinHandle: 0x01810000}, getTestPCRProfile(), key)
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "expected a key length of 256 bits (got 128)" {
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

		err := run(t, "", &KeyCreationParams{PinHandle: 0x01810000}, getTestPCRProfile(), key)
		if e, ok := err.(AuthFailError); !ok || e.Handle != tpm2.HandleOwner {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Provisioning/1", func(t *testing.T) {
		index, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
		if err != nil {
			t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
		}
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
		defer func() {
			index, err := tpm.CreateResourceContextFromTPM(LockNVDataHandle)
			if err != nil {
				t.Errorf("CreateResourceContextFromTPM failed: %v", err)
			}
			if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, nil); err != nil {
				t.Errorf("NVUndefineSpace failed: %v", err)
			}
			if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
				t.Errorf("Failed to re-provision TPM after test: %v", err)
			}
		}()
		if err := run(t, "", &KeyCreationParams{PinHandle: 0x01810000}, getTestPCRProfile(), key); err != ErrTPMProvisioning {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Provisioning/2", func(t *testing.T) {
		index, err := tpm.CreateResourceContextFromTPM(LockNVDataHandle)
		if err != nil {
			t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
		}
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, nil); err != nil {
			t.Errorf("NVUndefineSpace failed: %v", err)
		}
		defer func() {
			index, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
			if err != nil {
				t.Errorf("CreateResourceContextFromTPM failed: %v", err)
			}
			if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, nil); err != nil {
				t.Errorf("NVUndefineSpace failed: %v", err)
			}
			if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
				t.Errorf("Failed to re-provision TPM after test: %v", err)
			}
		}()
		if err := run(t, "", &KeyCreationParams{PinHandle: 0x01810000}, getTestPCRProfile(), key); err != ErrTPMProvisioning {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("FileExists/1", func(t *testing.T) {
		tmpDir, err := ioutil.TempDir("", "_TestSealKeyToTPMErrors_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		f, err := os.OpenFile(tmpDir+"/keydata", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		defer f.Close()
		err = run(t, tmpDir, &KeyCreationParams{PinHandle: 0x01810000}, getTestPCRProfile(), key)
		var e *os.PathError
		if !xerrors.As(err, &e) || e.Path != tmpDir+"/keydata" || e.Err != syscall.EEXIST {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("FileExists/2", func(t *testing.T) {
		tmpDir, err := ioutil.TempDir("", "_TestSealKeyToTPMErrors_")
		if err != nil {
			t.Fatalf("Creating temporary directory failed: %v", err)
		}
		f, err := os.OpenFile(tmpDir+"/keypolicyupdatedata", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		defer f.Close()
		err = run(t, tmpDir, &KeyCreationParams{PinHandle: 0x01810000}, getTestPCRProfile(), key)
		var e *os.PathError
		if !xerrors.As(err, &e) || e.Path != tmpDir+"/keypolicyupdatedata" || e.Err != syscall.EEXIST {
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
		err = run(t, "", &KeyCreationParams{PinHandle: public.Index}, getTestPCRProfile(), key)
		if e, ok := err.(TPMResourceExistsError); !ok || e.Handle != public.Index {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}
