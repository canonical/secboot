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
	"testing"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"

	"golang.org/x/xerrors"
)

func validateSRK(t *testing.T, tpm *tpm2.TPMContext) {
	srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		t.Errorf("Cannot create context for SRK: %v", err)
	}

	// Validate the properties of the SRK
	pub, _, _, err := tpm.ReadPublic(srk)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	if pub.Type != tpm2.ObjectTypeRSA {
		t.Errorf("SRK has unexpected type")
	}
	if pub.NameAlg != tpm2.HashAlgorithmSHA256 {
		t.Errorf("SRK has unexpected name algorithm")
	}
	if pub.Attrs != tpm2.AttrFixedTPM|tpm2.AttrFixedParent|tpm2.AttrSensitiveDataOrigin|tpm2.AttrUserWithAuth|tpm2.AttrNoDA|tpm2.AttrRestricted|
		tpm2.AttrDecrypt {
		t.Errorf("SRK has unexpected attributes")
	}
	if pub.Params.RSADetail().Symmetric.Algorithm != tpm2.SymObjectAlgorithmAES {
		t.Errorf("SRK has unexpected symmetric algorithm")
	}
	if pub.Params.RSADetail().Symmetric.KeyBits.Sym() != 128 {
		t.Errorf("SRK has unexpected symmetric key length")
	}
	if pub.Params.RSADetail().Symmetric.Mode.Sym() != tpm2.SymModeCFB {
		t.Errorf("SRK has unexpected symmetric mode")
	}
	if pub.Params.RSADetail().Scheme.Scheme != tpm2.RSASchemeNull {
		t.Errorf("SRK has unexpected RSA scheme")
	}
	if pub.Params.RSADetail().KeyBits != 2048 {
		t.Errorf("SRK has unexpected RSA public modulus length")
	}
	if pub.Params.RSADetail().Exponent != 0 {
		t.Errorf("SRK has an unexpected non-default public exponent")
	}
	if len(pub.Unique.RSA()) != 2048/8 {
		t.Errorf("SRK has an unexpected RSA public modulus length")
	}
}

func validateEK(t *testing.T, tpm *tpm2.TPMContext) {
	ek, err := tpm.CreateResourceContextFromTPM(tcg.EKHandle)
	if err != nil {
		t.Errorf("Cannot create context for EK: %v", err)
	}

	// Validate the properties of the EK
	pub, _, _, err := tpm.ReadPublic(ek)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	if pub.Type != tpm2.ObjectTypeRSA {
		t.Errorf("EK has unexpected type")
	}
	if pub.NameAlg != tpm2.HashAlgorithmSHA256 {
		t.Errorf("EK has unexpected name algorithm")
	}
	if pub.Attrs != tpm2.AttrFixedTPM|tpm2.AttrFixedParent|tpm2.AttrSensitiveDataOrigin|tpm2.AttrAdminWithPolicy|tpm2.AttrRestricted|
		tpm2.AttrDecrypt {
		t.Errorf("EK has unexpected attributes")
	}
	if !bytes.Equal(pub.AuthPolicy, []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7,
		0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa}) {
		t.Errorf("EK has unexpected auth policy")
	}
	if pub.Params.RSADetail().Symmetric.Algorithm != tpm2.SymObjectAlgorithmAES {
		t.Errorf("EK has unexpected symmetric algorithm")
	}
	if pub.Params.RSADetail().Symmetric.KeyBits.Sym() != 128 {
		t.Errorf("EK has unexpected symmetric key length")
	}
	if pub.Params.RSADetail().Symmetric.Mode.Sym() != tpm2.SymModeCFB {
		t.Errorf("EK has unexpected symmetric mode")
	}
	if pub.Params.RSADetail().Scheme.Scheme != tpm2.RSASchemeNull {
		t.Errorf("EK has unexpected RSA scheme")
	}
	if pub.Params.RSADetail().KeyBits != 2048 {
		t.Errorf("EK has unexpected RSA public modulus length")
	}
	if pub.Params.RSADetail().Exponent != 0 {
		t.Errorf("EK has an unexpected non-default public exponent")
	}
	if len(pub.Unique.RSA()) != 2048/8 {
		t.Errorf("EK has an unexpected RSA public modulus length")
	}
}

func TestProvisionNewTPM(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		mode ProvisionMode
	}{
		{
			desc: "Clear",
			mode: ProvisionModeClear,
		},
		{
			desc: "Full",
			mode: ProvisionModeFull,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			clearTPMWithPlatformAuth(t, tpm)

			lockoutAuth := []byte("1234")

			origEk, _ := tpm.EndorsementKey()
			origHmacSession := tpm.HmacSession()

			if err := tpm.EnsureProvisioned(data.mode, lockoutAuth); err != nil {
				t.Fatalf("EnsureProvisioned failed: %v", err)
			}

			validateEK(t, tpm.TPMContext)
			validateSRK(t, tpm.TPMContext)

			// Validate the DA parameters
			props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyMaxAuthFail, 3)
			if err != nil {
				t.Fatalf("GetCapability failed: %v", err)
			}
			if props[0].Value != uint32(32) || props[1].Value != uint32(7200) ||
				props[2].Value != uint32(86400) {
				t.Errorf("ProvisionTPM didn't set the DA parameters correctly")
			}

			// Verify that owner control is disabled, that the lockout hierarchy auth is set, and no
			// other hierarchy auth is set
			props, err = tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
			if err != nil {
				t.Fatalf("GetCapability failed: %v", err)
			}
			if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrLockoutAuthSet == 0 {
				t.Errorf("ProvisionTPM didn't set the lockout hierarchy auth")
			}
			if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear == 0 {
				t.Errorf("ProvisionTPM didn't disable owner clear")
			}
			if tpm2.PermanentAttributes(props[0].Value)&(tpm2.AttrOwnerAuthSet|tpm2.AttrEndorsementAuthSet) > 0 {
				t.Errorf("ProvisionTPM returned with authorizations set for owner or endorsement hierarchies")
			}

			// Test the lockout hierarchy auth
			tpm.LockoutHandleContext().SetAuthValue(lockoutAuth)
			if err := tpm.DictionaryAttackLockReset(tpm.LockoutHandleContext(), nil); err != nil {
				t.Errorf("Use of the lockout hierarchy auth failed: %v", err)
			}

			hmacSession := tpm.HmacSession()
			if hmacSession == nil || hmacSession.Handle().Type() != tpm2.HandleTypeHMACSession {
				t.Errorf("Invalid HMAC session handle")
			}
			if hmacSession == origHmacSession {
				t.Errorf("Invalid HMAC session handle")
			}

			ek, err := tpm.EndorsementKey()
			if err != nil {
				t.Fatalf("No EK context: %v", err)
			}
			if ek.Handle().Type() != tpm2.HandleTypePersistent {
				t.Errorf("Invalid EK handle")
			}
			if ek == origEk {
				t.Errorf("Invalid EK handle")
			}

			// Make sure ProvisionTPM didn't leak transient objects
			handles, err := tpm.GetCapabilityHandles(tpm2.HandleTypeTransient.BaseHandle(), tpm2.CapabilityMaxProperties)
			if err != nil {
				t.Fatalf("GetCapability failed: %v", err)
			}
			if len(handles) > 0 {
				t.Errorf("ProvisionTPM leaked transient handles")
			}

			handles, err = tpm.GetCapabilityHandles(tpm2.HandleTypeLoadedSession.BaseHandle(), tpm2.CapabilityMaxProperties)
			if err != nil {
				t.Fatalf("GetCapability failed: %v", err)
			}
			if len(handles) > 1 || (len(handles) > 0 && handles[0] != hmacSession.Handle()) {
				t.Errorf("ProvisionTPM leaked loaded session handles")
			}
		})
	}
}

func TestProvisionErrorHandling(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer func() {
		clearTPMWithPlatformAuth(t, tpm)
		closeTPM(t, tpm)
	}()

	errEndorsementAuthFail := AuthFailError{Handle: tpm2.HandleEndorsement}
	errOwnerAuthFail := AuthFailError{Handle: tpm2.HandleOwner}
	errLockoutAuthFail := AuthFailError{Handle: tpm2.HandleLockout}

	authValue := []byte("1234")

	setLockoutAuth := func(t *testing.T) {
		if err := tpm.HierarchyChangeAuth(tpm.LockoutHandleContext(), authValue, nil); err != nil {
			t.Fatalf("HierarchyChangeAuth failed: %v", err)
		}
	}
	disableOwnerClear := func(t *testing.T) {
		if err := tpm.ClearControl(tpm.LockoutHandleContext(), true, nil); err != nil {
			t.Fatalf("ClearControl failed: %v", err)
		}
	}

	for _, data := range []struct {
		desc        string
		mode        ProvisionMode
		lockoutAuth []byte
		prepare     func(*testing.T)
		err         error
	}{
		{
			desc: "ErrTPMClearRequiresPPI",
			mode: ProvisionModeClear,
			prepare: func(t *testing.T) {
				disableOwnerClear(t)
			},
			err: ErrTPMClearRequiresPPI,
		},
		{
			desc: "ErrTPMLockoutAuthFail/1",
			mode: ProvisionModeFull,
			prepare: func(t *testing.T) {
				setLockoutAuth(t)
			},
			lockoutAuth: []byte("5678"),
			err:         errLockoutAuthFail,
		},
		{
			desc: "ErrTPMLockoutAuthFail/2",
			mode: ProvisionModeClear,
			prepare: func(t *testing.T) {
				setLockoutAuth(t)
			},
			lockoutAuth: []byte("5678"),
			err:         errLockoutAuthFail,
		},
		{
			desc: "ErrInLockout/1",
			mode: ProvisionModeFull,
			prepare: func(t *testing.T) {
				setLockoutAuth(t)
				tpm.LockoutHandleContext().SetAuthValue(nil)
				tpm.HierarchyChangeAuth(tpm.LockoutHandleContext(), nil, nil)
			},
			lockoutAuth: authValue,
			err:         ErrTPMLockout,
		},
		{
			desc: "ErrInLockout/2",
			mode: ProvisionModeClear,
			prepare: func(t *testing.T) {
				setLockoutAuth(t)
				tpm.LockoutHandleContext().SetAuthValue(nil)
				tpm.HierarchyChangeAuth(tpm.LockoutHandleContext(), nil, nil)
			},
			lockoutAuth: authValue,
			err:         ErrTPMLockout,
		},
		{
			desc: "ErrOwnerAuthFail",
			mode: ProvisionModeWithoutLockout,
			prepare: func(t *testing.T) {
				if err := tpm.HierarchyChangeAuth(tpm.OwnerHandleContext(), authValue, nil); err != nil {
					t.Fatalf("HierarchyChangeAuth failed: %v", err)
				}
			},
			err: errOwnerAuthFail,
		},
		{
			desc: "ErrEndorsementAuthFail",
			mode: ProvisionModeWithoutLockout,
			prepare: func(t *testing.T) {
				if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), authValue, nil); err != nil {
					t.Fatalf("HierarchyChangeAuth failed: %v", err)
				}
			},
			err: errEndorsementAuthFail,
		},
		{
			desc: "ErrTPMProvisioningRequiresLockout/1",
			mode: ProvisionModeWithoutLockout,
			err:  ErrTPMProvisioningRequiresLockout,
		},
		{
			desc: "ErrTPMProvisioningRequiresLockout/2",
			mode: ProvisionModeWithoutLockout,
			prepare: func(t *testing.T) {
				disableOwnerClear(t)
			},
			err: ErrTPMProvisioningRequiresLockout,
		},
		{
			desc: "ErrTPMProvisioningRequiresLockout/3",
			mode: ProvisionModeWithoutLockout,
			prepare: func(t *testing.T) {
				setLockoutAuth(t)
			},
			err: ErrTPMProvisioningRequiresLockout,
		},
		{
			desc: "ErrTPMProvisioningRequiresLockout/4",
			mode: ProvisionModeWithoutLockout,
			prepare: func(t *testing.T) {
				setLockoutAuth(t)
				disableOwnerClear(t)
			},
			err: ErrTPMProvisioningRequiresLockout,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			clearTPMWithPlatformAuth(t, tpm)

			if data.prepare != nil {
				data.prepare(t)
			}
			tpm.LockoutHandleContext().SetAuthValue(data.lockoutAuth)
			tpm.OwnerHandleContext().SetAuthValue(nil)
			tpm.EndorsementHandleContext().SetAuthValue(nil)

			err := tpm.EnsureProvisioned(data.mode, nil)
			if err == nil {
				t.Fatalf("EnsureProvisioned should have returned an error")
			}
			if err != data.err {
				t.Errorf("EnsureProvisioned returned an unexpected error: %v", err)
			}
		})
	}
}

func TestRecreateEK(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		mode ProvisionMode
	}{
		{
			desc: "Full",
			mode: ProvisionModeFull,
		},
		{
			desc: "WithoutLockout",
			mode: ProvisionModeWithoutLockout,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			clearTPMWithPlatformAuth(t, tpm)

			lockoutAuth := []byte("1234")

			if err := tpm.EnsureProvisioned(ProvisionModeFull, lockoutAuth); err != nil {
				t.Fatalf("EnsureProvisioned failed: %v", err)
			}

			ek, err := tpm.EndorsementKey()
			if err != nil {
				t.Fatalf("No EK context: %v", err)
			}
			if ek.Handle().Type() != tpm2.HandleTypePersistent {
				t.Errorf("Invalid EK handle type")
			}
			hmacSession := tpm.HmacSession()
			if hmacSession == nil || hmacSession.Handle().Type() != tpm2.HandleTypeHMACSession {
				t.Errorf("Invalid HMAC session handle")
			}

			ek, err = tpm.CreateResourceContextFromTPM(tcg.EKHandle)
			if err != nil {
				t.Fatalf("No EK context: %v", err)
			}
			if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), ek, ek.Handle(), nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}

			if err := tpm.EnsureProvisioned(data.mode, lockoutAuth); err != nil {
				t.Fatalf("EnsureProvisioned failed: %v", err)
			}

			validateEK(t, tpm.TPMContext)

			hmacSession2 := tpm.HmacSession()
			if hmacSession2 == nil || hmacSession2.Handle().Type() != tpm2.HandleTypeHMACSession {
				t.Errorf("Invalid HMAC session handle")
			}
			ek2, err := tpm.EndorsementKey()
			if err != nil {
				t.Fatalf("No EK context: %v", err)
			}
			if ek2.Handle().Type() != tpm2.HandleTypePersistent {
				t.Errorf("Invalid EK handle")
			}
			if hmacSession.Handle() != tpm2.HandleUnassigned {
				t.Errorf("Original HMAC session should have been flushed")
			}
			if ek == ek2 {
				t.Errorf("Original EK context should have been evicted")
			}
		})
	}
}

func TestRecreateSRK(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		mode ProvisionMode
	}{
		{
			desc: "Full",
			mode: ProvisionModeFull,
		},
		{
			desc: "WithoutLockout",
			mode: ProvisionModeWithoutLockout,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			clearTPMWithPlatformAuth(t, tpm)

			lockoutAuth := []byte("1234")

			if err := tpm.EnsureProvisioned(ProvisionModeFull, lockoutAuth); err != nil {
				t.Fatalf("EnsureProvisioned failed: %v", err)
			}

			srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
			if err != nil {
				t.Fatalf("No SRK context: %v", err)
			}
			expectedName := srk.Name()

			if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srk, srk.Handle(), nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}

			if err := tpm.EnsureProvisioned(data.mode, lockoutAuth); err != nil {
				t.Fatalf("EnsureProvisioned failed: %v", err)
			}

			srk, err = tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
			if err != nil {
				t.Fatalf("No SRK context: %v", err)
			}
			if !bytes.Equal(srk.Name(), expectedName) {
				t.Errorf("Unexpected SRK name")
			}

			validateSRK(t, tpm.TPMContext)
		})
	}
}

func TestProvisionWithEndorsementAuth(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer func() {
		clearTPMWithPlatformAuth(t, tpm)
		closeTPM(t, tpm)
	}()

	clearTPMWithPlatformAuth(t, tpm)

	testAuth := []byte("1234")

	if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), testAuth, nil); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}

	if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
		t.Fatalf("EnsureProvisioned failed: %v", err)
	}

	validateEK(t, tpm.TPMContext)
	validateSRK(t, tpm.TPMContext)
}

func TestProvisionWithOwnerAuth(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer func() {
		clearTPMWithPlatformAuth(t, tpm)
		closeTPM(t, tpm)
	}()

	clearTPMWithPlatformAuth(t, tpm)

	testAuth := []byte("1234")

	if err := tpm.HierarchyChangeAuth(tpm.OwnerHandleContext(), testAuth, nil); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}

	if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
		t.Fatalf("EnsureProvisioned failed: %v", err)
	}

	validateEK(t, tpm.TPMContext)
	validateSRK(t, tpm.TPMContext)
}

func TestProvisionWithInvalidEkCert(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer func() {
		clearTPMWithPlatformAuth(t, tpm)
		closeTPM(t, tpm)
	}()

	clearTPMWithPlatformAuth(t, tpm)

	// Temporarily modify the public template so that ProvisionTPM generates a primary key that doesn't match the EK cert
	ekTemplate := tcg.MakeDefaultEKTemplate()
	ekTemplate.Unique.RSA()[0] = 0xff
	restore := testutil.MockEKTemplate(ekTemplate)
	defer restore()

	err := tpm.EnsureProvisioned(ProvisionModeFull, nil)
	if err == nil {
		t.Fatalf("EnsureProvisioned should have returned an error")
	}
	var ve TPMVerificationError
	if !xerrors.As(err, &ve) && err.Error() != "verification of the TPM failed: cannot verify TPM: endorsement key returned from the "+
		"TPM doesn't match the endorsement certificate" {
		t.Errorf("ProvisionTPM returned an unexpected error: %v", err)
	}
}
