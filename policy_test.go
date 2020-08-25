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
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"sort"
	"testing"
	"unsafe"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
)

func validateLockNVIndex(t *testing.T, tpm *tpm2.TPMContext) {
	index, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
	if err != nil {
		t.Fatalf("Cannot create context for lock NV index: %v", err)
	}

	// Validate the properties of the index
	pub, _, err := tpm.NVReadPublic(index)
	if err != nil {
		t.Fatalf("NVReadPublic failed: %v", err)
	}

	if pub.NameAlg != tpm2.HashAlgorithmSHA256 {
		t.Errorf("Lock NV index has the wrong name algorithm")
	}
	if pub.Attrs.Type() != tpm2.NVTypeOrdinary {
		t.Errorf("Lock NV index has the wrong type")
	}
	if pub.Attrs.AttrsOnly() != tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead|tpm2.AttrNVNoDA|tpm2.AttrNVReadStClear|tpm2.AttrNVWritten {
		t.Errorf("Lock NV index has the wrong attributes")
	}
	if pub.Size != uint16(0) {
		t.Errorf("Lock NV index has the wrong size")
	}

	dataIndex, err := tpm.CreateResourceContextFromTPM(LockNVDataHandle)
	if err != nil {
		t.Fatalf("Cannot create context for lock policy data NV index: %v", err)
	}

	dataPub, _, err := tpm.NVReadPublic(dataIndex)
	if err != nil {
		t.Fatalf("NVReadPublic failed: %v", err)
	}
	data, err := tpm.NVRead(dataIndex, dataIndex, dataPub.Size, 0, nil)
	if err != nil {
		t.Fatalf("NVRead failed: %v", err)
	}

	var version uint8
	var keyName tpm2.Name
	var clock uint64
	if _, err := tpm2.UnmarshalFromBytes(data, &version, &keyName, &clock); err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}

	if version != 0 {
		t.Errorf("Unexpected version for lock NV index policy")
	}

	clockBytes := make([]byte, binary.Size(clock))
	binary.BigEndian.PutUint64(clockBytes, clock)

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyCommandCode(tpm2.CommandNVWrite)
	trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
	trial.PolicySigned(keyName, nil)

	if !bytes.Equal(trial.GetDigest(), pub.AuthPolicy) {
		t.Errorf("Lock NV index has the wrong authorization policy")
	}
}

func TestIncrementDynamicPolicyCounter(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	key, err := rsa.GenerateKey(testutil.RandReader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		t.Fatalf("Cannot compute key name: %v", err)
	}

	policyCounterPub, err := CreateDynamicPolicyCounter(tpm.TPMContext, 0x0181ff00, keyName, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreateDynamicPolicyCounter failed: %v", err)
	}
	defer func() {
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(policyCounterPub)
		if err != nil {
			t.Errorf("CreateNVIndexResourceContextFromPublic failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}()

	initialCount, err := ReadDynamicPolicyCounter(tpm.TPMContext, CurrentMetadataVersion, policyCounterPub, nil, tpm.HmacSession())
	if err != nil {
		t.Errorf("ReadDynamicPolicyCounter failed: %v", err)
	}

	if err := IncrementDynamicPolicyCounter(tpm.TPMContext, CurrentMetadataVersion, policyCounterPub, nil, key, keyPublic, tpm.HmacSession()); err != nil {
		t.Fatalf("IncrementDynamicPolicyCounter failed: %v", err)
	}

	count, err := ReadDynamicPolicyCounter(tpm.TPMContext, CurrentMetadataVersion, policyCounterPub, nil, tpm.HmacSession())
	if err != nil {
		t.Errorf("ReadDynamicPolicyCounter failed: %v", err)
	}
	if count != initialCount+1 {
		t.Errorf("ReadDynamicPolicyCounter returned an unexpected count (got %d, expected %d)", count, initialCount+1)
	}
}

func TestReadDynamicPolicyCounter(t *testing.T) {
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

	policyCounterPub, err := CreateDynamicPolicyCounter(tpm.TPMContext, 0x0181ff00, nil, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreateDynamicPolicyCounter failed: %v", err)
	}
	defer func() {
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(policyCounterPub)
		if err != nil {
			t.Errorf("CreateNVIndexResourceContextFromPublic failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}()

	count, err := ReadDynamicPolicyCounter(tpm.TPMContext, CurrentMetadataVersion, policyCounterPub, nil, tpm.HmacSession())
	if err != nil {
		t.Errorf("ReadDynamicPolicyCounter failed: %v", err)
	}
	if count != testCount {
		t.Errorf("ReadDynamicPolicyCounter returned an unexpected count (got %d, expected %d)", count, testCount)
	}
}

func undefineLockNVIndices(t *testing.T, tpm *TPMConnection) {
	if index, err := tpm.CreateResourceContextFromTPM(LockNVHandle); err == nil {
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}
	if index, err := tpm.CreateResourceContextFromTPM(LockNVDataHandle); err == nil {
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}
}

func TestEnsureLockNVIndex(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	undefineLockNVIndices(t, tpm)
	if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("EnsureLockNVIndex failed: %v", err)
	}
	defer func() {
		index, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
		if err != nil {
			t.Errorf("CreateResourceContextFromTPM failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
		index, err = tpm.CreateResourceContextFromTPM(LockNVDataHandle)
		if err != nil {
			t.Errorf("CreateResourceContextFromTPM failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}()

	validateLockNVIndex(t, tpm.TPMContext)

	index, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
	if err != nil {
		t.Fatalf("No lock NV index created")
	}
	origName := index.Name()

	if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("EnsureLockNVIndex failed: %v", err)
	}

	index, err = tpm.CreateResourceContextFromTPM(LockNVHandle)
	if err != nil {
		t.Fatalf("No lock NV index created")
	}
	if !bytes.Equal(index.Name(), origName) {
		t.Errorf("lock NV index shouldn't have been recreated")
	}
}

func TestReadAndValidateLockNVIndexPublic(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	prepare := func(t *testing.T) (tpm2.ResourceContext, tpm2.ResourceContext) {
		undefineLockNVIndices(t, tpm)
		if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
			t.Errorf("EnsureLockNVIndex failed: %v", err)
		}
		index, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
		if err != nil {
			t.Fatalf("No lock NV index created")
		}
		dataIndex, err := tpm.CreateResourceContextFromTPM(LockNVDataHandle)
		if err != nil {
			t.Fatalf("No lock NV data index created")
		}
		return index, dataIndex
	}

	t.Run("Good", func(t *testing.T) {
		index, dataIndex := prepare(t)
		defer func() {
			undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
			undefineNVSpace(t, tpm, dataIndex, tpm.OwnerHandleContext())
		}()
		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err != nil {
			t.Fatalf("ReadAndValidateLockNVIndexPublic failed: %v", err)
		}
		if pub.Index != LockNVHandle {
			t.Errorf("Returned public area has wrong handle")
		}
		if pub.Attrs != LockNVIndexAttrs|tpm2.AttrNVWritten {
			t.Errorf("incorrect lock NV index attributes")
		}
	})

	t.Run("ReadLocked", func(t *testing.T) {
		index, dataIndex := prepare(t)
		defer func() {
			undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
			undefineNVSpace(t, tpm, dataIndex, tpm.OwnerHandleContext())
		}()
		if err := tpm.NVReadLock(index, index, nil); err != nil {
			t.Fatalf("NVReadLock failed: %v", err)
		}
		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err != nil {
			t.Fatalf("ReadAndValidateLockNVIndexPublic failed: %v", err)
		}
		if pub.Index != LockNVHandle {
			t.Errorf("Returned public area has wrong handle")
		}
		if pub.Attrs != LockNVIndexAttrs|tpm2.AttrNVWritten {
			t.Errorf("incorrect lock NV index attributes")
		}
	})

	t.Run("NoPolicyDataIndex", func(t *testing.T) {
		index, dataIndex := prepare(t)
		defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), dataIndex, nil); err != nil {
			t.Fatalf("NVUndefineSpace failed: %v", err)
		}
		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if pub != nil {
			t.Errorf("ReadAndValidateLockNVIndexPublic should have returned no public area")
		}
		if !tpm2.IsResourceUnavailableError(err, LockNVDataHandle) {
			t.Errorf("Unexpected error type")
		}
	})

	t.Run("IncorrectClockValue", func(t *testing.T) {
		index, dataIndex := prepare(t)
		dataIndexUndefined := false
		defer func() {
			undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
			if dataIndexUndefined {
				return
			}
			undefineNVSpace(t, tpm, dataIndex, tpm.OwnerHandleContext())
		}()

		// Test with a policy data index that indicates a time in the future.

		dataPub, _, err := tpm.NVReadPublic(dataIndex)
		if err != nil {
			t.Fatalf("NVReadPublic failed: %v", err)
		}
		data, err := tpm.NVRead(dataIndex, dataIndex, dataPub.Size, 0, nil)
		if err != nil {
			t.Fatalf("NVRead failed: %v", err)
		}
		var version uint8
		var keyName tpm2.Name
		var clock uint64
		if _, err := tpm2.UnmarshalFromBytes(data, &version, &keyName, &clock); err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
		}

		time, err := tpm.ReadClock()
		if err != nil {
			t.Fatalf("ReadClock failed: %v", err)
		}

		data, err = tpm2.MarshalToBytes(version, keyName, time.ClockInfo.Clock+3600000)
		if err != nil {
			t.Errorf("MarshalToBytes failed: %v", err)
		}

		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), dataIndex, nil); err != nil {
			t.Fatalf("NVUndefineSpace failed: %v", err)
		}
		dataIndexUndefined = true

		public := tpm2.NVPublic{
			Index:   LockNVDataHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
			Size:    uint16(len(data))}
		dataIndex, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &public, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, dataIndex, tpm.OwnerHandleContext())

		if err := tpm.NVWrite(dataIndex, dataIndex, data, 0, nil); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}
		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err == nil {
			t.Fatalf("ReadAndValidateLockNVIndexPublic should have failed")
		}
		if pub != nil {
			t.Errorf("ReadAndValidateLockNVIndexPublic should have returned no public area")
		}
		if err.Error() != "unexpected clock value in policy data" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("IncorrectPolicy", func(t *testing.T) {
		clearTPMWithPlatformAuth(t, tpm)

		// Test with a bogus lock NV index that allows writes far in to the future, making it possible
		// to recreate it to remove the read lock bit.

		key, err := rsa.GenerateKey(testutil.RandReader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
		keyName, err := keyPublic.Name()
		if err != nil {
			t.Errorf("Cannot compute key name: %v", err)
		}

		time, err := tpm.ReadClock()
		if err != nil {
			t.Fatalf("ReadClock failed: %v", err)
		}
		time.ClockInfo.Clock += 5000
		clockBytes := make(tpm2.Operand, binary.Size(time.ClockInfo.Clock))
		binary.BigEndian.PutUint64(clockBytes, time.ClockInfo.Clock+3600000000)

		trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
		trial.PolicyCommandCode(tpm2.CommandNVWrite)
		trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
		trial.PolicySigned(keyName, nil)

		public := tpm2.NVPublic{
			Index:      LockNVHandle,
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      LockNVIndexAttrs,
			AuthPolicy: trial.GetDigest(),
			Size:       0}
		index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &public, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())

		policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer tpm.FlushContext(policySession)

		h := tpm2.HashAlgorithmSHA256.NewHash()
		h.Write(policySession.NonceTPM())
		binary.Write(h, binary.BigEndian, int32(0))

		sig, err := rsa.SignPSS(testutil.RandReader, key, tpm2.HashAlgorithmSHA256.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			t.Errorf("SignPSS failed: %v", err)
		}

		keyLoaded, err := tpm.LoadExternal(nil, keyPublic, tpm2.HandleEndorsement)
		if err != nil {
			t.Fatalf("LoadExternal failed: %v", err)
		}
		defer tpm.FlushContext(keyLoaded)

		signature := tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgRSAPSS,
			Signature: tpm2.SignatureU{
				Data: &tpm2.SignatureRSAPSS{
					Hash: tpm2.HashAlgorithmSHA256,
					Sig:  tpm2.PublicKeyRSA(sig)}}}

		if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVWrite); err != nil {
			t.Errorf("Assertion failed: %v", err)
		}
		if err := tpm.PolicyCounterTimer(policySession, clockBytes, 8, tpm2.OpUnsignedLT); err != nil {
			t.Errorf("Assertion failed: %v", err)
		}
		if _, _, err := tpm.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, &signature); err != nil {
			t.Errorf("Assertion failed: %v", err)
		}

		if err := tpm.NVWrite(index, index, nil, 0, policySession); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}

		data, err := tpm2.MarshalToBytes(uint8(0), keyName, time.ClockInfo.Clock)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		// Create the data index.
		dataPublic := tpm2.NVPublic{
			Index:   LockNVDataHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
			Size:    uint16(len(data))}
		dataIndex, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &dataPublic, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, dataIndex, tpm.OwnerHandleContext())

		if err := tpm.NVWrite(dataIndex, dataIndex, data, 0, nil); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}

		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err == nil {
			t.Fatalf("ReadAndValidateLockNVIndexPublic should have failed")
		}
		if pub != nil {
			t.Errorf("ReadAndValidateLockNVIndexPublic should have returned no public area")
		}
		if err.Error() != "incorrect policy for NV index" {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestComputeStaticPolicy(t *testing.T) {
	block, _ := pem.Decode([]byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvVGKq3nV0WMpEEQBhroTTHjYRZWHjQlSFXkgvUxurXkMlkti
U8LKJqRUI+ekJ5mCQR5JTMnX59HE/jdL1zYzWP6PjKDlpBU5UcY3chWQ9gM2t7+l
VuY/b8fq4We/P6neNBAMOx8Ip8UAuPzCbWSxCqsMq1Mp3iDUcSGM54OEDupATsqj
LTm6elgHz6Ik92Tzy20Z66mYo02M41VenSSndEFA4zORePek2nHOfklRJvokgnX9
ujwuwUAG80EEOrQavBLQFSzmlc9q0N0GeWp23yfl5Cd84RkzNIFgxnLlUH4og5mN
4Ti3YpI57iXvBsOzFIZ+WXYQROEIP3aiJuNOhQIDAQABAoIBAQCMwk7fFdQDPb3v
SRD1ce4dYpAylG3XUAHG02ujM2vq8OCJ8nymGGMi/fVNSNJFWx58eh83x68OvmnA
Na7e0X62AXcLsSlsqRcYFM9utFg2gccyMXymMsUhwDuD4hZRKGR8wx3E61sNGi1i
XRPWMBJuAyWFUG0FqdUqVC6mh6MtTnh2rzPbU6UnT3a6UsGwy6U1FftuexkXY+bb
mfpwA3lR3p1hgqdKF9DC7C4vsSFzBI2M0vVWX0T76GxhVtVle2XLsKrVjqPnUn1D
59vQt1xr/lluHJp/FP9be0wL3bwOTnDdgpBN2APrFcfyJ6kqJuwL6EdFPSsg3C0M
Q73j0kVBAoGBAOP2FMuhsZxhyNDpTZqS6zbdXy2Z3Mjop70tFj2m11gYOYJ10I/J
7fLPhOuFeNA7Kp8S5iH0hTgk+dd9UD8SV/clj14+tdXjLoMDbqWQ4JXurdk/dXML
46eOuRUUxCFFxmR1EwPzaV1nsNOStFd2HG4s4vpPcOVJ7r0RimOjzj9VAoGBANSa
swXqzleRKrGtDRrqUDZXKP43dyVXgQdLRpAIK6W8GdIbcuvYXmBZG1sFYpK7COJR
/xG6CaPPbDHg8VbE7E5WW3tYi7RvycLJoyYW6EhjqVIMYNVFR6BrHugKNa7KSdHK
UwAYKgL6KYtYEU9ZDBEX2HT9Wd9SGXiwvhl/D/JxAoGAG6AIqRyxL2hSM67yLpc7
VezByf7pWJeJLE24ckQzuINHBN5OJf6sjU5Ep14HZASnh5t8tASz2Dfy5wBSpzIL
4vF0TFGBK6haTJov4HSMIt9HxhoAm66HKhkLqNhZZEbWYfomEcZ/sEgOj7UpkafI
jjl2UCssXTz2Z4cmpCiHp/kCgYA8IaUQv2CtE7nnlvJl8m/NbsmBXV6tiRpNXdUP
V8BAl/sVmf3fBstqpMk/7T38EjppCJgEA4JGepw3X0/jIr9TSMmHEXwyBIwkM7OZ
SlFYaBezxRx+NaIUlTegmYKldUF7vKXNGQiI3whxCO+caasoCn6GWEHbD/V0VUjv
HSj9gQKBgDMhQh5RaTBuU8BIEmzS8DVVv6DUi9Wr8vblVPDEDgTEEeRq1B7OIpnk
QZUMW/hqX6qMtjD1lnygOGT3mL9YlSuGyGymsTqWyJM09XbbK9fXm0g3UGv5sOyb
duwzA18V2dm66mFx1NcqfNyRUbclhN26KAaRnTDQrAaxFIgoO+Xm
-----END RSA PRIVATE KEY-----`))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey failed: %v", err)
	}
	publicKey := CreatePublicAreaForRSASigningKey(&key.PublicKey)
	publicKeyName, _ := publicKey.Name()

	policyCounterAuthPolicies, _ := ComputeDynamicPolicyCounterAuthPolicies(tpm2.HashAlgorithmSHA256, publicKeyName)
	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyOR(policyCounterAuthPolicies)

	policyCounterPub := &tpm2.NVPublic{
		Index:      0x0181fff0,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
		AuthPolicy: trial.GetDigest(),
		Size:       8}

	lockIndexPub := tpm2.NVPublic{
		Index:      LockNVHandle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVReadStClear | tpm2.AttrNVWritten),
		AuthPolicy: make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size()),
		Size:       0}
	lockName, _ := lockIndexPub.Name()

	for _, data := range []struct {
		desc             string
		alg              tpm2.HashAlgorithmId
		policyCounterPub *tpm2.NVPublic
		policy           tpm2.Digest
	}{
		{
			desc:             "SHA256",
			alg:              tpm2.HashAlgorithmSHA256,
			policyCounterPub: policyCounterPub,
			policy:           decodeHexStringT(t, "b3040eda571b46a83266c0d548e80dc69932eaa66f3ad724cd1a6db5606cca72"),
		},
		{
			desc:             "SHA1",
			alg:              tpm2.HashAlgorithmSHA1,
			policyCounterPub: policyCounterPub,
			policy:           decodeHexStringT(t, "53401cc75dc653571c955f004700a0f8efb85a34"),
		},
		{
			desc:   "NoPolicyCounter",
			alg:    tpm2.HashAlgorithmSHA256,
			policy: decodeHexStringT(t, "e172910f530f8ba086fd347f57709a5e7aa0528a766c5270d7fd2e2c5bad55ac"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			dataout, policy, err := ComputeStaticPolicy(data.alg, NewStaticPolicyComputeParams(publicKey, data.policyCounterPub, lockName))
			if err != nil {
				t.Fatalf("ComputeStaticPolicy failed: %v", err)
			}
			if dataout.AuthPublicKey().Params.RSADetail().Exponent != uint32(key.PublicKey.E) {
				t.Errorf("Auth key public area has wrong exponent")
			}
			if dataout.AuthPublicKey().Params.RSADetail().KeyBits != uint16(key.PublicKey.N.BitLen()) {
				t.Errorf("Auth key public area has wrong bit length")
			}
			if !bytes.Equal(dataout.AuthPublicKey().Unique.RSA(), key.PublicKey.N.Bytes()) {
				t.Errorf("Auth key public area has wrong modulus")
			}

			expectedPolicyCounterHandle := tpm2.HandleNull
			if data.policyCounterPub != nil {
				expectedPolicyCounterHandle = policyCounterPub.Index
			}
			if dataout.PolicyCounterHandle() != expectedPolicyCounterHandle {
				t.Errorf("Wrong policy counter index handle")
			}

			if len(dataout.V0PinIndexAuthPolicies()) != 0 {
				t.Errorf("Wrong number of legacy PIN NV index auth policies")
			}

			expectedDynamicPolicyRef, _ := ComputeDynamicPolicyRef(data.alg, data.policyCounterPub)
			if !bytes.Equal(dataout.DynamicPolicyRef(), expectedDynamicPolicyRef) {
				t.Errorf("Unexpected dynamic policy ref")
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
			outputPolicy: decodeHexStringT(t, "fd7451c024bafe5f117cab2841c2dd81f5304350bd8b17ef1f667bceda1ffcf9"),
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
			outputPolicy: decodeHexStringT(t, "4088de0181ede03662fabce88ba4385b16448a981f6b399da861dfe6cc955b68"),
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
			outputPolicy: decodeHexStringT(t, "0a023c5b9182d2456407c39bf0ab62f6b86f90a4cec61e594c026a087c43e84c"),
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
			outputPolicy: decodeHexStringT(t, "447f411c3cedd453e53e9b95958774413bea32267a75db8545cd258ed4968575"),
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
	key, err := rsa.GenerateKey(testutil.RandReader, 2048)
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
			policy:            decodeHexStringT(t, "983c996e26d08cdd5a67f3fbdb98fe737e7c6f499e0fd5189ac99719a14c00db"),
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
			policy:            decodeHexStringT(t, "166168f87e22c01dc62b19adab299f4ad18f5b313c81696d70c8bf64ed314208"),
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
			policy:            decodeHexStringT(t, "66f29c63a88ce0d5046999b5067ced2c9e7d9a48"),
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
			policy:            decodeHexStringT(t, "151216fb8a020dbf181c936cb32e03606d5fd0073aa3b3999365e3d9a08d1f8a"),
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
			policy:            decodeHexStringT(t, "a218c6db035ac2a84b229f2eddd3064a79c3b7c9f48d7bb2f3c6f3f3dda8712b"),
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
			policy:            decodeHexStringT(t, "e86c232ba03d8153fd1ebb8d248d64dd18d90acc7c0a3ddf6f0863af3f0c87f5"),
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
			policy:            decodeHexStringT(t, "983c996e26d08cdd5a67f3fbdb98fe737e7c6f499e0fd5189ac99719a14c00db"),
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
			policy:            decodeHexStringT(t, "e516f77fbd8a055c472d0cea472828a825b20096655bc1f5264504794b63d400"),
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
			policy:            decodeHexStringT(t, "926f36ead779ff00e413bba00df3dd0428bd570c7fedb828a8ea2f0c12cc72ac"),
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
			policy:       decodeHexStringT(t, "e76d63a3bf5a231bad618a41699cb15227f53dd7602b8ef79ddb10d3c253e826"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			var pcrDigests tpm2.DigestList
			for _, v := range data.pcrValues {
				d, _ := tpm2.ComputePCRDigest(data.alg, data.pcrs, v)
				pcrDigests = append(pcrDigests, d)
			}
			policyRef, _ := ComputeDynamicPolicyRef(data.alg, policyCounterPub)
			dataout, err := ComputeDynamicPolicy(CurrentMetadataVersion, data.alg, NewDynamicPolicyComputeParams(key, data.signAlg, data.pcrs, pcrDigests, policyCounterName, data.policyCount, policyRef))
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

				if dataout.AuthorizedPolicySignature().SigAlg != tpm2.SigSchemeAlgRSAPSS {
					t.Errorf("Unexpected authorized policy signature algorithm")
				}
				if dataout.AuthorizedPolicySignature().Signature.RSAPSS().Hash != data.signAlg {
					t.Errorf("Unexpected authorized policy signature digest algorithm")
				}

				h := data.signAlg.NewHash()
				h.Write(dataout.AuthorizedPolicy())
				h.Write(policyRef)

				if err := rsa.VerifyPSS(&key.PublicKey, data.signAlg.GetHash(), h.Sum(nil),
					[]byte(dataout.AuthorizedPolicySignature().Signature.RSAPSS().Sig),
					&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
					t.Errorf("Invalid authorized policy signature: %v", err)
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

	undefineLockNVIndices(t, tpm)
	if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("ensureLockNVIndex failed: %v", err)
	}

	key, err := rsa.GenerateKey(testutil.RandReader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		t.Fatalf("Cannot compute key name: %v", err)
	}

	policyCounterPub, err := CreateDynamicPolicyCounter(tpm.TPMContext, 0x0181ff00, keyName, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreateDynamicPolicyCounter failed: %v", err)
	}
	policyCounter, err := tpm2.CreateNVIndexResourceContextFromPublic(policyCounterPub)
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	defer func() { undefineNVSpace(t, tpm, policyCounter, tpm.OwnerHandleContext()) }()

	policyCount, err := ReadDynamicPolicyCounter(tpm.TPMContext, CurrentMetadataVersion, policyCounterPub, nil, tpm.HmacSession())
	if err != nil {
		t.Fatalf("readDynamicPolicyCounter failed: %v", err)
	}

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

		lockIndex, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
		if err != nil {
			t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
		}

		var policyCounterName tpm2.Name
		if data.policyCounterPub != nil {
			policyCounterName, _ = data.policyCounterPub.Name()
		}

		staticPolicyData, policy, err := ComputeStaticPolicy(data.alg, NewStaticPolicyComputeParams(CreatePublicAreaForRSASigningKey(&key.PublicKey), data.policyCounterPub, lockIndex.Name()))
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
			NewDynamicPolicyComputeParams(key, signAlg, data.pcrs, pcrDigests, policyCounterName, data.policyCount, staticPolicyData.DynamicPolicyRef()))
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
		if !IsDynamicPolicyDataError(err) || err.Error() != "the dynamic authorization policy has been revoked" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("Locked", func(t *testing.T) {
		// Test execution when access to sealed key objects has been locked (execution should fail)
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
			}}, func(*StaticPolicyData, *DynamicPolicyData) {
			lockIndex, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
			if err != nil {
				t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
			}
			if err := tpm.NVReadLock(lockIndex, lockIndex, nil); err != nil {
				t.Fatalf("NVReadLock failed: %v", err)
			}
		})
		if !tpm2.IsTPMError(err, tpm2.ErrorNVLocked, tpm2.CommandPolicyNV) || IsStaticPolicyDataError(err) || IsDynamicPolicyDataError(err) {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/PolicyCounterHandle/1", func(t *testing.T) {
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
			s.SetPolicyCounterHandle(0x40ffffff)
		})
		if !IsStaticPolicyDataError(err) || err.Error() != "invalid handle for dynamic authorization policy counter" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/PolicyCounterHandle/2", func(t *testing.T) {
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
			s.SetPolicyCounterHandle(s.PolicyCounterHandle() + 1)
		})
		if !IsStaticPolicyDataError(err) || err.Error() != "no dynamic authorization policy counter found" {
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
		if !IsStaticPolicyDataError(err) || err.Error() != "public area of dynamic authorization policy signature verification key has an "+
			"unsupported name algorithm" {
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
			key, err := rsa.GenerateKey(testutil.RandReader, 2048)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			s.AuthPublicKey().Params.RSADetail().KeyBits = uint16(key.N.BitLen())
			s.AuthPublicKey().Params.RSADetail().Exponent = uint32(key.E)
			s.AuthPublicKey().Unique.Data = tpm2.PublicKeyRSA(key.N.Bytes())
		})
		// Even though this error is caused by broken static metadata, we get a dynamicPolicyDataError error because the signature
		// verification fails. Validation with validateKeyData will detect the real issue though.
		if !IsDynamicPolicyDataError(err) || err.Error() != "cannot verify dynamic authorization policy signature" {
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
			key, err := rsa.GenerateKey(testutil.RandReader, 2048)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			alg := d.AuthorizedPolicySignature().Signature.RSAPSS().Hash
			h := alg.NewHash()
			h.Write(d.AuthorizedPolicy())
			h.Write(s.DynamicPolicyRef())

			sig, err := rsa.SignPSS(testutil.RandReader, key, alg.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Fatalf("SignPSS failed: %v", err)
			}
			d.AuthorizedPolicySignature().Signature.RSAPSS().Sig = tpm2.PublicKeyRSA(sig)
		})
		if !IsDynamicPolicyDataError(err) || err.Error() != "cannot verify dynamic authorization policy signature" {
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
			key, err := rsa.GenerateKey(testutil.RandReader, 2048)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			s.AuthPublicKey().Params.RSADetail().KeyBits = uint16(key.N.BitLen())
			s.AuthPublicKey().Params.RSADetail().Exponent = uint32(key.E)
			s.AuthPublicKey().Unique.Data = tpm2.PublicKeyRSA(key.N.Bytes())

			signAlg := d.AuthorizedPolicySignature().Signature.RSAPSS().Hash
			h := signAlg.NewHash()
			h.Write(d.AuthorizedPolicy())
			h.Write(s.DynamicPolicyRef())

			sig, err := rsa.SignPSS(testutil.RandReader, key, signAlg.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Fatalf("SignPSS failed: %v", err)
			}
			d.AuthorizedPolicySignature().Signature.RSAPSS().Sig = tpm2.PublicKeyRSA(sig)
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
		if !IsDynamicPolicyDataError(err) || err.Error() != "the dynamic authorization policy is invalid" {
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
		if !IsDynamicPolicyDataError(err) || err.Error() != "the dynamic authorization policy is invalid" {
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
		if !IsDynamicPolicyDataError(err) || err.Error() != "the dynamic authorization policy is invalid" {
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

	t.Run("InvalidStaticMetadata/PolicyCounterHandle/3", func(t *testing.T) {
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
			s.SetPolicyCounterHandle(policyCounterPub.Index)
			d.SetPolicyCount(policyCount)
		})
		if !IsDynamicPolicyDataError(err) || err.Error() != "the dynamic authorization policy is invalid" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})
}

func TestLockAccessToSealedKeys(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer func() {
		tpm, _ = resetTPMSimulator(t, tpm, tcti)
		closeTPM(t, tpm)
	}()

	undefineLockNVIndices(t, tpm)
	if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("EnsureLockNVIndex failed: %v", err)
	}

	lockIndex, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
	if err != nil {
		t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
	}

	key, err := rsa.GenerateKey(testutil.RandReader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		t.Fatalf("Cannot compute key name: %v", err)
	}

	policyCounterPub, err := CreateDynamicPolicyCounter(tpm.TPMContext, 0x0181ff00, keyName, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreateDynamicPolicyCounter failed: %v", err)
	}
	policyCounter, err := tpm2.CreateNVIndexResourceContextFromPublic(policyCounterPub)
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	defer func() { undefineNVSpace(t, tpm, policyCounter, tpm.OwnerHandleContext()) }()

	staticPolicyData, policy, err := ComputeStaticPolicy(tpm2.HashAlgorithmSHA256, NewStaticPolicyComputeParams(keyPublic, policyCounterPub, lockIndex.Name()))
	if err != nil {
		t.Fatalf("ComputeStaticPolicy failed: %v", err)
	}

	policyCount, err := ReadDynamicPolicyCounter(tpm.TPMContext, CurrentMetadataVersion, policyCounterPub, nil, tpm.HmacSession())
	if err != nil {
		t.Fatalf("readDynamicPolicyCounter failed: %v", err)
	}

	signAlg := staticPolicyData.AuthPublicKey().NameAlg
	pcrs := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}
	pcrDigest, _ := tpm2.ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrs, tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")}})
	dynamicPolicyData, err := ComputeDynamicPolicy(CurrentMetadataVersion, tpm2.HashAlgorithmSHA256,
		NewDynamicPolicyComputeParams(key, signAlg, pcrs, tpm2.DigestList{pcrDigest}, policyCounter.Name(), policyCount, staticPolicyData.DynamicPolicyRef()))
	if err != nil {
		t.Fatalf("ComputeDynamicPolicy failed: %v", err)
	}

	for i := 0; i < 2; i++ {
		func() {
			tpm, tcti = resetTPMSimulator(t, tpm, tcti)

			if _, err := tpm.PCREvent(tpm.PCRHandleContext(7), []byte("foo"), nil); err != nil {
				t.Fatalf("PCREvent failed: %v", err)
			}

			policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, policySession)

			err = ExecutePolicySession(tpm.TPMContext, policySession, CurrentMetadataVersion, staticPolicyData, dynamicPolicyData, "", tpm.HmacSession())
			if err != nil {
				t.Errorf("ExecutePolicySession failed: %v", err)
			}

			digest, err := tpm.PolicyGetDigest(policySession)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(digest, policy) {
				t.Errorf("Unexpected digests")
			}

			if err := LockAccessToSealedKeys(tpm); err != nil {
				t.Errorf("LockAccessToSealedKeys failed: %v", err)
			}

			if err := tpm.PolicyRestart(policySession); err != nil {
				t.Errorf("PolicyRestart failed: %v", err)
			}

			err = ExecutePolicySession(tpm.TPMContext, policySession, CurrentMetadataVersion, staticPolicyData, dynamicPolicyData, "", tpm.HmacSession())
			if !tpm2.IsTPMError(err, tpm2.ErrorNVLocked, tpm2.CommandPolicyNV) {
				t.Errorf("Unexpected error: %v", err)
			}

			digest, err = tpm.PolicyGetDigest(policySession)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			if bytes.Equal(digest, policy) {
				t.Errorf("Unexpected digests")
			}
		}()
	}
}

func TestLockAccessToSealedKeysUnprovisioned(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T) {
		if err := LockAccessToSealedKeys(tpm); err != nil {
			t.Errorf("LockAccessToSealedKeys failed: %v", err)
		}
	}

	t.Run("NoNVIndex", func(t *testing.T) {
		// Test with no NV index defined.
		undefineLockNVIndices(t, tpm)
		run(t)
	})

	t.Run("UnrelatedNVIndex/1", func(t *testing.T) {
		// Test with a NV index defined that has the wrong attributes.
		undefineLockNVIndices(t, tpm)
		public := tpm2.NVPublic{
			Index:   LockNVHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerWrite | tpm2.AttrNVOwnerRead),
			Size:    8}
		index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &public, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
		run(t)
	})

	t.Run("UnrelatedNVIndex/2", func(t *testing.T) {
		// Test with a NV index defined with the expected attributes, but with a non-empty authorization value.
		undefineLockNVIndices(t, tpm)
		public := tpm2.NVPublic{
			Index:   LockNVHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVReadStClear),
			Size:    0}
		index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), []byte("foo"), &public, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
		run(t)
	})
}
