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
	"encoding/binary"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	. "github.com/snapcore/secboot"

	"golang.org/x/xerrors"
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

func TestEnsureLockNVIndex(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	clearTPMWithPlatformAuth(t, tpm)

	if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("EnsureLockNVIndex failed: %v", err)
	}

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
	tpm, _ := openTPMSimulatorForTesting(t)
	defer func() {
		clearTPMWithPlatformAuth(t, tpm)
		closeTPM(t, tpm)
	}()

	prepare := func(t *testing.T) (tpm2.ResourceContext, tpm2.ResourceContext) {
		clearTPMWithPlatformAuth(t, tpm)
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
		index, _ := prepare(t)
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
		index, _ := prepare(t)
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
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), dataIndex, nil); err != nil {
			t.Fatalf("NVUndefineSpace failed: %v", err)
		}
		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err == nil {
			t.Fatalf("ReadAndValidateLockNVIndexPublic should have failed")
		}
		if pub != nil {
			t.Errorf("ReadAndValidateLockNVIndexPublic should have returned no public area")
		}
		var ruErr tpm2.ResourceUnavailableError
		if !xerrors.As(err, &ruErr) {
			t.Errorf("Unexpected error type")
		}
		if err.Error() != "cannot obtain context for policy data NV index: a resource at handle 0x01801101 is not available on the TPM" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("IncorrectClockValue", func(t *testing.T) {
		index, dataIndex := prepare(t)

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

		public := tpm2.NVPublic{
			Index:   LockNVDataHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
			Size:    uint16(len(data))}
		dataIndex, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &public, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
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

		key, err := rsa.GenerateKey(rand.Reader, 2048)
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

		policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer tpm.FlushContext(policySession)

		h := tpm2.HashAlgorithmSHA256.NewHash()
		h.Write(policySession.NonceTPM())
		binary.Write(h, binary.BigEndian, int32(0))

		sig, err := rsa.SignPSS(rand.Reader, key, tpm2.HashAlgorithmSHA256.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
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
