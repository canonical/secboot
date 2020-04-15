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
	"math/rand"
	"os"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	. "github.com/snapcore/secboot"

	. "gopkg.in/check.v1"
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

type pinSuite struct {
	tpmTestBase
	key       []byte
	pinHandle tpm2.Handle
	keyFile   string
}

var _ = Suite(&pinSuite{})

func (s *pinSuite) SetUpSuite(c *C) {
	s.key = make([]byte, 64)
	rand.Read(s.key)
	s.pinHandle = tpm2.Handle(0x0181fff0)
}

func (s *pinSuite) SetUpTest(c *C) {
	s.tpmTestBase.SetUpTest(c)
	c.Assert(ProvisionTPM(s.tpm, ProvisionModeFull, nil), IsNil)

	dir := c.MkDir()
	s.keyFile = dir + "/keydata"

	c.Assert(SealKeyToTPM(s.tpm, s.key, s.keyFile, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PINHandle: s.pinHandle}), IsNil)
	pinIndex, err := s.tpm.CreateResourceContextFromTPM(s.pinHandle)
	c.Assert(err, IsNil)
	s.addCleanupNVSpace(c, s.tpm.OwnerHandleContext(), pinIndex)
}

func (s *pinSuite) checkPIN(c *C, pin string) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)
	if pin == "" {
		c.Check(k.AuthMode2F(), Equals, AuthModeNone)
	} else {
		c.Check(k.AuthMode2F(), Equals, AuthModePIN)
	}

	// Verify that the PIN change succeeded by executing a PolicySecret assertion, which is immediate and will fail if it
	// didn't work.
	policySession, err := s.tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	pinIndex, err := s.tpm.CreateResourceContextFromTPM(k.PINIndexHandle())
	c.Assert(err, IsNil)
	pinIndex.SetAuthValue([]byte(pin))

	_, _, err = s.tpm.PolicySecret(pinIndex, policySession, nil, nil, 0, nil)
	c.Check(err, IsNil)
}

func (s *pinSuite) TestSetAndClearPIN(c *C) {
	testPIN := "1234"
	c.Check(ChangePIN(s.tpm, s.keyFile, "", testPIN), IsNil)
	s.checkPIN(c, testPIN)

	c.Check(ChangePIN(s.tpm, s.keyFile, testPIN, ""), IsNil)
	s.checkPIN(c, "")
}

func (s *pinSuite) TestChangePINDoesntUpdateFileIfAuthModeDoesntChange(c *C) {
	fi1, err := os.Stat(s.keyFile)
	c.Assert(err, IsNil)

	c.Check(ChangePIN(s.tpm, s.keyFile, "", ""), IsNil)
	s.checkPIN(c, "")

	fi2, err := os.Stat(s.keyFile)
	c.Assert(err, IsNil)
	c.Check(fi2.ModTime(), DeepEquals, fi1.ModTime())
}

type testChangePINErrorHandlingData struct {
	keyFile        string
	errChecker     Checker
	errCheckerArgs []interface{}
}

func (s *pinSuite) testChangePINErrorHandling(c *C, data *testChangePINErrorHandlingData) {
	c.Check(ChangePIN(s.tpm, data.keyFile, "", "1234"), data.errChecker, data.errCheckerArgs...)
}

func (s *pinSuite) TestChangePINErrorHandling1(c *C) {
	// Put the TPM in DA lockout mode
	c.Assert(s.tpm.DictionaryAttackParameters(s.tpm.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	s.testChangePINErrorHandling(c, &testChangePINErrorHandlingData{
		keyFile:        s.keyFile,
		errChecker:     Equals,
		errCheckerArgs: []interface{}{ErrTPMLockout},
	})
}

func (s *pinSuite) TestChangePINErrorHandling2(c *C) {
	c.Assert(ChangePIN(s.tpm, s.keyFile, "", "1234"), IsNil)
	s.testChangePINErrorHandling(c, &testChangePINErrorHandlingData{
		keyFile:        s.keyFile,
		errChecker:     Equals,
		errCheckerArgs: []interface{}{ErrPINFail},
	})
}

func (s *pinSuite) TestChangePINErrorHandling3(c *C) {
	s.testChangePINErrorHandling(c, &testChangePINErrorHandlingData{
		keyFile:        "/path/to/nothing",
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"cannot open key data file: open /path/to/nothing: no such file or directory"},
	})
}

func (s *pinSuite) TestChangePINErrorHandling4(c *C) {
	pinIndex, err := s.tpm.CreateResourceContextFromTPM(s.pinHandle)
	c.Assert(err, IsNil)
	c.Assert(s.tpm.NVUndefineSpace(s.tpm.OwnerHandleContext(), pinIndex, nil), IsNil)
	s.testChangePINErrorHandling(c, &testChangePINErrorHandlingData{
		keyFile:        s.keyFile,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"invalid key data file: cannot validate key data: PIN NV index is unavailable"},
	})
}
