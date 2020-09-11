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
	"math/rand"
	"testing"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

func TestPerformPinChange(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	if err := ProvisionTPM(tpm, ProvisionModeFull, nil); err != nil {
		t.Errorf("Failed to provision TPM for test: %v", err)
	}

	srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
	}

	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
		Params:  tpm2.PublicParamsU{Data: &tpm2.KeyedHashParams{Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}

	priv, pub, _, _, _, err := tpm.Create(srk, &sensitive, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	key, err := tpm.Load(srk, priv, pub, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, key)

	pin := "1234"

	newPriv, err := PerformPinChange(tpm.TPMContext, priv, pub, "", pin, tpm.HmacSession())
	if err != nil {
		t.Fatalf("PerformPinChange failed: %v", err)
	}

	// Verify that the PIN change succeeded by loading the new private area and trying to unseal it
	newKey, err := tpm.Load(srk, newPriv, pub, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, newKey)

	newKey.SetAuthValue([]byte(pin))

	data, err := tpm.Unseal(newKey, nil)
	if err != nil {
		t.Errorf("Unseal failed: %v", err)
	}

	if !bytes.Equal(data, sensitive.Data) {
		t.Errorf("Unexpected data")
	}
}

type pinSuite struct {
	testutil.TPMTestBase
	key                    []byte
	pcrPolicyCounterHandle tpm2.Handle
	keyFile                string
}

var _ = Suite(&pinSuite{})

func (s *pinSuite) SetUpSuite(c *C) {
	s.key = make([]byte, 64)
	rand.Read(s.key)
	s.pcrPolicyCounterHandle = tpm2.Handle(0x0181fff0)
}

func (s *pinSuite) SetUpTest(c *C) {
	s.TPMTestBase.SetUpTest(c)
	c.Assert(ProvisionTPM(s.TPM, ProvisionModeFull, nil), IsNil)

	dir := c.MkDir()
	s.keyFile = dir + "/keydata"

	_, err := SealKeyToTPM(s.TPM, s.key, s.keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: s.pcrPolicyCounterHandle})
	c.Assert(err, IsNil)
	policyCounter, err := s.TPM.CreateResourceContextFromTPM(s.pcrPolicyCounterHandle)
	c.Assert(err, IsNil)
	s.AddCleanupNVSpace(c, s.TPM.OwnerHandleContext(), policyCounter)
}

func (s *pinSuite) checkPIN(c *C, pin string) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)
	if pin == "" {
		c.Check(k.AuthMode2F(), Equals, AuthModeNone)
	} else {
		c.Check(k.AuthMode2F(), Equals, AuthModePIN)
	}

	key, _, err := k.UnsealFromTPM(s.TPM, pin)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, s.key)
}

func (s *pinSuite) TestSetAndClearPIN(c *C) {
	testPIN := "1234"
	c.Check(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)
	s.checkPIN(c, testPIN)

	c.Check(ChangePIN(s.TPM, s.keyFile, testPIN, ""), IsNil)
	s.checkPIN(c, "")
}

type testChangePINErrorHandlingData struct {
	keyFile        string
	errChecker     Checker
	errCheckerArgs []interface{}
}

func (s *pinSuite) testChangePINErrorHandling(c *C, data *testChangePINErrorHandlingData) {
	c.Check(ChangePIN(s.TPM, data.keyFile, "", "1234"), data.errChecker, data.errCheckerArgs...)
}

func (s *pinSuite) TestChangePINErrorHandling1(c *C) {
	// Put the TPM in DA lockout mode
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	s.testChangePINErrorHandling(c, &testChangePINErrorHandlingData{
		keyFile:        s.keyFile,
		errChecker:     Equals,
		errCheckerArgs: []interface{}{ErrTPMLockout},
	})
}

func (s *pinSuite) TestChangePINErrorHandling2(c *C) {
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", "1234"), IsNil)
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
