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

package compattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type compatTestV0Suite struct {
	compatTestSuiteBase
}

func (s *compatTestV0Suite) SetUpSuite(c *C) {
	s.compatTestSuiteBase.setUpSuiteBase(c, "testdata/v0")
}

var _ = Suite(&compatTestV0Suite{})

func (s *compatTestV0Suite) TestSealKeyToTPM(c *C) {
	// Verify that we can seal a new key on a TPM provisioned with a legacy style lock NV index
	key := make([]byte, 64)
	rand.Read(key)
	profile := secboot.NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7)
	c.Check(secboot.SealKeyToTPM(s.TPM, key, c.MkDir()+"/key", "", &secboot.KeyCreationParams{PCRProfile: profile, PCRPolicyCounterHandle: 0x01810001}), IsNil)
	// TODO: Validate the key file when we have an API for this
}

func (s *compatTestV0Suite) testSealKeyToTPMWithLockIndexProvisionError(c *C) {
	key := make([]byte, 64)
	rand.Read(key)
	profile := secboot.NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7)
	c.Check(secboot.SealKeyToTPM(s.TPM, key, c.MkDir()+"/key", "", &secboot.KeyCreationParams{PCRProfile: profile, PCRPolicyCounterHandle: 0x01810001}), ErrorMatches, "the TPM is not correctly provisioned")
}

func (s *compatTestV0Suite) TestSealKeyToTPMWithLockIndexProvisionError1(c *C) {
	// Verify that undefining the lock data NV index is detected as a provisioning error
	index, err := s.TPM.CreateResourceContextFromTPM(0x01801101)
	c.Assert(err, IsNil)
	c.Assert(s.TPM.NVUndefineSpace(s.TPM.OwnerHandleContext(), index, nil), IsNil)
	s.testSealKeyToTPMWithLockIndexProvisionError(c)
}

func (s *compatTestV0Suite) TestSealKeyToTPMWithLockIndexProvisionError2(c *C) {
	// Verify that a legacy lock data NV index containing a time in the future is detected as a provisioning error
	index, err := s.TPM.CreateResourceContextFromTPM(0x01801101)
	c.Assert(err, IsNil)
	pub, _, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)
	data, err := s.TPM.NVRead(index, index, pub.Size, 0, nil)
	c.Assert(err, IsNil)

	var version uint8
	var keyName tpm2.Name
	var clock uint64
	_, err = tpm2.UnmarshalFromBytes(data, &version, &keyName, &clock)
	c.Assert(err, IsNil)

	time, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	data, err = tpm2.MarshalToBytes(version, keyName, time.ClockInfo.Clock+3600000)
	c.Assert(err, IsNil)
	c.Assert(s.TPM.NVUndefineSpace(s.TPM.OwnerHandleContext(), index, nil), IsNil)
	pub = &tpm2.NVPublic{
		Index:   0x01801101,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		Size:    uint16(len(data))}
	index, err = s.TPM.NVDefineSpace(s.TPM.OwnerHandleContext(), nil, pub, nil)
	c.Assert(err, IsNil)
	c.Assert(s.TPM.NVWrite(index, index, data, 0, nil), IsNil)

	s.testSealKeyToTPMWithLockIndexProvisionError(c)
}

func fillBytes(x *big.Int, buf []byte) []byte {
	for i := range buf {
		buf[i] = 0
	}
	b := x.Bytes()
	copy(buf[len(buf)-len(b):], b)
	return buf
}

func (s *compatTestV0Suite) TestSealKeyToTPMWithLockIndexProvisionError3(c *C) {
	// Verify that a legacy lock index that has a policy that allows it to be recreated at this point in time and doesn't match the
	// corresponding data index is detected as a provisioning error.
	key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	keyPub := tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.ECCScheme{
					Scheme:  tpm2.ECCSchemeECDSA,
					Details: tpm2.AsymSchemeU{Data: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
				CurveID: tpm2.ECCCurveNIST_P256,
				KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}},
		Unique: tpm2.PublicIDU{
			Data: &tpm2.ECCPoint{
				X: fillBytes(key.X, make([]byte, key.Params().BitSize/8)),
				Y: fillBytes(key.Y, make([]byte, key.Params().BitSize/8))}}}
	keyName, err := keyPub.Name()
	c.Assert(err, IsNil)

	time, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)
	time.ClockInfo.Clock += 5000
	clockBytes := make(tpm2.Operand, binary.Size(time.ClockInfo.Clock))
	binary.BigEndian.PutUint64(clockBytes, time.ClockInfo.Clock+3600000000)

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyCommandCode(tpm2.CommandNVWrite)
	trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
	trial.PolicySigned(keyName, nil)

	pub := tpm2.NVPublic{
		Index:      0x01801100,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVReadStClear),
		AuthPolicy: trial.GetDigest(),
		Size:       0}

	index, err := s.TPM.CreateResourceContextFromTPM(0x01801100)
	c.Assert(err, IsNil)
	c.Assert(s.TPM.NVUndefineSpace(s.TPM.OwnerHandleContext(), index, nil), IsNil)
	index, err = s.TPM.NVDefineSpace(s.TPM.OwnerHandleContext(), nil, &pub, nil)
	c.Assert(err, IsNil)
	policySession, err := s.TPM.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	defer s.TPM.FlushContext(policySession)

	h := tpm2.HashAlgorithmSHA256.NewHash()
	h.Write(policySession.NonceTPM())
	binary.Write(h, binary.BigEndian, int32(0))
	sigR, sigS, err := ecdsa.Sign(testutil.RandReader, key, h.Sum(nil))
	c.Assert(err, IsNil)
	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgECDSA,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureECDSA{
				Hash:       tpm2.HashAlgorithmSHA256,
				SignatureR: sigR.Bytes(),
				SignatureS: sigS.Bytes()}}}

	keyLoaded, err := s.TPM.LoadExternal(nil, &keyPub, tpm2.HandleEndorsement)
	c.Assert(err, IsNil)
	defer s.TPM.FlushContext(keyLoaded)
	c.Assert(s.TPM.PolicyCommandCode(policySession, tpm2.CommandNVWrite), IsNil)
	c.Assert(s.TPM.PolicyCounterTimer(policySession, clockBytes, 8, tpm2.OpUnsignedLT), IsNil)
	_, _, err = s.TPM.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, &signature)
	c.Assert(err, IsNil)
	c.Assert(s.TPM.NVWrite(index, index, nil, 0, policySession), IsNil)

	s.testSealKeyToTPMWithLockIndexProvisionError(c)
}

func (s *compatTestV0Suite) TestUnseal1(c *C) {
	s.testUnseal(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV0Suite) TestUnseal2(c *C) {
	s.testUnseal(c, s.absPath("pcrSequence.2"))
}

func (s *compatTestV0Suite) TestUnsealAfterReprovision(c *C) {
	// Test that reprovisioning doesn't touch the legacy lock NV index if it is valid
	c.Assert(secboot.ProvisionTPM(s.TPM, secboot.ProvisionModeWithoutLockout, nil), IsNil)
	s.testUnseal(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV0Suite) TestUnsealWithPIN1(c *C) {
	s.testUnsealWithPIN(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV0Suite) TestUnsealWithPIN2(c *C) {
	s.testUnsealWithPIN(c, s.absPath("pcrSequence.2"))
}

func (s *compatTestV0Suite) TestUpdateKeyPCRProtectionPolicy(c *C) {
	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	s.testUpdateKeyPCRProtectionPolicy(c, profile)
}

func (s *compatTestV0Suite) TestUpdateKeyPCRProtectionPolicyRevokes(c *C) {
	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	s.testUpdateKeyPCRProtectionPolicyRevokes(c, profile, s.absPath("pcrSequence.1"))
}

func (s *compatTestV0Suite) TestUpdateKeyPCRProtectionPolicyAndUnseal(c *C) {
	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	var b bytes.Buffer
	fmt.Fprintf(&b, "7 11 %x\n", testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	fmt.Fprintf(&b, "12 11 %x\n", testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	s.testUpdateKeyPCRProtectionPolicyAndUnseal(c, profile, &b)
}

func (s *compatTestV0Suite) TestUpdateKeyPCRProtectionPolicyAfterLock(c *C) {
	c.Assert(secboot.LockAccessToSealedKeys(s.TPM), IsNil)

	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	s.testUpdateKeyPCRProtectionPolicy(c, profile)
}

func (s *compatTestV0Suite) TestUnsealAfterLock(c *C) {
	s.testUnsealAfterLock(c, s.absPath("pcrSequence.1"))
}
