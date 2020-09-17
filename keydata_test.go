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
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/rand"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type keyDataSuite struct {
	testutil.TPMSimulatorTestBase

	keyFile        string
	authPrivateKey TPMPolicyAuthKey
}

func (s *keyDataSuite) SetUpTest(c *C) {
	s.TPMSimulatorTestBase.SetUpTest(c)
	c.Assert(ProvisionTPM(s.TPM, ProvisionModeFull, nil), IsNil)

	key := make([]byte, 64)
	rand.Read(key)

	s.keyFile = c.MkDir() + "/keydata"
	pcrPolicyCounterHandle := tpm2.Handle(0x0181fff0)

	authPrivateKey, err := SealKeyToTPM(s.TPM, key, s.keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: pcrPolicyCounterHandle})
	s.authPrivateKey = authPrivateKey
	c.Assert(err, IsNil)

	pcrPolicyCounter, err := s.TPM.CreateResourceContextFromTPM(pcrPolicyCounterHandle)
	c.Assert(err, IsNil)
	s.AddCleanupNVSpace(c, s.TPM.OwnerHandleContext(), pcrPolicyCounter)
}

var _ = Suite(&keyDataSuite{})

func (s *keyDataSuite) TestValidateAfterLock(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)
	c.Check(k.Validate(s.TPM, s.authPrivateKey), IsNil)

	c.Assert(LockAccessToSealedKeys(s.TPM), IsNil)
	defer s.ResetTPMSimulator(c)

	k, err = ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)
	c.Check(k.Validate(s.TPM, s.authPrivateKey), IsNil)
}

func (s *keyDataSuite) TestValidateGood(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)
	c.Check(k.Validate(s.TPM, s.authPrivateKey), IsNil)
}

func (s *keyDataSuite) TestValidateGoodNoAuthKey(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)
	c.Check(k.Validate(s.TPM, nil), IsNil)
}

func (s *keyDataSuite) TestValidateInvalidVersion(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	k.SetVersion(10)

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: invalid metadata version")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateInvalidKeyPublic1(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	k.KeyPublic().Type = tpm2.ObjectTypeECC

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: sealed key object has the wrong type")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateInvalidKeyPublic2(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	k.KeyPublic().Attrs |= tpm2.AttrUserWithAuth

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: sealed key object has the wrong attributes")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateLoadFail(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	k.KeyPublic().AuthPolicy = make(tpm2.Digest, 32)

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: cannot load sealed key object in to TPM: bad sealed key object or parent object")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorTPMLoad)
}

func (s *keyDataSuite) TestValidateInvalidPCRPolicyCounterHandle1(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	k.SetPCRPolicyCounterHandle(tpm2.HandleEndorsement)

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: PCR policy counter handle is invalid")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateInvalidPCRPolicyCounterHandle2(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	// NULL is valid, but it should still be detected because the name is encoded in the authorization policy digest.
	// The same mechanism would catch the actual NV index on the TPM being changed.
	k.SetPCRPolicyCounterHandle(tpm2.HandleNull)

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateInvalidPCRPolicyCounterHandle3(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	index, err := s.TPM.CreateResourceContextFromTPM(k.PCRPolicyCounterHandle())
	c.Assert(err, IsNil)
	c.Assert(s.TPM.NVUndefineSpace(s.TPM.OwnerHandleContext(), index, nil), IsNil)

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: PCR policy counter is unavailable")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateInvalidAuthPublicKeyNameAlg(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	k.AuthPublicKey().NameAlg = tpm2.HashAlgorithmNull

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: cannot compute name of dynamic authorization policy key: unsupported name algorithm: TPM_ALG_NULL")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateInvalidAuthPublicKeyType(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	k.AuthPublicKey().Type = tpm2.ObjectTypeRSA

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: cannot decode dynamic auth policy signing key: unsupported type")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateInvalidAuthPublicKey(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	badAuthKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	k.AuthPublicKey().Unique.ECC().X = badAuthKey.X.Bytes()
	k.AuthPublicKey().Unique.ECC().Y = badAuthKey.Y.Bytes()

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateInvalidAuthPrivateKey(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	badAuthKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)

	err = k.Validate(s.TPM, badAuthKey.D.Bytes())
	c.Check(err, ErrorMatches, "invalid key data: dynamic authorization policy signing private key doesn't match public key")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateNoLockIndex(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	index, err := s.TPM.CreateResourceContextFromTPM(LockNVHandle)
	c.Assert(err, IsNil)
	c.Assert(s.TPM.NVUndefineSpace(s.TPM.OwnerHandleContext(), index, nil), IsNil)

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: no lock NV index")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}

func (s *keyDataSuite) TestValidateInvalidLockIndex(c *C) {
	k, err := ReadSealedKeyObject(s.keyFile)
	c.Assert(err, IsNil)

	for _, h := range []tpm2.Handle{LockNVHandle, LockNVDataHandle} {
		index, err := s.TPM.CreateResourceContextFromTPM(h)
		c.Assert(err, IsNil)
		c.Assert(s.TPM.NVUndefineSpace(s.TPM.OwnerHandleContext(), index, nil), IsNil)
	}
	c.Assert(ProvisionTPM(s.TPM, ProvisionModeWithoutLockout, nil), IsNil)

	err = k.Validate(s.TPM, s.authPrivateKey)
	c.Check(err, ErrorMatches, "invalid key data: the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
	ierr, ok := err.(InvalidKeyDataError)
	c.Assert(ok, Equals, true)
	c.Check(ierr.Type, Equals, InvalidKeyDataErrorFatal)
}
