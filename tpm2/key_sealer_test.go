// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2022 Canonical Ltd
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
	"crypto/rsa"

	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type sealedObjectKeySealerSuite struct {
	tpm2test.TPMTest
}

func (s *sealedObjectKeySealerSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureLockoutHierarchy | // Allow the test fixture to reset the DA counter
		tpm2test.TPMFeaturePCR |
		tpm2test.TPMFeatureNV
}

func (s *sealedObjectKeySealerSuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	c.Assert(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil),
		testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})
}

var _ = Suite(&sealedObjectKeySealerSuite{})

type testCreateSealedObjectData struct {
	data         tpm2.SensitiveData
	nameAlg      tpm2.HashAlgorithmId
	policyDigest tpm2.Digest
	noDA         bool
	session      tpm2.SessionContext
}

func (s *sealedObjectKeySealerSuite) testCreateSealedObject(c *C, data *testCreateSealedObjectData) {
	sealer := NewSealedObjectKeySealer(s.TPM())

	priv, pub, importSymSeed, err := sealer.CreateSealedObject(data.data, data.nameAlg, data.policyDigest, data.noDA)
	c.Assert(err, IsNil)
	c.Check(importSymSeed, IsNil)

	c.Check(pub.Type, Equals, tpm2.ObjectTypeKeyedHash)
	c.Check(pub.NameAlg, Equals, data.nameAlg)
	expectedAttrs := tpm2.AttrFixedParent | tpm2.AttrFixedTPM
	if data.noDA {
		expectedAttrs |= tpm2.AttrNoDA
	}
	c.Check(pub.Attrs, Equals, expectedAttrs)
	c.Check(pub.AuthPolicy, DeepEquals, data.policyDigest)
	c.Check(pub.Params, DeepEquals,
		&tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme:  tpm2.KeyedHashSchemeNull,
					Details: &tpm2.SchemeKeyedHashU{}}}})

	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)

	k, err := s.TPM().Load(srk, priv, pub, nil)
	c.Assert(err, IsNil)

	recoveredData, err := s.TPM().Unseal(k, data.session)
	c.Check(err, IsNil)
	c.Check(recoveredData, DeepEquals, data.data)
}

func (s *sealedObjectKeySealerSuite) TestCreateSealedObject(c *C) {
	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("foo"),
		nameAlg:      tpm2.HashAlgorithmSHA256,
		policyDigest: make([]byte, 32),
		noDA:         true,
		session:      s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)})
}

func (s *sealedObjectKeySealerSuite) TestCreateSealedObjectWithNewConnection(c *C) {
	// createSealedObject behaves slightly different if called immediately after
	// EnsureProvisioned with the same Connection
	s.ReinitTPMConnectionFromExisting(c)

	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("foo"),
		nameAlg:      tpm2.HashAlgorithmSHA256,
		policyDigest: make([]byte, 32),
		noDA:         true,
		session:      s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)})
}

func (s *sealedObjectKeySealerSuite) TestCreateSealedObjectMissingSRK(c *C) {
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	s.ReinitTPMConnectionFromExisting(c)

	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("foo"),
		nameAlg:      tpm2.HashAlgorithmSHA256,
		policyDigest: make([]byte, 32),
		noDA:         true,
		session:      s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)})
}

func (s *sealedObjectKeySealerSuite) TestCreateSealedObjectDifferentData(c *C) {
	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("bar"),
		nameAlg:      tpm2.HashAlgorithmSHA256,
		policyDigest: make([]byte, 32),
		noDA:         true,
		session:      s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)})
}

func (s *sealedObjectKeySealerSuite) TestCreateSealedObjectDifferentNameAlg(c *C) {
	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("foo"),
		nameAlg:      tpm2.HashAlgorithmSHA1,
		policyDigest: make([]byte, 20),
		noDA:         true,
		session:      s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA1)})
}

func (s *sealedObjectKeySealerSuite) TestCreateSealedObjectDifferentPolicy(c *C) {
	trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyAuthValue()

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	c.Check(s.TPM().PolicyAuthValue(session), IsNil)

	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("foo"),
		nameAlg:      tpm2.HashAlgorithmSHA256,
		policyDigest: trial.GetDigest(),
		noDA:         true,
		session:      session})
}

func (s *sealedObjectKeySealerSuite) TestCreateSealedObjectWithDA(c *C) {
	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("foo"),
		nameAlg:      tpm2.HashAlgorithmSHA256,
		policyDigest: make([]byte, 32),
		noDA:         false,
		session:      s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)})
}

type importableObjectKeySealerSuite struct{}

var _ = Suite(&importableObjectKeySealerSuite{})

func (s *importableObjectKeySealerSuite) testCreateSealedObject(c *C, data *testCreateSealedObjectData) {
	key, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)

	srk := tpm2_testutil.NewExternalRSAStoragePublicKey(&key.PublicKey)

	sealer := NewImportableObjectKeySealer(srk)

	priv, pub, importSymSeed, err := sealer.CreateSealedObject(data.data, data.nameAlg, data.policyDigest, data.noDA)
	c.Assert(err, IsNil)

	c.Check(pub.Type, Equals, tpm2.ObjectTypeKeyedHash)
	c.Check(pub.NameAlg, Equals, data.nameAlg)
	expectedAttrs := tpm2.ObjectAttributes(0)
	if data.noDA {
		expectedAttrs |= tpm2.AttrNoDA
	}
	c.Check(pub.Attrs, Equals, expectedAttrs)
	c.Check(pub.AuthPolicy, DeepEquals, data.policyDigest)
	c.Check(pub.Params, DeepEquals,
		&tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}})

	sensitive, err := util.UnwrapDuplicationObject(priv, pub, key, srk.NameAlg, &srk.Params.RSADetail.Symmetric, importSymSeed, nil, nil)
	c.Assert(err, IsNil)

	c.Check(sensitive.Type, Equals, tpm2.ObjectTypeKeyedHash)
	c.Check(sensitive.AuthValue, DeepEquals, make(tpm2.Auth, data.nameAlg.Size()))
	c.Check(sensitive.Sensitive.Bits, DeepEquals, data.data)
}

func (s *importableObjectKeySealerSuite) TestCreateSealedObject(c *C) {
	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("foo"),
		nameAlg:      tpm2.HashAlgorithmSHA256,
		policyDigest: make([]byte, 32),
		noDA:         true})
}

func (s *importableObjectKeySealerSuite) TestCreateSealedObjectDifferentData(c *C) {
	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("bar"),
		nameAlg:      tpm2.HashAlgorithmSHA256,
		policyDigest: make([]byte, 32),
		noDA:         true})
}

func (s *importableObjectKeySealerSuite) TestCreateSealedObjectiDifferentNameAlg(c *C) {
	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("foo"),
		nameAlg:      tpm2.HashAlgorithmSHA1,
		policyDigest: make([]byte, 20),
		noDA:         true})
}

func (s *importableObjectKeySealerSuite) TestCreateSealedObjectWithDifferentPolicy(c *C) {
	trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyAuthValue()

	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("foo"),
		nameAlg:      tpm2.HashAlgorithmSHA256,
		policyDigest: trial.GetDigest(),
		noDA:         true})
}

func (s *importableObjectKeySealerSuite) TestCreateSealedObjectWithDA(c *C) {
	s.testCreateSealedObject(c, &testCreateSealedObjectData{
		data:         []byte("foo"),
		nameAlg:      tpm2.HashAlgorithmSHA256,
		policyDigest: make([]byte, 32),
		noDA:         false})
}
