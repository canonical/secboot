// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package bootenv_test

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	. "github.com/snapcore/secboot"
	. "github.com/snapcore/secboot/bootenv"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"
)

type keyDataPlatformSuite struct {
	snapd_testutil.BaseTest
	Model    secboot.SnapModel
	BootMode string
}

var _ = Suite(&keyDataPlatformSuite{})

func (s *keyDataPlatformSuite) newPrimaryKey(c *C, sz1 int) PrimaryKey {
	primaryKey := make(PrimaryKey, sz1)
	_, err := rand.Read(primaryKey)
	c.Assert(err, IsNil)

	return primaryKey
}

func (s *keyDataPlatformSuite) TestNewKeyDataScopeSuccess(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       "test",
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)
	c.Check(kds, NotNil)

	err = kds.IsBootEnvironmentAuthorized()
	c.Check(err, IsNil)
}

func (s *keyDataPlatformSuite) TestNewKeyDataScopeErrorMissingKDF(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       "test",
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	}

	_, err := NewKeyDataScope(params)
	c.Assert(err, ErrorMatches, "KDF algorithm unavailable")
}

func (s *keyDataPlatformSuite) TestNewKeyDataScopeErrorMissingMD(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       "test",
		KDFAlg:     crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	}

	_, err := NewKeyDataScope(params)
	c.Assert(err, ErrorMatches, "MD algorithm unavailable")
}

func (s *keyDataPlatformSuite) TestNewKeyDataScopeErrorMissingModelAlg(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       "test",
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
	}

	_, err := NewKeyDataScope(params)
	c.Assert(err, ErrorMatches, "No model digest algorithm specified")
}

type testMakeAdditionalDataData struct {
	keyDataScopeVersion int
	baseVersion         int
	authMode            secboot.AuthMode
	mdAlg               crypto.Hash
	keyDigestHashAlg    crypto.Hash
	// These are used to derive the signing key whose digest go
	// into the additional data.
	signingKeyDerivationAlg crypto.Hash
	role                    string
}

func (s *keyDataPlatformSuite) testMakeAdditionalData(c *C, data *testMakeAdditionalDataData) {
	primaryKey := s.newPrimaryKey(c, 32)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       data.role,
		KDFAlg:     data.signingKeyDerivationAlg,
		MDAlg:      data.mdAlg,
		ModelAlg:   crypto.SHA256,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	if data.keyDataScopeVersion != 0 {
		kds.TestSetVersion(data.keyDataScopeVersion)
	}

	aadBytes, err := kds.MakeAdditionalData(data.baseVersion, data.keyDigestHashAlg, data.authMode)
	c.Check(err, IsNil)

	aad, err := UnmarshalAdditionalData(aadBytes)
	c.Assert(err, IsNil)

	c.Check(aad.Version, Equals, 1)
	c.Check(aad.BaseVersion, Equals, data.baseVersion)
	c.Check(crypto.Hash(aad.KdfAlg), Equals, data.keyDigestHashAlg)
	c.Check(aad.AuthMode, Equals, data.authMode)
	c.Check(crypto.Hash(aad.KeyIdentifierAlg), Equals, data.signingKeyDerivationAlg)

	c.Check(kds.TestMatch(data.keyDigestHashAlg, aad.KeyIdentifier), Equals, true)

}

func (s *keyDataPlatformSuite) TestMakeAdditionalData(c *C) {
	s.testMakeAdditionalData(c, &testMakeAdditionalDataData{
		baseVersion:             1,
		authMode:                secboot.AuthModeNone,
		mdAlg:                   crypto.SHA256,
		keyDigestHashAlg:        crypto.SHA256,
		signingKeyDerivationAlg: crypto.SHA256,
		role:                    "foo",
	})
}

func (s *keyDataPlatformSuite) TestMakeAdditionalDataWithPassphrase(c *C) {
	s.testMakeAdditionalData(c, &testMakeAdditionalDataData{
		baseVersion:             1,
		authMode:                secboot.AuthModePassphrase,
		mdAlg:                   crypto.SHA256,
		keyDigestHashAlg:        crypto.SHA256,
		signingKeyDerivationAlg: crypto.SHA256,
		role:                    "foo",
	})
}

func (s *keyDataPlatformSuite) mockState(c *C) {
	s.AddCleanup(
		MockSetModel(func(model SnapModel) bool {
			s.Model = model
			return true
		}),
	)
	s.AddCleanup(
		MockSetBootMode(func(mode string) bool {
			s.BootMode = mode
			return true
		}),
	)
	s.AddCleanup(
		MockLoadCurrentModel(func() (SnapModel, error) {
			return s.Model, nil
		}),
	)
	s.AddCleanup(
		MockLoadCurrenBootMode(func() (string, error) {
			return s.BootMode, nil
		}),
	)
}

func (s *keyDataPlatformSuite) makeMockModelAssertion(c *C, modelName string) SnapModel {
	return testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        modelName,
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")
}

func (s *keyDataPlatformSuite) TestBootEnvAuthStateErrors(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       "test",
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	authModels := []SnapModel{
		s.makeMockModelAssertion(c, "fake-model"),
	}

	c.Check(kds.SetAuthorizedSnapModels(primaryKey, params.Role, authModels...), IsNil)

	err = kds.IsBootEnvironmentAuthorized()
	c.Check(err, ErrorMatches, "SetModel hasn't been called yet")

	SetModel(authModels[0])

	authModes := []string{
		"modeFoo",
	}

	c.Check(kds.SetAuthorizedBootModes(primaryKey, params.Role, authModes...), IsNil)
	err = kds.IsBootEnvironmentAuthorized()
	c.Check(err, ErrorMatches, "SetBootMode hasn't been called yet")
}

type testSetAuthorizedSnapModelsData struct {
	kDFAlg      crypto.Hash
	mDAlg       crypto.Hash
	modelAlg    crypto.Hash
	validRole   string
	role        string
	validModels []SnapModel
}

func (s *keyDataPlatformSuite) testSetAuthorizedSnapModels(c *C, data *testSetAuthorizedSnapModelsData) error {
	primaryKey := s.newPrimaryKey(c, 32)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       data.validRole,
		KDFAlg:     data.kDFAlg,
		MDAlg:      data.mDAlg,
		ModelAlg:   data.modelAlg,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	err = kds.SetAuthorizedSnapModels(primaryKey, data.role, data.validModels...)
	return err
}

func (s *keyDataPlatformSuite) TestSetAuthorizedSnapModels(c *C) {
	validModels := []SnapModel{
		s.makeMockModelAssertion(c, "model-a"),
	}
	c.Check(
		s.testSetAuthorizedSnapModels(c, &testSetAuthorizedSnapModelsData{
			kDFAlg:      crypto.SHA256,
			mDAlg:       crypto.SHA256,
			modelAlg:    crypto.SHA256,
			validRole:   "test",
			role:        "test",
			validModels: validModels,
		}), IsNil)
}

func (s *keyDataPlatformSuite) TestSetAuthorizedSnapModelsInvalidRole(c *C) {
	// test authorization error when SetAuthorizedSnapModels is called with
	// a role different than the one set in its keyDataScope.
	validModels := []SnapModel{
		s.makeMockModelAssertion(c, "model-a"),
	}
	c.Check(
		s.testSetAuthorizedSnapModels(c, &testSetAuthorizedSnapModelsData{
			kDFAlg:      crypto.SHA256,
			mDAlg:       crypto.SHA256,
			modelAlg:    crypto.SHA256,
			validRole:   "test",
			role:        "different",
			validModels: validModels,
		}), ErrorMatches, "incorrect key supplied")
}

func (s *keyDataPlatformSuite) TestSetAuthorizedSnapModelsWrongKey(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)

	validModels := []SnapModel{
		s.makeMockModelAssertion(c, "model-a"),
	}
	data := &testSetAuthorizedSnapModelsData{
		kDFAlg:      crypto.SHA256,
		mDAlg:       crypto.SHA256,
		modelAlg:    crypto.SHA256,
		validRole:   "test",
		role:        "different",
		validModels: validModels,
	}

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       data.validRole,
		KDFAlg:     data.kDFAlg,
		MDAlg:      data.mDAlg,
		ModelAlg:   data.modelAlg,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	wrongKey := s.newPrimaryKey(c, 32)
	err = kds.SetAuthorizedSnapModels(wrongKey, data.role, data.validModels...)
	c.Check(err, ErrorMatches, "incorrect key supplied")
}

type testSetAuthorizedBootModesData struct {
	kDFAlg     crypto.Hash
	mDAlg      crypto.Hash
	modelAlg   crypto.Hash
	validRole  string
	role       string
	validModes []string
}

func (s *keyDataPlatformSuite) testSetAuthorizedBootModes(c *C, data *testSetAuthorizedBootModesData) error {
	primaryKey := s.newPrimaryKey(c, 32)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       data.validRole,
		KDFAlg:     data.kDFAlg,
		MDAlg:      data.mDAlg,
		ModelAlg:   data.modelAlg,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	err = kds.SetAuthorizedBootModes(primaryKey, data.role, data.validModes...)

	return err
}

func (s *keyDataPlatformSuite) TestSetAuthorizedBootModes(c *C) {
	validModes := []string{
		"modeFoo",
	}
	c.Check(
		s.testSetAuthorizedBootModes(c, &testSetAuthorizedBootModesData{
			kDFAlg:     crypto.SHA256,
			mDAlg:      crypto.SHA256,
			modelAlg:   crypto.SHA256,
			validRole:  "test",
			role:       "test",
			validModes: validModes,
		}), IsNil)
}

func (s *keyDataPlatformSuite) TestSetAuthorizedBootModesInvalidRole(c *C) {
	// test authorization error when SetAuthorizedBootModes is called with
	// a role different than the one set in its keyDataScope.
	validModes := []string{
		"modeFoo",
	}

	c.Check(
		s.testSetAuthorizedBootModes(c, &testSetAuthorizedBootModesData{
			kDFAlg:     crypto.SHA256,
			mDAlg:      crypto.SHA256,
			modelAlg:   crypto.SHA256,
			validRole:  "test",
			role:       "different",
			validModes: validModes,
		}), ErrorMatches, "incorrect key supplied")
}

func (s *keyDataPlatformSuite) TestSetAuthorizedBootModesWrongKey(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)

	validModes := []string{
		"modeFoo",
	}
	data := &testSetAuthorizedBootModesData{
		kDFAlg:     crypto.SHA256,
		mDAlg:      crypto.SHA256,
		modelAlg:   crypto.SHA256,
		validRole:  "test",
		role:       "different",
		validModes: validModes,
	}

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       data.validRole,
		KDFAlg:     data.kDFAlg,
		MDAlg:      data.mDAlg,
		ModelAlg:   data.modelAlg,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	wrongKey := s.newPrimaryKey(c, 32)
	err = kds.SetAuthorizedBootModes(wrongKey, data.role, data.validModes...)
	c.Check(err, ErrorMatches, "incorrect key supplied")
}

type testBootEnvAuthData struct {
	kDFAlg      crypto.Hash
	mDAlg       crypto.Hash
	modelAlg    crypto.Hash
	validRole   string
	role        string
	validModels []SnapModel
	model       SnapModel
	validModes  []string
	bootMode    string
}

func (s *keyDataPlatformSuite) testBootEnvAuth(c *C, data *testBootEnvAuthData) error {
	primaryKey := s.newPrimaryKey(c, 32)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       data.validRole,
		KDFAlg:     data.kDFAlg,
		MDAlg:      data.mDAlg,
		ModelAlg:   data.modelAlg,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	err = kds.SetAuthorizedSnapModels(primaryKey, data.role, data.validModels...)
	if err != nil {
		return err
	}

	err = kds.SetAuthorizedBootModes(primaryKey, data.role, data.validModes...)
	if err != nil {
		return err
	}

	SetModel(data.model)
	SetBootMode(data.bootMode)

	return kds.IsBootEnvironmentAuthorized()
}

func (s *keyDataPlatformSuite) TestBootEnvAuthValid1(c *C) {
	validModels := []SnapModel{
		s.makeMockModelAssertion(c, "model-a"),
	}

	validModes := []string{
		"modeFoo",
	}

	s.mockState(c)

	c.Check(s.testBootEnvAuth(c, &testBootEnvAuthData{
		kDFAlg:      crypto.SHA256,
		mDAlg:       crypto.SHA256,
		modelAlg:    crypto.SHA256,
		validRole:   "test",
		role:        "test",
		validModels: validModels,
		model:       validModels[0],
		validModes:  validModes,
		bootMode:    validModes[0],
	}), IsNil)
}

func (s *keyDataPlatformSuite) TestBootEnvAuthValid2(c *C) {
	validModels := []SnapModel{
		s.makeMockModelAssertion(c, "model-a"),
		s.makeMockModelAssertion(c, "model-b"),
	}

	validModes := []string{
		"modeFoo",
	}

	s.mockState(c)

	c.Check(s.testBootEnvAuth(c, &testBootEnvAuthData{
		kDFAlg:      crypto.SHA256,
		mDAlg:       crypto.SHA256,
		modelAlg:    crypto.SHA256,
		validRole:   "test",
		role:        "test",
		validModels: validModels,
		model:       validModels[1],
		validModes:  validModes,
		bootMode:    validModes[0],
	}), IsNil)
}

func (s *keyDataPlatformSuite) TestBootEnvAuthInvalidModel(c *C) {
	validModels := []SnapModel{
		s.makeMockModelAssertion(c, "model-a"),
	}

	invalidModel := s.makeMockModelAssertion(c, "model-b")

	validModes := []string{
		"modeFoo",
	}

	s.mockState(c)

	c.Check(s.testBootEnvAuth(c, &testBootEnvAuthData{
		kDFAlg:      crypto.SHA256,
		mDAlg:       crypto.SHA256,
		modelAlg:    crypto.SHA256,
		role:        "test",
		validRole:   "test",
		validModels: validModels,
		model:       invalidModel,
		validModes:  validModes,
		bootMode:    validModes[0],
	}), ErrorMatches, "unauthorized model")
}

func (s *keyDataPlatformSuite) TestBootEnvAuthInvalidBootMode(c *C) {
	validModels := []SnapModel{
		s.makeMockModelAssertion(c, "model-a"),
	}

	validModes := []string{
		"modeFoo",
	}

	invalidBootMode := "modeBar"

	s.mockState(c)

	c.Check(s.testBootEnvAuth(c, &testBootEnvAuthData{
		kDFAlg:      crypto.SHA256,
		mDAlg:       crypto.SHA256,
		modelAlg:    crypto.SHA256,
		validRole:   "test",
		role:        "test",
		validModels: validModels,
		model:       validModels[0],
		validModes:  validModes,
		bootMode:    invalidBootMode,
	}), ErrorMatches, "unauthorized boot mode")
}

func (s *keyDataPlatformSuite) TestHashAlgMarshalJSON(c *C) {
	for _, t := range []struct {
		alg     crypto.Hash
		nameAlg string
	}{
		{crypto.SHA1, "\"sha1\""},
		{crypto.SHA224, "\"sha224\""},
		{crypto.SHA256, "\"sha256\""},
		{crypto.SHA384, "\"sha384\""},
		{crypto.SHA512, "\"sha512\""},
	} {
		hashAlg := NewHashAlg(t.alg)
		hashAlgJSON, err := hashAlg.MarshalJSON()
		c.Assert(err, IsNil)
		c.Check(string(hashAlgJSON), Equals, t.nameAlg)
	}
}

func (s *keyDataPlatformSuite) TestHashAlgMarshalJSONInvalid(c *C) {
	unsupportedAlgorithms := []crypto.Hash{
		crypto.MD4,
		crypto.MD5,
		crypto.MD5SHA1,
		crypto.RIPEMD160,
		crypto.SHA3_224,
		crypto.SHA3_256,
		crypto.SHA3_384,
		crypto.SHA3_512,
		crypto.SHA512_224,
		crypto.SHA512_256,
		crypto.BLAKE2s_256,
		crypto.BLAKE2b_256,
		crypto.BLAKE2b_384,
		crypto.BLAKE2b_512,
	}

	for _, alg := range unsupportedAlgorithms {
		hashAlg := NewHashAlg(alg)
		hashAlgJSON, err := hashAlg.MarshalJSON()
		c.Assert(string(hashAlgJSON), Equals, "")
		c.Check(err.Error(), Equals, fmt.Sprintf("unknown hash algorithm: %v", crypto.Hash(alg)))
	}
}

func (s *keyDataPlatformSuite) TestHashAlgUnmarshalJSON(c *C) {
	for _, t := range []struct {
		alg     crypto.Hash
		nameAlg string
	}{
		{crypto.SHA1, "\"sha1\""},
		{crypto.SHA224, "\"sha224\""},
		{crypto.SHA256, "\"sha256\""},
		{crypto.SHA384, "\"sha384\""},
		{crypto.SHA512, "\"sha512\""},
		{0, "\"foo\""},
	} {
		hashAlg := NewHashAlg(crypto.SHA256)
		err := hashAlg.UnmarshalJSON([]byte(t.nameAlg))
		c.Assert(err, IsNil)
		c.Check(crypto.Hash(hashAlg), Equals, t.alg)
	}
}

func (s *keyDataPlatformSuite) TestHashAlgUnmarshalJSONInvalid(c *C) {
	hashAlg := NewHashAlg(crypto.SHA256)
	err := hashAlg.UnmarshalJSON([]byte("}"))

	e, ok := err.(*json.SyntaxError)
	c.Assert(ok, Equals, true)
	c.Assert(e, ErrorMatches, "invalid character '}' looking for beginning of value")
}

func (s *keyDataPlatformSuite) TestEcdsaPublicKeyMarshalJSONAndUnmarshalJSON(c *C) {
	rand := testutil.DecodeHexString(c, "12617b35cd4dea2364d2b5c99165c7d8a24249afdf58519796748335d842d0484a6b953e5a42a97d7f9a012d401ab007f1be6e964f48ed1138fdd902eadbea10d50e0eab02ed1a4935867bfa65e270df2100439d2a631b1c501da698a43031e709092b96")

	pk, err := NewEcdsaPublicKey(rand)
	c.Assert(err, IsNil)

	expected, err := base64.StdEncoding.DecodeString("Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRXlmU0tTbGJTSjcyYnQ1Yk1WWmpyd2tJeDVXZFNrRlcrMjJ1TXp6Um13VEVFN3VwZW9hYWZ3RmNheFBDSTA1NWI5UnlPdC9xbmRxQ3ZqSnhKQmwrNWpRPT0i")
	c.Assert(err, IsNil)

	pkBytes, err := pk.MarshalJSON()
	c.Assert(err, IsNil)

	c.Check(pkBytes, DeepEquals, expected)

	unmarshalledPk, err := NewEcdsaPublicKey(rand)
	c.Assert(err, IsNil)

	err = unmarshalledPk.UnmarshalJSON(pkBytes)
	c.Assert(err, IsNil)

	c.Check(unmarshalledPk, DeepEquals, pk)
}

func (s *keyDataPlatformSuite) TestEcdsaPublicKeyUnmarshalJSONInvalid(c *C) {
	// Test with a serialized RSA key
	pkBytes, err := base64.StdEncoding.DecodeString("Ik1Ed3dEUVlKS29aSWh2Y05BUUVCQlFBREt3QXdLQUloQU1jbC9Vdks0ZzdFZE5LQ0gwQTlraklzd1ZHOFI1S1BUOEVvQjd1V0dDZlRBZ01CQUFFPSI=")
	c.Assert(err, IsNil)

	rand := testutil.DecodeHexString(c, "617b35cd4dea2364d2b5c99165c7d8a24249afdf58519796748335d842d0484a6b953e5a42a97d7f9a012d401ab007f1be6e964f48ed1138fdd902eadbea10d50e0eab02ed1a4935867bfa65e270df2100439d2a631b1c501da698a43031e709092b96")
	unmarshalledPk, err := NewEcdsaPublicKey(rand)
	c.Assert(err, IsNil)

	err = unmarshalledPk.UnmarshalJSON(pkBytes)
	c.Check(err, ErrorMatches, "invalid key type")
}
