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

package bootscope_test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/xerrors"
	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	. "github.com/snapcore/secboot"
	. "github.com/snapcore/secboot/bootscope"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"
)

type keyDataPlatformSuite struct {
	snapd_testutil.BaseTest
}

func (s *keyDataPlatformSuite) SetUpTest(c *C) {
	ClearBootModeAndModel()
}

var _ = Suite(&keyDataPlatformSuite{})

func NewPrimaryKey(sz1 int) (secboot.PrimaryKey, error) {
	primaryKey := make(secboot.PrimaryKey, sz1)
	_, err := rand.Read(primaryKey)
	if err != nil {
		return nil, err
	}

	return primaryKey, nil
}

func (s *keyDataPlatformSuite) TestNewKeyDataScopeSuccess(c *C) {
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)

	role := "test"
	kdfAlg := crypto.SHA256
	mdAlg := crypto.SHA256
	modelAlg := crypto.SHA256

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       role,
		KDFAlg:     kdfAlg,
		MDAlg:      mdAlg,
		ModelAlg:   modelAlg,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)
	c.Check(kds, NotNil)

	c.Check(kds.IsBootEnvironmentAuthorized(), IsNil)

	data := kds.Data()

	c.Check(data.Version, Equals, 1)
	c.Check(crypto.Hash(data.Params.ModelDigests.Alg), Equals, modelAlg)
	c.Check(crypto.Hash(data.KDFAlg), Equals, kdfAlg)
	c.Check(crypto.Hash(data.MDAlg), Equals, mdAlg)

	signer, err := kds.DeriveSigner(primaryKey, role)
	c.Assert(err, IsNil)
	c.Check(data.PublicKey.PublicKey, DeepEquals, signer.Public().(*ecdsa.PublicKey))
}

func (s *keyDataPlatformSuite) TestNewKeyDataScopeErrorMissingKDF(c *C) {
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       "test",
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	}

	_, err = NewKeyDataScope(params)
	c.Assert(err, ErrorMatches, "KDF algorithm unavailable")
}

func (s *keyDataPlatformSuite) TestNewKeyDataScopeErrorMissingMD(c *C) {
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       "test",
		KDFAlg:     crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	}

	_, err = NewKeyDataScope(params)
	c.Assert(err, ErrorMatches, "MD algorithm unavailable")
}

func (s *keyDataPlatformSuite) TestNewKeyDataScopeErrorMissingModelAlg(c *C) {
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       "test",
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
	}

	_, err = NewKeyDataScope(params)
	c.Assert(err, ErrorMatches, "No model digest algorithm specified")
}

type testMakeAEADAdditionalDataData struct {
	primaryKey          PrimaryKey
	keyDataScopeVersion int
	generation          int
	authMode            AuthMode
	mdAlg               crypto.Hash
	keyDigestHashAlg    crypto.Hash
	// These are used to derive the signing key whose digest go
	// into the additional data.
	signingKeyDerivationAlg crypto.Hash
	role                    string
	expectedAad             []byte
}

func (s *keyDataPlatformSuite) testMakeAEADAdditionalData(c *C, data *testMakeAEADAdditionalDataData) {
	params := &KeyDataScopeParams{
		PrimaryKey: data.primaryKey,
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

	aadBytes, err := kds.MakeAEADAdditionalData(data.generation, data.keyDigestHashAlg, data.authMode)
	c.Check(err, IsNil)

	c.Check(aadBytes, DeepEquals, data.expectedAad)
}

func (s *keyDataPlatformSuite) TestMakeAEADAdditionalData(c *C) {
	primaryKey := testutil.DecodeHexString(c, "ab40b798dd6b47ca77d93241f40036d6d86e03f365b4ef9171b23e2bc38b9ef3")
	expectedAad := testutil.DecodeHexString(c, "3049020101020101300d060960864801650304020105000a0100300d06096086480165030402010500042077511e42d7c0b2df1881189bd4720806fc92a6dee76cd1c9fe40c32310f6068d")

	s.testMakeAEADAdditionalData(c, &testMakeAEADAdditionalDataData{
		primaryKey:              primaryKey,
		generation:              1,
		authMode:                AuthModeNone,
		mdAlg:                   crypto.SHA256,
		keyDigestHashAlg:        crypto.SHA256,
		signingKeyDerivationAlg: crypto.SHA256,
		role:                    "foo",
		expectedAad:             expectedAad,
	})
}

func (s *keyDataPlatformSuite) TestMakeAEADAdditionalDataWithPassphrase(c *C) {
	primaryKey := testutil.DecodeHexString(c, "45db13f9857336d338c12a5e71aae5434032c3419b9e4e82c2de42cf510d93ee")
	expectedAad := testutil.DecodeHexString(c, "3049020101020101300d060960864801650304020105000a0101300d060960864801650304020105000420765f9750024ce485a32d50c6595fa16fca71b4ea110a2e8361d070a975ba9bcc")

	s.testMakeAEADAdditionalData(c, &testMakeAEADAdditionalDataData{
		primaryKey:              primaryKey,
		generation:              1,
		authMode:                AuthModePassphrase,
		mdAlg:                   crypto.SHA256,
		keyDigestHashAlg:        crypto.SHA256,
		signingKeyDerivationAlg: crypto.SHA256,
		role:                    "foo",
		expectedAad:             expectedAad,
	})
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
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)

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
	kdfAlg      crypto.Hash
	mdAlg       crypto.Hash
	modelAlg    crypto.Hash
	validRole   string
	role        string
	validModels []SnapModel
}

func (s *keyDataPlatformSuite) testSetAuthorizedSnapModels(c *C, data *testSetAuthorizedSnapModelsData) error {
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       data.validRole,
		KDFAlg:     data.kdfAlg,
		MDAlg:      data.mdAlg,
		ModelAlg:   data.modelAlg,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	err = kds.SetAuthorizedSnapModels(primaryKey, data.role, data.validModels...)

	if err == nil {
		kdsData := kds.Data()

		c.Check(kdsData.Version, Equals, 1)
		c.Check(crypto.Hash(kdsData.Params.ModelDigests.Alg), Equals, data.modelAlg)
		c.Check(crypto.Hash(kdsData.KDFAlg), Equals, data.kdfAlg)
		c.Check(crypto.Hash(kdsData.MDAlg), Equals, data.mdAlg)

		signer, err := kds.DeriveSigner(primaryKey, data.validRole)
		c.Assert(err, IsNil)
		c.Check(kdsData.PublicKey.PublicKey, DeepEquals, signer.Public().(*ecdsa.PublicKey))
	}

	return err
}

func (s *keyDataPlatformSuite) TestSetAuthorizedSnapModels(c *C) {
	validModels := []SnapModel{
		s.makeMockModelAssertion(c, "model-a"),
	}
	c.Check(
		s.testSetAuthorizedSnapModels(c, &testSetAuthorizedSnapModelsData{
			kdfAlg:      crypto.SHA256,
			mdAlg:       crypto.SHA256,
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
			kdfAlg:      crypto.SHA256,
			mdAlg:       crypto.SHA256,
			modelAlg:    crypto.SHA256,
			validRole:   "test",
			role:        "different",
			validModels: validModels,
		}), ErrorMatches, "incorrect key supplied")
}

func (s *keyDataPlatformSuite) TestSetAuthorizedSnapModelsWrongKey(c *C) {
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)

	validModels := []SnapModel{
		s.makeMockModelAssertion(c, "model-a"),
	}

	validRole := "test"
	kdfAlg := crypto.SHA256
	mdAlg := crypto.SHA256
	modelAlg := crypto.SHA256

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       validRole,
		KDFAlg:     kdfAlg,
		MDAlg:      mdAlg,
		ModelAlg:   modelAlg,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	wrongKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)
	err = kds.SetAuthorizedSnapModels(wrongKey, "different", validModels...)
	c.Check(err, ErrorMatches, "incorrect key supplied")
}

type testSetAuthorizedBootModesData struct {
	kdfAlg     crypto.Hash
	mdAlg      crypto.Hash
	modelAlg   crypto.Hash
	validRole  string
	role       string
	validModes []string
}

func (s *keyDataPlatformSuite) testSetAuthorizedBootModes(c *C, data *testSetAuthorizedBootModesData) error {
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       data.validRole,
		KDFAlg:     data.kdfAlg,
		MDAlg:      data.mdAlg,
		ModelAlg:   data.modelAlg,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	err = kds.SetAuthorizedBootModes(primaryKey, data.role, data.validModes...)

	if err == nil {
		kdsData := kds.Data()

		c.Check(kdsData.Version, Equals, 1)
		c.Check(crypto.Hash(kdsData.Params.ModelDigests.Alg), Equals, data.modelAlg)
		c.Check(crypto.Hash(kdsData.KDFAlg), Equals, data.kdfAlg)
		c.Check(crypto.Hash(kdsData.MDAlg), Equals, data.mdAlg)

		signer, err := kds.DeriveSigner(primaryKey, data.validRole)
		c.Assert(err, IsNil)
		c.Check(kdsData.PublicKey.PublicKey, DeepEquals, signer.Public().(*ecdsa.PublicKey))
	}

	return err
}

func (s *keyDataPlatformSuite) TestSetAuthorizedBootModes(c *C) {
	validModes := []string{
		"modeFoo",
	}
	c.Check(
		s.testSetAuthorizedBootModes(c, &testSetAuthorizedBootModesData{
			kdfAlg:     crypto.SHA256,
			mdAlg:      crypto.SHA256,
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
			kdfAlg:     crypto.SHA256,
			mdAlg:      crypto.SHA256,
			modelAlg:   crypto.SHA256,
			validRole:  "test",
			role:       "different",
			validModes: validModes,
		}), ErrorMatches, "incorrect key supplied")
}

func (s *keyDataPlatformSuite) TestSetAuthorizedBootModesWrongKey(c *C) {
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)

	validModes := []string{
		"modeFoo",
	}
	data := &testSetAuthorizedBootModesData{
		kdfAlg:     crypto.SHA256,
		mdAlg:      crypto.SHA256,
		modelAlg:   crypto.SHA256,
		validRole:  "test",
		role:       "different",
		validModes: validModes,
	}

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       data.validRole,
		KDFAlg:     data.kdfAlg,
		MDAlg:      data.mdAlg,
		ModelAlg:   data.modelAlg,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)

	wrongKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)
	err = kds.SetAuthorizedBootModes(wrongKey, data.role, data.validModes...)
	c.Check(err, ErrorMatches, "incorrect key supplied")
}

type testBootEnvAuthData struct {
	kdfAlg      crypto.Hash
	mdAlg       crypto.Hash
	modelAlg    crypto.Hash
	validRole   string
	role        string
	validModels []SnapModel
	model       SnapModel
	validModes  []string
	bootMode    string
}

func (s *keyDataPlatformSuite) testBootEnvAuth(c *C, data *testBootEnvAuthData) error {
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       data.validRole,
		KDFAlg:     data.kdfAlg,
		MDAlg:      data.mdAlg,
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

	c.Check(s.testBootEnvAuth(c, &testBootEnvAuthData{
		kdfAlg:      crypto.SHA256,
		mdAlg:       crypto.SHA256,
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

	c.Check(s.testBootEnvAuth(c, &testBootEnvAuthData{
		kdfAlg:      crypto.SHA256,
		mdAlg:       crypto.SHA256,
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

	c.Check(s.testBootEnvAuth(c, &testBootEnvAuthData{
		kdfAlg:      crypto.SHA256,
		mdAlg:       crypto.SHA256,
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

	c.Check(s.testBootEnvAuth(c, &testBootEnvAuthData{
		kdfAlg:      crypto.SHA256,
		mdAlg:       crypto.SHA256,
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

func (s *keyDataPlatformSuite) TestDeriveSigner(c *C) {
	primaryKey, err := NewPrimaryKey(32)
	c.Assert(err, IsNil)
	role := "test"

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       role,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)
	c.Check(kds, NotNil)

	c.Check(kds.IsBootEnvironmentAuthorized(), IsNil)

	signer, err := kds.DeriveSigner(primaryKey, role)
	c.Assert(err, IsNil)

	prevKey, ok := signer.(*ecdsa.PrivateKey)
	c.Assert(ok, Equals, true)

	for i := 0; i < 10; i++ {
		signer, err := kds.DeriveSigner(primaryKey, role)
		c.Assert(err, IsNil)

		key, ok := signer.(*ecdsa.PrivateKey)
		c.Assert(ok, Equals, true)
		c.Check(key.Equal(prevKey), Equals, true)
		prevKey = key
	}
}

func (s *keyDataPlatformSuite) TestDeriveSignerFixedKey1(c *C) {
	primaryKey := testutil.DecodeHexString(c, "90e29c3b7902dfc239c1c7aa5928ee232be2f1e7a4018aa7c5465a03a4c0be30")
	role := "test"

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       role,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)
	c.Check(kds, NotNil)

	signer, err := kds.DeriveSigner(primaryKey, role)
	c.Assert(err, IsNil)

	prevKey, ok := signer.(*ecdsa.PrivateKey)
	c.Assert(ok, Equals, true)

	expectedDerivedKey := testutil.DecodeHexString(c, "ff7ac99d7a0f16980777b9ace6c316e43e3edb4b0575fab5c22ea80d3e031c1d")
	c.Check(prevKey.X.Bytes(), DeepEquals, expectedDerivedKey)
}

func (s *keyDataPlatformSuite) TestDeriveSignerFixedKey2(c *C) {
	primaryKey := testutil.DecodeHexString(c, "cc0ba15ded8561e2278d78a5c4c215653c9b1f872325a9e67882a89088e57023")
	role := "test"

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       role,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)
	c.Check(kds, NotNil)

	signer, err := kds.DeriveSigner(primaryKey, role)
	c.Assert(err, IsNil)

	privKey, ok := signer.(*ecdsa.PrivateKey)
	c.Assert(ok, Equals, true)

	expectedDerivedKey := testutil.DecodeHexString(c, "05962e1c19be2dc1c676b4d6fe0934f2f4af6f584bf03640f5acd9c399b960c6")
	c.Check(privKey.X.Bytes(), DeepEquals, expectedDerivedKey)
}

func (s *keyDataPlatformSuite) TestDeriveSignerDifferentRoleMismatch(c *C) {
	primaryKey := testutil.DecodeHexString(c, "90e29c3b7902dfc239c1c7aa5928ee232be2f1e7a4018aa7c5465a03a4c0be30")
	role := "test"

	params := &KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       role,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	}

	kds, err := NewKeyDataScope(params)
	c.Assert(err, IsNil)
	c.Check(kds, NotNil)

	signer, err := kds.DeriveSigner(primaryKey, role)
	c.Assert(err, IsNil)

	privKey, ok := signer.(*ecdsa.PrivateKey)
	c.Assert(ok, Equals, true)

	expectedDerivedKey := testutil.DecodeHexString(c, "ff7ac99d7a0f16980777b9ace6c316e43e3edb4b0575fab5c22ea80d3e031c1d")
	c.Check(privKey.X.Bytes(), DeepEquals, expectedDerivedKey)

	signer2, err := kds.DeriveSigner(primaryKey, "different")
	c.Assert(err, IsNil)

	privKey2, ok := signer2.(*ecdsa.PrivateKey)
	c.Assert(ok, Equals, true)

	expectedDerivedKey2 := testutil.DecodeHexString(c, "d518d18c366e6faac72c8fc1a180e01a7d52bc3e60512e990c10309fd6c82c9d")
	c.Check(privKey2.X.Bytes(), DeepEquals, expectedDerivedKey2)

	c.Check(privKey2.X.Bytes(), Not(DeepEquals), privKey.X.Bytes())
}

type mockPlatformKeyDataHandle struct {
	Key         []byte `json:"key"`
	IV          []byte `json:"iv"`
	AuthKeyHMAC []byte `json:"auth-key-hmac"`
}

const (
	mockPlatformDeviceStateOK = iota
	mockPlatformDeviceStateUnavailable
	mockPlatformDeviceStateUninitialized
)

type mockPlatformKeyDataHandler struct {
	state  int
	scopes []*KeyDataScope
}

func (h *mockPlatformKeyDataHandler) checkState() error {
	switch h.state {
	case mockPlatformDeviceStateUnavailable:
		return &PlatformHandlerError{Type: PlatformHandlerErrorUnavailable, Err: errors.New("the platform device is unavailable")}
	case mockPlatformDeviceStateUninitialized:
		return &PlatformHandlerError{Type: PlatformHandlerErrorUninitialized, Err: errors.New("the platform device is uninitialized")}
	default:
		return nil
	}
}

func (h *mockPlatformKeyDataHandler) unmarshalHandle(data *PlatformKeyData) (*mockPlatformKeyDataHandle, error) {
	var handle mockPlatformKeyDataHandle
	if err := json.Unmarshal(data.EncodedHandle, &handle); err != nil {
		return nil, &PlatformHandlerError{Type: PlatformHandlerErrorInvalidData, Err: xerrors.Errorf("JSON decode error: %w", err)}
	}
	return &handle, nil
}

func (h *mockPlatformKeyDataHandler) checkKey(handle *mockPlatformKeyDataHandle, key []byte) error {
	m := hmac.New(func() hash.Hash { return crypto.SHA256.New() }, handle.Key)
	m.Write(key)
	if !bytes.Equal(handle.AuthKeyHMAC, m.Sum(nil)) {
		return &PlatformHandlerError{Type: PlatformHandlerErrorInvalidAuthKey, Err: errors.New("the supplied key is incorrect")}
	}

	return nil
}

func (h *mockPlatformKeyDataHandler) recoverKeys(handle *mockPlatformKeyDataHandle, payload []byte) ([]byte, error) {
	var authorized bool
	var err error
	for _, s := range h.scopes {
		err = s.IsBootEnvironmentAuthorized()
		if err == nil {
			authorized = true
			break
		}
	}

	if len(h.scopes) > 0 && !authorized {
		return nil, err
	}

	b, err := aes.NewCipher(handle.Key)
	if err != nil {
		return nil, xerrors.Errorf("cannot create cipher: %w", err)
	}

	s := cipher.NewCFBDecrypter(b, handle.IV)
	out := make([]byte, len(payload))
	s.XORKeyStream(out, payload)
	return out, nil
}

func (h *mockPlatformKeyDataHandler) RecoverKeys(data *PlatformKeyData, encryptedPayload []byte) ([]byte, error) {
	if err := h.checkState(); err != nil {
		return nil, err
	}

	handle, err := h.unmarshalHandle(data)
	if err != nil {
		return nil, err
	}

	return h.recoverKeys(handle, encryptedPayload)
}

func (h *mockPlatformKeyDataHandler) RecoverKeysWithAuthKey(data *PlatformKeyData, encryptedPayload []byte, key []byte) ([]byte, error) {
	if err := h.checkState(); err != nil {
		return nil, err
	}

	handle, err := h.unmarshalHandle(data)
	if err != nil {
		return nil, err
	}

	if err := h.checkKey(handle, key); err != nil {
		return nil, err
	}

	return h.recoverKeys(handle, encryptedPayload)
}

func (h *mockPlatformKeyDataHandler) ChangeAuthKey(data *PlatformKeyData, old, new []byte) ([]byte, error) {
	if err := h.checkState(); err != nil {
		return nil, err
	}

	handle, err := h.unmarshalHandle(data)
	if err != nil {
		return nil, err
	}

	if err := h.checkKey(handle, old); err != nil {
		return nil, err
	}

	m := hmac.New(func() hash.Hash { return crypto.SHA256.New() }, handle.Key)
	m.Write(new)
	handle.AuthKeyHMAC = m.Sum(nil)

	return json.Marshal(&handle)
}

type keyDataScopeSuite struct {
	handler *mockPlatformKeyDataHandler
}

func (s *keyDataScopeSuite) SetUpTest(c *C) {
	s.handler = &mockPlatformKeyDataHandler{}
	RegisterPlatformKeyDataHandler("mock-scope", s.handler)
	s.handler.scopes = nil
}

var _ = Suite(&keyDataScopeSuite{})

func (s *keyDataScopeSuite) mockProtectKeys(c *C, primaryKey PrimaryKey, KDFAlg crypto.Hash, modelAuthHash crypto.Hash) (out *KeyParams, unlockKey DiskUnlockKey) {
	unique := make([]byte, len(primaryKey))
	_, err := rand.Read(unique)
	c.Assert(err, IsNil)

	reader := new(bytes.Buffer)
	reader.Write(unique)

	unlockKey, payload, err := MakeDiskUnlockKey(reader, crypto.SHA256, primaryKey)
	c.Assert(err, IsNil)

	k := make([]byte, 48)
	_, err = rand.Read(k)
	c.Assert(err, IsNil)

	handle := mockPlatformKeyDataHandle{
		Key: k[:32],
		IV:  k[32:],
	}

	h := hmac.New(func() hash.Hash { return crypto.SHA256.New() }, handle.Key)
	h.Write(make([]byte, 32))
	handle.AuthKeyHMAC = h.Sum(nil)

	b, err := aes.NewCipher(handle.Key)
	c.Assert(err, IsNil)
	stream := cipher.NewCFBEncrypter(b, handle.IV)

	out = &KeyParams{
		PlatformName:     "mock-scope",
		Handle:           &handle,
		EncryptedPayload: make([]byte, len(payload)),
		KDFAlg:           KDFAlg}
	stream.XORKeyStream(out.EncryptedPayload, payload)

	return out, unlockKey
}
