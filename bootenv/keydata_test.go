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

func (s *keyDataPlatformSuite) TestMakeAdditionalData(c *C) {
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

	_, err = kds.MakeAdditionalData(1, crypto.SHA256, secboot.AuthModeNone)
	c.Check(err, IsNil)

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
