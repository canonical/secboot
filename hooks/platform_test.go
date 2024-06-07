// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package hooks_test

import (
	"crypto"
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/json"
	"errors"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/bootscope"
	. "github.com/snapcore/secboot/hooks"
	"github.com/snapcore/secboot/internal/testutil"
)

type platformSuite struct{}

func (s *platformSuite) SetUpSuite(c *C) {
	SetKeyRevealer(makeMockKeyRevealer(mockHooksRevealer))
}

func (s *platformSuite) TearDownSuite(c *C) {
	SetKeyRevealer(nil)
}

var _ = Suite(&platformSuite{})

type testRecoverKeysParams struct {
	model    secboot.SnapModel
	bootMode string

	generation    int
	useInvalidKDF bool
	keyData       *KeyData
	ciphertext    []byte

	expectedPlaintext []byte
}

func (s *platformSuite) testRecoverKeys(c *C, params *testRecoverKeysParams) error {
	bootscope.SetModel(params.model)
	bootscope.SetBootMode(params.bootMode)

	handle, err := json.Marshal(params.keyData)
	c.Assert(err, IsNil)

	kdf := crypto.SHA256
	if params.useInvalidKDF {
		kdf = crypto.Hash(0)
	}
	var platform HooksPlatform
	payload, err := platform.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    params.generation,
		EncodedHandle: handle,
		KDFAlg:        kdf,
		AuthMode:      secboot.AuthModeNone,
	}, params.ciphertext)
	if err != nil {
		return err
	}
	c.Check(payload, DeepEquals, params.expectedPlaintext)
	return nil
}

func (s *platformSuite) TestRecoverKeys(c *C) {
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
			Scope:  *scope,
		}),
		ciphertext:        testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
	c.Check(err, IsNil)
}

func (s *platformSuite) TestRecoverKeysDifferentKey(c *C) {
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: testutil.DecodeHexString(c, "a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c04"),
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a22494b6f7068576a4f2b53776a495175635a764878484b6863415861546d6c76476a47796b457547684d46773d222c226e6f6e6365223a22336f4448465062543443737064623750227d"),
			Scope:  *scope,
		}),
		ciphertext:        testutil.DecodeHexString(c, "5771906fbc10156461de5ad0005a3043d58250adf5af92fcc93b265aa5a49ef93f9392b08e91f23390a9e270d87d8413f609dbf80ae08f207f0cbb7bc57957e0b866255b26bc728a8fc515a8f7f92785aaed6e6cc23f"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c0404205f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57"),
	})
	c.Check(err, IsNil)
}

func (s *platformSuite) TestRecoverKeysWithParams(c *C) {
	primaryKey := testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa")
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: primaryKey,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)
	c.Check(scope.SetAuthorizedSnapModels(primaryKey, "foo", model), IsNil)
	c.Check(scope.SetAuthorizedBootModes(primaryKey, "foo", "run"), IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model:      model,
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
			Scope:  *scope,
		}),
		ciphertext:        testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
	c.Check(err, IsNil)
}

func (s *platformSuite) TestRecoverKeysWithDiffererntParams(c *C) {
	primaryKey := testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa")
	models := []secboot.SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
	}

	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: primaryKey,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)
	c.Check(scope.SetAuthorizedSnapModels(primaryKey, "foo", models...), IsNil)
	c.Check(scope.SetAuthorizedBootModes(primaryKey, "foo", "run", "recover"), IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model:      models[0],
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
			Scope:  *scope,
		}),
		ciphertext:        testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
	c.Check(err, IsNil)
}

func (s *platformSuite) TestRecoverKeysWithParamsDifferentRole(c *C) {
	primaryKey := testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa")
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "bar",
		PrimaryKey: primaryKey,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)
	c.Check(scope.SetAuthorizedSnapModels(primaryKey, "bar", model), IsNil)
	c.Check(scope.SetAuthorizedBootModes(primaryKey, "bar", "run"), IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model:      model,
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
			Scope:  *scope,
		}),
		ciphertext:        testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cfc2bdf4b15c347ee9daadabb11995fb0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
	c.Check(err, IsNil)
}

func (s *platformSuite) TestRecoverKeysInvalidHandle(c *C) {
	bootscope.SetModel(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"))
	bootscope.SetBootMode("run")

	var platform HooksPlatform
	_, err := platform.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    2,
		EncodedHandle: []byte("foo"),
		KDFAlg:        crypto.SHA256,
		AuthMode:      secboot.AuthModeNone,
	}, testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"))
	c.Check(err, ErrorMatches, `invalid character 'o' in literal false \(expecting 'a'\)`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

func (s *platformSuite) TestRecoverKeysInvalidBootEnvironment(c *C) {
	primaryKey := testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa")
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: primaryKey,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	authModel := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")
	c.Check(scope.SetAuthorizedSnapModels(primaryKey, "foo", authModel), IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
			Scope:  *scope,
		}),
		ciphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
	})
	c.Check(err, ErrorMatches, `cannot authorize boot environment: unauthorized model`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

func (s *platformSuite) TestRecoverKeysMakeAADError(c *C) {
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:      "run",
		generation:    2,
		useInvalidKDF: true, // pass an invalid KDF to RecoverKeys to that DER marshalling fails
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
			Scope:  *scope,
		}),
		ciphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
	})
	c.Check(err, ErrorMatches, `cannot make AAD: unknown hash algorithm: unknown hash value 0`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

func (s *platformSuite) TestRecoverKeysKeyRevealerError(c *C) {
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:   "run",
		generation: 3, // change the AAD to make the hook RevealKey return an error
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
			Scope:  *scope,
		}),
		ciphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
	})
	c.Check(err, ErrorMatches, `cannot recover key: cipher: message authentication failed`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

type platformSuiteNoAEAD struct{}

func (s *platformSuiteNoAEAD) SetUpSuite(c *C) {
	SetKeyRevealer(makeMockKeyRevealer(mockHooksRevealerNoAEAD))
}

func (s *platformSuiteNoAEAD) TearDownSuite(c *C) {
	SetKeyRevealer(nil)
}

var _ = Suite(&platformSuiteNoAEAD{})

func (s *platformSuiteNoAEAD) testRecoverKeys(c *C, params *testRecoverKeysParams) error {
	bootscope.SetModel(params.model)
	bootscope.SetBootMode(params.bootMode)

	handle, err := json.Marshal(params.keyData)
	c.Assert(err, IsNil)

	var platform HooksPlatform
	payload, err := platform.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    params.generation,
		EncodedHandle: handle,
		KDFAlg:        crypto.SHA256,
		AuthMode:      secboot.AuthModeNone,
	}, params.ciphertext)
	if err != nil {
		return err
	}
	c.Check(payload, DeepEquals, params.expectedPlaintext)
	return nil
}

func (s *platformSuiteNoAEAD) TestRecoverKeys(c *C) {
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
			Scope:  *scope,
			AEADCompat: &AeadCompatData{
				Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
				EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
			},
		}),
		ciphertext:        testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
	c.Check(err, IsNil)
}

func (s *platformSuiteNoAEAD) TestRecoverKeysDifferentKey(c *C) {
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: testutil.DecodeHexString(c, "a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c04"),
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a2266703363566f4950723979746b593670724d76644c376a7055614d6a73543664786d6d467679356f36356f3d222c226976223a22546b762b622f4163646b61686e326b616175595267673d3d227d"),
			Scope:  *scope,
			AEADCompat: &AeadCompatData{
				Nonce:        testutil.DecodeHexString(c, "de80c714f6d3e02b2975becf"),
				EncryptedKey: testutil.DecodeHexString(c, "e3c1c9cbc4a01639662f779052596c340d9c031a7b36f3f467630987623d3c09"),
			},
		}),
		ciphertext:        testutil.DecodeHexString(c, "beb0415d20f9a4982be7c4151217e6861cf895376e89848295a539ad25548901acd67741fe26f52a48a541a7c8e359e2c6515190433c163806239e685b8cb3c83870c6aae38e43123f704ca037d194088193e869043e"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c0404205f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57"),
	})
	c.Check(err, IsNil)
}

func (s *platformSuiteNoAEAD) TestRecoverKeysWithParams(c *C) {
	primaryKey := testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa")
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: primaryKey,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)
	c.Check(scope.SetAuthorizedSnapModels(primaryKey, "foo", model), IsNil)
	c.Check(scope.SetAuthorizedBootModes(primaryKey, "foo", "run"), IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model:      model,
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
			Scope:  *scope,
			AEADCompat: &AeadCompatData{
				Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
				EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
			},
		}),
		ciphertext:        testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
	c.Check(err, IsNil)
}

func (s *platformSuiteNoAEAD) TestRecoverKeysWithDiffererentParams(c *C) {
	primaryKey := testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa")
	models := []secboot.SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
	}

	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: primaryKey,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)
	c.Check(scope.SetAuthorizedSnapModels(primaryKey, "foo", models...), IsNil)
	c.Check(scope.SetAuthorizedBootModes(primaryKey, "foo", "run", "recover"), IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model:      models[0],
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
			Scope:  *scope,
			AEADCompat: &AeadCompatData{
				Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
				EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
			},
		}),
		ciphertext:        testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
	c.Check(err, IsNil)
}

func (s *platformSuiteNoAEAD) TestRecoverKeysWithParamsDifferentRole(c *C) {
	primaryKey := testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa")
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "bar",
		PrimaryKey: primaryKey,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)
	c.Check(scope.SetAuthorizedSnapModels(primaryKey, "bar", model), IsNil)
	c.Check(scope.SetAuthorizedBootModes(primaryKey, "bar", "run"), IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model:      model,
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
			Scope:  *scope,
			AEADCompat: &AeadCompatData{
				Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
				EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
			},
		}),
		ciphertext:        testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f523c5c96bc534986143866987aaa0e2e0a"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
	c.Check(err, IsNil)
}

func (s *platformSuiteNoAEAD) TestRecoverKeysKeyRevealerError(c *C) {
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	// Decode the same hook handle that's used in other tests and then trim a byte off the IV
	// to make the hook RevealKey fail.
	var handle *mockHooksNoAEADKeyData
	c.Assert(json.Unmarshal(testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"), &handle), IsNil)
	handle.IV = handle.IV[:15] // Save a 15 byte IV
	handleBytes, err := json.Marshal(handle)
	c.Assert(err, IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: handleBytes,
			Scope:  *scope,
			AEADCompat: &AeadCompatData{
				Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
				EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
			},
		}),
		ciphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
	})
	c.Check(err, ErrorMatches, `cannot recover symmetric key: invalid IV size`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

func (s *platformSuiteNoAEAD) TestRecoverKeysNewCipherError(c *C) {
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
			Scope:  *scope,
			AEADCompat: &AeadCompatData{
				Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
				EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e928707"), // chop a byte off the key to make it 31 bytes
			},
		}),
		ciphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
	})
	c.Check(err, ErrorMatches, `cannot create cipher: crypto/aes: invalid key size 31`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

func (s *platformSuiteNoAEAD) TestRecoverKeysNewGCMError(c *C) {
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:   "run",
		generation: 2,
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
			Scope:  *scope,
			AEADCompat: &AeadCompatData{
				// Supply an empty nonce, which is invalid
				EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
			},
		}),
		ciphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
	})
	c.Check(err, ErrorMatches, `cannot create AEAD: cipher: the nonce can't have zero length, or the security of the key will be immediately compromised`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

func (s *platformSuiteNoAEAD) TestRecoverKeyOpenError(c *C) {
	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		Role:       "foo",
		PrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	c.Assert(err, IsNil)

	err = s.testRecoverKeys(c, &testRecoverKeysParams{
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode:   "run",
		generation: 3, // invalidate the AAD so that Open fails
		keyData: MakeKeyData(&PrivateKeyData{
			Handle: testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
			Scope:  *scope,
			AEADCompat: &AeadCompatData{
				Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
				EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
			},
		}),
		ciphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
	})
	c.Check(err, ErrorMatches, `cannot recover key: cipher: message authentication failed`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

type platformSuiteIntegrated struct{}

var _ = Suite(&platformSuiteIntegrated{})

func (s *platformSuiteIntegrated) SetUpSuite(c *C) {
	SetKeyProtector(makeMockKeyProtector(mockHooksProtector), 0)
	SetKeyRevealer(makeMockKeyRevealer(mockHooksRevealer))
}

func (s *platformSuiteIntegrated) TearDownSuite(c *C) {
	SetKeyProtector(nil, 0)
	SetKeyRevealer(nil)
}

func (s *platformSuiteIntegrated) TestRecoverKeys(c *C) {
	params := &KeyParams{
		Role: "run",
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		},
		AuthorizedBootModes: []string{"run"},
	}
	kd, expectedPrimaryKey, expectedUnlockKey, err := NewProtectedKey(rand.Reader, params)
	c.Assert(err, IsNil)

	bootscope.SetModel(params.AuthorizedSnapModels[0])
	bootscope.SetBootMode(params.AuthorizedBootModes[0])

	unlockKey, primaryKey, err := kd.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(unlockKey, DeepEquals, expectedUnlockKey)
	c.Check(primaryKey, DeepEquals, expectedPrimaryKey)
}

func (s *platformSuiteIntegrated) TestRecoverKeysInvalidModel(c *C) {
	params := &KeyParams{
		Role: "run",
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		},
		AuthorizedBootModes: []string{"run"},
	}
	kd, _, _, err := NewProtectedKey(rand.Reader, params)
	c.Assert(err, IsNil)

	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "other-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	bootscope.SetModel(model)
	bootscope.SetBootMode(params.AuthorizedBootModes[0])

	_, _, err = kd.RecoverKeys()
	c.Check(err, ErrorMatches, `invalid key data: cannot authorize boot environment: unauthorized model`)

	var e *secboot.InvalidKeyDataError
	c.Check(errors.As(err, &e), testutil.IsTrue)
}

func (s *platformSuiteIntegrated) TestRecoverKeysInvalidBootMode(c *C) {
	params := &KeyParams{
		Role: "run",
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		},
		AuthorizedBootModes: []string{"run"},
	}
	kd, _, _, err := NewProtectedKey(rand.Reader, params)
	c.Assert(err, IsNil)

	bootscope.SetModel(params.AuthorizedSnapModels[0])
	bootscope.SetBootMode("recover")

	_, _, err = kd.RecoverKeys()
	c.Check(err, ErrorMatches, `invalid key data: cannot authorize boot environment: unauthorized boot mode`)

	var e *secboot.InvalidKeyDataError
	c.Check(errors.As(err, &e), testutil.IsTrue)
}
