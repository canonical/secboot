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
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/json"
	"fmt"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/bootscope"
	. "github.com/snapcore/secboot/hooks"
	"github.com/snapcore/secboot/internal/testutil"
)

type keydataSuite struct{}

var _ = Suite(&keydataSuite{})

func (*keydataSuite) SetUpSuite(c *C) {
	SetKeyProtector(makeMockKeyProtector(mockHooksProtector), 0)
	SetKeyRevealer(makeMockKeyRevealer(mockHooksRevealer))
}

func (*keydataSuite) TearDownSuite(c *C) {
	SetKeyProtector(nil, 0)
	SetKeyRevealer(nil)
}

type testNewProtectedKeyParams struct {
	rand   []byte
	params *KeyParams

	expectedPrimaryKey secboot.PrimaryKey
	expectedUnlockKey  secboot.DiskUnlockKey
	expectedHandle     json.RawMessage
	expectedScope      []byte
	expectedAeadCompat *AeadCompatData
	expectedCiphertext []byte
	expectedCleartext  []byte

	model    secboot.SnapModel
	bootMode string
}

func (s *keydataSuite) testNewProtectedKey(c *C, params *testNewProtectedKeyParams) {
	// Note that these tests will fail if secboot.KeyDataGeneration changes because the
	// expected ciphertexts will need to be updated. It would also be worth adapting
	// the tests in platformSuite if anything in these tests change, as those are based
	// on the data here.
	restore := MockSecbootNewKeyData(func(keyParams *secboot.KeyParams) (*secboot.KeyData, error) {
		c.Check(keyParams.Handle, testutil.ConvertibleTo, &KeyData{})
		c.Check(keyParams.Role, Equals, params.params.Role)
		c.Check(keyParams.EncryptedPayload, DeepEquals, params.expectedCiphertext)
		c.Check(keyParams.PlatformName, Equals, PlatformName)
		c.Check(keyParams.KDFAlg, Equals, crypto.SHA256)

		kd := keyParams.Handle.(*KeyData).Data()
		aad, err := kd.Scope.MakeAEADAdditionalData(secboot.KeyDataGeneration, keyParams.KDFAlg, secboot.AuthModeNone)
		c.Assert(err, IsNil)

		cleartext, err := mockHooksRevealer(kd.Handle, params.expectedCiphertext, aad)
		c.Assert(err, IsNil)
		c.Check(cleartext, DeepEquals, params.expectedCleartext)

		return secboot.NewKeyData(keyParams)
	})
	defer restore()

	kd, primaryKey, unlockKey, err := NewProtectedKey(testutil.BypassMaybeReadByte(bytes.NewReader(params.rand), true), params.params)
	c.Assert(err, IsNil)

	c.Check(primaryKey, DeepEquals, params.expectedPrimaryKey)
	c.Check(unlockKey, DeepEquals, params.expectedUnlockKey)

	keyData, err := NewKeyData(kd)
	c.Assert(err, IsNil)
	c.Check(keyData.K(), Equals, kd)
	c.Check(keyData.Data().Handle, DeepEquals, params.expectedHandle)
	c.Check(keyData.Data().AEADCompat, IsNil)

	scope, err := json.Marshal(keyData.Data().Scope)
	c.Assert(err, IsNil)
	c.Check(scope, DeepEquals, params.expectedScope)

	bootscope.SetModel(params.model)
	bootscope.SetBootMode(params.bootMode)

	c.Check(keyData.Data().Scope.IsBootEnvironmentAuthorized(), IsNil)
}

func (s *keydataSuite) TestNewProtectedKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:               testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params:             &KeyParams{Role: "foo"},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey1),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey1, "foo", nil, nil))),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeyDifferentRand(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:               testutil.DecodeHexString(c, primaryKey2+"5f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57a48c18e42222a6cb544c600b6b931768e38efff5d7a3cad929a28074994d977220aa298568cef92c23210b9c66f1f11ca85c0176939a5bc68c6ca412e1a1305cde80c714f6d3e02b2975becf"),
		params:             &KeyParams{Role: "foo"},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey2),
		expectedUnlockKey:  testutil.DecodeHexString(c, "4e32153664e678725f5b919fc33f7b8ae9f238388996f058355b948346629cb2"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22494b6f7068576a4f2b53776a495175635a764878484b6863415861546d6c76476a47796b457547684d46773d222c226e6f6e6365223a22336f4448465062543443737064623750227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzfzG2nPCUbuEkfdoCyhgqCq0i/NZGse1SyigJ9WbNfiBUwP8oPp85l48pq3agC7SP2JElpOBEdqZ+4SXAcVnWQ==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey2, "foo", nil, nil))),
		expectedCiphertext: testutil.DecodeHexString(c, "5771906fbc10156461de5ad0005a3043d58250adf5af92fcc93b265aa5a49ef93f9392b08e91f23390a9e270d87d8413f609dbf80ae08f207f0cbb7bc57957e0b866255b26bc728a8fc515a8f7f92785aaed6e6cc23f"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c0404205f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeySuppliedPrimaryKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			PrimaryKey: testutil.DecodeHexString(c, primaryKey1),
			Role:       "foo",
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey1),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey1, "foo", nil, nil))),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeyDifferentSuppliedPrimaryKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			PrimaryKey: testutil.DecodeHexString(c, primaryKey3),
			Role:       "foo",
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey3),
		expectedUnlockKey:  testutil.DecodeHexString(c, "8f8ee08ab3650d3218a202b55489f0790bb3c801b99210b3747c2961845b7d9d"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElmmKQ1NztKQ8a/SxC/ntozqx5jsDt7j6zyt2e2jDw0HrLf1qGJ9YuO5ZSttspVTL+82xmWsyDBBQUVH+ChcogQ==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey3, "foo", nil, nil))),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724f5ab02c4be8de464264290be35205bf7b04682e190e63e552e8105584fd7d065e2a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59c0d08d7f2ecf34eabcfb99b8409da539c"),
		expectedCleartext:  testutil.DecodeHexString(c, "304404204ace63fad0a9adc77234322739d873c81da6e4e3d006214411d18ad81b2518b50420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeyWithAuthorizedParams(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model1},
			AuthorizedBootModes:  []string{"run"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey1),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU="]},"modes":["run"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run"}, []secboot.SnapModel{model1}))),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeyWithOtherAuthorizedParams(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model1, model2},
			AuthorizedBootModes:  []string{"run", "recover"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey1),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU=","ZSIpjch5LBY6AP8X9YdKCqAmb7RtxW+rSEe1HP9EVnU="]},"modes":["run","recover"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run", "recover"}, []secboot.SnapModel{model1, model2}))),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model2,
		bootMode:           "recover",
	})
}

func (s *keydataSuite) TestNewProtectedKeyWithAuthorizedParamsDifferentRole(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			Role:                 "bar",
			AuthorizedSnapModels: []secboot.SnapModel{model1},
			AuthorizedBootModes:  []string{"run"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey1),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU="]},"modes":["run"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmuh6hs927c/VU+tf/TATilcbbkF/qN2wFhfXttwxXY7kLUYvN940eC8WVAd1I6NlJI4lrbaep2zt13GI1eMp0A==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey1, "bar", []string{"run"}, []secboot.SnapModel{model1}))),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cfc2bdf4b15c347ee9daadabb11995fb0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeyKeyProtectorError(c *C) {
	// Provide a single byte too little so that reading the nonce inside the hook fails
	rand := testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff4")
	_, _, _, err := NewProtectedKey(testutil.BypassMaybeReadByte(bytes.NewReader(rand), false, 64), nil)
	c.Check(err, ErrorMatches, `cannot protect key using hook: unexpected EOF`)
}

type testMarshalKeyDataParams struct {
	rand   []byte
	params *KeyParams

	expected []byte
}

func (s *keydataSuite) testMarshalKeyData(c *C, params *testMarshalKeyDataParams) {
	skd, _, _, err := NewProtectedKey(testutil.BypassMaybeReadByte(bytes.NewReader(params.rand), true), params.params)
	c.Assert(err, IsNil)

	kd, err := NewKeyData(skd)
	c.Assert(err, IsNil)

	data, err := json.Marshal(kd)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, params.expected)
}

func (s *keydataSuite) TestMarshalKeyData(c *C) {
	s.testMarshalKeyData(c, &testMarshalKeyDataParams{
		rand:     testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params:   &KeyParams{Role: "foo"},
		expected: []byte(fmt.Sprintf(`{"handle":{"salt":"vdt2YrEMLmplfSEfI3ApiXMXu+jb1edbql5hdWZ5D5Y=","nonce":"lCgGdbPIj/dVL/Rc"},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}}`, bootscopeJsonSignature(c, primaryKey1, "foo", nil, nil))),
	})
}

func (s *keydataSuite) TestMarshalKeyDataDifferentKey(c *C) {
	s.testMarshalKeyData(c, &testMarshalKeyDataParams{
		rand:     testutil.DecodeHexString(c, primaryKey2+"5f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57a48c18e42222a6cb544c600b6b931768e38efff5d7a3cad929a28074994d977220aa298568cef92c23210b9c66f1f11ca85c0176939a5bc68c6ca412e1a1305cde80c714f6d3e02b2975becf"),
		params:   &KeyParams{Role: "foo"},
		expected: []byte(fmt.Sprintf(`{"handle":{"salt":"IKophWjO+SwjIQucZvHxHKhcAXaTmlvGjGykEuGhMFw=","nonce":"3oDHFPbT4Cspdb7P"},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzfzG2nPCUbuEkfdoCyhgqCq0i/NZGse1SyigJ9WbNfiBUwP8oPp85l48pq3agC7SP2JElpOBEdqZ+4SXAcVnWQ==","kdf_alg":"sha256","md_alg":"sha256"}}`, bootscopeJsonSignature(c, primaryKey2, "foo", nil, nil))),
	})
}

func (s *keydataSuite) TestMarshalKeyDataWithParams(c *C) {
	s.testMarshalKeyData(c, &testMarshalKeyDataParams{
		rand: testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model1},
			AuthorizedBootModes:  []string{"run"},
		},
		expected: []byte(fmt.Sprintf(`{"handle":{"salt":"vdt2YrEMLmplfSEfI3ApiXMXu+jb1edbql5hdWZ5D5Y=","nonce":"lCgGdbPIj/dVL/Rc"},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU="]},"modes":["run"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run"}, []secboot.SnapModel{model1}))),
	})
}

func (s *keydataSuite) TestMarshalKeyDataWithOtherParams(c *C) {
	s.testMarshalKeyData(c, &testMarshalKeyDataParams{
		rand: testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model1, model2},
			AuthorizedBootModes:  []string{"run", "recover"},
		},
		expected: []byte(fmt.Sprintf(`{"handle":{"salt":"vdt2YrEMLmplfSEfI3ApiXMXu+jb1edbql5hdWZ5D5Y=","nonce":"lCgGdbPIj/dVL/Rc"},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU=","ZSIpjch5LBY6AP8X9YdKCqAmb7RtxW+rSEe1HP9EVnU="]},"modes":["run","recover"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run", "recover"}, []secboot.SnapModel{model1, model2}))),
	})
}

type testUnmarshalKeyDataParams struct {
	data       []byte
	model      secboot.SnapModel
	bootMode   string
	ciphertext []byte

	expectedPlaintext []byte
}

func (s *keydataSuite) testUnmarshalKeyData(c *C, params *testUnmarshalKeyDataParams) {
	bootscope.SetModel(params.model)
	bootscope.SetBootMode(params.bootMode)

	var platform HooksPlatform
	plaintext, err := platform.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    2,
		EncodedHandle: params.data,
		KDFAlg:        crypto.SHA256,
		AuthMode:      secboot.AuthModeNone,
	}, params.ciphertext)
	c.Check(err, IsNil)
	c.Check(plaintext, DeepEquals, params.expectedPlaintext)
}

func (s *keydataSuite) TestUnmarshalKeyData(c *C) {
	s.testUnmarshalKeyData(c, &testUnmarshalKeyDataParams{
		data:              []byte(fmt.Sprintf(`{"handle":{"salt":"vdt2YrEMLmplfSEfI3ApiXMXu+jb1edbql5hdWZ5D5Y=","nonce":"lCgGdbPIj/dVL/Rc"},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}}`, bootscopeJsonSignature(c, primaryKey1, "foo", nil, nil))),
		model:             model1,
		bootMode:          "run",
		ciphertext:        testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
}

func (s *keydataSuite) TestUnmarshalKeyDataDifferentKey(c *C) {
	s.testUnmarshalKeyData(c, &testUnmarshalKeyDataParams{
		data:              []byte(fmt.Sprintf(`{"handle":{"salt":"IKophWjO+SwjIQucZvHxHKhcAXaTmlvGjGykEuGhMFw=","nonce":"3oDHFPbT4Cspdb7P"},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzfzG2nPCUbuEkfdoCyhgqCq0i/NZGse1SyigJ9WbNfiBUwP8oPp85l48pq3agC7SP2JElpOBEdqZ+4SXAcVnWQ==","kdf_alg":"sha256","md_alg":"sha256"}}`, bootscopeJsonSignature(c, primaryKey2, "foo", nil, nil))),
		model:             model1,
		bootMode:          "run",
		ciphertext:        testutil.DecodeHexString(c, "5771906fbc10156461de5ad0005a3043d58250adf5af92fcc93b265aa5a49ef93f9392b08e91f23390a9e270d87d8413f609dbf80ae08f207f0cbb7bc57957e0b866255b26bc728a8fc515a8f7f92785aaed6e6cc23f"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c0404205f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57"),
	})
}

func (s *keydataSuite) TestUnmarshalKeyDataWithParams(c *C) {
	s.testUnmarshalKeyData(c, &testUnmarshalKeyDataParams{
		data:              []byte(fmt.Sprintf(`{"handle":{"salt":"vdt2YrEMLmplfSEfI3ApiXMXu+jb1edbql5hdWZ5D5Y=","nonce":"lCgGdbPIj/dVL/Rc"},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU="]},"modes":["run"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run"}, []secboot.SnapModel{model1}))),
		model:             model1,
		bootMode:          "run",
		ciphertext:        testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
}

func (s *keydataSuite) TestUnmarshalKeyDataWithOtherParams(c *C) {
	s.testUnmarshalKeyData(c, &testUnmarshalKeyDataParams{
		data:              []byte(fmt.Sprintf(`{"handle":{"salt":"vdt2YrEMLmplfSEfI3ApiXMXu+jb1edbql5hdWZ5D5Y=","nonce":"lCgGdbPIj/dVL/Rc"},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU=","ZSIpjch5LBY6AP8X9YdKCqAmb7RtxW+rSEe1HP9EVnU="]},"modes":["run","recover"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run", "recover"}, []secboot.SnapModel{model1, model2}))),
		model:             model2,
		bootMode:          "recover",
		ciphertext:        testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
}

type testSetAuthorizedSnapModelsParams struct {
	model    secboot.SnapModel
	bootMode string

	params *KeyParams

	authorizedModels []secboot.SnapModel
}

func (s *keydataSuite) testSetAuthorizedSnapModels(c *C, params *testSetAuthorizedSnapModelsParams) {
	bootscope.SetModel(params.model)
	bootscope.SetBootMode(params.bootMode)

	// Create an initial key that isn't authorized
	kd, primaryKey, _, err := NewProtectedKey(rand.Reader, params.params)
	c.Assert(err, IsNil)

	keyData, err := NewKeyData(kd)
	c.Assert(err, IsNil)
	c.Check(keyData.Data().Scope.IsBootEnvironmentAuthorized(), NotNil)

	c.Check(keyData.SetAuthorizedSnapModels(rand.Reader, primaryKey, params.authorizedModels...), IsNil)

	// Make sure that SetAuthorizedSnapModels updated the secboot.KeyData by decoding the handle again
	keyData, err = NewKeyData(kd)
	c.Assert(err, IsNil)

	c.Check(keyData.Data().Scope.IsBootEnvironmentAuthorized(), IsNil)
}

func (s *keydataSuite) TestSetAuthorizedSnapModelsGood1(c *C) {
	s.testSetAuthorizedSnapModels(c, &testSetAuthorizedSnapModelsParams{
		model:    model1,
		bootMode: "run",
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model2},
		},
		authorizedModels: []secboot.SnapModel{model1},
	})
}

func (s *keydataSuite) TestSetAuthorizedSnapModelsGood2(c *C) {
	s.testSetAuthorizedSnapModels(c, &testSetAuthorizedSnapModelsParams{
		model:    model2,
		bootMode: "run",
		params: &KeyParams{
			Role: "foo",
			AuthorizedSnapModels: []secboot.SnapModel{testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "other-model2",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")},
		},
		authorizedModels: []secboot.SnapModel{model1, model2},
	})
}

func (s *keydataSuite) TestSetAuthorizedSnapModelsInvalidPrimaryKey(c *C) {
	kd, primaryKey, _, err := NewProtectedKey(rand.Reader, nil)
	c.Assert(err, IsNil)

	keyData, err := NewKeyData(kd)
	c.Assert(err, IsNil)

	primaryKey[0] ^= 0xff

	c.Check(keyData.SetAuthorizedSnapModels(rand.Reader, primaryKey), ErrorMatches, `incorrect key supplied`)
}

type testSetAuthorizedBootModesParams struct {
	model    secboot.SnapModel
	bootMode string

	params *KeyParams

	authorizedBootModes []string
}

func (s *keydataSuite) testSetAuthorizedBootModes(c *C, params *testSetAuthorizedBootModesParams) {
	bootscope.SetModel(params.model)
	bootscope.SetBootMode(params.bootMode)

	// Create an initial key that isn't authorized
	kd, primaryKey, _, err := NewProtectedKey(rand.Reader, params.params)
	c.Assert(err, IsNil)

	keyData, err := NewKeyData(kd)
	c.Assert(err, IsNil)
	c.Check(keyData.Data().Scope.IsBootEnvironmentAuthorized(), NotNil)

	c.Check(keyData.SetAuthorizedBootModes(rand.Reader, primaryKey, params.authorizedBootModes...), IsNil)

	// Make sure that SetAuthorizedBootModes updated the secboot.KeyData by decoding the handle again
	keyData, err = NewKeyData(kd)
	c.Assert(err, IsNil)

	c.Check(keyData.Data().Scope.IsBootEnvironmentAuthorized(), IsNil)
}

func (s *keydataSuite) TestSetAuthorizedBootModesGood1(c *C) {
	s.testSetAuthorizedBootModes(c, &testSetAuthorizedBootModesParams{
		model:    model1,
		bootMode: "run",
		params: &KeyParams{
			Role:                "foo",
			AuthorizedBootModes: []string{"recover"},
		},
		authorizedBootModes: []string{"run"},
	})
}

func (s *keydataSuite) TestSetAuthorizedBootModesGood2(c *C) {
	s.testSetAuthorizedBootModes(c, &testSetAuthorizedBootModesParams{
		model:    model1,
		bootMode: "recover",
		params: &KeyParams{
			Role:                "foo",
			AuthorizedBootModes: []string{"factory-reset"},
		},
		authorizedBootModes: []string{"run", "recover"},
	})
}

func (s *keydataSuite) TestSetAuthorizedBootModesInvalidPrimaryKey(c *C) {
	kd, primaryKey, _, err := NewProtectedKey(rand.Reader, nil)
	c.Assert(err, IsNil)

	keyData, err := NewKeyData(kd)
	c.Assert(err, IsNil)

	primaryKey[0] ^= 0xff

	c.Check(keyData.SetAuthorizedBootModes(rand.Reader, primaryKey), ErrorMatches, `incorrect key supplied`)
}

type keydataNoAEADSuite struct{}

var _ = Suite(&keydataNoAEADSuite{})

func (*keydataNoAEADSuite) SetUpSuite(c *C) {
	SetKeyProtector(makeMockKeyProtector(mockHooksProtectorNoAEAD), KeyProtectorNoAEAD)
	SetKeyRevealer(makeMockKeyRevealer(mockHooksRevealerNoAEAD))
}

func (*keydataNoAEADSuite) TearDownSuite(c *C) {
	SetKeyProtector(nil, 0)
	SetKeyRevealer(nil)
}

func (s *keydataNoAEADSuite) testNewProtectedKey(c *C, params *testNewProtectedKeyParams) {
	// Note that these tests will fail if secboot.KeyDataGeneration changes because the
	// expected ciphertexts will need to be updated. It would also be worth adapting
	// the tests in platformSuite to use the new version as well, as those are based
	// on the data here.
	restore := MockSecbootNewKeyData(func(keyParams *secboot.KeyParams) (*secboot.KeyData, error) {
		c.Check(keyParams.Handle, testutil.ConvertibleTo, &KeyData{})
		c.Check(keyParams.Role, Equals, params.params.Role)
		c.Check(keyParams.EncryptedPayload, DeepEquals, params.expectedCiphertext)
		c.Check(keyParams.PlatformName, Equals, PlatformName)
		c.Check(keyParams.KDFAlg, Equals, crypto.SHA256)

		kd := keyParams.Handle.(*KeyData).Data()
		symKey, err := mockHooksRevealerNoAEAD(kd.Handle, kd.AEADCompat.EncryptedKey, nil)
		c.Assert(err, IsNil)

		b, err := aes.NewCipher(symKey)
		c.Assert(err, IsNil)
		aead, err := cipher.NewGCMWithNonceSize(b, len(kd.AEADCompat.Nonce))
		c.Assert(err, IsNil)

		aad, err := kd.Scope.MakeAEADAdditionalData(secboot.KeyDataGeneration, keyParams.KDFAlg, secboot.AuthModeNone)
		c.Assert(err, IsNil)

		cleartext, err := aead.Open(nil, kd.AEADCompat.Nonce, params.expectedCiphertext, aad)
		c.Check(err, IsNil)
		c.Check(cleartext, DeepEquals, params.expectedCleartext)

		return secboot.NewKeyData(keyParams)
	})
	defer restore()

	kd, primaryKey, unlockKey, err := NewProtectedKey(testutil.BypassMaybeReadByte(bytes.NewReader(params.rand), true), params.params)
	c.Assert(err, IsNil)

	c.Check(primaryKey, DeepEquals, params.expectedPrimaryKey)
	c.Check(unlockKey, DeepEquals, params.expectedUnlockKey)

	keyData, err := NewKeyData(kd)
	c.Assert(err, IsNil)
	c.Check(keyData.K(), Equals, kd)
	c.Check(keyData.Data().Handle, DeepEquals, params.expectedHandle)
	c.Check(keyData.Data().AEADCompat, DeepEquals, params.expectedAeadCompat)

	scopeBytes, err := json.Marshal(keyData.Data().Scope)
	c.Assert(err, IsNil)
	c.Check(scopeBytes, DeepEquals, params.expectedScope)

	bootscope.SetModel(params.model)
	bootscope.SetBootMode(params.bootMode)

	c.Check(keyData.Data().Scope.IsBootEnvironmentAuthorized(), IsNil)
}

func (s *keydataNoAEADSuite) TestNewProtectedKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:               testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params:             &KeyParams{Role: "foo"},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey1),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey1, "foo", nil, nil))),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyDifferentRand(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:               testutil.DecodeHexString(c, primaryKey2+"5f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57a48c18e42222a6cb544c600b6b931768e38efff5d7a3cad929a28074994d977220aa298568cef92c23210b9c66f1f11ca85c0176939a5bc68c6ca412e1a1305cde80c714f6d3e02b2975becf7e9ddc56820fafdcad918ea9accbdd2fb8e951a323b13e9dc66985bf2e68eb9a4e4bfe6ff01c7646a19f691a6ae61182"),
		params:             &KeyParams{Role: "foo"},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey2),
		expectedUnlockKey:  testutil.DecodeHexString(c, "4e32153664e678725f5b919fc33f7b8ae9f238388996f058355b948346629cb2"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2266703363566f4950723979746b593670724d76644c376a7055614d6a73543664786d6d467679356f36356f3d222c226976223a22546b762b622f4163646b61686e326b616175595267673d3d227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzfzG2nPCUbuEkfdoCyhgqCq0i/NZGse1SyigJ9WbNfiBUwP8oPp85l48pq3agC7SP2JElpOBEdqZ+4SXAcVnWQ==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey2, "foo", nil, nil))),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "de80c714f6d3e02b2975becf"),
			EncryptedKey: testutil.DecodeHexString(c, "e3c1c9cbc4a01639662f779052596c340d9c031a7b36f3f467630987623d3c09"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "beb0415d20f9a4982be7c4151217e6861cf895376e89848295a539ad25548901acd67741fe26f52a48a541a7c8e359e2c6515190433c163806239e685b8cb3c83870c6aae38e43123f704ca037d194088193e869043e"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c0404205f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeySuppliedPrimaryKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			PrimaryKey: testutil.DecodeHexString(c, primaryKey1),
			Role:       "foo",
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey1),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey1, "foo", nil, nil))),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyDifferentSuppliedPrimaryKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			PrimaryKey: testutil.DecodeHexString(c, primaryKey3),
			Role:       "foo",
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey3),
		expectedUnlockKey:  testutil.DecodeHexString(c, "8f8ee08ab3650d3218a202b55489f0790bb3c801b99210b3747c2961845b7d9d"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElmmKQ1NztKQ8a/SxC/ntozqx5jsDt7j6zyt2e2jDw0HrLf1qGJ9YuO5ZSttspVTL+82xmWsyDBBQUVH+ChcogQ==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey3, "foo", nil, nil))),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb964ea168b4623d6813cbd501e4bb7f7afcd1950ee312f5dba2c8d369d7c206dd7c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52abb72b2542b2c34981b587e4beecf58d"),
		expectedCleartext:  testutil.DecodeHexString(c, "304404204ace63fad0a9adc77234322739d873c81da6e4e3d006214411d18ad81b2518b50420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyWithAuthorizedParams(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model1},
			AuthorizedBootModes:  []string{"run"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey1),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU="]},"modes":["run"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run"}, []secboot.SnapModel{model1}))),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyWithOtherAuthorizedParams(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model1, model2},
			AuthorizedBootModes:  []string{"run", "recover"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, primaryKey1),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU=","ZSIpjch5LBY6AP8X9YdKCqAmb7RtxW+rSEe1HP9EVnU="]},"modes":["run","recover"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run", "recover"}, []secboot.SnapModel{model1, model2}))),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model2,
		bootMode:           "recover",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyWithAuthorizedParamsiDifferentRole(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			Role:                 "bar",
			AuthorizedSnapModels: []secboot.SnapModel{model1},
			AuthorizedBootModes:  []string{"run"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      []byte(fmt.Sprintf(`{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU="]},"modes":["run"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmuh6hs927c/VU+tf/TATilcbbkF/qN2wFhfXttwxXY7kLUYvN940eC8WVAd1I6NlJI4lrbaep2zt13GI1eMp0A==","kdf_alg":"sha256","md_alg":"sha256"}`, bootscopeJsonSignature(c, primaryKey1, "bar", []string{"run"}, []secboot.SnapModel{model1}))),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f523c5c96bc534986143866987aaa0e2e0a"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model1,
		bootMode:           "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyKeyProtectorError(c *C) {
	// Provide a single byte too little so that reading the IV inside the hook fails
	rand := testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63")
	_, _, _, err := NewProtectedKey(testutil.BypassMaybeReadByte(bytes.NewReader(rand), false, 64), nil)
	c.Check(err, ErrorMatches, `cannot protect symmetric key for AEAD compat using hook: unexpected EOF`)
}

func (s *keydataNoAEADSuite) testMarshalKeyData(c *C, params *testMarshalKeyDataParams) {
	skd, _, _, err := NewProtectedKey(testutil.BypassMaybeReadByte(bytes.NewReader(params.rand), true), params.params)
	c.Assert(err, IsNil)

	kd, err := NewKeyData(skd)
	c.Assert(err, IsNil)

	data, err := json.Marshal(kd)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, params.expected)
}

func (s *keydataNoAEADSuite) TestMarshalKeyData(c *C) {
	s.testMarshalKeyData(c, &testMarshalKeyDataParams{
		rand:     testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params:   &KeyParams{Role: "foo"},
		expected: []byte(fmt.Sprintf(`{"handle":{"salt":"e7ZGda992+LuzGom+quLixcMe5Venv3muPEUmAsyWIU=","iv":"aHzANSRq5xvOnvbHVtpjwg=="},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"},"aead_compat":{"nonce":"lCgGdbPIj/dVL/Rc","encrypted_key":"Y2O32i8KtriV+2JgktVnHH2zXr47ll2lu8MffpKHB24="}}`, bootscopeJsonSignature(c, primaryKey1, "foo", nil, nil))),
	})
}

func (s *keydataNoAEADSuite) TestMarshalKeyDataDifferentKey(c *C) {
	s.testMarshalKeyData(c, &testMarshalKeyDataParams{
		rand:     testutil.DecodeHexString(c, primaryKey2+"5f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57a48c18e42222a6cb544c600b6b931768e38efff5d7a3cad929a28074994d977220aa298568cef92c23210b9c66f1f11ca85c0176939a5bc68c6ca412e1a1305cde80c714f6d3e02b2975becf7e9ddc56820fafdcad918ea9accbdd2fb8e951a323b13e9dc66985bf2e68eb9a4e4bfe6ff01c7646a19f691a6ae61182"),
		params:   &KeyParams{Role: "foo"},
		expected: []byte(fmt.Sprintf(`{"handle":{"salt":"fp3cVoIPr9ytkY6prMvdL7jpUaMjsT6dxmmFvy5o65o=","iv":"Tkv+b/Acdkahn2kaauYRgg=="},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzfzG2nPCUbuEkfdoCyhgqCq0i/NZGse1SyigJ9WbNfiBUwP8oPp85l48pq3agC7SP2JElpOBEdqZ+4SXAcVnWQ==","kdf_alg":"sha256","md_alg":"sha256"},"aead_compat":{"nonce":"3oDHFPbT4Cspdb7P","encrypted_key":"48HJy8SgFjlmL3eQUllsNA2cAxp7NvP0Z2MJh2I9PAk="}}`, bootscopeJsonSignature(c, primaryKey2, "foo", nil, nil))),
	})
}

func (s *keydataNoAEADSuite) TestMarshalKeyDataWithParams(c *C) {
	s.testMarshalKeyData(c, &testMarshalKeyDataParams{
		rand: testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model1},
			AuthorizedBootModes:  []string{"run"},
		},
		expected: []byte(fmt.Sprintf(`{"handle":{"salt":"e7ZGda992+LuzGom+quLixcMe5Venv3muPEUmAsyWIU=","iv":"aHzANSRq5xvOnvbHVtpjwg=="},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU="]},"modes":["run"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"},"aead_compat":{"nonce":"lCgGdbPIj/dVL/Rc","encrypted_key":"Y2O32i8KtriV+2JgktVnHH2zXr47ll2lu8MffpKHB24="}}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run"}, []secboot.SnapModel{model1}))),
	})
}

func (s *keydataNoAEADSuite) TestMarshalKeyDataWithOtherParams(c *C) {
	s.testMarshalKeyData(c, &testMarshalKeyDataParams{
		rand: testutil.DecodeHexString(c, primaryKey1+"e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model1, model2},
			AuthorizedBootModes:  []string{"run", "recover"},
		},
		expected: []byte(fmt.Sprintf(`{"handle":{"salt":"e7ZGda992+LuzGom+quLixcMe5Venv3muPEUmAsyWIU=","iv":"aHzANSRq5xvOnvbHVtpjwg=="},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU=","ZSIpjch5LBY6AP8X9YdKCqAmb7RtxW+rSEe1HP9EVnU="]},"modes":["run","recover"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"},"aead_compat":{"nonce":"lCgGdbPIj/dVL/Rc","encrypted_key":"Y2O32i8KtriV+2JgktVnHH2zXr47ll2lu8MffpKHB24="}}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run", "recover"}, []secboot.SnapModel{model1, model2}))),
	})
}

func (s *keydataNoAEADSuite) testUnmarshalKeyData(c *C, params *testUnmarshalKeyDataParams) {
	bootscope.SetModel(params.model)
	bootscope.SetBootMode(params.bootMode)

	var platform HooksPlatform
	plaintext, err := platform.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    2,
		EncodedHandle: params.data,
		KDFAlg:        crypto.SHA256,
		AuthMode:      secboot.AuthModeNone,
	}, params.ciphertext)
	c.Check(err, IsNil)
	c.Check(plaintext, DeepEquals, params.expectedPlaintext)
}

func (s *keydataNoAEADSuite) TestUnmarshalKeyData(c *C) {
	s.testUnmarshalKeyData(c, &testUnmarshalKeyDataParams{
		data:              []byte(fmt.Sprintf(`{"handle":{"salt":"e7ZGda992+LuzGom+quLixcMe5Venv3muPEUmAsyWIU=","iv":"aHzANSRq5xvOnvbHVtpjwg=="},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"},"aead_compat":{"nonce":"lCgGdbPIj/dVL/Rc","encrypted_key":"Y2O32i8KtriV+2JgktVnHH2zXr47ll2lu8MffpKHB24="}}`, bootscopeJsonSignature(c, primaryKey1, "foo", nil, nil))),
		model:             model1,
		bootMode:          "run",
		ciphertext:        testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
}

func (s *keydataNoAEADSuite) TestUnmarshalKeyDataDifferentKey(c *C) {
	s.testUnmarshalKeyData(c, &testUnmarshalKeyDataParams{
		data:              []byte(fmt.Sprintf(`{"handle":{"salt":"fp3cVoIPr9ytkY6prMvdL7jpUaMjsT6dxmmFvy5o65o=","iv":"Tkv+b/Acdkahn2kaauYRgg=="},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":null}},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzfzG2nPCUbuEkfdoCyhgqCq0i/NZGse1SyigJ9WbNfiBUwP8oPp85l48pq3agC7SP2JElpOBEdqZ+4SXAcVnWQ==","kdf_alg":"sha256","md_alg":"sha256"},"aead_compat":{"nonce":"3oDHFPbT4Cspdb7P","encrypted_key":"48HJy8SgFjlmL3eQUllsNA2cAxp7NvP0Z2MJh2I9PAk="}}`, bootscopeJsonSignature(c, primaryKey2, "foo", nil, nil))),
		model:             model1,
		bootMode:          "run",
		ciphertext:        testutil.DecodeHexString(c, "beb0415d20f9a4982be7c4151217e6861cf895376e89848295a539ad25548901acd67741fe26f52a48a541a7c8e359e2c6515190433c163806239e685b8cb3c83870c6aae38e43123f704ca037d194088193e869043e"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c0404205f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57"),
	})
}

func (s *keydataNoAEADSuite) TestUnmarshalKeyDataWithParams(c *C) {
	s.testUnmarshalKeyData(c, &testUnmarshalKeyDataParams{
		data:              []byte(fmt.Sprintf(`{"handle":{"salt":"e7ZGda992+LuzGom+quLixcMe5Venv3muPEUmAsyWIU=","iv":"aHzANSRq5xvOnvbHVtpjwg=="},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU="]},"modes":["run"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"},"aead_compat":{"nonce":"lCgGdbPIj/dVL/Rc","encrypted_key":"Y2O32i8KtriV+2JgktVnHH2zXr47ll2lu8MffpKHB24="}}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run"}, []secboot.SnapModel{model1}))),
		model:             model1,
		bootMode:          "run",
		ciphertext:        testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
}

func (s *keydataNoAEADSuite) TestUnmarshalKeyDataWithOtherParams(c *C) {
	s.testUnmarshalKeyData(c, &testUnmarshalKeyDataParams{
		data:              []byte(fmt.Sprintf(`{"handle":{"salt":"e7ZGda992+LuzGom+quLixcMe5Venv3muPEUmAsyWIU=","iv":"aHzANSRq5xvOnvbHVtpjwg=="},"scope":{"version":1,"params":{"model_digests":{"alg":"sha256","digests":["OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU=","ZSIpjch5LBY6AP8X9YdKCqAmb7RtxW+rSEe1HP9EVnU="]},"modes":["run","recover"]},"signature":%q,"pubkey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE74IiBOQeg9TfT3jaVoVp5jcpcMVvmL7oDOUFgsmwRagZy4pM8pEn/wFlTZSB9BBSQcEPbfxT9Cov496E7OVj+Q==","kdf_alg":"sha256","md_alg":"sha256"},"aead_compat":{"nonce":"lCgGdbPIj/dVL/Rc","encrypted_key":"Y2O32i8KtriV+2JgktVnHH2zXr47ll2lu8MffpKHB24="}}`, bootscopeJsonSignature(c, primaryKey1, "foo", []string{"run", "recover"}, []secboot.SnapModel{model1, model2}))),
		model:             model2,
		bootMode:          "recover",
		ciphertext:        testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
	})
}
