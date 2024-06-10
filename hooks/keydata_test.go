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
	"encoding/json"

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
}

func (*keydataSuite) TearDownSuite(c *C) {
	SetKeyProtector(nil, 0)
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

	scopeBytes, err := json.Marshal(keyData.Data().Scope)
	c.Assert(err, IsNil)
	c.Check(scopeBytes, DeepEquals, params.expectedScope)

	bootscope.SetModel(params.model)
	bootscope.SetBootMode(params.bootMode)

	c.Check(keyData.Data().Scope.IsBootEnvironmentAuthorized(), IsNil)
}

func (s *keydataSuite) TestNewProtectedKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:               testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params:             &KeyParams{Role: "foo"},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a6e756c6c7d7d2c227369676e6174757265223a224d4555434951447a50716f707a2b763530355065747542736e78764d462b4664786777645145315a6d6f58573551364c5a41496745794d6a6e6239426e6452366c364b55614c7a676e4d446f4b39383643785a342f6366494f454c6d5953733d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414537344969424f51656739546654336a61566f5670356a6370634d56766d4c376f444f554667736d775261675a7934704d3870456e2f77466c545a534239424253516345506266785439436f7634393645374f566a2b513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode: "run",
	})
}

func (s *keydataSuite) TestNewProtectedDifferentRand(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:               testutil.DecodeHexString(c, "a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c045f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57a48c18e42222a6cb544c600b6b931768e38efff5d7a3cad929a28074994d977220aa298568cef92c23210b9c66f1f11ca85c0176939a5bc68c6ca412e1a1305cde80c714f6d3e02b2975becf"),
		params:             &KeyParams{Role: "foo"},
		expectedPrimaryKey: testutil.DecodeHexString(c, "a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c04"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "4e32153664e678725f5b919fc33f7b8ae9f238388996f058355b948346629cb2"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22494b6f7068576a4f2b53776a495175635a764878484b6863415861546d6c76476a47796b457547684d46773d222c226e6f6e6365223a22336f4448465062543443737064623750227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a6e756c6c7d7d2c227369676e6174757265223a224d4555434951443272315468347874777a6a6a3870394c51774c4966393851504f6c4d626d4344764b3244564149437147774967564b6f36744e706a6366486967754c4c416350665446324b457067576f7a576878535270446e364973654d3d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741457a667a47326e5043556275456b66646f4379686771437130692f4e5a47736531537969674a3957624e666942557750386f507038356c3438707133616743375350324a456c704f424564715a2b3453584163566e57513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedCiphertext: testutil.DecodeHexString(c, "5771906fbc10156461de5ad0005a3043d58250adf5af92fcc93b265aa5a49ef93f9392b08e91f23390a9e270d87d8413f609dbf80ae08f207f0cbb7bc57957e0b866255b26bc728a8fc515a8f7f92785aaed6e6cc23f"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c0404205f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57"),
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode: "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeySuppliedPrimaryKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			PrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
			Role:       "foo",
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a6e756c6c7d7d2c227369676e6174757265223a224d4555434951447a50716f707a2b763530355065747542736e78764d462b4664786777645145315a6d6f58573551364c5a41496745794d6a6e6239426e6452366c364b55614c7a676e4d446f4b39383643785a342f6366494f454c6d5953733d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414537344969424f51656739546654336a61566f5670356a6370634d56766d4c376f444f554667736d775261675a7934704d3870456e2f77466c545a534239424253516345506266785439436f7634393645374f566a2b513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode: "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeyDifferentSuppliedPrimaryKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			PrimaryKey: testutil.DecodeHexString(c, "4ace63fad0a9adc77234322739d873c81da6e4e3d006214411d18ad81b2518b5"),
			Role:       "foo",
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "4ace63fad0a9adc77234322739d873c81da6e4e3d006214411d18ad81b2518b5"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "8f8ee08ab3650d3218a202b55489f0790bb3c801b99210b3747c2961845b7d9d"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a6e756c6c7d7d2c227369676e6174757265223a224d455143494337472f7a4f3442745037505951514b7666316a5234686d397654627a6361376b35682f5a756947683748416941646662706c495a765774553033425951773471316f4f7052744e33346d70526b466e4f66317433593759513d3d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741456c6d6d4b51314e7a744b5138612f5378432f6e746f7a7178356a734474376a367a79743265326a44773048724c663171474a3959754f355a537474737056544c2b3832786d577379444242515556482b4368636f67513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724f5ab02c4be8de464264290be35205bf7b04682e190e63e552e8105584fd7d065e2a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59c0d08d7f2ecf34eabcfb99b8409da539c"),
		expectedCleartext:  testutil.DecodeHexString(c, "304404204ace63fad0a9adc77234322739d873c81da6e4e3d006214411d18ad81b2518b50420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode: "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeyWithAuthorizedParams(c *C) {
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model},
			AuthorizedBootModes:  []string{"run"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a5b224f647444314f7a2b4c56473441373752546b45314a614b6f704438702f41786355517361394d2f505072553d225d7d2c226d6f646573223a5b2272756e225d7d2c227369676e6174757265223a224d45514349413139534555416869474d704670427a5a5955666943336947433957336e39473244667a746a4e614f525241694270582f367a485255433658465363582b3076616a704d5964677270636b586d6c4f34696d795944727643773d3d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414537344969424f51656739546654336a61566f5670356a6370634d56766d4c376f444f554667736d775261675a7934704d3870456e2f77466c545a534239424253516345506266785439436f7634393645374f566a2b513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model,
		bootMode:           "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeyWithOtherAuthorizedParams(c *C) {
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

	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: models,
			AuthorizedBootModes:  []string{"run", "recover"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a5b224f647444314f7a2b4c56473441373752546b45314a614b6f704438702f41786355517361394d2f505072553d222c225a5349706a6368354c425936415038583959644b4371416d6237527478572b725345653148503945566e553d225d7d2c226d6f646573223a5b2272756e222c227265636f766572225d7d2c227369676e6174757265223a224d4551434947524b70336158624e796e327649625a432f63413635466372684747614f77674e7332536e724b595a4a36416941424e614573314a44424344697456473954643638502f44384873615373384b6c4b4c57497038474e612f773d3d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414537344969424f51656739546654336a61566f5670356a6370634d56766d4c376f444f554667736d775261675a7934704d3870456e2f77466c545a534239424253516345506266785439436f7634393645374f566a2b513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cf7b30f2689ca11b1750c65cb0e0d52a0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              models[1],
		bootMode:           "recover",
	})
}

func (s *keydataSuite) TestNewProtectedKeyWithAuthorizedParamsDifferentRole(c *C) {
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c"),
		params: &KeyParams{
			Role:                 "bar",
			AuthorizedSnapModels: []secboot.SnapModel{model},
			AuthorizedBootModes:  []string{"run"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a22766474325972454d4c6d706c665345664933417069584d58752b6a6231656462716c356864575a354435593d222c226e6f6e6365223a226c436747646250496a2f64564c2f5263227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a5b224f647444314f7a2b4c56473441373752546b45314a614b6f704438702f41786355517361394d2f505072553d225d7d2c226d6f646573223a5b2272756e225d7d2c227369676e6174757265223a224d4559434951446247754f7a2b31434a4f50757a58464a746338374f6a4835647537725063504f363659344e3379707950514968414d6c4d564d6379584c674178475672684d654d704e4c75562b784265556f2b506a7131657a74336d366932222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741456d7568366873393237632f56552b74662f544154696c6362626b462f714e327746686658747477785859376b4c5559764e393430654338575641643149364e6c4a49346c7262616570327a743133474931654d7030413d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedCiphertext: testutil.DecodeHexString(c, "6244724fe5649c7ed7610c82774eea6dff2c32bad54c08549fe31124d63b7173887346112a0662331fb14e2645f872da5808f703b9bb779496e7afe33412a4e21f7157b5f59cfc2bdf4b15c347ee9daadabb11995fb0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model,
		bootMode:           "run",
	})
}

func (s *keydataSuite) TestNewProtectedKeyKeyProtectorError(c *C) {
	// Provide a single byte too little so that reading the nonce inside the hook fails
	rand := testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff4")
	_, _, _, err := NewProtectedKey(testutil.BypassMaybeReadByte(bytes.NewReader(rand), false, 64), nil)
	c.Check(err, ErrorMatches, `cannot protect key using hook: unexpected EOF`)
}

type keydataNoAEADSuite struct{}

var _ = Suite(&keydataNoAEADSuite{})

func (*keydataNoAEADSuite) SetUpSuite(c *C) {
	SetKeyProtector(makeMockKeyProtector(mockHooksProtectorNoAEAD), KeyProtectorNoAEAD)
}

func (*keydataNoAEADSuite) TearDownSuite(c *C) {
	SetKeyProtector(nil, 0)
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
		rand:               testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params:             &KeyParams{Role: "foo"},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a6e756c6c7d7d2c227369676e6174757265223a224d4555434951447a50716f707a2b763530355065747542736e78764d462b4664786777645145315a6d6f58573551364c5a41496745794d6a6e6239426e6452366c364b55614c7a676e4d446f4b39383643785a342f6366494f454c6d5953733d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414537344969424f51656739546654336a61566f5670356a6370634d56766d4c376f444f554667736d775261675a7934704d3870456e2f77466c545a534239424253516345506266785439436f7634393645374f566a2b513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode: "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedDifferentRand(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:               testutil.DecodeHexString(c, "a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c045f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57a48c18e42222a6cb544c600b6b931768e38efff5d7a3cad929a28074994d977220aa298568cef92c23210b9c66f1f11ca85c0176939a5bc68c6ca412e1a1305cde80c714f6d3e02b2975becf7e9ddc56820fafdcad918ea9accbdd2fb8e951a323b13e9dc66985bf2e68eb9a4e4bfe6ff01c7646a19f691a6ae61182"),
		params:             &KeyParams{Role: "foo"},
		expectedPrimaryKey: testutil.DecodeHexString(c, "a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c04"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "4e32153664e678725f5b919fc33f7b8ae9f238388996f058355b948346629cb2"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2266703363566f4950723979746b593670724d76644c376a7055614d6a73543664786d6d467679356f36356f3d222c226976223a22546b762b622f4163646b61686e326b616175595267673d3d227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a6e756c6c7d7d2c227369676e6174757265223a224d4555434951443272315468347874777a6a6a3870394c51774c4966393851504f6c4d626d4344764b3244564149437147774967564b6f36744e706a6366486967754c4c416350665446324b457067576f7a576878535270446e364973654d3d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741457a667a47326e5043556275456b66646f4379686771437130692f4e5a47736531537969674a3957624e666942557750386f507038356c3438707133616743375350324a456c704f424564715a2b3453584163566e57513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "de80c714f6d3e02b2975becf"),
			EncryptedKey: testutil.DecodeHexString(c, "e3c1c9cbc4a01639662f779052596c340d9c031a7b36f3f467630987623d3c09"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "beb0415d20f9a4982be7c4151217e6861cf895376e89848295a539ad25548901acd67741fe26f52a48a541a7c8e359e2c6515190433c163806239e685b8cb3c83870c6aae38e43123f704ca037d194088193e869043e"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c0404205f0fa7ff8a2fac95a921a812ae84175990cc93ae9df65ceaf5916cefba237a57"),
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode: "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeySuppliedPrimaryKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			PrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
			Role:       "foo",
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a6e756c6c7d7d2c227369676e6174757265223a224d4555434951447a50716f707a2b763530355065747542736e78764d462b4664786777645145315a6d6f58573551364c5a41496745794d6a6e6239426e6452366c364b55614c7a676e4d446f4b39383643785a342f6366494f454c6d5953733d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414537344969424f51656739546654336a61566f5670356a6370634d56766d4c376f444f554667736d775261675a7934704d3870456e2f77466c545a534239424253516345506266785439436f7634393645374f566a2b513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode: "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyDifferentSuppliedPrimaryKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			PrimaryKey: testutil.DecodeHexString(c, "4ace63fad0a9adc77234322739d873c81da6e4e3d006214411d18ad81b2518b5"),
			Role:       "foo",
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "4ace63fad0a9adc77234322739d873c81da6e4e3d006214411d18ad81b2518b5"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "8f8ee08ab3650d3218a202b55489f0790bb3c801b99210b3747c2961845b7d9d"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a6e756c6c7d7d2c227369676e6174757265223a224d455143494337472f7a4f3442745037505951514b7666316a5234686d397654627a6361376b35682f5a756947683748416941646662706c495a765774553033425951773471316f4f7052744e33346d70526b466e4f66317433593759513d3d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741456c6d6d4b51314e7a744b5138612f5378432f6e746f7a7178356a734474376a367a79743265326a44773048724c663171474a3959754f355a537474737056544c2b3832786d577379444242515556482b4368636f67513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb964ea168b4623d6813cbd501e4bb7f7afcd1950ee312f5dba2c8d369d7c206dd7c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52abb72b2542b2c34981b587e4beecf58d"),
		expectedCleartext:  testutil.DecodeHexString(c, "304404204ace63fad0a9adc77234322739d873c81da6e4e3d006214411d18ad81b2518b50420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		bootMode: "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyWithAuthorizedParams(c *C) {
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: []secboot.SnapModel{model},
			AuthorizedBootModes:  []string{"run"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a5b224f647444314f7a2b4c56473441373752546b45314a614b6f704438702f41786355517361394d2f505072553d225d7d2c226d6f646573223a5b2272756e225d7d2c227369676e6174757265223a224d45514349413139534555416869474d704670427a5a5955666943336947433957336e39473244667a746a4e614f525241694270582f367a485255433658465363582b3076616a704d5964677270636b586d6c4f34696d795944727643773d3d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414537344969424f51656739546654336a61566f5670356a6370634d56766d4c376f444f554667736d775261675a7934704d3870456e2f77466c545a534239424253516345506266785439436f7634393645374f566a2b513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model,
		bootMode:           "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyWithOtherAuthorizedParams(c *C) {
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

	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			Role:                 "foo",
			AuthorizedSnapModels: models,
			AuthorizedBootModes:  []string{"run", "recover"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a5b224f647444314f7a2b4c56473441373752546b45314a614b6f704438702f41786355517361394d2f505072553d222c225a5349706a6368354c425936415038583959644b4371416d6237527478572b725345653148503945566e553d225d7d2c226d6f646573223a5b2272756e222c227265636f766572225d7d2c227369676e6174757265223a224d4551434947524b70336158624e796e327649625a432f63413635466372684747614f77674e7332536e724b595a4a36416941424e614573314a44424344697456473954643638502f44384873615373384b6c4b4c57497038474e612f773d3d222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414537344969424f51656739546654336a61566f5670356a6370634d56766d4c376f444f554667736d775261675a7934704d3870456e2f77466c545a534239424253516345506266785439436f7634393645374f566a2b513d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f52ed0c03e313494304d479a96f7d409cc0"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              models[1],
		bootMode:           "recover",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyWithAuthorizedParamsiDifferentRole(c *C) {
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abaf84f48f671b2a4bf0074821013ead8b3b83b5781cd88a8d265c05ed6e8bdd7ef7736bf590d0a91b9072ba8216d653a632ff9386f6550afe8683ef88c941e8d89fbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63c2"),
		params: &KeyParams{
			Role:                 "bar",
			AuthorizedSnapModels: []secboot.SnapModel{model},
			AuthorizedBootModes:  []string{"run"},
		},
		expectedPrimaryKey: testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"),
		expectedUnlockKey:  testutil.DecodeHexString(c, "06c6b1deae42060f7da12ca1210da10ff1f0477639129ba0d552961daa9c14ff"),
		expectedHandle:     testutil.DecodeHexString(c, "7b2273616c74223a2265375a4764613939322b4c757a476f6d2b71754c6978634d653556656e76336d755045556d4173795749553d222c226976223a2261487a414e5352713578764f6e7662485674706a77673d3d227d"),
		expectedScope:      testutil.DecodeHexString(c, "7b2276657273696f6e223a312c22706172616d73223a7b226d6f64656c5f64696765737473223a7b22616c67223a22736861323536222c2264696765737473223a5b224f647444314f7a2b4c56473441373752546b45314a614b6f704438702f41786355517361394d2f505072553d225d7d2c226d6f646573223a5b2272756e225d7d2c227369676e6174757265223a224d4559434951446247754f7a2b31434a4f50757a58464a746338374f6a4835647537725063504f363659344e3379707950514968414d6c4d564d6379584c674178475672684d654d704e4c75562b784265556f2b506a7131657a74336d366932222c227075626b6579223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741456d7568366873393237632f56552b74662f544154696c6362626b462f714e327746686658747477785859376b4c5559764e393430654338575641643149364e6c4a49346c7262616570327a743133474931654d7030413d3d222c226b64665f616c67223a22736861323536222c226d645f616c67223a22736861323536227d"),
		expectedAeadCompat: &AeadCompatData{
			Nonce:        testutil.DecodeHexString(c, "94280675b3c88ff7552ff45c"),
			EncryptedKey: testutil.DecodeHexString(c, "6363b7da2f0ab6b895fb626092d5671c7db35ebe3b965da5bbc31f7e9287076e"),
		},
		expectedCiphertext: testutil.DecodeHexString(c, "c9f3f5cb299a115d8bdd77a800ac348f4992f2bb2df5b343729201ad9ce3f79ea2cc46927c7ef3bd809603d12521991229bcb7deaac249d568afc62390c99ddccaf759e17f523c5c96bc534986143866987aaa0e2e0a"),
		expectedCleartext:  testutil.DecodeHexString(c, "30440420f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa0420e51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc396"),
		model:              model,
		bootMode:           "run",
	})
}

func (s *keydataNoAEADSuite) TestNewProtectedKeyKeyProtectorError(c *C) {
	// Provide a single byte too little so that reading the IV inside the hook fails
	rand := testutil.DecodeHexString(c, "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fae51f16354d289d1fcf0f66a4f69841fb3bbb9917932ab439a2250a50d45cc3965d423006828c06b1bb2340acefdab22eeeb42903a39feff752d2b93e3eb5abafbddb7662b10c2e6a657d211f237029897317bbe8dbd5e75baa5e617566790f9694280675b3c88ff7552ff45c7bb64675af7ddbe2eecc6a26faab8b8b170c7b955e9efde6b8f114980b325885687cc035246ae71bce9ef6c756da63")
	_, _, _, err := NewProtectedKey(testutil.BypassMaybeReadByte(bytes.NewReader(rand), false, 64), nil)
	c.Check(err, ErrorMatches, `cannot protect symmetric key for AEAD compat using hook: unexpected EOF`)
}
