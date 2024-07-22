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

package plainkey_test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"

	"golang.org/x/crypto/cryptobyte"
	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	. "github.com/snapcore/secboot/plainkey"
)

type keydataSuite struct{}

var _ = Suite(&keydataSuite{})

type testNewProtectedKeyParams struct {
	rand         []byte
	protectorKey []byte
	primaryKey   secboot.PrimaryKey

	expectedPrimaryKey         secboot.PrimaryKey
	expectedUnlockKey          secboot.DiskUnlockKey
	expectedSalt               []byte
	expectedNonce              []byte
	expectedProtectorKeyIdSalt []byte
	expectedProtectorKeyId     []byte
	expectedCiphertext         []byte
	expectedPlaintext          []byte
}

func (s *keydataSuite) testNewProtectedKey(c *C, params *testNewProtectedKeyParams) {
	// Note that these tests will fail if secboot.KeyDataGeneration changes because the
	// expected ciphertexts will need to be updated. It would also be worth adapting
	// the tests in platformSuite to use the new version as well, as those are based
	// on the data here.
	var expectedHandle []byte
	restore := MockSecbootNewKeyData(func(keyParams *secboot.KeyParams) (*secboot.KeyData, error) {
		c.Assert(keyParams.Handle, testutil.ConvertibleTo, &KeyData{})

		kd := keyParams.Handle.(*KeyData)
		c.Check(kd.Version, Equals, 1)
		c.Check(kd.Salt, DeepEquals, params.expectedSalt)
		c.Assert(kd.Nonce, DeepEquals, params.expectedNonce)
		c.Check(crypto.Hash(kd.ProtectorKeyID.Alg), Equals, crypto.SHA256)
		c.Check(kd.ProtectorKeyID.Salt, DeepEquals, params.expectedProtectorKeyIdSalt)
		c.Check(kd.ProtectorKeyID.Digest, DeepEquals, params.expectedProtectorKeyId)

		c.Check(keyParams.EncryptedPayload, DeepEquals, params.expectedCiphertext)
		c.Check(keyParams.PlatformName, Equals, PlatformName)
		c.Check(keyParams.KDFAlg, Equals, crypto.SHA256)

		var err error
		expectedHandle, err = json.Marshal(kd)
		c.Assert(err, IsNil)

		b, err := aes.NewCipher(DeriveAESKey(params.protectorKey, kd.Salt))
		c.Assert(err, IsNil)

		aead, err := cipher.NewGCM(b)
		c.Assert(err, IsNil)

		aad := AdditionalData{
			Version:    kd.Version,
			Generation: secboot.KeyDataGeneration,
			KDFAlg:     HashAlg(crypto.SHA256),
			AuthMode:   secboot.AuthModeNone,
		}
		builder := cryptobyte.NewBuilder(nil)
		aad.MarshalASN1(builder)
		aadBytes, err := builder.Bytes()
		c.Check(err, IsNil)

		payload, err := aead.Open(nil, kd.Nonce, keyParams.EncryptedPayload, aadBytes)
		c.Check(err, IsNil)
		c.Check(payload, DeepEquals, params.expectedPlaintext)

		return secboot.NewKeyData(keyParams)
	})
	defer restore()

	kd, primaryKey, unlockKey, err := NewProtectedKey(bytes.NewReader(params.rand), params.protectorKey, params.primaryKey)
	c.Assert(err, IsNil)
	c.Check(primaryKey, DeepEquals, params.expectedPrimaryKey)
	c.Check(unlockKey, DeepEquals, params.expectedUnlockKey)

	var handle json.RawMessage
	c.Check(kd.UnmarshalPlatformHandle(&handle), IsNil)
	c.Check([]byte(handle), DeepEquals, expectedHandle)
}

func (s *keydataSuite) TestNewProtectedKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:                       testutil.DecodeHexString(c, "179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb078535cc101b9d12d9b8f40edada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
		protectorKey:               testutil.DecodeHexString(c, "8f13251b23450e1d184facfd28752c14c26439fce2765ecd92ff4b060713b5d1"),
		primaryKey:                 testutil.DecodeHexString(c, "707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa373"),
		expectedPrimaryKey:         testutil.DecodeHexString(c, "707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa373"),
		expectedUnlockKey:          testutil.DecodeHexString(c, "f1cffa65c76b15ac7e21dfd0894f21c5ce8986103bfb4916c4ff435513865980"),
		expectedSalt:               testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
		expectedNonce:              testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
		expectedProtectorKeyIdSalt: testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
		expectedProtectorKeyId:     testutil.DecodeHexString(c, "119812533946d04cd3fe72626f61cf364877a8f1a6663ce8f0604da52cf0b8f3"),
		expectedCiphertext:         testutil.DecodeHexString(c, "d3ee9e1c228a7436f33377239701059b801dd5167dde322e557edda7a42405f345d534e9728c9158c854a0eb8b11399bcd36a299a40e5258c230f61d5e0b948138fe54718b238f4f6063b782ac2b613a58fc1fdc6d49"),
		expectedPlaintext:          testutil.DecodeHexString(c, "30440420707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa3730420179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696"),
	})
}

func (s *keydataSuite) TestNewProtectedKeyDifferentRand(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:                       testutil.DecodeHexString(c, "c4f8f04115eb2320f2bba3777240234b535d666b64c0ab10fe32e9b44e07c436dab12d7fa9c4dfb05bcc70bbd3d56ff87d5658c2f42e9e94e6273173a9d0931689b9b05919c41170f32cb00132b030249e7b9c614d160be5985a031654c9bba87842c40e8d1b7f8adf0b277e"),
		protectorKey:               testutil.DecodeHexString(c, "8f13251b23450e1d184facfd28752c14c26439fce2765ecd92ff4b060713b5d1"),
		primaryKey:                 testutil.DecodeHexString(c, "707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa373"),
		expectedPrimaryKey:         testutil.DecodeHexString(c, "707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa373"),
		expectedUnlockKey:          testutil.DecodeHexString(c, "0187af22705f098123812aa31032ce003f24bd69649d260153604fb7c0293925"),
		expectedSalt:               testutil.DecodeHexString(c, "dab12d7fa9c4dfb05bcc70bbd3d56ff87d5658c2f42e9e94e6273173a9d09316"),
		expectedNonce:              testutil.DecodeHexString(c, "89b9b05919c41170f32cb001"),
		expectedProtectorKeyIdSalt: testutil.DecodeHexString(c, "32b030249e7b9c614d160be5985a031654c9bba87842c40e8d1b7f8adf0b277e"),
		expectedProtectorKeyId:     testutil.DecodeHexString(c, "777cae054f1c5103149f5e30152fad0b197b3f0bb4b801327307aca50a02acff"),
		expectedCiphertext:         testutil.DecodeHexString(c, "b268bb69cafa29a490511819e12f0da25454bf724a76fc9a17b6f72019353371d6c8c13c26251e9e3169936146aa725da7000f39cebdc873adbb6bc6d02c64a6069e71b0c3116657ff8498164a7ab5e6488f552ccc88"),
		expectedPlaintext:          testutil.DecodeHexString(c, "30440420707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa3730420c4f8f04115eb2320f2bba3777240234b535d666b64c0ab10fe32e9b44e07c436"),
	})
}

func (s *keydataSuite) TestNewProtectedKeyDifferentProtectorKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:                       testutil.DecodeHexString(c, "179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb078535cc101b9d12d9b8f40edada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
		protectorKey:               testutil.DecodeHexString(c, "1d3ae75ec26e284ab2f032256202d653025f2a1969d956a7c3b582aa368db198"),
		primaryKey:                 testutil.DecodeHexString(c, "707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa373"),
		expectedPrimaryKey:         testutil.DecodeHexString(c, "707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa373"),
		expectedUnlockKey:          testutil.DecodeHexString(c, "f1cffa65c76b15ac7e21dfd0894f21c5ce8986103bfb4916c4ff435513865980"),
		expectedSalt:               testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
		expectedNonce:              testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
		expectedProtectorKeyIdSalt: testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
		expectedProtectorKeyId:     testutil.DecodeHexString(c, "a7d200c3951659d5132db221a376cfd937d65e6e991e651b62fbed48855efeaf"),
		expectedCiphertext:         testutil.DecodeHexString(c, "ad5f76499f91a47a04b1a1e26625cb4e18f6ac38e888b0a2882853d23bfdd6a3d8f1feecf0956cf3667817009c2c3023331e2601dc94f5aad80a1996dcc691b3f9b430ddc7a5cad10566ee530311a3bf267bff9a81b8"),
		expectedPlaintext:          testutil.DecodeHexString(c, "30440420707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa3730420179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696"),
	})
}

func (s *keydataSuite) TestNewProtectedKeyDifferentPrimaryKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:                       testutil.DecodeHexString(c, "179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb078535cc101b9d12d9b8f40edada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
		protectorKey:               testutil.DecodeHexString(c, "8f13251b23450e1d184facfd28752c14c26439fce2765ecd92ff4b060713b5d1"),
		primaryKey:                 testutil.DecodeHexString(c, "6e5eb7de5a75ec77bbec2f0927f6503bc7d0e2a6ebcb971d7dbe7a77e0d924a7"),
		expectedPrimaryKey:         testutil.DecodeHexString(c, "6e5eb7de5a75ec77bbec2f0927f6503bc7d0e2a6ebcb971d7dbe7a77e0d924a7"),
		expectedUnlockKey:          testutil.DecodeHexString(c, "0685e55582e4465ba2336e95304166eaa839d1a645dec1c0629a63f9748fb182"),
		expectedSalt:               testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
		expectedNonce:              testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
		expectedProtectorKeyIdSalt: testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
		expectedProtectorKeyId:     testutil.DecodeHexString(c, "119812533946d04cd3fe72626f61cf364877a8f1a6663ce8f0604da52cf0b8f3"),
		expectedCiphertext:         testutil.DecodeHexString(c, "d3ee9e1c3cab20fc4def991994b1f7ea6582b7eae091c2ed1e40508b38e7cdeca313b33d728c9158c854a0eb8b11399bcd36a299a40e5258c230f61d5e0b948138fe54718b23778d5679118961498d551cacecf81ee9"),
		expectedPlaintext:          testutil.DecodeHexString(c, "304404206e5eb7de5a75ec77bbec2f0927f6503bc7d0e2a6ebcb971d7dbe7a77e0d924a70420179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696"),
	})
}

func (s *keydataSuite) TestNewProtectedKeyGeneratePrimaryKey(c *C) {
	s.testNewProtectedKey(c, &testNewProtectedKeyParams{
		rand:                       testutil.DecodeHexString(c, "707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa373179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb078535cc101b9d12d9b8f40edada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
		protectorKey:               testutil.DecodeHexString(c, "8f13251b23450e1d184facfd28752c14c26439fce2765ecd92ff4b060713b5d1"),
		expectedPrimaryKey:         testutil.DecodeHexString(c, "707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa373"),
		expectedUnlockKey:          testutil.DecodeHexString(c, "f1cffa65c76b15ac7e21dfd0894f21c5ce8986103bfb4916c4ff435513865980"),
		expectedSalt:               testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
		expectedNonce:              testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
		expectedProtectorKeyIdSalt: testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
		expectedProtectorKeyId:     testutil.DecodeHexString(c, "119812533946d04cd3fe72626f61cf364877a8f1a6663ce8f0604da52cf0b8f3"),
		expectedCiphertext:         testutil.DecodeHexString(c, "d3ee9e1c228a7436f33377239701059b801dd5167dde322e557edda7a42405f345d534e9728c9158c854a0eb8b11399bcd36a299a40e5258c230f61d5e0b948138fe54718b238f4f6063b782ac2b613a58fc1fdc6d49"),
		expectedPlaintext:          testutil.DecodeHexString(c, "30440420707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa3730420179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696"),
	})
}

func (s *keydataSuite) TestKeyDataMarshalAndUnmarshal(c *C) {
	orig := &KeyData{
		Version: 1,
		Salt:    testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
		Nonce:   testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
		ProtectorKeyID: ProtectorKeyId{
			Alg:    HashAlg(crypto.SHA256),
			Salt:   testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
			Digest: testutil.DecodeHexString(c, "119812533946d04cd3fe72626f61cf364877a8f1a6663ce8f0604da52cf0b8f3"),
		},
	}

	b, err := json.Marshal(orig)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, []byte(`{"version":1,"salt":"1LC2+izu+rryH4jqQs+441ODWtnBkEScwBpdJ13chMs=","nonce":"B4U1zBAbnRLZuPQO","protector-key-id":{"alg":"sha256","salt":"2tqBZOoNYvf8ItCcw0vUNARVS7X/xRk31UbJqX1o4v4=","digest":"EZgSUzlG0EzT/nJib2HPNkh3qPGmZjzo8GBNpSzwuPM="}}`))
	c.Logf("%s", string(b))

	var unmarshalled *KeyData
	c.Assert(json.Unmarshal(b, &unmarshalled), IsNil)
	c.Check(unmarshalled, DeepEquals, orig)
}
