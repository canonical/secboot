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
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	. "github.com/snapcore/secboot/plainkey"
)

type platformSuite struct{}

var _ = Suite(&platformSuite{})

type testRecoverKeysParams struct {
	platformKeys [][]byte
	generation   int
	keyData      *KeyData
	ciphertext   []byte

	expectedPlaintext []byte
}

func (s *platformSuite) testRecoverKeys(c *C, params *testRecoverKeysParams) {
	SetPlatformKeys(params.platformKeys...)
	defer SetPlatformKeys(nil)

	handle, err := json.Marshal(params.keyData)
	c.Assert(err, IsNil)

	var platform PlatformKeyDataHandler
	payload, err := platform.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    params.generation,
		EncodedHandle: handle,
		KDFAlg:        crypto.SHA256,
		AuthMode:      secboot.AuthModeNone,
	}, params.ciphertext)
	c.Check(err, IsNil)
	c.Check(payload, DeepEquals, params.expectedPlaintext)
}

func (s *platformSuite) TestRecoverKeys(c *C) {
	s.testRecoverKeys(c, &testRecoverKeysParams{
		platformKeys: [][]byte{testutil.DecodeHexString(c, "8f13251b23450e1d184facfd28752c14c26439fce2765ecd92ff4b060713b5d1")},
		generation:   2,
		keyData: &KeyData{
			Version: 1,
			Salt:    testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
			Nonce:   testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
			PlatformKeyID: PlatformKeyId{
				Alg:    HashAlg(crypto.SHA256),
				Salt:   testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
				Digest: testutil.DecodeHexString(c, "119812533946d04cd3fe72626f61cf364877a8f1a6663ce8f0604da52cf0b8f3"),
			},
		},
		ciphertext:        testutil.DecodeHexString(c, "d3ee9e1c228a7436f33377239701059b801dd5167dde322e557edda7a42405f345d534e9728c9158c854a0eb8b11399bcd36a299a40e5258c230f61d5e0b948138fe54718b238f4f6063b782ac2b613a58fc1fdc6d49"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa3730420179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696"),
	})
}

func (s *platformSuite) TestRecoverKeysDifferentKey(c *C) {
	s.testRecoverKeys(c, &testRecoverKeysParams{
		platformKeys: [][]byte{testutil.DecodeHexString(c, "8f13251b23450e1d184facfd28752c14c26439fce2765ecd92ff4b060713b5d1")},
		generation:   2,
		keyData: &KeyData{
			Version: 1,
			Salt:    testutil.DecodeHexString(c, "dab12d7fa9c4dfb05bcc70bbd3d56ff87d5658c2f42e9e94e6273173a9d09316"),
			Nonce:   testutil.DecodeHexString(c, "89b9b05919c41170f32cb001"),
			PlatformKeyID: PlatformKeyId{
				Alg:    HashAlg(crypto.SHA256),
				Salt:   testutil.DecodeHexString(c, "32b030249e7b9c614d160be5985a031654c9bba87842c40e8d1b7f8adf0b277e"),
				Digest: testutil.DecodeHexString(c, "777cae054f1c5103149f5e30152fad0b197b3f0bb4b801327307aca50a02acff"),
			},
		},
		ciphertext:        testutil.DecodeHexString(c, "b268bb69cafa29a490511819e12f0da25454bf724a76fc9a17b6f72019353371d6c8c13c26251e9e3169936146aa725da7000f39cebdc873adbb6bc6d02c64a6069e71b0c3116657ff8498164a7ab5e6488f552ccc88"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa3730420c4f8f04115eb2320f2bba3777240234b535d666b64c0ab10fe32e9b44e07c436"),
	})
}

func (s *platformSuite) TestRecoverKeysDifferentPlatformKey(c *C) {
	s.testRecoverKeys(c, &testRecoverKeysParams{
		platformKeys: [][]byte{testutil.DecodeHexString(c, "1d3ae75ec26e284ab2f032256202d653025f2a1969d956a7c3b582aa368db198")},
		generation:   2,
		keyData: &KeyData{
			Version: 1,
			Salt:    testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
			Nonce:   testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
			PlatformKeyID: PlatformKeyId{
				Alg:    HashAlg(crypto.SHA256),
				Salt:   testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
				Digest: testutil.DecodeHexString(c, "a7d200c3951659d5132db221a376cfd937d65e6e991e651b62fbed48855efeaf"),
			},
		},
		ciphertext:        testutil.DecodeHexString(c, "ad5f76499f91a47a04b1a1e26625cb4e18f6ac38e888b0a2882853d23bfdd6a3d8f1feecf0956cf3667817009c2c3023331e2601dc94f5aad80a1996dcc691b3f9b430ddc7a5cad10566ee530311a3bf267bff9a81b8"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa3730420179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696"),
	})
}

func (s *platformSuite) TestRecoverKeysMultiplePlatformKeys(c *C) {
	s.testRecoverKeys(c, &testRecoverKeysParams{
		platformKeys: [][]byte{
			testutil.DecodeHexString(c, "1d3ae75ec26e284ab2f032256202d653025f2a1969d956a7c3b582aa368db198"),
			testutil.DecodeHexString(c, "8f13251b23450e1d184facfd28752c14c26439fce2765ecd92ff4b060713b5d1"),
		},
		generation: 2,
		keyData: &KeyData{
			Version: 1,
			Salt:    testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
			Nonce:   testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
			PlatformKeyID: PlatformKeyId{
				Alg:    HashAlg(crypto.SHA256),
				Salt:   testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
				Digest: testutil.DecodeHexString(c, "119812533946d04cd3fe72626f61cf364877a8f1a6663ce8f0604da52cf0b8f3"),
			},
		},
		ciphertext:        testutil.DecodeHexString(c, "d3ee9e1c228a7436f33377239701059b801dd5167dde322e557edda7a42405f345d534e9728c9158c854a0eb8b11399bcd36a299a40e5258c230f61d5e0b948138fe54718b238f4f6063b782ac2b613a58fc1fdc6d49"),
		expectedPlaintext: testutil.DecodeHexString(c, "30440420707fe314e4a9024db85cdd78c26932c75a9f1265a0f51a31e17db268061fa3730420179059840680febea1a486309c881f3486bcedc2f47b579e7699e1621db74696"),
	})
}

func (s *platformSuite) TestRecoverKeysInvalidKDFAlg(c *C) {
	kd := &KeyData{
		Version: 1,
		Salt:    testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
		Nonce:   testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
		PlatformKeyID: PlatformKeyId{
			Alg:    HashAlg(crypto.SHA256),
			Salt:   testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
			Digest: testutil.DecodeHexString(c, "119812533946d04cd3fe72626f61cf364877a8f1a6663ce8f0604da52cf0b8f3"),
		},
	}
	handle, err := json.Marshal(kd)
	c.Check(err, IsNil)

	var platform PlatformKeyDataHandler
	_, err = platform.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    2,
		EncodedHandle: handle,
		KDFAlg:        crypto.SHA3_256,
		AuthMode:      secboot.AuthModeNone,
	}, nil)
	c.Check(err, ErrorMatches, `cannot serialize AAD: unknown hash algorithm: SHA3-256`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

func (s *platformSuite) TestRecoverKeysNoPlatformKey(c *C) {
	kd := &KeyData{
		Version: 1,
		Salt:    testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
		Nonce:   testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
		PlatformKeyID: PlatformKeyId{
			Alg:    HashAlg(crypto.SHA256),
			Salt:   testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
			Digest: testutil.DecodeHexString(c, "119812533946d04cd3fe72626f61cf364877a8f1a6663ce8f0604da52cf0b8f3"),
		},
	}
	handle, err := json.Marshal(kd)
	c.Check(err, IsNil)

	var platform PlatformKeyDataHandler
	_, err = platform.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    2,
		EncodedHandle: handle,
		KDFAlg:        crypto.SHA256,
		AuthMode:      secboot.AuthModeNone,
	}, nil)
	c.Check(err, ErrorMatches, `cannot select platform key: no key available`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

func (s *platformSuite) TestRecoverKeysCannotOpen(c *C) {
	SetPlatformKeys(testutil.DecodeHexString(c, "8f13251b23450e1d184facfd28752c14c26439fce2765ecd92ff4b060713b5d1"))
	defer SetPlatformKeys(nil)

	kd := &KeyData{
		Version: 1,
		Salt:    testutil.DecodeHexString(c, "d4b0b6fa2ceefabaf21f88ea42cfb8e353835ad9c190449cc01a5d275ddc84cb"),
		Nonce:   testutil.DecodeHexString(c, "078535cc101b9d12d9b8f40e"),
		PlatformKeyID: PlatformKeyId{
			Alg:    HashAlg(crypto.SHA256),
			Salt:   testutil.DecodeHexString(c, "dada8164ea0d62f7fc22d09cc34bd43404554bb5ffc51937d546c9a97d68e2fe"),
			Digest: testutil.DecodeHexString(c, "119812533946d04cd3fe72626f61cf364877a8f1a6663ce8f0604da52cf0b8f3"),
		},
	}
	handle, err := json.Marshal(kd)
	c.Check(err, IsNil)

	var platform PlatformKeyDataHandler
	_, err = platform.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    2,
		EncodedHandle: handle,
		KDFAlg:        crypto.SHA384, // make authentication fail.
		AuthMode:      secboot.AuthModeNone,
	}, testutil.DecodeHexString(c, "d3ee9e1c228a7436f33377239701059b801dd5167dde322e557edda7a42405f345d534e9728c9158c854a0eb8b11399bcd36a299a40e5258c230f61d5e0b948138fe54718b238f4f6063b782ac2b613a58fc1fdc6d49"))
	c.Check(err, ErrorMatches, `cannot open payload: cipher: message authentication failed`)

	var phe *secboot.PlatformHandlerError
	c.Assert(errors.As(err, &phe), testutil.IsTrue)
	c.Check(phe.Type, Equals, secboot.PlatformHandlerErrorInvalidData)
}

type platformSuiteIntegrated struct{}

var _ = Suite(&platformSuiteIntegrated{})

func (s *platformSuiteIntegrated) TestRecoverKeys(c *C) {
	platformKey := testutil.DecodeHexString(c, "8f13251b23450e1d184facfd28752c14c26439fce2765ecd92ff4b060713b5d1")
	SetPlatformKeys(platformKey)
	defer SetPlatformKeys(nil)

	kd, expectedPrimaryKey, expectedUnlockKey, err := NewProtectedKey(rand.Reader, platformKey, nil)
	c.Assert(err, IsNil)

	unlockKey, primaryKey, err := kd.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(unlockKey, DeepEquals, expectedUnlockKey)
	c.Check(primaryKey, DeepEquals, expectedPrimaryKey)
}

func (s *platformSuiteIntegrated) TestRecoverKeysNoPlatformKey(c *C) {
	platformKey := testutil.DecodeHexString(c, "8f13251b23450e1d184facfd28752c14c26439fce2765ecd92ff4b060713b5d1")

	kd, _, _, err := NewProtectedKey(rand.Reader, platformKey, nil)
	c.Assert(err, IsNil)

	_, _, err = kd.RecoverKeys()
	c.Check(err, ErrorMatches, `invalid key data: cannot select platform key: no key available`)

	var e *secboot.InvalidKeyDataError
	c.Check(errors.As(err, &e), testutil.IsTrue)
}
