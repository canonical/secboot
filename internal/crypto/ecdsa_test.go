// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package crypto_test

import (
	"bytes"
	"crypto/elliptic"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/internal/crypto"
	"github.com/snapcore/secboot/internal/testutil"
)

type ecdsaSuite struct{}

var _ = Suite(&ecdsaSuite{})

func (s *ecdsaSuite) TestGenerateECDSAKey(c *C) {
	rand := testutil.DecodeHexString(c, "26be875535d98e705cbd60c34f068985fc808e0b83ad1c8ac467ec8294b622a39657d3b9207ba865")

	key, err := GenerateECDSAKey(elliptic.P256(), bytes.NewReader(rand))
	c.Assert(err, IsNil)
	c.Check(key.D.Bytes(), DeepEquals, testutil.DecodeHexString(c, "9296ef32f26e73c106a834e0415fa32ee2a6dc84d4359431ad4abd21dea061d6"))
	c.Check(key.X.Bytes(), DeepEquals, testutil.DecodeHexString(c, "918457cb51bde6efaa14eb028cfab900c02778ac7978ab2d6c9d451f1cf153ea"))
	c.Check(key.Y.Bytes(), DeepEquals, testutil.DecodeHexString(c, "08a18bb52b3cb984ef71e76d449f8c6c98ad1b5e3702089ad63a02b25f232812"))
	c.Check(elliptic.P256().IsOnCurve(key.X, key.Y), testutil.IsTrue)
	c.Logf("d=%x", key.D)
	c.Logf("x=%x", key.X)
	c.Logf("y=%x", key.Y)
}

func (s *ecdsaSuite) TestGenerateECDSAKeyDifferentRandomBytes(c *C) {
	rand := testutil.DecodeHexString(c, "9a79e8343e4848e428a1f680bd1fb44d9e8c32e80794a197f6f96958dbda15fbc9083ce3ba8f56df")

	key, err := GenerateECDSAKey(elliptic.P256(), bytes.NewReader(rand))
	c.Assert(err, IsNil)
	c.Check(key.D.Bytes(), DeepEquals, testutil.DecodeHexString(c, "66ea3f63e45d8335c70933cb9bb429b04ed877c35a6b7d5a5252e96f507f8760"))
	c.Check(key.X.Bytes(), DeepEquals, testutil.DecodeHexString(c, "9ef4c92f4db77ebc84299c73832da6188e6b1c1d852218c70509ceac0d8a8613"))
	c.Check(key.Y.Bytes(), DeepEquals, testutil.DecodeHexString(c, "cf7345866f20b51bb21a01f68f18c7f95c70d3555a8eddeafe572794e0306118"))
	c.Check(elliptic.P256().IsOnCurve(key.X, key.Y), testutil.IsTrue)
	c.Logf("d=%x", key.D)
	c.Logf("x=%x", key.X)
	c.Logf("y=%x", key.Y)
}

func (s *ecdsaSuite) TestGenerateECDSAKeyDifferentCurve(c *C) {
	rand := testutil.DecodeHexString(c, "cd0f04ff79ad3c799d200113c090d7c84d1a71f12e9fa52a710813a52dcea456819aa394fc1c969148ab1406c2ce9c6e020656bb842314fe377bb3d12079a70cb3188483f974d5c151")
	key, err := GenerateECDSAKey(elliptic.P521(), bytes.NewReader(rand))
	c.Assert(err, IsNil)
	c.Check(key.D.Bytes(), DeepEquals, testutil.DecodeHexString(c, "019d200113c090d7c84d1a71f12e9fa52a710813a52dcea45683e129e27b964638d954c64c5232245fa8a4bae23fe9cc940e188531ec10ad43b213203c9d1f315f72"))
	c.Check(key.X.Bytes(), DeepEquals, testutil.DecodeHexString(c, "01eb7185ee58a503f743581c1ceea4a40b367c7cbe5a81aae539280921b008defa7a2427e070f4b6ca4c383e2f844e7e48fd8da64c59a9d052c29f0c75fbe3c77aa4"))
	c.Check(key.Y.Bytes(), DeepEquals, testutil.DecodeHexString(c, "01a8a21ba6ff4ad05c70d1b29a37e11bdfa8092d434b982b80341c3e229f7479431422b1b9d45ca0354b32211b083d8a31ab55a4d4d01a8be1e75a0e02526d4656c4"))
	c.Check(elliptic.P521().IsOnCurve(key.X, key.Y), testutil.IsTrue)
	c.Logf("d=%x", key.D)
	c.Logf("x=%x", key.X)
	c.Logf("y=%x", key.Y)
}
