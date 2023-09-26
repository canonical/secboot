// -*- Mode: Go; indent-tabs-mode: t -*-

//go:build !go1.20
// +build !go1.20

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
	"crypto/ecdsa"
	"crypto/elliptic"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/internal/crypto"
	"github.com/snapcore/secboot/internal/testutil"
)

type ecdsa1_19Suite struct{}

var _ = Suite(&ecdsa1_19Suite{})

func (s *ecdsa1_19Suite) TestGenerateECDSAKey(c *C) {
	rand := testutil.DecodeHexString(c, "26be875535d98e705cbd60c34f068985fc808e0b83ad1c8ac467ec8294b622a39657d3b9207ba865")

	key1, err := GenerateECDSAKey(elliptic.P256(), bytes.NewReader(rand))
	c.Assert(err, IsNil)

	key2, err := ecdsa.GenerateKey(elliptic.P256(), bytes.NewReader(rand))
	c.Assert(err, IsNil)

	c.Check(key1.Equal(key2), testutil.IsTrue)
}
