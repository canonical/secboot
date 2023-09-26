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

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"math/big"
)

var one = new(big.Int).SetInt64(1)

// GenerateECDSAKey generates a new elliptic key pair using the method described by
// FIPS186-4 section B.4.1. This method is deterministic (given the same sequence of
// random bytes, it will generate the same key) and is not sensitive to changes in the
// standard library between go releases. This is required because the tpm2 package needs
// to be able to deterministically derive keys from a sequence of bytes. The method
// used to generate keys using crypto/ecdsa package changed in go1.20 to one that is
// non-deterministic.
func GenerateECDSAKey(curve elliptic.Curve, rand io.Reader) (*ecdsa.PrivateKey, error) {
	params := curve.Params()

	// 1. N=len(n)
	N := params.N.BitLen() / 8

	// 4. Obtain a string of N+64 bits from an RBG
	//
	//  For P-521, this is N+63 bits because of the rounding error, but the original
	//  crypto/ecdsa had this quirk as well and this function has to be compatible with
	//  that.
	b := make([]byte, N+8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		return nil, err
	}

	// 5. Convert to integer c
	c := new(big.Int).SetBytes(b)

	// 6. d = (c*mod(n-1))+1
	nMinusOne := new(big.Int).Sub(params.N, one)
	c.Mod(c, nMinusOne)
	d := new(big.Int).Add(c, one)

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = d

	// 7. Q=dG
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	return priv, nil
}
