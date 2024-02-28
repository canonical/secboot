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

package bootscope

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"sync/atomic"

	"github.com/snapcore/secboot"
	internal_crypto "github.com/snapcore/secboot/internal/crypto"
)

var (
	ComputeSnapModelHash = computeSnapModelHash
)

func ClearBootModeAndModel() {
	currentModel = atomic.Value{}
	currentBootMode = atomic.Value{}
}

func (d *KeyDataScope) TestSetVersion(version int) {
	d.data.Version = version
}

func (d *KeyDataScope) TestMatch(KDFAlg crypto.Hash, keyIdentifier []byte) bool {
	der, err := x509.MarshalPKIXPublicKey(d.data.PublicKey.PublicKey)
	if err != nil {
		return false
	}

	h := KDFAlg.New()
	h.Write(der)
	return bytes.Equal(h.Sum(nil), keyIdentifier)
}

func (d *KeyDataScope) DeriveSigner(key secboot.PrimaryKey, role string) (crypto.Signer, error) {
	return d.deriveSigner(key, role)
}

func NewHashAlg(alg crypto.Hash) hashAlg {
	return hashAlg(alg)
}

func NewEcdsaPublicKey(rand []byte) (ecdsaPublicKey, error) {
	var pk ecdsaPublicKey

	privateKey, err := internal_crypto.GenerateECDSAKey(elliptic.P256(), bytes.NewReader(rand))
	if err != nil {
		return pk, err
	}

	pk.PublicKey = privateKey.Public().(*ecdsa.PublicKey)

	return pk, nil
}

func (d *KeyDataScope) Data() keyDataScope {
	return d.data
}
