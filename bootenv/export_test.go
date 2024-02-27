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

package bootenv

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/snapcore/secboot"
	internal_crypto "github.com/snapcore/secboot/internal/crypto"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	ComputeSnapModelHash = computeSnapModelHash
)

func MockSetModel(f func(secboot.SnapModel) bool) (restore func()) {
	origSetModel := SetModel
	SetModel = f
	return func() {
		SetModel = origSetModel
	}
}

func MockSetBootMode(f func(string) bool) (restore func()) {
	origSetBootMode := SetBootMode
	SetBootMode = f
	return func() {
		SetBootMode = origSetBootMode
	}
}

func MockLoadCurrentModel(f func() (secboot.SnapModel, error)) (restore func()) {
	origLoadCurrentModel := loadCurrentModel
	loadCurrentModel = f
	return func() {
		loadCurrentModel = origLoadCurrentModel
	}
}

func MockLoadCurrenBootMode(f func() (string, error)) (restore func()) {
	origLoadCurrentBootMode := loadCurrentBootMode
	loadCurrentBootMode = f
	return func() {
		loadCurrentBootMode = origLoadCurrentBootMode
	}
}

func (d *KeyDataScope) TestSetVersion(version int) {
	d.data.Version = version
}

func unmarshalHashAlg(s *cryptobyte.String) (hashAlg, error) {
	var str cryptobyte.String

	if !s.ReadASN1(&str, cryptobyte_asn1.SEQUENCE) {
		return 0, errors.New("malformed input")
	}

	var oid asn1.ObjectIdentifier

	if !str.ReadASN1ObjectIdentifier(&oid) {
		return 0, errors.New("malformed Algorithm identifier")
	}

	var null uint8

	if !str.ReadUint8(&null) {
		return 0, errors.New("malformed input")
	}

	if len(oid) == len(sha1Oid) {
		return hashAlg(crypto.SHA1), nil
	}

	switch oid[8] {
	case sha224Oid[8]:
		return hashAlg(crypto.SHA224), nil
	case sha256Oid[8]:
		return hashAlg(crypto.SHA256), nil
	case sha384Oid[8]:
		return hashAlg(crypto.SHA384), nil
	case sha512Oid[8]:
		return hashAlg(crypto.SHA512), nil
	default:
		return 0, errors.New("unsupported hash algorithm")
	}
}

func UnmarshalAdditionalData(data []byte) (*additionalData, error) {
	s := cryptobyte.String(data)

	if !s.ReadASN1(&s, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("malformed input")
	}

	aad := new(additionalData)

	if !s.ReadASN1Integer(&aad.Version) {
		return nil, errors.New("malformed version")
	}

	if !s.ReadASN1Integer(&aad.BaseVersion) {
		return nil, errors.New("malformed base version")
	}

	kdfAlg, err := unmarshalHashAlg(&s)
	if err != nil {
		return nil, errors.New("malformed kdf")
	}
	aad.KdfAlg = kdfAlg

	var authMode int
	if !s.ReadASN1Enum(&authMode) {
		return nil, errors.New("malformed Auth mode")
	}
	aad.AuthMode = secboot.AuthMode(authMode)

	keyIdAlg, err := unmarshalHashAlg(&s)
	if err != nil {
		return nil, errors.New("malformed kdf")
	}
	aad.KeyIdentifierAlg = keyIdAlg

	if !s.ReadASN1Bytes(&aad.KeyIdentifier, cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("malformed Key identifier")
	}

	return aad, nil
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

func NewPrimaryKey(sz1 int) (secboot.PrimaryKey, error) {
	primaryKey := make(secboot.PrimaryKey, sz1)
	_, err := rand.Read(primaryKey)
	if err != nil {
		return nil, err
	}

	return primaryKey, nil
}
