// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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

package fido2

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/cryptobyte"

	"github.com/snapcore/secboot"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	nonceSize = 12
)

var (
	nilHash   hashAlg = 0
	sha1Oid           = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	sha224Oid         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	sha256Oid         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sha384Oid         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	sha512Oid         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	secbootNewKeyData = secboot.NewKeyData
)

// hashAlg corresponds to a digest algorithm.
// XXX: This is the third place this appears now - we almost certainly want to put this
// in one place. Maybe for another PR.
type hashAlg crypto.Hash

func (a hashAlg) Available() bool {
	return crypto.Hash(a).Available()
}

func (a hashAlg) New() hash.Hash {
	return crypto.Hash(a).New()
}

func (a hashAlg) Size() int {
	return crypto.Hash(a).Size()
}

func (a hashAlg) MarshalASN1(b *cryptobyte.Builder) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // AlgorithmIdentifier ::= SEQUENCE {
		var oid asn1.ObjectIdentifier

		switch crypto.Hash(a) {
		case crypto.SHA1:
			oid = sha1Oid
		case crypto.SHA224:
			oid = sha224Oid
		case crypto.SHA256:
			oid = sha256Oid
		case crypto.SHA384:
			oid = sha384Oid
		case crypto.SHA512:
			oid = sha512Oid
		default:
			b.SetError(fmt.Errorf("unknown hash algorithm: %v", crypto.Hash(a)))
			return
		}
		b.AddASN1ObjectIdentifier(oid) // algorithm OBJECT IDENTIFIER
		b.AddASN1NULL()                // parameters ANY DEFINED BY algorithm OPTIONAL
	})
}

func (a hashAlg) MarshalJSON() ([]byte, error) {
	var s string

	switch crypto.Hash(a) {
	case crypto.SHA1:
		s = "sha1"
	case crypto.SHA224:
		s = "sha224"
	case crypto.SHA256:
		s = "sha256"
	case crypto.SHA384:
		s = "sha384"
	case crypto.SHA512:
		s = "sha512"
	case crypto.Hash(nilHash):
		s = "null"
	default:
		return nil, fmt.Errorf("unknown hash algorithm: %v", crypto.Hash(a))
	}

	return json.Marshal(s)
}

func (a *hashAlg) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	switch s {
	case "sha1":
		*a = hashAlg(crypto.SHA1)
	case "sha224":
		*a = hashAlg(crypto.SHA224)
	case "sha256":
		*a = hashAlg(crypto.SHA256)
	case "sha384":
		*a = hashAlg(crypto.SHA384)
	case "sha512":
		*a = hashAlg(crypto.SHA512)
	default:
		// be permissive here and allow everything to be
		// unmarshalled.
		*a = nilHash
	}

	return nil
}

type additionalData struct {
	Version      int
	Generation   int
	KDFAlg       hashAlg
	AuthMode     secboot.AuthMode
	SaltProvider []byte
}

func (d additionalData) MarshalASN1(b *cryptobyte.Builder) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(d.Version))
		b.AddASN1Int64(int64(d.Generation))
		d.KDFAlg.MarshalASN1(b)
		b.AddASN1Enum(int64(d.AuthMode))
		b.AddASN1OctetString(d.SaltProvider)
	})
}

type keyData struct {
	Version int `json:"version"`

	// the nonce used for the GCM step
	Nonce []byte `json:"nonce"`

	// The FIDO2 credential ID that is associated with this key data
	CredentialID []byte `json:"credential_id"`

	// Alg is the digest algorithm used for creating the salt passed to
	// the authenticator's hmac-secret and for deriving the final symmetric key.
	Alg hashAlg `json:"alg"` // the digest algorithm
}

func newFIDO2ProtectedKey(authenticator *FIDO2Authenticator, providerName string, symA []byte, primaryKey secboot.PrimaryKey) (fkd *keyData, encryptedPayload []byte, primaryKeyOut secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
	kdfAlg := crypto.SHA256
	if len(symA) < kdfAlg.Size() {
		return nil, nil, nil, nil, fmt.Errorf("input symmetric key must be at least %d bytes long", kdfAlg.Size())
	}

	// The salt passed as input to the authenticator's hmac-secret, is created as salt=HMAC-SHA3_256(symA, "ubuntu-fde-fido2").
	// This is done to hide the actual symmetric key from the authenticator.
	salt := make([]byte, kdfAlg.Size())
	r := hmac.New(kdfAlg.New, symA)
	r.Write([]byte("ubuntu-fde-fido2"))
	salt = r.Sum(nil)

	// Communicate with the fido2 authenticator to retrieve hmac-secret(salt)
	credentialID, hmacSecret, err := authenticator.MakeFDECredential(salt)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot create FIDO2 credential: %w", err)
	}

	if len(hmacSecret) < kdfAlg.Size() {
		return nil, nil, nil, nil, fmt.Errorf("hmac-secret must be at least %d bytes long", kdfAlg.Size())
	}

	// Combine the result with the original symmetric key using HMAC-SHA256 to obtain the final symmetric key
	symB := make([]byte, kdfAlg.Size())
	r = hmac.New(kdfAlg.New, symA)
	r.Write(hmacSecret)
	symB = r.Sum(nil)

	// Create payload
	unlockKey, payload, err := secboot.MakeDiskUnlockKey(rand.Reader, kdfAlg, primaryKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot create new unlock key: %w", err)
	}

	// Encrypt using aead
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot obtain required random bytes: %w", err)
	}

	aad := additionalData{
		Version:      1,
		Generation:   secboot.KeyDataGeneration,
		KDFAlg:       hashAlg(kdfAlg),
		AuthMode:     secboot.AuthModeNone,
		SaltProvider: []byte(providerName),
	}
	builder := cryptobyte.NewBuilder(nil)
	aad.MarshalASN1(builder)
	aadBytes, err := builder.Bytes()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot serialize AAD: %w", err)
	}

	b, err := aes.NewCipher(symB)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(b)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot create AEAD: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, payload, aadBytes)

	fkd = &keyData{
		Version:      1,
		Nonce:        nonce,
		CredentialID: credentialID,
		Alg:          hashAlg(kdfAlg),
	}

	return fkd, ciphertext, primaryKey, unlockKey, nil
}

func NewFIDO2ProtectedKey(authenticator *FIDO2Authenticator, providerName string, symA []byte, primaryKey secboot.PrimaryKey) (protectedKey *secboot.KeyData, primaryKeyOut secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
	fkd, fidoEncPayload, primaryKey, unlockKey, err := newFIDO2ProtectedKey(authenticator, providerName, symA, primaryKey)
	if err != nil {
		return nil, nil, nil, err
	}

	kd, err := secbootNewKeyData(&secboot.KeyParams{
		Handle:           fkd,
		EncryptedPayload: fidoEncPayload,
		PlatformName:     platformName,
		KDFAlg:           crypto.Hash(fkd.Alg),
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create key data: %w", err)
	}

	return kd, primaryKey, unlockKey, nil
}

func NewFIDO2ProtectedKeyWithSaltProvider(authenticator *FIDO2Authenticator, pkd *secboot.KeyData, primaryKey secboot.PrimaryKey) (protectedKey *secboot.KeyData, primaryKeyOut secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
	providerName, providerPlatformKeyData, sym, err := pkd.RecoverSymmetricKey()
	if err != nil {
		return nil, nil, nil, err
	}

	fkd, fidoEncPayload, primaryKey, unlockKey, err := newFIDO2ProtectedKey(authenticator, providerName, sym, primaryKey)
	if err != nil {
		return nil, nil, nil, err
	}

	combinedPlatformKeyData := &providerKeyData{
		Version:  1,
		Provider: providerPlatformKeyData,
		Fido2:    fkd,
	}

	combinedPlatformName := providerName + "-" + platformName

	kdOut, err := secbootNewKeyData(&secboot.KeyParams{
		Handle:           *combinedPlatformKeyData,
		EncryptedPayload: fidoEncPayload,
		PlatformName:     combinedPlatformName,
		KDFAlg:           crypto.Hash(fkd.Alg),
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create key data: %w", err)
	}

	return kdOut, primaryKey, unlockKey, nil
}

// TODO
// func NewFIDO2PassphraseProtectedKey(authenticator *FIDO2Authenticator, primaryKey secboot.PrimaryKey, salt []byte) (protectedKey *secboot.KeyData, primaryKeyOut secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
// 	return nil, nil, nil, nil
// }
