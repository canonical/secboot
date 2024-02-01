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

package plainkey

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"

	"github.com/snapcore/secboot"
)

const (
	symKeySaltSize = 32
	nonceSize      = 12
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

func deriveAESKey(ikm, salt []byte) []byte {
	r := hkdf.New(crypto.SHA256.New, ikm, salt, []byte("ENCRYPT"))

	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(fmt.Sprintf("cannot derive key: %v", err))
	}

	return key
}

type additionalData struct {
	Version    int
	Generation int
	KDFAlg     hashAlg
	AuthMode   secboot.AuthMode
}

func (d additionalData) MarshalASN1(b *cryptobyte.Builder) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(d.Version))
		b.AddASN1Int64(int64(d.Generation))
		d.KDFAlg.MarshalASN1(b)
		b.AddASN1Enum(int64(d.AuthMode))
	})
}

type platformKeyId struct {
	Alg    hashAlg `json:"alg"`
	Salt   []byte  `json:"salt"`
	Digest []byte  `json:"digest"`
}

type keyData struct {
	Version int    `json:"version"`
	Nonce   []byte `json:"nonce"`

	PlatformKeyID platformKeyId `json:"platform-key-id"`
}

// NewProtectedKey creates a new key that is protected by this platform with the supplied
// platform key. The platform key is typically stored inside of an encrypted container that
// is unlocked via another mechanism, such as a TPM, and then loaded via [SetPlatformKeys]
// or [AddPlatformKeys] after unlocking that container.
//
// If primaryKey isn't supplied, then one will be generated.
func NewProtectedKey(rand io.Reader, platformKey []byte, primaryKey secboot.PrimaryKey) (protectedKey *secboot.KeyData, primaryKeyOut secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
	if len(primaryKey) == 0 {
		primaryKey = make(secboot.PrimaryKey, 32)
		if _, err := io.ReadFull(rand, primaryKey); err != nil {
			return nil, nil, nil, fmt.Errorf("cannot obtain primary key: %w", err)
		}

	}

	kdfAlg := crypto.SHA256
	unlockKey, payload, err := secboot.MakeDiskUnlockKey(rand, kdfAlg, primaryKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create new unlock key: %w", err)
	}

	// The nonce contains a 32 byte salt and 12 byte GCM nonce
	nonce := make([]byte, symKeySaltSize+nonceSize)
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("cannot obtain nonce: %w", err)
	}

	aad := additionalData{
		Version:    1,
		Generation: secboot.KeyDataGeneration,
		KDFAlg:     hashAlg(kdfAlg),
		AuthMode:   secboot.AuthModeNone,
	}
	builder := cryptobyte.NewBuilder(nil)
	aad.MarshalASN1(builder)
	aadBytes, err := builder.Bytes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot serialize AAD: %w", err)
	}

	idAlg := crypto.SHA256
	salt := make([]byte, idAlg.Size())
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, nil, nil, fmt.Errorf("cannot obtain salt for platform key ID: %w", err)
	}
	id := platformKeyId{
		Alg:  hashAlg(idAlg),
		Salt: salt,
	}
	h := hmac.New(id.Alg.New, platformKey)
	h.Write(id.Salt)
	id.Digest = h.Sum(nil)

	b, err := aes.NewCipher(deriveAESKey(platformKey, nonce[:symKeySaltSize]))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(b)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create AEAD: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce[symKeySaltSize:], payload, aadBytes)

	kd, err := secbootNewKeyData(&secboot.KeyParams{
		Handle: &keyData{
			Version:       1,
			Nonce:         nonce,
			PlatformKeyID: id,
		},
		EncryptedPayload: ciphertext,
		PlatformName:     platformName,
		KDFAlg:           kdfAlg,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create key data: %w", err)
	}

	return kd, primaryKey, unlockKey, nil
}
