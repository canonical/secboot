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
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	"github.com/snapcore/secboot"
	internal_crypto "github.com/snapcore/secboot/internal/crypto"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/xerrors"
)

const (
	nilHash hashAlg = 0
)

var (
	sha1Oid   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	sha224Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	sha256Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sha384Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	sha512Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// hashAlg corresponds to a digest algorithm.
type hashAlg crypto.Hash

func (a hashAlg) Available() bool {
	return crypto.Hash(a).Available()
}

func (a hashAlg) New() hash.Hash {
	return crypto.Hash(a).New()
}

func (a hashAlg) HashFunc() crypto.Hash {
	return crypto.Hash(a)
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

func (a hashAlg) marshalASN1(b *cryptobyte.Builder) {
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

// digestList corresponds to a list of digests.
type digestList struct {
	Alg     hashAlg  `json:"alg"`     // The digest algorithm
	Digests [][]byte `json:"digests"` // The list of digests
}

func (l *digestList) marshalASN1WithTag(tag cryptobyte_asn1.Tag, b *cryptobyte.Builder) {
	b.AddASN1(tag, func(b *cryptobyte.Builder) { // DigestList ::= SEQUENCE {
		l.Alg.marshalASN1(b)                                         // algorithm AlgorithmIdentifier
		b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) { // digests Digests
			for _, digest := range l.Digests {
				b.AddASN1OctetString(digest)
			}
		})
	})
}

type scopeParams struct {
	ModelDigests digestList `json:"model_digests,omitempty"`
	Modes        []string   `json:"modes,omitempty"`
}

func (s *scopeParams) marshalASN1(b *cryptobyte.Builder) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // Scope ::= SEQUENCE {
		if len(s.ModelDigests.Digests) > 0 {
			s.ModelDigests.marshalASN1WithTag(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), b) // modelDigests [0] IMPLICIT DigestList OPTIONAL
		}
		if len(s.Modes) > 0 {
			b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // modes [1] IMPLICIT BootModes OPTIONAL
				for _, mode := range s.Modes {
					b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(mode))
					})
				}
			})
		}
	})
}

type ecdsaPublicKey struct {
	*ecdsa.PublicKey
}

func (k ecdsaPublicKey) MarshalJSON() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(k.PublicKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(der)
}

func (k *ecdsaPublicKey) UnmarshalJSON(data []byte) error {
	var der []byte
	if err := json.Unmarshal(data, &der); err != nil {
		return err
	}
	pubKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return err
	}
	ecdsaKey, isECDSA := pubKey.(*ecdsa.PublicKey)
	if !isECDSA {
		return errors.New("invalid key type")
	}
	k.PublicKey = ecdsaKey
	return nil
}

type keyDataScope struct {
	Version int `json:"version"`

	Params    scopeParams    `json:"params"`
	Signature []byte         `json:"signature"`
	PublicKey ecdsaPublicKey `json:"pubkey"`

	KDFAlg hashAlg `json:"kdf_alg"`
	MDAlg  hashAlg `json:"md_alg"`
}

type additionalData struct {
	version          int
	baseVersion      int
	kdfAlg           hashAlg
	authMode         secboot.AuthMode
	keyIdentifierAlg hashAlg
	keyIdentifier    []byte
}

func (d *additionalData) marshalASN1(b *cryptobyte.Builder) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // SEQUENCE {
		b.AddASN1Int64(int64(d.version))      // version INTEGER
		b.AddASN1Int64(int64(d.baseVersion))  // baseVersion INTEGER
		d.kdfAlg.marshalASN1(b)               // kdfAlg AlgorithmIdentifier
		b.AddASN1Enum(int64(d.authMode))      // authMode ENUMERATED
		d.keyIdentifierAlg.marshalASN1(b)     // keyIdentifierAlg AlgorithmIdentifier
		b.AddASN1OctetString(d.keyIdentifier) // keyIdentifier OCTET STRING
	})
}

type KeyDataScopeParams struct {
	PrimaryKey secboot.PrimaryKey
	Role       string
	KDFAlg     crypto.Hash
	MDAlg      crypto.Hash
	ModelAlg   crypto.Hash
}

type KeyDataScope struct {
	data keyDataScope
}

func NewKeyDataScope(params *KeyDataScopeParams) (*KeyDataScope, error) {

	if params.ModelAlg == 0 {
		return nil, errors.New("No model digest algorithm specified")
	}

	out := &KeyDataScope{
		data: keyDataScope{
			Version: 1,
			KDFAlg:  hashAlg(params.KDFAlg),
			MDAlg:   hashAlg(params.MDAlg),
			Params: scopeParams{
				ModelDigests: digestList{
					Alg: hashAlg(params.ModelAlg),
				},
			},
		},
	}

	signer, err := out.deriveSigner(params.PrimaryKey, params.Role)
	if err != nil {
		return nil, err
	}
	out.data.PublicKey.PublicKey = signer.Public().(*ecdsa.PublicKey)

	if err := out.authorize(params.PrimaryKey, params.Role); err != nil {
		return nil, err
	}

	return out, nil
}

func (d *KeyDataScope) deriveSigner(key secboot.PrimaryKey, role string) (crypto.Signer, error) {
	alg := d.data.KDFAlg
	if !alg.Available() {
		return nil, errors.New("KDF algorithm unavailable")
	}

	r := hkdf.New(func() hash.Hash { return alg.New() }, key, []byte(role), []byte("SCOPE-AUTH"))
	return internal_crypto.GenerateECDSAKey(elliptic.P256(), r)
}

func (d *KeyDataScope) authorize(key secboot.PrimaryKey, role string) error {
	signer, err := d.deriveSigner(key, role)
	if err != nil {
		return fmt.Errorf("cannot derive signing key: %w", err)
	}

	if !signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(d.data.PublicKey.PublicKey) {
		return errors.New("incorrect key supplied")
	}

	builder := cryptobyte.NewBuilder(nil)
	d.data.Params.marshalASN1(builder)
	scope, err := builder.Bytes()
	if err != nil {
		return xerrors.Errorf("cannot serialize scope: %w", err)
	}

	alg := d.data.MDAlg
	if !alg.Available() {
		return errors.New("MD algorithm unavailable")
	}

	h := alg.New()
	h.Write(scope)
	sig, err := signer.Sign(rand.Reader, h.Sum(nil), alg)
	if err != nil {
		return err
	}
	d.data.Signature = sig

	return nil
}

func (d *KeyDataScope) isAuthorized() (bool, error) {
	builder := cryptobyte.NewBuilder(nil)
	d.data.Params.marshalASN1(builder)
	scope, err := builder.Bytes()
	if err != nil {
		return false, fmt.Errorf("cannot serialize scope: %w", err)
	}

	alg := d.data.MDAlg
	if !alg.Available() {
		return false, errors.New("MD algorithm unavailable")
	}

	h := alg.New()
	h.Write(scope)
	return ecdsa.VerifyASN1(d.data.PublicKey.PublicKey, h.Sum(nil), d.data.Signature), nil
}

func (d *KeyDataScope) SetAuthorizedSnapModels(key secboot.PrimaryKey, role string, models ...secboot.SnapModel) (err error) {
	alg := d.data.Params.ModelDigests.Alg
	if !alg.Available() {
		return
	}

	var modelDigests [][]byte
	for _, model := range models {
		digest, err := computeSnapModelHash(crypto.Hash(alg), model)
		if err != nil {
			return fmt.Errorf("cannot compute snap model digest: %w", err)
		}
		modelDigests = append(modelDigests, digest)
	}

	currentModelDigests := d.data.Params.ModelDigests.Digests
	d.data.Params.ModelDigests.Digests = modelDigests

	defer func() {
		if err == nil {
			return
		}
		d.data.Params.ModelDigests.Digests = currentModelDigests
	}()

	return d.authorize(key, role)
}

func (d *KeyDataScope) SetAuthorizedBootModes(key secboot.PrimaryKey, role string, modes ...string) (err error) {
	currentModes := d.data.Params.Modes
	d.data.Params.Modes = modes

	defer func() {
		if err == nil {
			return
		}
		d.data.Params.Modes = currentModes
	}()

	return d.authorize(key, role)
}

func (d *KeyDataScope) IsBootEnvironmentAuthorized() error {
	ok, err := d.isAuthorized()
	if err != nil {
		return fmt.Errorf("cannot verify signature: %w", err)
	}
	if !ok {
		return errors.New("invalid signature")
	}

	alg := d.data.Params.ModelDigests.Alg
	if !alg.Available() {
		return errors.New("model digest algorithm unavailable")
	}

	if len(d.data.Params.ModelDigests.Digests) > 0 {
		model, ok := currentModel.Load().(secboot.SnapModel)
		if !ok {
			return errors.New("SetModel hasn't been called yet")
		}

		currentModelDigest, err := computeSnapModelHash(crypto.Hash(alg), model)
		if err != nil {
			return fmt.Errorf("cannot compute snap model digest: %w", err)
		}

		found := false
		for _, modelDigest := range d.data.Params.ModelDigests.Digests {
			if bytes.Equal(modelDigest, currentModelDigest) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("unauthorized model")
		}
	}

	if len(d.data.Params.Modes) > 0 {
		mode, ok := currentBootMode.Load().(string)
		if !ok {
			return errors.New("SetBootMode hasn't been called yet")
		}

		found := false
		for _, m := range d.data.Params.Modes {
			if m == mode {
				found = true
				break
			}
		}
		if !found {
			return errors.New("unauthorized boot mode")
		}
	}

	return nil
}

func (d *KeyDataScope) MakeAdditionalData(baseVersion int, kdfAlg crypto.Hash, authMode secboot.AuthMode) ([]byte, error) {
	alg := d.data.MDAlg
	if !alg.Available() {
		return nil, errors.New("MD algorithm unavailable")
	}

	der, err := x509.MarshalPKIXPublicKey(d.data.PublicKey.PublicKey)
	if err != nil {
		return nil, xerrors.Errorf("cannot marshal public key: %w", err)
	}

	h := alg.New()
	h.Write(der)

	aad := &additionalData{
		version:          d.data.Version,
		authMode:         authMode,
		keyIdentifierAlg: alg,
		keyIdentifier:    h.Sum(nil),
	}

	builder := cryptobyte.NewBuilder(nil)
	aad.marshalASN1(builder)

	return builder.Bytes()
}
