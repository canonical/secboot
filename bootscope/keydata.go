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
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/snapcore/secboot"
	internal_bootscope "github.com/snapcore/secboot/internal/bootscope"
	internal_crypto "github.com/snapcore/secboot/internal/crypto"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/xerrors"
)

const (
	nilHash secboot.HashAlg = 0
)

var (
	sha1Oid   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	sha224Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	sha256Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sha384Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	sha512Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// digestList corresponds to a list of digests.
type digestList struct {
	Alg     secboot.HashAlg `json:"alg"`     // The digest algorithm
	Digests [][]byte        `json:"digests"` // The list of digests
}

func (l *digestList) marshalASN1WithTag(tag cryptobyte_asn1.Tag, b *cryptobyte.Builder) {
	b.AddASN1(tag, func(b *cryptobyte.Builder) { // DigestList ::= SEQUENCE {
		l.Alg.MarshalASN1(b)                                         // algorithm AlgorithmIdentifier
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

	KDFAlg secboot.HashAlg `json:"kdf_alg"`
	MDAlg  secboot.HashAlg `json:"md_alg"`
}

type additionalData struct {
	// Version corresponds to the version field of the keyDataScope object
	Version int
	// Generation corresponds to the generation field of the keyData object
	Generation       int
	KdfAlg           secboot.HashAlg
	AuthMode         secboot.AuthMode
	KeyIdentifierAlg secboot.HashAlg
	KeyIdentifier    []byte
}

func (d *additionalData) marshalASN1(b *cryptobyte.Builder) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // SEQUENCE {
		b.AddASN1Int64(int64(d.Version))      // version INTEGER
		b.AddASN1Int64(int64(d.Generation))   // generation INTEGER
		d.KdfAlg.MarshalASN1(b)               // kdfAlg AlgorithmIdentifier
		b.AddASN1Enum(int64(d.AuthMode))      // authMode ENUMERATED
		d.KeyIdentifierAlg.MarshalASN1(b)     // keyIdentifierAlg AlgorithmIdentifier
		b.AddASN1OctetString(d.KeyIdentifier) // keyIdentifier OCTET STRING
	})
}

// KeyDataScopeParams defines the parameters for the creation of a
// key data scope object.
type KeyDataScopeParams struct {
	PrimaryKey secboot.PrimaryKey
	Role       string

	// KDFAlg specifies the algorithm used to derive the role unique
	// signing key from the primary key.
	KDFAlg crypto.Hash

	// MDAlg specifies the algorithm used to compute the digest of the scope
	// object (which includes model digests and the boot modes). This is signed
	// with the role unique signing key to produce the scope signature.
	MDAlg crypto.Hash

	// ModelAlg specifies the algorithm used to compute the model digests.
	ModelAlg crypto.Hash
}

// KeyDataScope represents a key data's scope object which encapsulates information
// about the scope of the key such as valid models or boot modes.
type KeyDataScope struct {
	data keyDataScope
}

func (d KeyDataScope) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.data)
}

func (d *KeyDataScope) UnmarshalJSON(data []byte) error {
	var kds keyDataScope
	if err := json.Unmarshal(data, &kds); err != nil {
		return err
	}
	d.data = kds
	return nil
}

// NewKeyDataScope creates a new scope object from the given parameters.
//
// The PrimaryKey and the role parameters are used to derive a role unique
// signing key which is used to sign a hash (using MDAlg) of a DER encoded
// payload containing model digests and boot modes (which are now considered as
// authorized for the scope). Initially that payload is empty.
// The produced signature is stored in the scope object.
func NewKeyDataScope(rand io.Reader, params *KeyDataScopeParams) (*KeyDataScope, error) {

	if params.ModelAlg == 0 {
		return nil, errors.New("No model digest algorithm specified")
	}

	out := &KeyDataScope{
		data: keyDataScope{
			Version: 1,
			KDFAlg:  secboot.HashAlg(params.KDFAlg),
			MDAlg:   secboot.HashAlg(params.MDAlg),
			Params: scopeParams{
				ModelDigests: digestList{
					Alg: secboot.HashAlg(params.ModelAlg),
				},
			},
		},
	}

	signer, err := out.deriveSigner(params.PrimaryKey, params.Role)
	if err != nil {
		return nil, err
	}
	out.data.PublicKey.PublicKey = signer.Public().(*ecdsa.PublicKey)

	if err := out.authorize(rand, params.PrimaryKey, params.Role); err != nil {
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

func (d *KeyDataScope) authorize(rand io.Reader, key secboot.PrimaryKey, role string) error {
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
	sig, err := signer.Sign(rand, h.Sum(nil), alg)
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

// SetAuthorizedSnapModels is used to set new authorized models for an existing key data scope.
//
// Each supplied model is DER encoded and a digest is produced (using a model digest
// algorithm that can be specific per digest list). The PrimaryKey and the role parameters
// are used to derive a role unique signing key which is used to sign a hash (using scope's
// MDAlg) of a DER encoded payload containing the already authorized boot modes and the
// new models' digest list.
// On error the scope's already authorized model digests remain unchanged.
func (d *KeyDataScope) SetAuthorizedSnapModels(rand io.Reader, key secboot.PrimaryKey, role string, models ...secboot.SnapModel) (err error) {
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

	return d.authorize(rand, key, role)
}

// SetAuthorizedBootModes is used to set new authorized boot modes for existing key data scope.
//
// The PrimaryKey and the role parameters are used to derive a role unique signing key which is
// used to sign a hash (using scope's MDAlg) of a DER encoded payload containing the already
// authorized model digests and the new boot modes.
// On error the scope's already authorized boot modes remain unchanged.
func (d *KeyDataScope) SetAuthorizedBootModes(rand io.Reader, key secboot.PrimaryKey, role string, modes ...string) (err error) {
	currentModes := d.data.Params.Modes
	d.data.Params.Modes = modes

	defer func() {
		if err == nil {
			return
		}
		d.data.Params.Modes = currentModes
	}()

	return d.authorize(rand, key, role)
}

// IsBootEnvironmentAuthorized checks if the current boot environment (model and boot mode) is
// compatible with the bound authorized models and boot modes.
//
// This must be called from within an environment where the integrity is protected by
// some other mechanism, such as verified boot, or where the platform device has some way
// of authenticating the current environment, and it must be called before the authenticated
// boot environment parameters are processed and used.
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
		model := internal_bootscope.GetModel()
		if model == nil {
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

// MakeAEADAdditionalData constructs the additional data that need to be integrity protected for
// a key data scope. For example a platform using AES-GCM can use it to ensure that the authentication
// mode of a key data object is immutable and tampering of this can be detected by the early boot
// environment.
func (d *KeyDataScope) MakeAEADAdditionalData(generation int, kdfAlg crypto.Hash, authMode secboot.AuthMode) ([]byte, error) {
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
		Version:          d.data.Version,
		Generation:       generation,
		KdfAlg:           secboot.HashAlg(kdfAlg),
		AuthMode:         authMode,
		KeyIdentifierAlg: alg,
		KeyIdentifier:    h.Sum(nil),
	}

	builder := cryptobyte.NewBuilder(nil)
	aad.marshalASN1(builder)

	return builder.Bytes()
}
