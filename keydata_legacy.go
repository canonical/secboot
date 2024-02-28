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

package secboot

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"

	drbg "github.com/canonical/go-sp800.90a-drbg"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/xerrors"
)

var (
	snapModelHMACKDFLabel = []byte("SNAP-MODEL-HMAC")
)

func unmarshalV1KeyPayload(data []byte) (unlockKey DiskUnlockKey, auxKey PrimaryKey, err error) {
	r := bytes.NewReader(data)

	var sz uint16
	if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
		return nil, nil, err
	}

	if sz > 0 {
		unlockKey = make(DiskUnlockKey, sz)
		if _, err := r.Read(unlockKey); err != nil {
			return nil, nil, err
		}
	}

	if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
		return nil, nil, err
	}

	if sz > 0 {
		auxKey = make(PrimaryKey, sz)
		if _, err := r.Read(auxKey); err != nil {
			return nil, nil, err
		}
	}

	if r.Len() > 0 {
		return nil, nil, fmt.Errorf("%v excess byte(s)", r.Len())
	}

	return unlockKey, auxKey, nil
}

type snapModelHMAC []byte

type snapModelHMACList []snapModelHMAC

func (l snapModelHMACList) contains(h snapModelHMAC) bool {
	for _, v := range l {
		if bytes.Equal(v, h) {
			return true
		}
	}
	return false
}

type authorizedSnapModelsRaw struct {
	Alg       hashAlg           `json:"alg"`
	KDFAlg    hashAlg           `json:"kdf_alg,omitempty"`
	KeyDigest json.RawMessage   `json:"key_digest"`
	Hmacs     snapModelHMACList `json:"hmacs"`
}

// keyDigest contains a salted digest to verify the correctness of a key.
type keyDigest struct {
	Alg    hashAlg `json:"alg"`
	Salt   []byte  `json:"salt"`
	Digest []byte  `json:"digest"`
}

// authorizedSnapModels defines the Snap models that have been
// authorized to access the data protected by a key.
type authorizedSnapModels struct {
	alg       hashAlg           // Digest algorithm used for the authorized model HMACs
	kdfAlg    hashAlg           // Digest algorithm used to derive the HMAC key with HKDF. Zero for legacy (DRBG) derivation.
	keyDigest keyDigest         // information used to validate the correctness of the HMAC key
	hmacs     snapModelHMACList // the list of HMACs of authorized models

	// legacyKeyDigest is true when keyDigest should be marshalled
	// as a plain key rather than a keyDigest object.
	legacyKeyDigest bool
}

// MarshalJSON implements custom marshalling to handle older key data
// objects where the key_digest field was just a base64 encoded key.
func (m authorizedSnapModels) MarshalJSON() ([]byte, error) {
	var digest json.RawMessage
	var err error
	if m.legacyKeyDigest {
		digest, err = json.Marshal(m.keyDigest.Digest)
	} else {
		digest, err = json.Marshal(&m.keyDigest)
	}
	if err != nil {
		return nil, err
	}

	return json.Marshal(&authorizedSnapModelsRaw{
		Alg:       m.alg,
		KDFAlg:    m.kdfAlg,
		KeyDigest: digest,
		Hmacs:     m.hmacs})
}

// UnmarshalJSON implements custom unmarshalling to handle older key data
// objects where the key_digest field was just a base64 encoded key.
func (m *authorizedSnapModels) UnmarshalJSON(b []byte) error {
	var raw authorizedSnapModelsRaw
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	*m = authorizedSnapModels{
		alg:    raw.Alg,
		kdfAlg: raw.KDFAlg,
		hmacs:  raw.Hmacs}

	token, err := json.NewDecoder(bytes.NewReader(raw.KeyDigest)).Token()
	switch {
	case err == io.EOF:
		// Empty field, ignore
		return nil
	case err != nil:
		return err
	}

	switch t := token.(type) {
	case json.Delim:
		// Newer data, where the KeyDigest field is an object.
		if t != '{' {
			return fmt.Errorf("invalid delim (%v) at start of key_digest field", t)
		}
		if err := json.Unmarshal(raw.KeyDigest, &m.keyDigest); err != nil {
			return err
		}
	case string:
		// Older data, where the KeyDigest field was a base64 encoded key.
		// Convert it to an object.
		_ = t
		m.keyDigest.Alg = raw.Alg
		m.legacyKeyDigest = true
		if err := json.Unmarshal(raw.KeyDigest, &m.keyDigest.Digest); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid token (%v) at start of key_digest field", token)
	}

	return nil
}

func (d *KeyData) snapModelHMACKeyLegacy(key PrimaryKey) ([]byte, error) {
	if d.data.AuthorizedSnapModels == nil {
		return nil, errors.New("no authorized_snap_models")
	}
	alg := d.data.AuthorizedSnapModels.alg
	if alg == nilHash {
		return nil, errors.New("invalid digest algorithm")
	}

	rng, err := drbg.NewCTRWithExternalEntropy(32, key, nil, snapModelHMACKDFLabel, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot instantiate DRBG: %w", err)
	}

	hmacKey := make([]byte, alg.Size())
	if _, err := rng.Read(hmacKey); err != nil {
		return nil, xerrors.Errorf("cannot derive key: %w", err)
	}

	return hmacKey, nil
}

func (d *KeyData) snapModelHMACKey(key PrimaryKey) ([]byte, error) {
	if d.data.AuthorizedSnapModels == nil {
		return nil, errors.New("no authorized_snap_models")
	}
	kdfAlg := d.data.AuthorizedSnapModels.kdfAlg
	if kdfAlg == nilHash {
		return d.snapModelHMACKeyLegacy(key)
	}
	if !kdfAlg.Available() {
		return nil, errors.New("invalid KDF digest algorithm")
	}

	alg := d.data.AuthorizedSnapModels.alg
	if alg == nilHash {
		return nil, errors.New("invalid digest algorithm")
	}

	r := hkdf.Expand(func() hash.Hash { return kdfAlg.New() }, key, snapModelHMACKDFLabel)

	// Derive a key with a length matching the output size of the
	// algorithm used for the HMAC.
	hmacKey := make([]byte, alg.Size())
	if _, err := io.ReadFull(r, hmacKey); err != nil {
		return nil, err
	}

	return hmacKey, nil
}

// IsSnapModelAuthorized indicates whether the supplied Snap device model is trusted to
// access the data on the encrypted volume protected by this key data.
//
// The supplied key is obtained using one of the RecoverKeys* functions.
//
// This is deprecated where [Generation] returns greater than 1, and will return an error.
// The value returned by [Generation] is indirectly protected because its used to decide
// how to decode the payload returned by [RecoverKeys].
func (d *KeyData) IsSnapModelAuthorized(key PrimaryKey, model SnapModel) (bool, error) {
	switch d.Generation() {
	case 1:
		hmacKey, err := d.snapModelHMACKey(key)
		if err != nil {
			return false, xerrors.Errorf("cannot obtain auth key: %w", err)
		}

		alg := d.data.AuthorizedSnapModels.alg
		if !alg.Available() {
			return false, errors.New("invalid digest algorithm")
		}

		h, err := computeSnapModelHMAC(crypto.Hash(alg), hmacKey, model)
		if err != nil {
			return false, xerrors.Errorf("cannot compute HMAC of model: %w", err)
		}

		return d.data.AuthorizedSnapModels.hmacs.contains(h), nil
	case 2:
		return false, errors.New("unsupported key data generation number")
	default:
		return false, fmt.Errorf("invalid keydata generation number %d", d.Generation())
	}
}

// SetAuthorizedSnapModels marks the supplied Snap device models as trusted to access
// the data on the encrypted volume protected by this key data. This function replaces all
// previously trusted models.
//
// This makes changes to the key data, which will need to persisted afterwards using
// WriteAtomic.
//
// The supplied key is obtained using one of the RecoverKeys* functions. If the
// supplied auxKey is incorrect, then an error will be returned.
//
// This is deprecated where [Generation] returns greater than 1, and will return an error.
func (d *KeyData) SetAuthorizedSnapModels(key PrimaryKey, models ...SnapModel) (err error) {
	switch d.Generation() {
	case 1:
		hmacKey, err := d.snapModelHMACKey(key)
		if err != nil {
			return xerrors.Errorf("cannot obtain auth key: %w", err)
		}

		alg := d.data.AuthorizedSnapModels.keyDigest.Alg
		if !alg.Available() {
			return errors.New("invalid digest algorithm")
		}

		h := alg.New()
		h.Write(hmacKey)
		h.Write(d.data.AuthorizedSnapModels.keyDigest.Salt)
		if !bytes.Equal(h.Sum(nil), d.data.AuthorizedSnapModels.keyDigest.Digest) {
			return errors.New("incorrect key supplied")
		}

		alg = d.data.AuthorizedSnapModels.alg
		if !alg.Available() {
			return errors.New("invalid digest algorithm")
		}

		var modelHMACs snapModelHMACList

		for _, model := range models {
			h, err := computeSnapModelHMAC(crypto.Hash(alg), hmacKey, model)
			if err != nil {
				return xerrors.Errorf("cannot compute HMAC of model: %w", err)
			}

			modelHMACs = append(modelHMACs, h)
		}

		d.data.AuthorizedSnapModels.hmacs = modelHMACs
		return nil
	case 2:
		return errors.New("unsupported key data generation number")
	default:
		return fmt.Errorf("invalid keydata generation number %d", d.Generation())
	}
}
