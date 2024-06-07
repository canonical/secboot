// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package hooks

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/bootscope"
)

var (
	keyProtectorMu    sync.Mutex
	keyProtector      KeyProtector = nullKeyProtector{}
	keyProtectorFlags KeyProtectorFlags

	secbootNewKeyData = secboot.NewKeyData
)

// KeyProtectorFlags is used to specify features of the external key setup hook.
type KeyProtectorFlags int

const (
	// KeyProtectorAEAD indicates that the external key setup hook does not
	// have a way to accept additional authenticated data.
	KeyProtectorNoAEAD KeyProtectorFlags = 1 << iota
)

// KeyProtector is an abstraction for an externally supplied key setup hook.
type KeyProtector interface {
	ProtectKey(rand io.Reader, cleartext, aad []byte) (ciphertext []byte, handle []byte, err error)
}

// SetKeyProtector is used to configure the global external key setup hook, used
// by [NewProtectedKey].
func SetKeyProtector(protector KeyProtector, flags KeyProtectorFlags) {
	keyProtectorMu.Lock()
	defer keyProtectorMu.Unlock()
	if protector == nil {
		keyProtector = nullKeyProtector{}
		keyProtectorFlags = 0
	} else {
		keyProtector = protector
		keyProtectorFlags = flags
	}
}

type nullKeyProtector struct{}

func (nullKeyProtector) ProtectKey(rand io.Reader, cleartext, aad []byte) (ciphertext []byte, handle []byte, err error) {
	return nil, nil, errors.New("no hooks key protector set - call hooks.SetKeyProtector")
}

type aeadCompatData struct {
	Nonce        []byte `json:"nonce"`
	EncryptedKey []byte `json:"encrypted_key"`
}

type keyData struct {
	Handle     json.RawMessage        `json:"handle"`
	Scope      bootscope.KeyDataScope `json:"scope"`
	AEADCompat *aeadCompatData        `json:"aead_compat,omitempty"`
}

// KeyData encapsulates the metadata used to recover keys using the hooks platform.
type KeyData struct {
	k    *secboot.KeyData
	data keyData
}

// KeyParams is the parameters for [NewProtectedKey].
type KeyParams struct {
	// PrimaryKey is the primary key to use for a new protected key.
	PrimaryKey secboot.PrimaryKey

	// Role is the role to use for a new protected key.
	Role string

	// AuthorizedSnapModels is the initial set of authorized snap models
	// for a new protected key.
	AuthorizedSnapModels []secboot.SnapModel

	// AuthorizedBootModes is the initial set of authorized boot modes to
	// use for a new protected key.
	AuthorizedBootModes []string
}

// NewProtectedKey creates a new key that is protected by the registered [KeyProtector].
//
// The caller may supply a primary key via the optional params argument, but a 32-byte primary
// key will be generated and returned if one is not supplied.
//
// This function requires some cryptographically strong randomness, obtained from the rand
// argument. Whilst this will normally be from [rand.Reader], it can be provided from other
// secure sources or mocked during tests.
//
// The caller can supply a set of snap models and boot modes to bind to the new key.
//
// On success, a new key data object is returned, along with primary key and an unlock key
// that can be added to a storage container.
func NewProtectedKey(rand io.Reader, params *KeyParams) (protectedKey *secboot.KeyData, primaryKeyOut secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
	if params == nil {
		params = new(KeyParams)
	}

	primaryKey := params.PrimaryKey
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

	scope, err := bootscope.NewKeyDataScope(&bootscope.KeyDataScopeParams{
		PrimaryKey: primaryKey,
		Role:       params.Role,
		KDFAlg:     crypto.SHA256,
		MDAlg:      crypto.SHA256,
		ModelAlg:   crypto.SHA256,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create boot environment scope: %w", err)
	}

	if err := scope.SetAuthorizedSnapModels(primaryKey, params.Role, params.AuthorizedSnapModels...); err != nil {
		return nil, nil, nil, fmt.Errorf("cannot set authorized snap models: %w", err)
	}
	if err := scope.SetAuthorizedBootModes(primaryKey, params.Role, params.AuthorizedBootModes...); err != nil {
		return nil, nil, nil, fmt.Errorf("cannot set authorized boot modes: %w", err)
	}

	aad, err := scope.MakeAEADAdditionalData(secboot.KeyDataGeneration, kdfAlg, secboot.AuthModeNone)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot make AAD: %w", err)
	}

	var (
		ciphertext []byte
		handle     []byte
		aeadCompat *aeadCompatData
	)

	keyProtectorMu.Lock()
	defer keyProtectorMu.Unlock()

	switch {
	case keyProtectorFlags&KeyProtectorNoAEAD != 0:
		randBytes := make([]byte, 32+12)
		if _, err := io.ReadFull(rand, randBytes); err != nil {
			return nil, nil, nil, fmt.Errorf("cannot obtain random bytes for AEAD compat: %w", err)
		}

		symKey := randBytes[:32]
		nonce := randBytes[32:]

		b, err := aes.NewCipher(symKey)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot create cipher for AEAD compat: %w", err)
		}
		aead, err := cipher.NewGCM(b)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot create AEAD for AEAD compat: %w", err)
		}
		ciphertext = aead.Seal(nil, nonce, payload, aad)

		var encryptedKey []byte
		encryptedKey, handle, err = keyProtector.ProtectKey(rand, symKey, nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot protect symmetric key for AEAD compat using hook: %w", err)
		}

		aeadCompat = &aeadCompatData{
			Nonce:        nonce,
			EncryptedKey: encryptedKey,
		}
	default:
		ciphertext, handle, err = keyProtector.ProtectKey(rand, payload, aad)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot protect key using hook: %w", err)
		}
	}

	kd, err := secbootNewKeyData(&secboot.KeyParams{
		Handle: &KeyData{
			data: keyData{
				Handle:     handle,
				Scope:      *scope,
				AEADCompat: aeadCompat,
			},
		},
		Role:             params.Role,
		EncryptedPayload: ciphertext,
		PlatformName:     platformName,
		KDFAlg:           kdfAlg,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create key data: %w", err)
	}

	return kd, primaryKey, unlockKey, nil
}

// NewKeyData creates a new KeyData object for the supplied secboot.KeyData.
func NewKeyData(k *secboot.KeyData) (*KeyData, error) {
	var kd *KeyData
	if err := k.UnmarshalPlatformHandle(&kd); err != nil {
		return nil, fmt.Errorf("cannot unmarshal platform key data: %w", err)
	}
	kd.k = k

	return kd, nil
}

// MarshalJSON implements [json.Marshaler].
func (d KeyData) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.data)
}

// UnmarshalJSON implements [json.Unmarshaler].
func (d *KeyData) UnmarshalJSON(data []byte) error {
	var kd keyData
	if err := json.Unmarshal(data, &kd); err != nil {
		return err
	}
	d.data = kd
	return nil
}

// SetAuthorizedSnapModels updates the snap models that this key data is
// bound to. This update has to be authenticated, which requires the primary
// key that was originally supplied to [NewProtectedKey].
//
// On success, this will automatically update the corresponding *[secboot.KeyData]
// that this key data was created from using [NewKeyData].
func (d *KeyData) SetAuthorizedSnapModels(key secboot.PrimaryKey, models ...secboot.SnapModel) error {
	if err := d.data.Scope.SetAuthorizedSnapModels(key, d.k.Role(), models...); err != nil {
		return err
	}
	return d.k.MarshalAndUpdatePlatformHandle(d)
}

// SetAuthorizedBootModes updates the boot modes that this key data is
// bound to. This update has to be authenticated, which requires the primary
// key that was originally supplied to [NewProtectedKey].
//
// On success, this will automatically update the corresponding *[secboot.KeyData]
// that this key data was created from using [NewKeyData].
func (d *KeyData) SetAuthorizedBootModes(key secboot.PrimaryKey, modes ...string) error {
	if err := d.data.Scope.SetAuthorizedBootModes(key, d.k.Role(), modes...); err != nil {
		return err
	}
	return d.k.MarshalAndUpdatePlatformHandle(d)
}
