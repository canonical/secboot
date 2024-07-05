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

// Package hooks provides a way to protect keys using hooks supplied via a gadget
// and kernel snap for a device.
//
// It provides a mechanism to bind model assertions and boot modes to key data objects.
// As enforcing of the binding of these is performed in software, this platform relies on
// another mechanism to secure the environment in which keys are recovered, such as verified
// boot which is non configurable or not configurable in a way that would allow execution of
// components that do not enforce these binding.
package hooks

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/snapcore/secboot"
)

const (
	platformName = "fde-hooks-v3"
)

var (
	keyRevealerMu sync.Mutex
	keyRevealer   KeyRevealer = nullKeyRevealer{}
)

type hooksPlatform struct{}

func (*hooksPlatform) RecoverKeys(data *secboot.PlatformKeyData, encryptedPayload []byte) ([]byte, error) {
	var kd KeyData
	if err := json.Unmarshal(data.EncodedHandle, &kd); err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  err,
		}
	}

	if err := kd.data.Scope.IsBootEnvironmentAuthorized(); err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  fmt.Errorf("cannot authorize boot environment: %w", err),
		}
	}

	aad, err := kd.data.Scope.MakeAEADAdditionalData(data.Generation, data.KDFAlg, data.AuthMode)
	if err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  fmt.Errorf("cannot make AAD: %w", err),
		}
	}

	keyRevealerMu.Lock()
	defer keyRevealerMu.Unlock()

	switch {
	case kd.data.AEADCompat != nil:
		symKey, err := keyRevealer.RevealKey(kd.data.Handle, kd.data.AEADCompat.EncryptedKey, nil)
		if err != nil {
			// XXX: This shouldn't always return invalid key data
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorInvalidData,
				Err:  fmt.Errorf("cannot recover symmetric key: %w", err),
			}
		}

		b, err := aes.NewCipher(symKey)
		if err != nil {
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorInvalidData,
				Err:  fmt.Errorf("cannot create cipher: %w", err),
			}
		}
		aead, err := cipher.NewGCMWithNonceSize(b, len(kd.data.AEADCompat.Nonce))
		if err != nil {
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorInvalidData,
				Err:  fmt.Errorf("cannot create AEAD: %w", err),
			}
		}
		payload, err := aead.Open(nil, kd.data.AEADCompat.Nonce, encryptedPayload, aad)
		if err != nil {
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorInvalidData,
				Err:  fmt.Errorf("cannot recover key: %w", err),
			}
		}
		return payload, nil
	default:
		payload, err := keyRevealer.RevealKey(kd.data.Handle, encryptedPayload, aad)
		if err != nil {
			// XXX: This shouldn't always return invalid key data
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorInvalidData,
				Err:  fmt.Errorf("cannot recover key: %w", err),
			}
		}
		return payload, nil
	}
}

func (*hooksPlatform) RecoverKeysWithAuthKey(data *secboot.PlatformKeyData, encryptedPayload, key []byte) ([]byte, error) {
	return nil, errors.New("unsupported action")
}

func (*hooksPlatform) ChangeAuthKey(data *secboot.PlatformKeyData, old, new []byte) ([]byte, error) {
	return nil, errors.New("unsupported action")
}

// KeyRevealer is an abstraction for an externally supplied key reveal hook.
type KeyRevealer interface {
	RevealKey(handle, ciphertext, aad []byte) (plaintext []byte, err error)
}

// SetKeyRevealer is used to configure the global key reveal hook, used by this
// platform.
func SetKeyRevealer(revealer KeyRevealer) {
	keyRevealerMu.Lock()
	defer keyRevealerMu.Unlock()
	if revealer == nil {
		keyRevealer = nullKeyRevealer{}
	} else {
		keyRevealer = revealer
	}
}

type nullKeyRevealer struct{}

func (nullKeyRevealer) RevealKey(handle, ciphertext, aad []byte) (plaintext []byte, err error) {
	return nil, errors.New("no hooks key revealer set - call hooks.SetKeyRevealer")
}

func init() {
	secboot.RegisterPlatformKeyDataHandler(platformName, new(hooksPlatform))
}
