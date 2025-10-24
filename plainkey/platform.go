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

// Package plainkey is a platform for recovering keys that are protected by a key that
// is protected by some other mechanism.
//
// This is typically used to unlock storage containers after unlocking an initial
// storage container with a key that is hardware protected, if access to that storage
// container implies access to others.
package plainkey

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/cryptobyte"

	"github.com/snapcore/secboot"
)

const (
	platformName = "plainkey"
)

var (
	protectorKeysMu sync.RWMutex
	protectorKeys   [][]byte
)

// SetProtectorKeys sets the keys that will be used by this platform to recover other
// keys. These are typically stored in and loaded from an encrypted container that is
// unlocked via some other mechanism.
func SetProtectorKeys(keys ...[]byte) {
	protectorKeysMu.Lock()
	protectorKeys = keys
	protectorKeysMu.Unlock()
}

func getProtectorKey(id *protectorKeyId) ([]byte, error) {
	if !id.Alg.Available() {
		return nil, errors.New("digest algorithm unavailable")
	}

	protectorKeysMu.RLock()
	keys := protectorKeys
	protectorKeysMu.RUnlock()

	for _, key := range keys {
		h := hmac.New(id.Alg.New, key)
		h.Write(id.Salt)
		if bytes.Equal(h.Sum(nil), id.Digest) {
			return key, nil
		}
	}
	return nil, errors.New("no key available")
}

type platformKeyDataHandler struct{}

func (*platformKeyDataHandler) RecoverKeys(data *secboot.PlatformKeyData, encryptedPayload []byte) ([]byte, error) {
	var kd keyData
	if err := json.Unmarshal(data.EncodedHandle, &kd); err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  err,
		}
	}

	aad := additionalData{
		Version:    kd.Version,
		Generation: data.Generation,
		KDFAlg:     hashAlg(data.KDFAlg),
		AuthMode:   data.AuthMode,
	}
	builder := cryptobyte.NewBuilder(nil)
	aad.MarshalASN1(builder)
	aadBytes, err := builder.Bytes()
	if err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  fmt.Errorf("cannot serialize AAD: %w", err),
		}
	}

	key, err := getProtectorKey(&kd.ProtectorKeyID)
	if err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  fmt.Errorf("cannot select protector key: %w", err),
		}
	}

	b, err := aes.NewCipher(deriveAESKey(key, kd.Salt))
	if err != nil {
		return nil, fmt.Errorf("cannot create cipher: %w", err)
	}

	aead, err := cipher.NewGCMWithNonceSize(b, len(kd.Nonce))
	if err != nil {
		return nil, fmt.Errorf("cannot create AEAD: %w", err)
	}

	payload, err := aead.Open(nil, kd.Nonce, encryptedPayload, aadBytes)
	if err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  fmt.Errorf("cannot open payload: %w", err),
		}
	}

	return payload, nil
}

func (*platformKeyDataHandler) RecoverKeysWithAuthKey(data *secboot.PlatformKeyData, encryptedPayload, key []byte) ([]byte, error) {
	return nil, errors.New("unsupported action")
}

func (*platformKeyDataHandler) ChangeAuthKey(data *secboot.PlatformKeyData, old, new []byte, context any) ([]byte, error) {
	return nil, errors.New("unsupported action")
}

func init() {
	// Add the current version of this platform to the flags.
	flags := secboot.PlatformProtectedByStorageContainer.AddPlatformFlags(1)
	secboot.RegisterPlatformKeyDataHandler(platformName, &platformKeyDataHandler{}, flags)
}
