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

// Package fido2 is a platform for recovering keys that are protected by an authenticator
// that implements the CTAP2 protocol.
package fido2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/snapcore/secboot"
)

const (
	platformName = "fido2"
)

var (
	ErrNoFIDO2ProviderRegistered = errors.New("no appropriate FIDO2 provider is registered")
)

func recoverKeys(kd *keyData, providerName string, encryptedPayload, symA []byte, authenticator *FIDO2Authenticator) ([]byte, error) {

	kdfAlg := kd.Alg

	if len(symA) < kdfAlg.Size() {
		return nil, fmt.Errorf("input symmetric key must be at least %d bytes long", kdfAlg.Size())
	}

	salt := make([]byte, kdfAlg.Size())
	r := hmac.New(kdfAlg.New, symA)
	r.Write([]byte("ubuntu-fde-fido2"))
	salt = r.Sum(nil)

	hmacSecret, err := authenticator.GetHmacSecret(kd.CredentialID, salt)
	if err != nil {
		return nil, fmt.Errorf("cannot get hmac-secret from FIDO2 token: %w", err)
	}

	if len(hmacSecret) < kdfAlg.Size() {
		return nil, fmt.Errorf("hmac-secret must be at least %d bytes long", kdfAlg.Size())
	}

	symB := make([]byte, kdfAlg.Size())
	r = hmac.New(kdfAlg.New, symA)
	r.Write(hmacSecret)
	symB = r.Sum(nil)

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
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  fmt.Errorf("cannot serialize AAD: %w", err),
		}
	}

	b, err := aes.NewCipher(symB)
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

func RecoverKeys(data *secboot.PlatformKeyData, encryptedPayload, sym []byte, authenticator *FIDO2Authenticator) ([]byte, error) {
	var kd keyData
	if err := json.Unmarshal(data.EncodedHandle, &kd); err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  err,
		}
	}

	return recoverKeys(&kd, "", encryptedPayload, sym, authenticator)
}

type providerKeyData struct {
	Version  int                      `json:"version"`
	Provider *secboot.PlatformKeyData `json:"provider"`
	Fido2    *keyData                 `json:"fido2"`
}

var RecoverKeysWithFIDOProvider = func(providerName string, data *secboot.PlatformKeyData, encryptedPayload []byte, authenticator *FIDO2Authenticator) ([]byte, error) {
	handler, _, err := secboot.RegisteredPlatformKeyDataHandler(providerName)
	if err != nil {
		return nil, err
	}

	// TODO consistency check that the flags indicate that the platform can be used as a fido2 hmac-secret salt provider
	provider, ok := handler.(secboot.FIDO2Provider)
	if !ok {
		return nil, fmt.Errorf("%s handler %T does not implement FIDO2Provider", providerName, handler)
	}

	var kd providerKeyData
	if err := json.Unmarshal(data.EncodedHandle, &kd); err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  err,
		}
	}

	symA, err := provider.GetSymmetricKey(kd.Provider, nil)
	if err != nil {
		return nil, err
	}

	payload, err := recoverKeys(kd.Fido2, providerName, encryptedPayload, symA, authenticator)
	if err != nil {
		return nil, err
	}

	return payload, nil

}

func init() {
	// NOTE: the fido2 platform doesn't register itself as a standalone platform.
	// For now it is only used through the tpm2+fido2 platform.
}
