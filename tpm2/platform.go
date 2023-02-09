// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2022 Canonical Ltd
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

package tpm2

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	_ "crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/canonical/go-tpm2"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
)

const platformName = "tpm2"

// deriveAuthValue derives the TPM authorization value from a passphrase derived key.
// XXX: I want this to live in the secboot package but there needs to be a way for
// this package to express the desired key size, so it's here for now.
func deriveAuthValue(key []byte, sz int) ([]byte, error) {
	r := hkdf.Expand(func() hash.Hash { return crypto.SHA256.New() }, key, []byte("PASSPHRASE-AUTH"))

	authValue := make([]byte, sz)
	if _, err := io.ReadFull(r, authValue); err != nil {
		return nil, xerrors.Errorf("cannot obtain auth value: %w", err)
	}

	return authValue, nil
}

type platformKeyDataHandler struct{}

func (h *platformKeyDataHandler) recoverKeysCommon(data *secboot.PlatformKeyData, authKey []byte) (secboot.KeyPayload, error) {
	tpm, err := ConnectToTPM()
	switch {
	case err == ErrNoTPM2Device:
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorUnavailable,
			Err:  err}
	case err != nil:
		return nil, xerrors.Errorf("cannot connect to TPM: %w", err)
	}
	defer tpm.Close()

	var k *SealedKeyData
	if err := json.Unmarshal(data.EncodedHandle, &k); err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  err}
	}
	if k.data.Version() < 3 {
		// All KeyData objects created for this platform are at least v3, so this
		// should never fail. Test it though to avoid a panic later on if the version
		// has been manipulated.
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  fmt.Errorf("invalid key data version: %d", k.data.Version())}
	}
	if !k.data.Public().NameAlg.IsValid() {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  fmt.Errorf("invalid name algorithm for sealed object: %d", k.data.Version())}
	}

	var authValue []byte
	if authKey != nil {
		authValue, err = deriveAuthValue(authKey, k.data.Public().NameAlg.Size())
		if err != nil {
			return nil, xerrors.Errorf("cannot derive auth value: %w", err)
		}
	}

	symKey, err := k.unsealDataFromTPM(tpm.TPMContext, authValue, tpm.HmacSession())
	if err != nil {
		var e InvalidKeyDataError
		switch {
		case xerrors.As(err, &e):
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorInvalidData,
				Err:  errors.New(e.msg)}
		case err == ErrTPMProvisioning:
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorUninitialized,
				Err:  err}
		case err == ErrTPMLockout:
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorUnavailable,
				Err:  err}
		case tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandUnseal, 1):
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorInvalidAuthKey,
				Err:  err}
		}
		return nil, xerrors.Errorf("cannot unseal key: %w", err)
	}

	if len(symKey) != 32+aes.BlockSize {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  errors.New("unsealed symmetric key has the wrong length")}
	}

	payload := make(secboot.KeyPayload, len(data.EncryptedPayload))

	b, err := aes.NewCipher(symKey[:32])
	if err != nil {
		return nil, xerrors.Errorf("cannot create new cipher: %w", err)
	}
	stream := cipher.NewCFBDecrypter(b, symKey[32:])
	stream.XORKeyStream(payload, data.EncryptedPayload)

	return payload, nil
}

func (h *platformKeyDataHandler) RecoverKeys(data *secboot.PlatformKeyData) (secboot.KeyPayload, error) {
	return h.recoverKeysCommon(data, nil)
}

func (h *platformKeyDataHandler) RecoverKeysWithAuthKey(data *secboot.PlatformKeyData, key []byte) (secboot.KeyPayload, error) {
	return h.recoverKeysCommon(data, key)
}

func (h *platformKeyDataHandler) ChangeAuthKey(handle, old, new []byte) ([]byte, error) {
	tpm, err := ConnectToTPM()
	switch {
	case err == ErrNoTPM2Device:
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorUnavailable,
			Err:  err}
	case err != nil:
		return nil, xerrors.Errorf("cannot connect to TPM: %w", err)
	}
	defer tpm.Close()

	var k *SealedKeyData
	if err := json.Unmarshal(handle, &k); err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  err}
	}
	if k.data.Version() < 3 {
		// All KeyData objects created for this platform are at least v3, so this
		// should never fail. Test it though to avoid a panic later on if the version
		// has been manipulated.
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  fmt.Errorf("invalid key data version: %d", k.data.Version())}
	}

	// Validate the initial key data
	_, err = k.validateData(tpm.TPMContext, tpm.HmacSession())
	switch {
	case isKeyDataError(err):
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  err}
	case err != nil:
		return nil, xerrors.Errorf("cannot validate key data: %w", err)
	}

	srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	switch {
	case tpm2.IsResourceUnavailableError(err, tcg.SRKHandle):
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorUninitialized,
			Err:  ErrTPMProvisioning}
	case err != nil:
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	keyObject, err := k.load(tpm.TPMContext, srk, tpm.HmacSession())
	switch {
	case isLoadInvalidParamError(err) || isImportInvalidParamError(err):
		// The supplied key data is invalid or is not protected by the supplied SRK.
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  xerrors.Errorf("cannot load sealed key object into TPM: %w", err)}
	case isLoadInvalidParentError(err) || isImportInvalidParentError(err):
		// The supplied SRK is not a valid storage parent.
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorUninitialized,
			Err:  ErrTPMProvisioning}
	case err != nil:
		// This is an unexpected error
		return nil, xerrors.Errorf("cannot load sealed key object into TPM: %w", err)
	}
	defer tpm.FlushContext(keyObject)

	if len(old) > 0 {
		v, err := deriveAuthValue(old, keyObject.Name().Algorithm().Size())
		if err != nil {
			return nil, xerrors.Errorf("cannot derive old auth value: %w", err)
		}
		keyObject.SetAuthValue(v)
	}

	var newAuthValue []byte
	if len(new) > 0 {
		newAuthValue, err = deriveAuthValue(new, keyObject.Name().Algorithm().Size())
		if err != nil {
			return nil, xerrors.Errorf("cannot derive new auth value: %w", err)
		}
	}

	priv, err := tpm.ObjectChangeAuth(keyObject, srk, newAuthValue, tpm.HmacSession().IncludeAttrs(tpm2.AttrCommandEncrypt))
	if err != nil {
		if tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandObjectChangeAuth, 1) {
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorInvalidAuthKey,
				Err:  err}
		}
		return nil, err
	}

	k.data.SetPrivate(priv)

	// Validate the modified key. There's no reason for this to fail, but do it anyway. We haven't made
	// any persistent changes yet and still have an opportunity to back out.
	if _, err = k.validateData(tpm.TPMContext, tpm.HmacSession()); err != nil {
		return nil, xerrors.Errorf("cannot validate key data after auth value change: %w", err)
	}

	newHandle, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}

	return newHandle, nil
}

func init() {
	secboot.RegisterPlatformKeyDataHandler(platformName, &platformKeyDataHandler{})
}
