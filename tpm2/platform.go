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
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
)

const platformName = "tpm2"

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

	symKey, err := k.unsealDataFromTPM(tpm.TPMContext, tpm.HmacSession())
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
	return nil, fmt.Errorf("passphrase authentication is not supported for the %s platform", platformName)
}

func (h *platformKeyDataHandler) ChangeAuthKey(handle, old, new []byte) ([]byte, error) {
	return nil, fmt.Errorf("passphrase authentication is not supported for the %s platform", platformName)
}

func init() {
	secboot.RegisterPlatformKeyDataHandler(platformName, &platformKeyDataHandler{})
}
