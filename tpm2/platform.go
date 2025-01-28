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
	_ "crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
)

const platformName = "tpm2"

type platformKeyDataHandler struct{}

func (h *platformKeyDataHandler) recoverKeysCommon(data *secboot.PlatformKeyData, encryptedPayload, authKey []byte) ([]byte, error) {
	if data.Generation < 0 || int64(data.Generation) > math.MaxUint32 {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  fmt.Errorf("invalid key data generation: %d", data.Generation)}
	}

	kdfAlg, err := hashAlgorithmIdFromCryptoHash(data.KDFAlg)
	if err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  errors.New("invalid KDF algorithm")}
	}

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

	tpm, err := ConnectToDefaultTPM()
	switch {
	case err == ErrNoTPM2Device:
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorUnavailable,
			Err:  err}
	case err != nil:
		return nil, fmt.Errorf("cannot connect to TPM: %w", err)
	}
	defer tpm.Close()

	symKey, err := k.unsealDataFromTPM(tpm.TPMContext, authKey, tpm.HmacSession())
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

	payload, err := k.data.Decrypt(symKey, encryptedPayload, uint32(data.Generation), []byte(data.Role), kdfAlg, data.AuthMode)
	if err != nil {
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  xerrors.Errorf("cannot recover encrypted payload: %w", err)}
	}

	return payload, nil
}

func (h *platformKeyDataHandler) RecoverKeys(data *secboot.PlatformKeyData, encryptedPayload []byte) ([]byte, error) {
	return h.recoverKeysCommon(data, encryptedPayload, nil)
}

func (h *platformKeyDataHandler) RecoverKeysWithAuthKey(data *secboot.PlatformKeyData, encryptedPayload, key []byte) ([]byte, error) {
	return h.recoverKeysCommon(data, encryptedPayload, key)
}

func (h *platformKeyDataHandler) ChangeAuthKey(data *secboot.PlatformKeyData, old, new []byte, context any) ([]byte, error) {
	var tpm *Connection
	switch c := context.(type) {
	case *Connection:
		tpm = c
	}

	if tpm == nil {
		var err error
		tpm, err = ConnectToDefaultTPM()
		switch {
		case err == ErrNoTPM2Device:
			return nil, &secboot.PlatformHandlerError{
				Type: secboot.PlatformHandlerErrorUnavailable,
				Err:  err}
		case err != nil:
			return nil, fmt.Errorf("cannot connect to TPM: %w", err)
		}
		defer tpm.Close()
	}

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

	// Validate the initial key data
	_, err := k.validateData(tpm.TPMContext, data.Role)
	switch {
	case isKeyDataError(err):
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorInvalidData,
			Err:  err}
	case err != nil:
		return nil, xerrors.Errorf("cannot validate key data: %w", err)
	}

	srk, err := tpm.NewResourceContext(tcg.SRKHandle)
	switch {
	case tpm2.IsResourceUnavailableError(err, tcg.SRKHandle):
		return nil, &secboot.PlatformHandlerError{
			Type: secboot.PlatformHandlerErrorUninitialized,
			Err:  ErrTPMProvisioning}
	case err != nil:
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	keyObject, err := k.load(tpm.TPMContext, srk)
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

	// Begin session for parameter encryption, salted with the SRK.
	symmetric := &tpm2.SymDef{
		Algorithm: tpm2.SymAlgorithmAES,
		KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
		Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB},
	}
	session, err := tpm.StartAuthSession(srk, nil, tpm2.SessionTypeHMAC, symmetric, k.data.Public().NameAlg, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot create session: %w", err)
	}
	defer tpm.FlushContext(session)

	keyObject.SetAuthValue(old)

	// Use a HMAC session for authentication. This avoids sending the old value in the clear.
	// It also encrypts the new value, although this only provides protection against passive
	// interposers as we don't verify the key that is used to salt the session is actually a
	// TPM protected key.
	priv, err := tpm.ObjectChangeAuth(keyObject, srk, new, tpm.HmacSession().IncludeAttrs(tpm2.AttrCommandEncrypt))
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
	if _, err = k.validateData(tpm.TPMContext, data.Role); err != nil {
		return nil, xerrors.Errorf("cannot validate key data after auth value change: %w", err)
	}

	newHandle, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}

	return newHandle, nil
}

func init() {
	secboot.RegisterPlatformKeyDataHandler(platformName, new(platformKeyDataHandler))
}
