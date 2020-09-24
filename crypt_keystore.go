// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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
	"errors"

	"golang.org/x/xerrors"
)

// ErrUnsupportedKeyHandle is returned from a KeyStore that doesn't handle the supplied KeyHandle type.
var ErrUnsupportedKeyHandle = errors.New("the supplied key handle is not supported by the key store")

// KeyRecoverErrorCode describes an error returned from KeyStore.Recover.
type KeyRecoverErrorCode int

const (
	// KeyRecoverUnexpectedError indicates an error that was unexpected and doesn't have a more appropriate error code.
	KeyRecoverUnexpectedError KeyRecoverErrorCode = iota + 1

	// KeyRecoverKeyStoreTemporarilyUnavailableError indicates that the keystore backend is temporarily unable to recover
	// a key. In the case of a TPM, this could be because the TPM's dictionary attack protection has been triggered.
	KeyRecoverKeyStoreTemporarilyUnavailableError

	// KeyRecoverKeyStoreResourcesUnavailableError indicates that a key store doesn't contain the resources required to
	// recover a key. In the case of a TPM, this could be because the TPM is not correctly provisioned.
	KeyRecoverKeyStoreResourcesUnavailableError

	// KeyRecoverInvalidKeyDataError indicates that a key store couldn't recover a key because the data provided with the
	// key handle was invalid.
	KeyRecoverInvalidKeyDataError

	// KeyRecoverPINFailError indicates that a key store couldn't recover a key because the supplied PIN was incorrect.
	KeyRecoverPINFailError
)

// KeyRecoverError is returned from KeyRecoverContext implementations to indicate the reason that a key could not be recovered.
type KeyRecoverError struct {
	Code KeyRecoverErrorCode
	err  error
}

// WrapKeyRecoverError wraps the supplied error with a KeyRecoverError with the supplied error code. The err argument can be nil
// if there is no need to provide any additional context.
func WrapKeyRecoverError(code KeyRecoverErrorCode, err error) error {
	return &KeyRecoverError{Code: code, err: err}
}

func (e *KeyRecoverError) Error() string {
	var prefix string
	switch e.Code {
	case KeyRecoverUnexpectedError:
		prefix = "unexpected error"
	case KeyRecoverKeyStoreTemporarilyUnavailableError:
		prefix = "the keystore is temporarily unavailable for recovering keys"
	case KeyRecoverKeyStoreResourcesUnavailableError:
		prefix = "the keystore is not correctly provisioned"
	case KeyRecoverInvalidKeyDataError:
		prefix = "the key data is invalid"
	case KeyRecoverPINFailError:
		prefix = "the supplied PIN is incorrect"
	}

	if e.err == nil {
		return prefix
	}

	return prefix + ": " + e.err.Error()
}

func (e *KeyRecoverError) Unwrap() error {
	return e.err
}

func isKeyRecoverError(err error, code KeyRecoverErrorCode) bool {
	var e *KeyRecoverError
	return xerrors.As(err, &e) && e.Code == code
}

// KeyHandle corresponds to a key that can be recovered by a corresponding KeyStore.
type KeyHandle interface {
	PINRequired() bool // Indicates whether a PIN is required to recover this key.

	// DidUseForDevice indicates that this key was used to activate a volume with the specified device path.
	// Implementations can use this to add data to the kernel keyring if required.
	DidUseForDevice(devicePath string)
}

// KeyStore corresponds to a device from which keys can be recovered.
type KeyStore interface {
	// Recover will attempt to recover the supplied key using the supplied PIN and one.
	RecoverKey(handle KeyHandle, pin string) ([]byte, error)

	// Lock will prevent any more keys from being recovered from this keystore, on stores that support this.
	Lock() error
}

type KeyStores []KeyStore

type tpmKeyHandle struct {
	k *SealedKeyObject
	// TODO: Add a field for the policy authorization key
}

func (c *tpmKeyHandle) PINRequired() bool {
	return c.k.AuthMode2F() == AuthModePIN
}

func (c *tpmKeyHandle) DidUseForDevice(devicePath string) {
	// TODO: Add the auth private key to the keyring in a format that can be decoded by GetActivationDataFromKernel later on
}

type tpmKeyStore struct {
	tpm *TPMConnection
}

func NewTPMKeyStore(tpm *TPMConnection) KeyStore {
	return &tpmKeyStore{tpm}
}

func (s *tpmKeyStore) RecoverKey(handle KeyHandle, pin string) ([]byte, error) {
	h, ok := handle.(*tpmKeyHandle)
	if !ok {
		return nil, ErrUnsupportedKeyHandle
	}

	key, err := h.k.UnsealFromTPM(s.tpm, pin)
	if err == ErrTPMProvisioning {
		// ErrTPMProvisioning in this context might indicate that there isn't a valid persistent SRK. Have a go at creating one now and then
		// retrying the unseal operation - if the previous SRK was evicted, the TPM owner hasn't changed and the storage hierarchy still
		// has a null authorization value, then this will allow us to unseal the key without requiring any type of manual recovery. If the
		// storage hierarchy has a non-null authorization value, ProvionTPM will fail. If the TPM owner has changed, ProvisionTPM might
		// succeed, but UnsealFromTPM will fail with InvalidKeyFileError when retried.
		if pErr := ProvisionTPM(s.tpm, ProvisionModeWithoutLockout, nil); pErr == nil {
			key, err = h.k.UnsealFromTPM(s.tpm, pin)
		}
	}

	switch {
	case xerrors.Is(err, ErrTPMLockout):
		return nil, WrapKeyRecoverError(KeyRecoverKeyStoreTemporarilyUnavailableError, nil)
	case xerrors.Is(err, ErrTPMProvisioning):
		return nil, WrapKeyRecoverError(KeyRecoverKeyStoreResourcesUnavailableError, nil)
	case isInvalidKeyFileError(err):
		return nil, WrapKeyRecoverError(KeyRecoverInvalidKeyDataError, err)
	case xerrors.Is(err, ErrPINFail):
		return nil, WrapKeyRecoverError(KeyRecoverPINFailError, nil)
	case err != nil:
		return nil, WrapKeyRecoverError(KeyRecoverUnexpectedError, err)
	}

	return key, nil
}

func (s *tpmKeyStore) Lock() error {
	return LockAccessToSealedKeys(s.tpm)
}
