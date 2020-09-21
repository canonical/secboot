// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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
	"io"

	"golang.org/x/xerrors"
)

type TPMKeyUnsealer struct {
	tpm       *TPMConnection
	keyPath   string
	pinReader io.Reader
	pinTries  int
	lock      bool
}

func NewTPMKeyUnsealer(tpm *TPMConnection, keyPath string, pinReader io.Reader, pinTries int, lock bool) (*TPMKeyUnsealer, error) {
	if pinTries < 0 {
		return nil, errors.New("invalid PassphraseTries")
	}

	return &TPMKeyUnsealer{
		tpm:       tpm,
		keyPath:   keyPath,
		pinReader: pinReader,
		pinTries:  pinTries,
		lock:      lock,
	}, nil
}

func (u *TPMKeyUnsealer) UnsealKey(volumeName, sourceDevicePath string, p Prompter) (key, resealAuthKey []byte, err error) {
	var lockErr error
	tpm := u.tpm
	sealedKey, authPrivateKey, err := func() ([]byte, TPMPolicyAuthKey, error) {
		defer func() {
			if !u.lock {
				return
			}
			lockErr = LockAccessToSealedKeys(tpm)
		}()

		k, err := ReadSealedKeyObject(u.keyPath)
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot read sealed key object: %w", err)
		}

		pinTries := u.pinTries
		switch {
		case pinTries == 0 && k.AuthMode2F() == AuthModePIN:
			return nil, nil, requiresPinErr
		case pinTries == 0:
			pinTries = 1
		}

		var sealedKey []byte
		var authPrivateKey []byte

		for ; pinTries > 0; pinTries-- {
			var pin string
			if k.AuthMode2F() == AuthModePIN {
				pin, err = p.PromptFor2FA(sourceDevicePath, "PIN")
				if err != nil {
					return nil, nil, xerrors.Errorf("cannot obtain PIN: %w", err)
				}
			}

			sealedKey, authPrivateKey, err = unsealKeyFromTPM(tpm, k, pin)
			if err != nil && (err != ErrPINFail || k.AuthMode2F() != AuthModePIN) {
				break
			}
		}

		if err != nil {
			return nil, nil, xerrors.Errorf("cannot unseal key: %w", err)
		}
		return sealedKey, authPrivateKey, nil
	}()

	switch {
	case lockErr != nil:
		return nil, nil, lockAccessError{err}
	case err != nil:
		return nil, nil, err
	}

	return sealedKey, authPrivateKey, nil
}

func (*TPMKeyUnsealer) UnderstoodError(e error, isCryptsetupError bool) (bool, RecoveryKeyUsageReason, error) {
	switch {
	case isLockAccessError(e):
		return false, 0, LockAccessToSealedKeysError(e.Error())
	case xerrors.Is(e, ErrTPMLockout):
		return true, RecoveryKeyUsageReasonTPMLockout, nil
	case xerrors.Is(e, ErrTPMProvisioning):
		return true, RecoveryKeyUsageReasonTPMProvisioningError, nil
	case isInvalidKeyFileError(e):
		return true, RecoveryKeyUsageReasonInvalidKeyFile, nil
	case xerrors.Is(e, requiresPinErr):
		return true, RecoveryKeyUsageReasonPassphraseFail, nil
	case xerrors.Is(e, ErrPINFail):
		return true, RecoveryKeyUsageReasonPassphraseFail, nil
	case isCryptsetupError:
		// systemd-cryptsetup only provides 2 exit codes - success or fail - so we don't know the reason it failed yet. If activation
		// with the recovery key is successful, then it's safe to assume that it failed because the key unsealed from the TPM is incorrect.
		return true, RecoveryKeyUsageReasonInvalidKeyFile, nil
	}
	return false, 0, nil
}

func unsealKeyFromTPM(tpm *TPMConnection, k *SealedKeyObject, pin string) ([]byte, []byte, error) {
	sealedKey, authPrivateKey, err := k.UnsealFromTPM(tpm, pin)
	if err == ErrTPMProvisioning {
		// ErrTPMProvisioning in this context might indicate that there isn't a valid persistent SRK. Have a go at creating one now and then
		// retrying the unseal operation - if the previous SRK was evicted, the TPM owner hasn't changed and the storage hierarchy still
		// has a null authorization value, then this will allow us to unseal the key without requiring any type of manual recovery. If the
		// storage hierarchy has a non-null authorization value, ProvionTPM will fail. If the TPM owner has changed, ProvisionTPM might
		// succeed, but UnsealFromTPM will fail with InvalidKeyFileError when retried.
		if pErr := ProvisionTPM(tpm, ProvisionModeWithoutLockout, nil); pErr == nil {
			sealedKey, authPrivateKey, err = k.UnsealFromTPM(tpm, pin)
		}
	}
	return sealedKey, authPrivateKey, err
}

var requiresPinErr = errors.New("no PIN tries permitted when a PIN is required")

type lockAccessError struct {
	err error
}

func (e lockAccessError) Error() string {
	return e.err.Error()
}

func (e lockAccessError) Unwrap() error {
	return e.err
}

func isLockAccessError(err error) bool {
	var e lockAccessError
	return xerrors.As(err, &e)
}
