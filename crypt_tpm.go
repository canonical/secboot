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

	"golang.org/x/xerrors"
)

// TPMKeyUnsealer is used to recover the key from the TPM sealed key
// object at the specified keyPath passed to NewTPMKeyUnsealer.
type TPMKeyUnsealer struct {
	tpm     *TPMConnection
	keyPath string
}

func NewTPMKeyUnsealer(tpm *TPMConnection, keyPath string) *TPMKeyUnsealer {
	return &TPMKeyUnsealer{
		tpm:     tpm,
		keyPath: keyPath,
	}
}

// UnsealKey attempts to recover the key in TPM sealed key object at
// the path specified when creating the TPMKeyUnsealer, for use to
// activate the specified volume.
//
// If the TPM sealed key object has a user passphrase/PIN defined,
// then the function will use the given Prompter to request it. The
// PassphraseTries field of options defines how many attempts should
// be made to obtain the correct passphrase before failing.
//
// If the LockSealedKeys field of options is true, then this function
// will call LockAccessToSealedKeys after unsealing the key.
//
// If the LockSealedKeys field of options is true and the call to
// LockAccessToSealedKeys fails, a LockAccessToSealedKeysError error
// will be returned. In this case, the caller should not attempt
// activation with either the TPM sealed key or the fallback recovery
// key.
//
// If other errors are returned the caller can attempt to use the fallback
// recovery key. (XXX this decision is mediated via UnderstoodError ATM).
//
// If key recovery is successful from the TPM sealed key and the TPM
// sealed key has a version of greater than 1, the caller can store
// (via the kernel keyring) activationData - containing the private
// part of the key used for authorizing PCR policy updates - such that
// calling GetActivationDataFromKernel will return it as
// TPMPolicyAuthKey for use with UpdateKeyPCRProtectionPolicy.
func (u *TPMKeyUnsealer) UnsealKey(volumeName, sourceDevicePath string, p Prompter, options *ActivateVolumeOptions) (key, resealAuthKey []byte, err error) {
	var lockErr error
	tpm := u.tpm
	sealedKey, authPrivateKey, err := func() ([]byte, TPMPolicyAuthKey, error) {
		defer func() {
			if !options.LockSealedKeys {
				return
			}
			lockErr = LockAccessToSealedKeys(tpm)
		}()

		k, err := ReadSealedKeyObject(u.keyPath)
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot read sealed key object: %w", err)
		}

		pinTries := options.PassphraseTries
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
				pin, err = p.PromptForPassphrase(volumeName, sourceDevicePath, "PIN")
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

// XXX factor this away
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
		// systemd-cryptsetup only provides 2 exit codes -
		// success or fail - so we don't know the reason it
		// failed yet. If activation with the recovery key is
		// successful, then it's safe to assume that it failed
		// because the key unsealed from the TPM is incorrect.
		return true, RecoveryKeyUsageReasonInvalidKeyFile, nil
	}
	return false, 0, nil
}

// ActivationDataType returns the type ("tpm") under which
// activationData from UnsealKey should be store in the kernel
// keyring.
func (*TPMKeyUnsealer) ActivationDataType() string {
	return "tpm"
}

func unsealKeyFromTPM(tpm *TPMConnection, k *SealedKeyObject, pin string) ([]byte, []byte, error) {
	sealedKey, authPrivateKey, err := k.UnsealFromTPM(tpm, pin)
	if err == ErrTPMProvisioning {
		// ErrTPMProvisioning in this context might indicate
		// that there isn't a valid persistent SRK. Have a go
		// at creating one now and then retrying the unseal
		// operation - if the previous SRK was evicted, the
		// TPM owner hasn't changed and the storage hierarchy
		// still has a null authorization value, then this
		// will allow us to unseal the key without requiring
		// any type of manual recovery. If the storage
		// hierarchy has a non-null authorization value,
		// ProvionTPM will fail. If the TPM owner has changed,
		// ProvisionTPM might succeed, but UnsealFromTPM will
		// fail with InvalidKeyFileError when retried.
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
