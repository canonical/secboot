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
	"fmt"
	"io"

	"golang.org/x/xerrors"
)

func unsealKeyFromTPM(tpm *TPMConnection, k *SealedKeyObject, pin string) ([]byte, error) {
	sealedKey, _, err := k.UnsealFromTPM(tpm, pin)
	if err == ErrTPMProvisioning {
		// XXX: We should update this to execute on InvalidKeyFileError as well.
		// ErrTPMProvisioning in this context might indicate that there isn't a valid persistent SRK. Have a go at creating one now and then
		// retrying the unseal operation - if the previous SRK was evicted, the TPM owner hasn't changed and the storage hierarchy still
		// has a null authorization value, then this will allow us to unseal the key without requiring any type of manual recovery. If the
		// storage hierarchy has a non-null authorization value, ProvisionTPM will fail. If the TPM owner has changed, ProvisionTPM might
		// succeed, but UnsealFromTPM will fail with InvalidKeyFileError when retried.
		if pErr := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); pErr == nil || pErr == ErrTPMProvisioningRequiresLockout {
			sealedKey, _, err = k.UnsealFromTPM(tpm, pin)
		}
	}
	return sealedKey, err
}

func unsealKeyFromTPMAndActivate(tpm *TPMConnection, volumeName, sourceDevicePath, keyringPrefix string, k *SealedKeyObject, pin string) error {
	sealedKey, err := unsealKeyFromTPM(tpm, k, pin)
	if err != nil {
		return xerrors.Errorf("cannot unseal key: %w", err)
	}

	if err := luks2Activate(volumeName, sourceDevicePath, sealedKey); err != nil {
		return xerrors.Errorf("cannot activate volume: %w", err)
	}

	return nil
}

var requiresPinErr = errors.New("no PIN tries permitted when a PIN is required")

type activateWithTPMKeyError struct {
	path string
	err  error
}

func (e *activateWithTPMKeyError) Error() string {
	return fmt.Sprintf("%s: %v", e.path, e.err)
}

func (e *activateWithTPMKeyError) Unwrap() error {
	return e.err
}

type activateTPMKeyContext struct {
	path string
	k    *SealedKeyObject
	err  error
}

func (c *activateTPMKeyContext) Err() *activateWithTPMKeyError {
	if c.err == nil {
		return nil
	}
	return &activateWithTPMKeyError{path: c.path, err: c.err}
}

func activateWithTPMKeys(tpm *TPMConnection, volumeName, sourceDevicePath string, keyPaths []string, passphraseReader io.Reader, passphraseTries int, keyringPrefix string) (succeeded bool, errs []*activateWithTPMKeyError) {
	var contexts []*activateTPMKeyContext
	// Read key files
	for _, path := range keyPaths {
		k, err := ReadSealedKeyObject(path)
		if err != nil {
			err = xerrors.Errorf("cannot read sealed key object: %w", err)
		}
		contexts = append(contexts, &activateTPMKeyContext{path: path, k: k, err: err})
	}

	// Try key files that don't require a passphrase first.
	for _, c := range contexts {
		if c.err != nil {
			continue
		}
		if c.k.AuthMode2F() != AuthModeNone {
			continue
		}

		if err := unsealKeyFromTPMAndActivate(tpm, volumeName, sourceDevicePath, keyringPrefix, c.k, ""); err != nil {
			c.err = err
			continue
		}

		return true, nil
	}

	// Try key files that do require a passhprase last.
	for _, c := range contexts {
		if c.err != nil {
			continue
		}
		if c.k.AuthMode2F() != AuthModePassphrase {
			continue
		}
		if passphraseTries == 0 {
			c.err = requiresPinErr
			continue
		}

		var pin string
		for i := 0; i < passphraseTries; i++ {
			r := passphraseReader
			passphraseReader = nil
			var err error
			pin, err = getPassword(sourceDevicePath, "PIN", r)
			if err != nil {
				c.err = xerrors.Errorf("cannot obtain PIN: %w", err)
				break
			}
		}

		if c.err != nil {
			continue
		}

		if err := unsealKeyFromTPMAndActivate(tpm, volumeName, sourceDevicePath, keyringPrefix, c.k, pin); err != nil {
			c.err = err
			continue
		}

		return true, nil
	}

	// Activation has failed if we reach this point.
	for _, c := range contexts {
		errs = append(errs, c.Err())
	}
	return false, errs

}

// ActivateVolumeWithMultipleTPMSealedKeys attempts to activate the LUKS encrypted volume at sourceDevicePath and create a
// mapping with the name volumeName, using the TPM sealed key objects at the specified keyPaths. This makes use of
// systemd-cryptsetup. This function will try the sealed key objects that don't require a passphrase first, and then
// try sealed key objects that do require a passphrase. Sealed key objects are otherwise tried in the order in which
// they are provided.
//
// If this function tries a TPM sealed key object that has a user passphrase/PIN defined, then this function will use
// systemd-ask-password to request it. If passphraseReader is not nil, then an attempt to read the user passphrase/PIN from this
// will be made instead by reading all characters until the first newline. The PassphraseTries field of options defines how many
// attempts should be made to obtain the correct passphrase for each TPM sealed key before failing.
//
// If activation with the TPM sealed key objects fails, this function will attempt to activate it with the fallback recovery key
// instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of options specifies
// how many attempts should be made to activate the volume with the recovery key before failing. If this is set to 0, then no attempts
// will be made to activate the encrypted volume with the fallback recovery key.
//
// If either the PassphraseTries or RecoveryKeyTries fields of options are less than zero, an error will be returned.
//
// If activation with the TPM sealed keys fails, a *ActivateWithMultipleTPMSealedKeysError error will be returned, even if the
// subsequent fallback recovery activation is successful. In this case, the RecoveryKeyUsageErr field of the returned error will
// be nil, and the TPMErrs field will contain the original errors for each of the TPM sealed keys. If activation with the fallback
// recovery key also fails, the RecoveryKeyUsageErr field of the returned error will also contain details of the error encountered
// during recovery key activation.
//
// If the volume is successfully activated, either with a TPM sealed key or the fallback recovery key, this function returns true.
// If it is not successfully activated, then this function returns false.
func ActivateVolumeWithMultipleTPMSealedKeys(tpm *TPMConnection, volumeName, sourceDevicePath string, keyPaths []string, passphraseReader io.Reader, options *ActivateVolumeOptions) (bool, error) {
	if len(keyPaths) == 0 {
		return false, errors.New("no key files provided")
	}

	if options.PassphraseTries < 0 {
		return false, errors.New("invalid PassphraseTries")
	}
	if options.RecoveryKeyTries < 0 {
		return false, errors.New("invalid RecoveryKeyTries")
	}

	if success, errs := activateWithTPMKeys(tpm, volumeName, sourceDevicePath, keyPaths, passphraseReader, options.PassphraseTries, options.KeyringPrefix); !success {
		var tpmErrs []error
		for _, e := range errs {
			tpmErrs = append(tpmErrs, e)
		}
		rErr := activateWithRecoveryKey(volumeName, sourceDevicePath, nil, options.RecoveryKeyTries, options.KeyringPrefix)
		return rErr == nil, &ActivateWithMultipleTPMSealedKeysError{tpmErrs, rErr}
	}

	return true, nil
}

// ActivateVolumeWithTPMSealedKey attempts to activate the LUKS encrypted volume at sourceDevicePath and create a mapping with the
// name volumeName, using the TPM sealed key object at the specified keyPath. This makes use of systemd-cryptsetup.
//
// If the TPM sealed key object has a user passphrase/PIN defined, then this function will use systemd-ask-password to request
// it. If passphraseReader is not nil, then an attempt to read the user passphrase/PIN from this will be made instead by reading
// all characters until the first newline. The PassphraseTries field of options defines how many attempts should be made to
// obtain the correct passphrase before failing.
//
// If activation with the TPM sealed key object fails, this function will attempt to activate it with the fallback recovery key
// instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of options specifies
// how many attempts should be made to activate the volume with the recovery key before failing. If this is set to 0, then no attempts
// will be made to activate the encrypted volume with the fallback recovery key.
//
// If either the PassphraseTries or RecoveryKeyTries fields of options are less than zero, an error will be returned.
//
// If activation with the TPM sealed key fails, a *ActivateWithTPMSealedKeyError error will be returned, even if the subsequent
// fallback recovery activation is successful. In this case, the RecoveryKeyUsageErr field of the returned error will be nil, and the
// TPMErr field will contain the original error. If activation with the fallback recovery key also fails, the RecoveryKeyUsageErr
// field of the returned error will also contain details of the error encountered during recovery key activation.
//
// If the volume is successfully activated, either with the TPM sealed key or the fallback recovery key, this function returns true.
// If it is not successfully activated, then this function returns false.
func ActivateVolumeWithTPMSealedKey(tpm *TPMConnection, volumeName, sourceDevicePath, keyPath string, passphraseReader io.Reader, options *ActivateVolumeOptions) (bool, error) {
	succeeded, err := ActivateVolumeWithMultipleTPMSealedKeys(tpm, volumeName, sourceDevicePath, []string{keyPath}, passphraseReader, options)
	if e1, ok := err.(*ActivateWithMultipleTPMSealedKeysError); ok {
		if e2, ok := e1.TPMErrs[0].(*activateWithTPMKeyError); ok {
			err = &ActivateWithTPMSealedKeyError{e2.err, e1.RecoveryKeyUsageErr}
		} else {
			err = &ActivateWithTPMSealedKeyError{e1.TPMErrs[0], e1.RecoveryKeyUsageErr}
		}
	}
	return succeeded, err
}
