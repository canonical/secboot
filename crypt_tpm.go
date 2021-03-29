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

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

func unsealKeyFromTPM(tpm *TPMConnection, k *SealedKeyObject, pin string) ([]byte, []byte, error) {
	sealedKey, authPrivateKey, err := k.UnsealFromTPM(tpm, pin)
	if err == ErrTPMProvisioning {
		// ErrTPMProvisioning in this context might indicate that there isn't a valid persistent SRK. Have a go at creating one now and then
		// retrying the unseal operation - if the previous SRK was evicted, the TPM owner hasn't changed and the storage hierarchy still
		// has a null authorization value, then this will allow us to unseal the key without requiring any type of manual recovery. If the
		// storage hierarchy has a non-null authorization value, ProvionTPM will fail. If the TPM owner has changed, ProvisionTPM might
		// succeed, but UnsealFromTPM will fail with InvalidKeyFileError when retried.
		if pErr := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); pErr == nil || pErr == ErrTPMProvisioningRequiresLockout {
			sealedKey, authPrivateKey, err = k.UnsealFromTPM(tpm, pin)
		}
	}
	return sealedKey, authPrivateKey, err
}

func unsealKeyFromTPMAndActivate(tpm *TPMConnection, volumeName, sourceDevicePath, keyringPrefix string, activateOptions []string, k *SealedKeyObject, pin string) error {
	sealedKey, authPrivateKey, err := unsealKeyFromTPM(tpm, k, pin)
	if err != nil {
		return xerrors.Errorf("cannot unseal key: %w", err)
	}

	if err := activate(volumeName, sourceDevicePath, sealedKey, activateOptions); err != nil {
		return xerrors.Errorf("cannot activate volume: %w", err)
	}

	// Add a key to the calling user's user keyring with default 0x3f010000 permissions (these defaults are hardcoded in the kernel).
	// This permission flags define the following permissions:
	// Possessor Set Attribute / Possessor Link / Possessor Search / Possessor Write / Possessor Read / Possessor View / User View.
	// Possessor permissions only apply to a process with a searchable link to the key from one of its own keyrings - just having the
	// same UID is not sufficient. Read permission is required to read the contents of the key (view permission only permits viewing
	// of the description and other public metadata that isn't the key payload).
	//
	// Note that by default, systemd starts services with a private session keyring which does not contain a link to the user keyring.
	// Therefore these services cannot access the contents of keys in the root user's user keyring if those keys only permit
	// possessor-read.
	//
	// Ignore errors - we've activated the volume and so we shouldn't return an error at this point unless we close the volume again.
	unix.AddKey("user", fmt.Sprintf("%s:%s?type=tpm", keyringPrefixOrDefault(keyringPrefix), sourceDevicePath), authPrivateKey, userKeyring)
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

func activateWithTPMKeys(tpm *TPMConnection, volumeName, sourceDevicePath string, keyPaths []string, passphraseReader io.Reader, passphraseTries int, activateOptions []string, keyringPrefix string) (succeeded bool, errs []*activateWithTPMKeyError) {
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

		if err := unsealKeyFromTPMAndActivate(tpm, volumeName, sourceDevicePath, keyringPrefix, activateOptions, c.k, ""); err != nil {
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

		if err := unsealKeyFromTPMAndActivate(tpm, volumeName, sourceDevicePath, keyringPrefix, activateOptions, c.k, pin); err != nil {
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
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup.
//
// If activation with the TPM sealed key objects fails, this function will attempt to activate it with the fallback recovery key
// instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of options specifies
// how many attempts should be made to activate the volume with the recovery key before failing. If this is set to 0, then no attempts
// will be made to activate the encrypted volume with the fallback recovery key. If activation with the recovery key is successful,
// calling GetActivationDataFromKernel will return a *RecoveryActivationData containing the recovery key and the error codes
// associated with the supplied TPM sealed keys.
//
// If either the PassphraseTries or RecoveryKeyTries fields of options are less than zero, an error will be returned. If the ActivateOptions
// field of options contains the "tries=" option, then an error will be returned. This option cannot be used with this function.
//
// If activation with the TPM sealed keys fails, a *ActivateWithMultipleTPMSealedKeysError error will be returned, even if the
// subsequent fallback recovery activation is successful. In this case, the RecoveryKeyUsageErr field of the returned error will
// be nil, and the TPMErrs field will contain the original errors for each of the TPM sealed keys. If activation with the fallback
// recovery key also fails, the RecoveryKeyUsageErr field of the returned error will also contain details of the error encountered
// during recovery key activation.
//
// If the volume is successfully activated with a TPM sealed key and the TPM sealed key has a version of greater than 1, calling
// GetActivationDataFromKernel will return a TPMPolicyAuthKey containing the private part of the key used for authorizing PCR policy
// updates with UpdateKeyPCRProtectionPolicy.
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

	activateOptions, err := makeActivateOptions(options.ActivateOptions)
	if err != nil {
		return false, err
	}

	if success, errs := activateWithTPMKeys(tpm, volumeName, sourceDevicePath, keyPaths, passphraseReader, options.PassphraseTries, activateOptions, options.KeyringPrefix); !success {
		var tpmErrCodes []KeyErrorCode
		var tpmErrs []error

		for _, e := range errs {
			code := KeyUnexpectedError
			switch {
			case xerrors.Is(e, ErrTPMLockout):
				code = KeyErrorTPMLockout
			case xerrors.Is(e, ErrTPMProvisioning):
				code = KeyErrorTPMProvisioning
			case isInvalidKeyFileError(e):
				code = KeyErrorInvalidFile
			case xerrors.Is(e, requiresPinErr):
				code = KeyErrorPassphraseFail
			case xerrors.Is(e, ErrPINFail):
				code = KeyErrorPassphraseFail
			case isExecError(e, systemdCryptsetupPath):
				// systemd-cryptsetup only provides 2 exit codes - success or fail - so we don't know the reason it failed yet.
				// If activation with the recovery key is successful, then it's safe to assume that it failed because the key
				// unsealed from the TPM is incorrect.
				code = KeyErrorInvalidFile
			}
			tpmErrCodes = append(tpmErrCodes, code)
			tpmErrs = append(tpmErrs, e)

		}
		rErr := activateWithRecoveryKey(volumeName, sourceDevicePath, nil, options.RecoveryKeyTries, tpmErrCodes, activateOptions, options.KeyringPrefix)
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
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup.
//
// If activation with the TPM sealed key object fails, this function will attempt to activate it with the fallback recovery key
// instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of options specifies
// how many attempts should be made to activate the volume with the recovery key before failing. If this is set to 0, then no attempts
// will be made to activate the encrypted volume with the fallback recovery key. If activation with the recovery key is successful,
// calling GetActivationDataFromKernel will return a *RecoveryActivationData containing the recovery key and the error code
// associated with the TPM sealed key.
//
// If either the PassphraseTries or RecoveryKeyTries fields of options are less than zero, an error will be returned. If the
// ActivateOptions field of options contains the "tries=" option, then an error will be returned. This option cannot be used with
// this function.
//
// If activation with the TPM sealed key fails, a *ActivateWithTPMSealedKeyError error will be returned, even if the subsequent
// fallback recovery activation is successful. In this case, the RecoveryKeyUsageErr field of the returned error will be nil, and the
// TPMErr field will contain the original error. If activation with the fallback recovery key also fails, the RecoveryKeyUsageErr
// field of the returned error will also contain details of the error encountered during recovery key activation.
//
// If the volume is successfully activated with the TPM sealed key and the TPM sealed key has a version of greater than 1, calling
// GetActivationDataFromKernel will return a TPMPolicyAuthKey containing the private part of the key used for authorizing PCR policy
// updates with UpdateKeyPCRProtectionPolicy.
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
