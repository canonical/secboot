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

package tpm2

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luks2"
)

var (
	luks2Activate                        = luks2.Activate
	secbootActivateVolumeWithRecoveryKey = secboot.ActivateVolumeWithRecoveryKey
)

// XXX: This code is duplicated temporarily from github.com/snapcore/secboot:crypt.go
// It will go away once there is an abstract interface for handling authorization requests,
// or we figure out a way to do activation with TPM key files using the new API so that
// this one can be removed.
func askPassword(sourceDevicePath, msg string) (string, error) {
	cmd := exec.Command(
		"systemd-ask-password",
		"--icon", "drive-harddisk",
		"--id", filepath.Base(os.Args[0])+":"+sourceDevicePath,
		msg)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return "", err
	}
	result, err := out.ReadString('\n')
	if err != nil {
		return "", xerrors.Errorf("cannot read result from systemd-ask-password: %w", err)
	}
	return strings.TrimRight(result, "\n"), nil
}

func getPassword(sourceDevicePath, description string, reader io.Reader) (string, error) {
	if reader != nil {
		scanner := bufio.NewScanner(reader)
		switch {
		case scanner.Scan():
			return scanner.Text(), nil
		case scanner.Err() != nil:
			return "", xerrors.Errorf("cannot obtain %s from scanner: %w", description, scanner.Err())
		}
	}
	return askPassword(sourceDevicePath, "Please enter the "+description+" for disk "+sourceDevicePath+":")
}

func unsealKeyFromTPM(tpm *Connection, k *SealedKeyObject) ([]byte, error) {
	sealedKey, _, err := k.UnsealFromTPM(tpm)
	if err == ErrTPMProvisioning {
		// XXX: We should update this to execute on InvalidKeyFileError as well.
		// ErrTPMProvisioning in this context might indicate that there isn't a valid persistent SRK. Have a go at creating one now and then
		// retrying the unseal operation - if the previous SRK was evicted, the TPM owner hasn't changed and the storage hierarchy still
		// has a null authorization value, then this will allow us to unseal the key without requiring any type of manual recovery. If the
		// storage hierarchy has a non-null authorization value, ProvisionTPM will fail. If the TPM owner has changed, ProvisionTPM might
		// succeed, but UnsealFromTPM will fail with InvalidKeyFileError when retried.
		if pErr := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); pErr == nil || pErr == ErrTPMProvisioningRequiresLockout {
			sealedKey, _, err = k.UnsealFromTPM(tpm)
		}
	}
	return sealedKey, err
}

func unsealKeyFromTPMAndActivate(tpm *Connection, volumeName, sourceDevicePath, keyringPrefix string, k *SealedKeyObject) error {
	sealedKey, err := unsealKeyFromTPM(tpm, k)
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

func activateWithTPMKeys(tpm *Connection, volumeName, sourceDevicePath string, keyPaths []string, keyringPrefix string) (succeeded bool, errs []*activateWithTPMKeyError) {
	var contexts []*activateTPMKeyContext
	// Read key files
	for _, path := range keyPaths {
		k, err := ReadSealedKeyObject(path)
		if err != nil {
			err = xerrors.Errorf("cannot read sealed key object: %w", err)
		}
		contexts = append(contexts, &activateTPMKeyContext{path: path, k: k, err: err})
	}

	for _, c := range contexts {
		if c.err != nil {
			continue
		}

		if err := unsealKeyFromTPMAndActivate(tpm, volumeName, sourceDevicePath, keyringPrefix, c.k); err != nil {
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

// ActivateVolumeWithMultipleSealedKeys attempts to activate the LUKS encrypted volume at sourceDevicePath and create a
// mapping with the name volumeName, using the TPM sealed key objects at the specified keyPaths. This makes use of
// systemd-cryptsetup. This function will try the sealed key objects that don't require a passphrase first, and then
// try sealed key objects that do require a passphrase. Sealed key objects are otherwise tried in the order in which
// they are provided.
//
// If activation with the TPM sealed key objects fails, this function will attempt to activate it with the fallback recovery key
// instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of options specifies
// how many attempts should be made to activate the volume with the recovery key before failing. If this is set to 0, then no attempts
// will be made to activate the encrypted volume with the fallback recovery key.
//
// If the RecoveryKeyTries field of options is less than zero, an error will be returned.
//
// If activation with the TPM sealed keys fails, a *ActivateWithMultipleSealedKeysError error will be returned, even if the
// subsequent fallback recovery activation is successful. In this case, the RecoveryKeyUsageErr field of the returned error will
// be nil, and the TPMErrs field will contain the original errors for each of the TPM sealed keys. If activation with the fallback
// recovery key also fails, the RecoveryKeyUsageErr field of the returned error will also contain details of the error encountered
// during recovery key activation.
//
// If the volume is successfully activated, either with a TPM sealed key or the fallback recovery key, this function returns true.
// If it is not successfully activated, then this function returns false.
func ActivateVolumeWithMultipleSealedKeys(tpm *Connection, volumeName, sourceDevicePath string, keyPaths []string, options *secboot.ActivateVolumeOptions) (bool, error) {
	if len(keyPaths) == 0 {
		return false, errors.New("no key files provided")
	}

	if options.RecoveryKeyTries < 0 {
		return false, errors.New("invalid RecoveryKeyTries")
	}

	if success, errs := activateWithTPMKeys(tpm, volumeName, sourceDevicePath, keyPaths, options.KeyringPrefix); !success {
		var tpmErrs []error
		for _, e := range errs {
			tpmErrs = append(tpmErrs, e)
		}
		rErr := secbootActivateVolumeWithRecoveryKey(volumeName, sourceDevicePath, nil, options)
		return rErr == nil, &ActivateWithMultipleSealedKeysError{tpmErrs, rErr}
	}

	return true, nil
}

// ActivateVolumeWithSealedKey attempts to activate the LUKS encrypted volume at sourceDevicePath and create a mapping with the
// name volumeName, using the TPM sealed key object at the specified keyPath. This makes use of systemd-cryptsetup.
//
// If activation with the TPM sealed key object fails, this function will attempt to activate it with the fallback recovery key
// instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of options specifies
// how many attempts should be made to activate the volume with the recovery key before failing. If this is set to 0, then no attempts
// will be made to activate the encrypted volume with the fallback recovery key.
//
// If the RecoveryKeyTries field of options is less than zero, an error will be returned.
//
// If activation with the TPM sealed key fails, a *ActivateWithSealedKeyError error will be returned, even if the subsequent
// fallback recovery activation is successful. In this case, the RecoveryKeyUsageErr field of the returned error will be nil, and the
// TPMErr field will contain the original error. If activation with the fallback recovery key also fails, the RecoveryKeyUsageErr
// field of the returned error will also contain details of the error encountered during recovery key activation.
//
// If the volume is successfully activated, either with the TPM sealed key or the fallback recovery key, this function returns true.
// If it is not successfully activated, then this function returns false.
func ActivateVolumeWithSealedKey(tpm *Connection, volumeName, sourceDevicePath, keyPath string, options *secboot.ActivateVolumeOptions) (bool, error) {
	succeeded, err := ActivateVolumeWithMultipleSealedKeys(tpm, volumeName, sourceDevicePath, []string{keyPath}, options)
	if e1, ok := err.(*ActivateWithMultipleSealedKeysError); ok {
		if e2, ok := e1.TPMErrs[0].(*activateWithTPMKeyError); ok {
			err = &ActivateWithSealedKeyError{e2.err, e1.RecoveryKeyUsageErr}
		} else {
			err = &ActivateWithSealedKeyError{e1.TPMErrs[0], e1.RecoveryKeyUsageErr}
		}
	}
	return succeeded, err
}
