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
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const userKeyring = -4

var (
	runDir                = "/run"
	systemdCryptsetupPath = "/lib/systemd/systemd-cryptsetup"
)

type execError struct {
	path string
	err  error
}

func (e *execError) Error() string {
	return fmt.Sprintf("%s failed: %s", e.path, e.err)
}

func (e *execError) Unwrap() error {
	return e.err
}

func wrapExecError(cmd *exec.Cmd, err error) error {
	if err == nil {
		return nil
	}
	return &execError{path: cmd.Path, err: err}
}

func isExecError(err error, path string) bool {
	var e *execError
	return xerrors.As(err, &e) && e.path == path
}

func activate(volumeName, sourceDevicePath string, key []byte, options []string) error {
	keyFilePath, err := func() (string, error) {
		f, err := ioutil.TempFile(runDir, filepath.Base(os.Args[0])+".")
		if err != nil {
			return "", xerrors.Errorf("cannot create temporary file: %w", err)
		}
		defer f.Close()
		if err := f.Chmod(0600); err != nil {
			return "", err
		}
		if _, err := f.Write(key); err != nil {
			return "", xerrors.Errorf("cannot write key to file: %w", err)
		}
		return f.Name(), nil
	}()
	if err != nil {
		return xerrors.Errorf("cannot temporarily save key for systemd-cryptsetup: %w", err)
	}
	defer os.Remove(keyFilePath)

	cmd := exec.Command(systemdCryptsetupPath, "attach", volumeName, sourceDevicePath, keyFilePath, strings.Join(options, ","))
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "SYSTEMD_LOG_TARGET=console")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return xerrors.Errorf("cannot create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return xerrors.Errorf("cannot create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan bool, 2)
	go func() {
		rd := bufio.NewScanner(stdout)
		for rd.Scan() {
			fmt.Printf("systemd-cryptsetup: %s\n", rd.Text())
		}
		done <- true
	}()
	go func() {
		rd := bufio.NewScanner(stderr)
		for rd.Scan() {
			fmt.Fprintf(os.Stderr, "systemd-cryptsetup: %s\n", rd.Text())
		}
		done <- true
	}()
	for i := 0; i < 2; i++ {
		<-done
	}

	return wrapExecError(cmd, cmd.Wait())
}

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
		return "", wrapExecError(cmd, err)
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

func decodeRecoveryKey(passphrase string) ([]byte, error) {
	// The recovery key should be provided as 8 groups of 5 base-10 digits, with each 5 digits being converted to a 2-byte number to
	// make a 16-byte key.
	var key bytes.Buffer
	for len(passphrase) > 0 {
		if len(passphrase) < 5 {
			return nil, errors.New("incorrectly formatted (insufficient characters)")
		}
		x, err := strconv.ParseUint(passphrase[0:5], 10, 16)
		if err != nil {
			return nil, errors.New("incorrectly formatted (invalid base-10 number)")
		}
		binary.Write(&key, binary.LittleEndian, uint16(x))

		// Move to the next 5 digits
		passphrase = passphrase[5:]
		// Permit each set of 5 digits to be separated by '-', but don't allow the recovery key to end or begin with one.
		if len(passphrase) > 1 && passphrase[0] == '-' {
			passphrase = passphrase[1:]
		}
	}
	return key.Bytes(), nil
}

// RecoveryKeyUsageReason indicates the reason that a volume had to be activated with the fallback recovery key instead of the TPM
// sealed key.
type RecoveryKeyUsageReason uint8

const (
	// RecoveryKeyUsageReasonUnexpectedError indicates that a volume had to be activated with the fallback recovery key because an
	// unexpected error was encountered during activation with the TPM sealed key.
	RecoveryKeyUsageReasonUnexpectedError RecoveryKeyUsageReason = iota + 1

	// RecoveryKeyUsageReasonRequested indicates that a volume was activated with the fallback recovery key via the
	// ActivateVolumeWithRecoveryKey API.
	RecoveryKeyUsageReasonRequested

	// RecoveryKeyUsageReasonTPMLockout indicates that a volume had to be activated with the fallback recovery key because the TPM is in
	// dictionary attack lockout mode.
	RecoveryKeyUsageReasonTPMLockout

	// RecoveryKeyUsageReasonTPMProvisioningError indicates that a volume had to be activated with the fallback recovery key because the
	// TPM is not correctly provisioned.
	RecoveryKeyUsageReasonTPMProvisioningError

	// RecoveryKeyUsageReasonInvalidKeyFile indicates that a volume had to be activated with the fallback recovery key because the TPM
	// sealed key file is invalid. Note that attempts to resolve this by creating a new file with SealKeyToTPM may indicate that the TPM
	// is also not correctly provisioned.
	RecoveryKeyUsageReasonInvalidKeyFile

	// RecoveryKeyUsageReasonPINFail indicates that a volume had to be activated with the fallback recovery key because the correct PIN
	// was not provided.
	RecoveryKeyUsageReasonPINFail
)

func activateWithRecoveryKey(volumeName, sourceDevicePath string, keyReader io.Reader, tries int, reason RecoveryKeyUsageReason, activateOptions []string) error {
	if tries == 0 {
		return errors.New("no recovery key tries permitted")
	}

	var lastErr error

	for ; tries > 0; tries-- {
		lastErr = nil

		r := keyReader
		keyReader = nil

		passphrase, err := getPassword(sourceDevicePath, "recovery key", r)
		if err != nil {
			return xerrors.Errorf("cannot obtain recovery key: %w", err)
		}

		key, err := decodeRecoveryKey(passphrase)
		if err != nil {
			lastErr = xerrors.Errorf("cannot decode recovery key: %w", err)
			continue
		}

		if err := activate(volumeName, sourceDevicePath, key, activateOptions); err != nil {
			err = xerrors.Errorf("cannot activate volume: %w", err)
			var e *exec.ExitError
			if !xerrors.As(err, &e) {
				return err
			}
			lastErr = err
			continue
		}

		if _, err := unix.AddKey("user", fmt.Sprintf("%s:%s:reason=%d", filepath.Base(os.Args[0]), volumeName, reason), key, userKeyring); err != nil {
			lastErr = xerrors.Errorf("cannot add recovery key to user keyring: %w", err)
		}
		break
	}

	return lastErr
}

func unsealKeyFromTPM(tpm *TPMConnection, k *SealedKeyObject, pin string) ([]byte, error) {
	key, err := k.UnsealFromTPM(tpm, pin)
	if err == ErrTPMProvisioning {
		// ErrTPMProvisioning in this context might indicate that there isn't a valid persistent SRK. Have a go at creating one now and then
		// retrying the unseal operation - if the previous SRK was evicted, the TPM owner hasn't changed and the storage hierarchy still
		// has a null authorization value, then this will allow us to unseal the key without requiring any type of manual recovery. If the
		// storage hierarchy has a non-null authorization value, ProvionTPM will fail. If the TPM owner has changed, ProvisionTPM might
		// succeed, but UnsealFromTPM will fail with InvalidKeyFileError when retried.
		if pErr := ProvisionTPM(tpm, ProvisionModeWithoutLockout, nil); pErr == nil {
			key, err = k.UnsealFromTPM(tpm, pin)
		}
	}
	return key, err
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

func activateWithTPMKey(tpm *TPMConnection, volumeName, sourceDevicePath, keyPath string, pinReader io.Reader, pinTries int, lock bool, activateOptions []string) error {
	var lockErr error
	key, err := func() ([]byte, error) {
		defer func() {
			if !lock {
				return
			}
			lockErr = LockAccessToSealedKeys(tpm)
		}()

		k, err := ReadSealedKeyObject(keyPath)
		if err != nil {
			return nil, xerrors.Errorf("cannot read sealed key object: %w", err)
		}

		switch {
		case pinTries == 0 && k.AuthMode2F() == AuthModePIN:
			return nil, requiresPinErr
		case pinTries == 0:
			pinTries = 1
		}

		var key []byte

		for ; pinTries > 0; pinTries-- {
			var pin string
			if k.AuthMode2F() == AuthModePIN {
				r := pinReader
				pinReader = nil
				pin, err = getPassword(sourceDevicePath, "PIN", r)
				if err != nil {
					return nil, xerrors.Errorf("cannot obtain PIN: %w", err)
				}
			}

			key, err = unsealKeyFromTPM(tpm, k, pin)
			if err != nil && (err != ErrPINFail || k.AuthMode2F() != AuthModePIN) {
				break
			}
		}

		if err != nil {
			return nil, xerrors.Errorf("cannot unseal key: %w", err)
		}
		return key, nil
	}()

	switch {
	case lockErr != nil:
		return lockAccessError{err}
	case err != nil:
		return err
	}

	if err := activate(volumeName, sourceDevicePath, key, activateOptions); err != nil {
		return xerrors.Errorf("cannot activate volume: %w", err)
	}

	return nil
}

func makeActivateOptions(in []string) ([]string, error) {
	var out []string
	for _, o := range in {
		if strings.HasPrefix(o, "tries=") {
			return nil, errors.New("cannot specify the \"tries=\" option for systemd-cryptsetup")
		}
		out = append(out, o)
	}
	return append(out, "tries=1"), nil
}

// ActivateWithTPMSealedKeyOptions provides options to ActivateVolumeWtthTPMSealedKey.
type ActivateWithTPMSealedKeyOptions struct {
	// PINTries specifies the maximum number of times that unsealing with a PIN should be attempted before failing with an error and
	// falling back to activating with the recovery key if RecoveryKeyTries is greater than zero. Setting this to zero disables unsealing
	// with a PIN - in this case, an error will be returned if the sealed key object indicates that a PIN has been set. Attempts to
	// unseal with a PIN will stop if the TPM enters dictionary attack lockout mode before this limit is reached.
	PINTries int

	// RecoveryKeyTries specifies the maximum number of times that activation with the fallback recovery key should be attempted
	// if activation with the TPM sealed key fails, before failing with an error. Setting this to zero will disable attempts to activate
	// with the fallback recovery key.
	RecoveryKeyTries int

	// ActivateOptions provides a mechanism to pass additional options to systemd-cryptsetup.
	ActivateOptions []string

	// LockSealedKeyAccess controls whether LockAccessToSealedKeys should be called after unsealing the TPM sealed key. It is called if
	// this is set to true, and not called if this is set to false.
	LockSealedKeyAccess bool
}

// ActivateVolumeWithTPMSealedKey attempts to activate the LUKS encrypted volume at sourceDevicePath and create a mapping with the
// name volumeName, using the TPM sealed key object at the specified keyPath. This makes use of systemd-cryptsetup.
//
// If the TPM sealed key object has a PIN defined, then this function will use systemd-ask-password to request it. If pinReader is not
// nil, then an attempt to read the PIN from this will be made instead by reading all characters until the first newline. The PINTries
// field of options defines how many attempts should be made to obtain the correct PIN before failing.
//
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup.
//
// If the LockSealedKeyAccess field of options is true, then this function will call LockAccessToSealedKeys after unsealing the key
// and before activating the LUKS volume.
//
// If activation with the TPM sealed key object fails, this function will attempt to activate it with the fallback recovery key
// instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of options specifies
// how many attempts should be made to activate the volume with the recovery key before failing. If this is set to 0, then no attempts
// will be made to activate the encrypted volume with the fallback recovery key. If activation with the recovery key is successful,
// the recovery key will be added to the root user keyring in the kernel with a description of the format
// "<argv[0]>:<volumeName>:reason=<reason>" where reason is an integer that describes the recovery reason - see the
// RecoveryKeyUsageReason type.
//
// If either the PINTries or RecoveryKeyTries fields of options are less than zero, an error will be returned. If the ActivateOptions
// field of options contains the "tries=" option, then an error will be returned. This option cannot be used with this function.
//
// If the LockSealedKeyAccess field of options is true and the call to LockAccessToSealedKeys fails, a LockAccessToSealedKeysError
// error will be returned. In this case, activation with either the TPM sealed key or the fallback recovery key will not be attempted.
//
// If activation with the TPM sealed key fails, a *ActivateWithTPMSealedKeyError error will be returned, even if the subsequent
// fallback recovery activation is successful. In this case, the RecoveryKeyUsageErr field of the returned error will be nil, and the
// TPMErr field will contain the original error. If activation with the fallback recovery key also fails, the RecoveryKeyUsageErr
// field of the returned error will also contain details of the error encountered during recovery key activation.
//
// If the volume is successfully activated, either with the TPM sealed key or the fallback recovery key, this function returns true.
// If it is not successfully activated, then this function returns false.
func ActivateVolumeWithTPMSealedKey(tpm *TPMConnection, volumeName, sourceDevicePath, keyPath string, pinReader io.Reader, options *ActivateWithTPMSealedKeyOptions) (bool, error) {
	if options.PINTries < 0 {
		return false, errors.New("invalid PINTries")
	}
	if options.RecoveryKeyTries < 0 {
		return false, errors.New("invalid RecoveryKeyTries")
	}

	activateOptions, err := makeActivateOptions(options.ActivateOptions)
	if err != nil {
		return false, err
	}

	if err := activateWithTPMKey(tpm, volumeName, sourceDevicePath, keyPath, pinReader, options.PINTries, options.LockSealedKeyAccess, activateOptions); err != nil {
		reason := RecoveryKeyUsageReasonUnexpectedError
		switch {
		case isLockAccessError(err):
			return false, LockAccessToSealedKeysError(err.Error())
		case xerrors.Is(err, ErrTPMLockout):
			reason = RecoveryKeyUsageReasonTPMLockout
		case xerrors.Is(err, ErrTPMProvisioning):
			reason = RecoveryKeyUsageReasonTPMProvisioningError
		case isInvalidKeyFileError(err):
			reason = RecoveryKeyUsageReasonInvalidKeyFile
		case xerrors.Is(err, requiresPinErr):
			reason = RecoveryKeyUsageReasonPINFail
		case xerrors.Is(err, ErrPINFail):
			reason = RecoveryKeyUsageReasonPINFail
		case isExecError(err, systemdCryptsetupPath):
			// systemd-cryptsetup only provides 2 exit codes - success or fail - so we don't know the reason it failed yet. If activation
			// with the recovery key is successful, then it's safe to assume that it failed because the key unsealed from the TPM is incorrect.
			reason = RecoveryKeyUsageReasonInvalidKeyFile
		}
		rErr := activateWithRecoveryKey(volumeName, sourceDevicePath, nil, options.RecoveryKeyTries, reason, activateOptions)
		return rErr == nil, &ActivateWithTPMSealedKeyError{err, rErr}
	}

	return true, nil
}

// ActivateWithRecoveryKeyOptions provides options to ActivateVolumeWithRecoveryKey.
type ActivateWithRecoveryKeyOptions struct {
	// Tries specifies the maximum number of times that activation with the fallback recovery key should be attempted before failing
	// with an error.
	Tries int

	// ActivateOptions provides a mechanism to pass additional options to systemd-cryptsetup.
	ActivateOptions []string
}

// ActivateVolumeWithRecoveryKey attempts to activate the LUKS encrypted volume at sourceDevicePath and create a mapping with the
// name volumeName, using the fallback recovery key. This makes use of systemd-cryptsetup.
//
// This function will use systemd-ask-password to request the recovery key. If keyReader is not nil, then an attempt to read the key
// from this will be made instead by reading all characters until the first newline. The Tries field of options defines how many
// attempts should be made to activate the volume with the recovery key before failing.
//
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup.
//
// If activation with the recovery key is successful, the recovery key will be added to the root user keyring in the kernel with a
// description of the format "<argv[0]>:<volumeName>:reason=2".
//
// If the Tries field of options is less than zero, an error will be returned. If the ActivateOptions field of options contains the
// "tries=" option, then an error will be returned. This option cannot be used with this function.
func ActivateVolumeWithRecoveryKey(volumeName, sourceDevicePath string, keyReader io.Reader, options *ActivateWithRecoveryKeyOptions) error {
	if options.Tries < 0 {
		return errors.New("invalid Tries")
	}

	activateOptions, err := makeActivateOptions(options.ActivateOptions)
	if err != nil {
		return err
	}

	return activateWithRecoveryKey(volumeName, sourceDevicePath, keyReader, options.Tries, RecoveryKeyUsageReasonRequested, activateOptions)
}
