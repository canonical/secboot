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

	"github.com/snapcore/snapd/osutil"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const userKeyring = -4

var (
	runDir                = "/run"
	systemdCryptsetupPath = "/lib/systemd/systemd-cryptsetup"
)

// RecoveryKey corresponds to a 16-byte recovery key in its binary form.
type RecoveryKey [16]byte

func (k RecoveryKey) String() string {
	var u16 [8]uint16
	for i := 0; i < 8; i++ {
		u16[i] = binary.LittleEndian.Uint16(k[i*2:])
	}
	return fmt.Sprintf("%05d-%05d-%05d-%05d-%05d-%05d-%05d-%05d", u16[0], u16[1], u16[2], u16[3], u16[4], u16[5], u16[6], u16[7])
}

// ParseRecoveryKey interprets the supplied string and returns the corresponding RecoveryKey. The recovery key is a
// 16-byte number, and the formatted version of this is represented as 8 5-digit zero-extended base-10 numbers (each
// with a range of 00000-65535) which may be separated by an optional '-', eg:
//
// "61665-00531-54469-09783-47273-19035-40077-28287"
//
// The formatted version of the recovery key is designed to be able to be inputted on a numeric keypad.
func ParseRecoveryKey(s string) (out RecoveryKey, err error) {
	for i := 0; i < 8; i++ {
		if len(s) < 5 {
			return RecoveryKey{}, errors.New("incorrectly formatted: insufficient characters")
		}
		x, err := strconv.ParseUint(s[0:5], 10, 16)
		if err != nil {
			return RecoveryKey{}, xerrors.Errorf("incorrectly formatted: %w", err)
		}
		binary.LittleEndian.PutUint16(out[i*2:], uint16(x))

		// Move to the next 5 digits
		s = s[5:]
		// Permit each set of 5 digits to be separated by an optional '-', but don't allow the formatted key to end or begin with one.
		if len(s) > 1 && s[0] == '-' {
			s = s[1:]
		}
	}

	if len(s) > 0 {
		return RecoveryKey{}, errors.New("incorrectly formatted: too many characters")
	}

	return
}

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

func mkFifo() (string, func(), error) {
	// /run is not world writable but we create a unique directory here because this
	// code can be invoked by a public API and we shouldn't fail if more than one
	// process reaches here at the same time.
	dir, err := ioutil.TempDir(runDir, filepath.Base(os.Args[0])+".")
	if err != nil {
		return "", nil, xerrors.Errorf("cannot create temporary directory: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(dir)
	}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		cleanup()
	}()

	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		return "", nil, xerrors.Errorf("cannot create FIFO: %w", err)
	}

	succeeded = true
	return fifo, cleanup, nil
}

func activate(volumeName, sourceDevicePath string, key []byte, options []string) error {
	fifoPath, cleanupFifo, err := mkFifo()
	if err != nil {
		return xerrors.Errorf("cannot create FIFO for passing key to systemd-cryptsetup: %w", err)
	}
	defer cleanupFifo()

	cmd := exec.Command(systemdCryptsetupPath, "attach", volumeName, sourceDevicePath, fifoPath, strings.Join(options, ","))
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

	f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
	if err != nil {
		// If we fail to open the write end, the read end will be blocked in open()
		cmd.Process.Kill()
		return xerrors.Errorf("cannot open FIFO for passing key to systemd-cryptsetup: %w", err)
	}

	if _, err := f.Write(key); err != nil {
		f.Close()
		// The read end is open and blocked inside read(). Closing our write end will result in the
		// read end returning 0 bytes (EOF) and exitting cleanly.
		cmd.Wait()
		return xerrors.Errorf("cannot pass key to systemd-cryptsetup: %w", err)
	}

	f.Close()
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

		key, err := ParseRecoveryKey(passphrase)
		if err != nil {
			lastErr = xerrors.Errorf("cannot decode recovery key: %w", err)
			continue
		}

		if err := activate(volumeName, sourceDevicePath, key[:], activateOptions); err != nil {
			err = xerrors.Errorf("cannot activate volume: %w", err)
			var e *exec.ExitError
			if !xerrors.As(err, &e) {
				return err
			}
			lastErr = err
			continue
		}

		if _, err := unix.AddKey("user", fmt.Sprintf("%s:%s:reason=%d", filepath.Base(os.Args[0]), volumeName, reason), key[:], userKeyring); err != nil {
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
		if pErr := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); pErr == nil || pErr == ErrTPMProvisioningRequiresLockout {
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

func setLUKS2KeyslotPreferred(devicePath string, slot int) error {
	cmd := exec.Command("cryptsetup", "config", "--priority", "prefer", "--key-slot", strconv.Itoa(slot), devicePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}

	return nil
}

// InitializeLUKS2Container will initialize the partition at the specified devicePath as a new LUKS2 container. This can only
// be called on a partition that isn't mapped. The label for the new LUKS2 container is provided via the label argument.
//
// The initial key used for unlocking the container is provided via the key argument, and must be a cryptographically secure
// 64-byte random number. The key should be stored encrypted by using SealKeyToTPM.
//
// The container will be configured to encrypt data with AES-256 and XTS block cipher mode.
//
// On failure, this will return an error containing the output of the cryptsetup command.
//
// WARNING: This function is destructive. Calling this on an existing LUKS container will make the data contained inside of it
// irretrievable.
func InitializeLUKS2Container(devicePath, label string, key []byte) error {
	if len(key) != 64 {
		return fmt.Errorf("expected a key length of 512-bits (got %d)", len(key)*8)
	}

	cmd := exec.Command("cryptsetup",
		// batch processing, no password verification for formatting an existing LUKS container
		"-q",
		// formatting a new volume
		"luksFormat",
		// use LUKS2
		"--type", "luks2",
		// read the key from stdin
		"--key-file", "-",
		// use AES-256 with XTS block cipher mode (XTS requires 2 keys)
		"--cipher", "aes-xts-plain64", "--key-size", "512",
		// use argon2i as the KDF with minimum cost (lowest possible time and memory costs). This is done
		// because the supplied input key has the same entropy (512-bits) as the derived key and therefore
		// increased time or memory cost don't provide a security benefit (but does slow down unlocking).
		"--pbkdf", "argon2i", "--pbkdf-force-iterations", "4", "--pbkdf-memory", "32",
		// set LUKS2 label
		"--label", label,
		// device to format
		devicePath)
	cmd.Stdin = bytes.NewReader(key)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}

	return setLUKS2KeyslotPreferred(devicePath, 0)
}

func addKeyToLUKS2Container(devicePath string, existingKey, key []byte, extraOptionArgs []string) error {
	fifoPath, cleanupFifo, err := mkFifo()
	if err != nil {
		return xerrors.Errorf("cannot create FIFO for passing existing key to cryptsetup: %w", err)
	}
	defer cleanupFifo()

	args := []string{
		// add a new key
		"luksAddKey",
		// read existing key from named pipe
		"--key-file", fifoPath}
	args = append(args, extraOptionArgs...)
	args = append(args,
		// container to add key to
		devicePath,
		// read new key from stdin
		"-")
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = bytes.NewReader(key)

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b

	if err := cmd.Start(); err != nil {
		return xerrors.Errorf("cannot start cryptsetup: %w", err)
	}

	f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
	if err != nil {
		// If we fail to open the write end, the read end will be blocked in open()
		cmd.Process.Kill()
		return xerrors.Errorf("cannot open FIFO for passing existing key to cryptsetup: %w", err)
	}

	if _, err := f.Write(existingKey); err != nil {
		f.Close()
		// The read end is open and blocked inside read(). Closing our write end will result in the
		// read end returning 0 bytes (EOF) and exitting cleanly.
		cmd.Wait()
		return xerrors.Errorf("cannot pass existing key to cryptsetup: %w", err)
	}

	f.Close()
	if err := cmd.Wait(); err != nil {
		return osutil.OutputErr(b.Bytes(), err)
	}
	return nil
}

// AddRecoveryKeyToLUKS2Container adds a fallback recovery key to an existing LUKS2 container created with InitializeLUKS2Container.
// The recovery key is intended to be used as a fallback mechanism that operates independently of the TPM in order to unlock the
// container in the event that the key encrypted with SealKeyToTPM cannot be used to unlock it. The devicePath argument specifies
// the device node for the partition that contains the LUKS2 container. The existing key for the container is provided via the
// key argument.
//
// The recovery key is provided via the recoveryKey argument and must be a cryptographically secure 16-byte number.
func AddRecoveryKeyToLUKS2Container(devicePath string, key []byte, recoveryKey RecoveryKey) error {
	return addKeyToLUKS2Container(devicePath, key, recoveryKey[:], []string{
		// use argon2i as the KDF with an increased cost
		"--pbkdf", "argon2i", "--iter-time", "5000"})
}

// ChangeLUKS2KeyUsingRecoveryKey changes the key normally used for unlocking the LUKS2 container at devicePath. This function
// is intended to be used after the container is unlocked with the recovery key, in the scenario that the TPM sealed key is
// invalid and needs to be recreated.
//
// In order to perform this action, the recovery key needs to be supplied via the recoveryKey argument. The new key is provided via
// the key argument. The new key should be stored encrypted with SealKeyToTPM.
//
// Note that this operation is not atomic. It will delete the existing key from the container before configuring the keyslot with
// the new key. This is not a problem, because this function is intended to be called in the scenario that the default key cannot
// be used to activate the LUKS2 container.
func ChangeLUKS2KeyUsingRecoveryKey(devicePath string, recoveryKey RecoveryKey, key []byte) error {
	if len(key) != 64 {
		return fmt.Errorf("expected a key length of 512-bits (got %d)", len(key)*8)
	}

	cmd := exec.Command("cryptsetup", "luksKillSlot", "--key-file", "-", devicePath, "0")
	cmd.Stdin = bytes.NewReader(recoveryKey[:])
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}

	if err := addKeyToLUKS2Container(devicePath, recoveryKey[:], key, []string{
		// use argon2i as the KDF with minimum cost (lowest possible time and memory costs). This is done
		// because the supplied input key has the same entropy (512-bits) as the derived key and therefore
		// increased time or memory cost don't provide a security benefit (but does slow down unlocking).
		"--pbkdf", "argon2i", "--pbkdf-force-iterations", "4", "--pbkdf-memory", "32",
		// always have the main key in slot 0 for now
		"--key-slot", "0"}); err != nil {
		return err
	}

	return setLUKS2KeyslotPreferred(devicePath, 0)
}
