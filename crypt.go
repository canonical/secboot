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
	"regexp"
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

	defaultKeyringPrefix = "secboot"
)

func keyringPrefixOrDefault(prefix string) string {
	if prefix == "" {
		return defaultKeyringPrefix
	}
	return prefix
}

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

	// RecoveryKeyUsageReasonPassphraseFail indicates that a
	// volume had to be activated with the fallback recovery key
	// because the correct user passphrase/PIN was not provided.
	RecoveryKeyUsageReasonPassphraseFail
)

func activateWithRecoveryKey(volumeName, sourceDevicePath string, keyReader io.Reader, tries int, reason RecoveryKeyUsageReason, activateOptions []string, keyringPrefix string) error {
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
		unix.AddKey("user", fmt.Sprintf("%s:%s?type=recovery&reason=%d", keyringPrefixOrDefault(keyringPrefix), sourceDevicePath, reason), key[:], userKeyring)
		break
	}

	return lastErr
}

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

func activateWithTPMKey(tpm *TPMConnection, volumeName, sourceDevicePath, keyPath string, passphraseReader io.Reader, passphraseTries int, lock bool, activateOptions []string, keyringPrefix string) error {
	var lockErr error
	sealedKey, authPrivateKey, err := func() ([]byte, TPMPolicyAuthKey, error) {
		defer func() {
			if !lock {
				return
			}
			// TODO: Figure out what to do with this
			//lockErr = LockAccessToSealedKeys(tpm)
		}()

		k, err := ReadSealedKeyObject(keyPath)
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot read sealed key object: %w", err)
		}

		switch {
		case passphraseTries == 0 && k.AuthMode2F() == AuthModePIN:
			return nil, nil, requiresPinErr
		case passphraseTries == 0:
			passphraseTries = 1
		}

		var sealedKey []byte
		var authPrivateKey []byte

		for ; passphraseTries > 0; passphraseTries-- {
			var pin string
			if k.AuthMode2F() == AuthModePIN {
				r := passphraseReader
				passphraseReader = nil
				pin, err = getPassword(sourceDevicePath, "PIN", r)
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
		return lockAccessError{err}
	case err != nil:
		return err
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

// ActivateVolumeOptions provides options to the ActivateVolumeWith*
// family of functions.
type ActivateVolumeOptions struct {
	// PassphraseTries specifies the maximum number of times
	// that unsealing with a user passphrase should be attempted
	// before failing with an error and falling back to activating
	// with the recovery key (see RecoveryKeyTries).
	// Setting this to zero disables unsealing with a user
	// passphrase - in this case, an error will be returned if the
	// sealed key object indicates that a user passphrase has been
	// set.
	// With a TPM, attempts to unseal will stop if the TPM enters
	// dictionary attack lockout mode before this limit is
	// reached.
	// It is ignored by ActivateWithRecoveryKey.
	PassphraseTries int

	// RecoveryKeyTries specifies the maximum number of times that
	// activation with the fallback recovery key should be
	// attempted.
	// It is used directly by ActivateWithRecoveryKey and
	// indirectly with other methods upon failure, for example
	// failed TPM unsealing.  Setting this to zero will disable
	// attempts to activate with the fallback recovery key.
	RecoveryKeyTries int

	// ActivateOptions provides a mechanism to pass additional
	// options to systemd-cryptsetup.
	ActivateOptions []string

	// LockSealedKeys controls whether access to the keys is
	// locked after unsealing by calling LockAccessToSealedKeys in
	// TPM case for example.
	LockSealedKeys bool

	// KeyringPrefix is the prefix used for the description of any
	// kernel keys created during activation.
	KeyringPrefix string
}

// ActivateVolumeWithTPMSealedKey attempts to activate the LUKS encrypted volume at sourceDevicePath and create a mapping with the
// name volumeName, using the TPM sealed key object at the specified keyPath. This makes use of systemd-cryptsetup.
//
// If the TPM sealed key object has a user passphrase/PIN defined, then this function will use systemd-ask-password to request it. If passphraseReader is not
// nil, then an attempt to read the user passphrase/PIN from this will be made instead by reading all characters until the first newline. The PassphraseTries
// field of options defines how many attempts should be made to obtain the correct passphrase before failing.
//
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup.
//
// If the LockSealedKeys field of options is true, then this function will call LockAccessToSealedKeys after unsealing the key
// and before activating the LUKS volume.
//
// If activation with the TPM sealed key object fails, this function will attempt to activate it with the fallback recovery key
// instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of options specifies
// how many attempts should be made to activate the volume with the recovery key before failing. If this is set to 0, then no attempts
// will be made to activate the encrypted volume with the fallback recovery key. If activation with the recovery key is successful,
// calling GetActivationDataFromKernel will return a *RecoveryActivationData containing the recovery key and the reason that the
// recovery key was requested.
//
// If either the PassphraseTries or RecoveryKeyTries fields of options are less than zero, an error will be returned. If the ActivateOptions
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
// If the volume is successfully activated with the TPM sealed key and the TPM sealed key has a version of greater than 1, calling
// GetActivationDataFromKernel will return a TPMPolicyAuthKey containing the private part of the key used for authorizing PCR policy
// updates with UpdateKeyPCRProtectionPolicy.
//
// If the volume is successfully activated, either with the TPM sealed key or the fallback recovery key, this function returns true.
// If it is not successfully activated, then this function returns false.
func ActivateVolumeWithTPMSealedKey(tpm *TPMConnection, volumeName, sourceDevicePath, keyPath string, passphraseReader io.Reader, options *ActivateVolumeOptions) (bool, error) {
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

	if err := activateWithTPMKey(tpm, volumeName, sourceDevicePath, keyPath, passphraseReader, options.PassphraseTries, options.LockSealedKeys, activateOptions, options.KeyringPrefix); err != nil {
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
			reason = RecoveryKeyUsageReasonPassphraseFail
		case xerrors.Is(err, ErrPINFail):
			reason = RecoveryKeyUsageReasonPassphraseFail
		case isExecError(err, systemdCryptsetupPath):
			// systemd-cryptsetup only provides 2 exit codes - success or fail - so we don't know the reason it failed yet. If activation
			// with the recovery key is successful, then it's safe to assume that it failed because the key unsealed from the TPM is incorrect.
			reason = RecoveryKeyUsageReasonInvalidKeyFile
		}
		rErr := activateWithRecoveryKey(volumeName, sourceDevicePath, nil, options.RecoveryKeyTries, reason, activateOptions, options.KeyringPrefix)
		return rErr == nil, &ActivateWithTPMSealedKeyError{err, rErr}
	}

	return true, nil
}

// ActivateVolumeWithRecoveryKey attempts to activate the LUKS encrypted volume at sourceDevicePath and create a mapping with the
// name volumeName, using the fallback recovery key. This makes use of systemd-cryptsetup.
//
// This function will use systemd-ask-password to request the recovery key. If keyReader is not nil, then an attempt to read the key
// from this will be made instead by reading all characters until the first newline. The RecoveryKeyTries field of options defines how many
// attempts should be made to activate the volume with the recovery key before failing.
//
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup.
//
// If activation with the recovery key is successful, calling GetActivationDataFromKernel will return a *RecoveryActivationData
// containing the recovery key and RecoveryKeyUsageReasonRequested as the recovery reason.
//
// If the RecoveryKeyTries field of options is less than zero, an error will be returned. If the ActivateOptions field of options contains the
// "tries=" option, then an error will be returned. This option cannot be used with this function.
func ActivateVolumeWithRecoveryKey(volumeName, sourceDevicePath string, keyReader io.Reader, options *ActivateVolumeOptions) error {
	if options.RecoveryKeyTries < 0 {
		return errors.New("invalid RecoveryKeyTries")
	}

	activateOptions, err := makeActivateOptions(options.ActivateOptions)
	if err != nil {
		return err
	}

	return activateWithRecoveryKey(volumeName, sourceDevicePath, keyReader, options.RecoveryKeyTries, RecoveryKeyUsageReasonRequested, activateOptions, options.KeyringPrefix)
}

// ActivationData corresponds to some data added to the user keyring by one of the ActivateVolume functions.
type ActivationData interface{}

// RecoveryActivationData is added to the user keyring when a recovery key is used to activate a volume.
type RecoveryActivationData struct {
	Key    RecoveryKey
	Reason RecoveryKeyUsageReason
}

// GetActivationDataFromKernel retrieves data that was added to the current user's user keyring by ActivateVolumeWithTPMSealedKey or
// ActivateVolumeWithRecoveryKey for the specified source block device, using the prefix that was passed to either of those functions.
// The block device path must match the path passed to one of the ActivateVolume functions. The type of data returned is dependent on
// how the volume was activated - see the documentation for each function, If no data is found for the specified device, a
// ErrNoActivationData error is returned.
//
// If remove is true, this function will unlink the key from the user's user keyring.
func GetActivationDataFromKernel(prefix, sourceDevicePath string, remove bool) (ActivationData, error) {
	var userKeys []int

	sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, userKeyring, nil, 0)
	if err != nil {
		return nil, xerrors.Errorf("cannot determine size of user keyring payload: %w", err)
	}

	for {
		payload := make([]byte, sz)
		n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, userKeyring, payload, 0)
		if err != nil {
			return nil, xerrors.Errorf("cannot read user keyring payload: %w", err)
		}

		if n <= sz {
			payload = payload[:n]

			for len(payload) > 0 {
				userKeys = append(userKeys, int(binary.LittleEndian.Uint32(payload)))
				payload = payload[4:]
			}
			break
		}

		sz = n
	}

	re := regexp.MustCompile(fmt.Sprintf(`^user;[[:digit:]]+;[[:digit:]]+;[[:xdigit:]]+;%s:([^\?]+)\??(.*)`, keyringPrefixOrDefault(prefix)))
	for _, id := range userKeys {
		desc, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, id)
		if err != nil {
			continue
		}
		m := re.FindStringSubmatch(desc)
		if len(m) == 0 {
			continue
		}
		if m[1] != sourceDevicePath {
			continue
		}

		sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, nil, 0)
		if err != nil {
			return nil, xerrors.Errorf("cannot determine size of key payload: %w", err)
		}
		payload := make([]byte, sz)
		_, err = unix.KeyctlBuffer(unix.KEYCTL_READ, id, payload, 0)
		if err != nil {
			return nil, xerrors.Errorf("cannot read key payload: %w", err)
		}

		if remove {
			// XXX: What should we do if unlinking fails?
			unix.KeyctlInt(unix.KEYCTL_UNLINK, id, userKeyring, 0, 0)
		}

		params := make(map[string]string)
		if len(m) > 2 {
			for _, p := range strings.Split(m[2], "&") {
				s := strings.SplitN(p, "=", 2)
				k := s[0]
				var v string
				if len(s) > 1 {
					v = s[1]
				}
				params[k] = v
			}
		}

		t, ok := params["type"]
		if !ok {
			return nil, errors.New("invalid description (no type)")
		}
		switch t {
		case "tpm":
			return TPMPolicyAuthKey(payload), nil
		case "recovery":
			reason, ok := params["reason"]
			if !ok {
				return nil, errors.New("no recovery reason")
			}
			n, err := strconv.Atoi(reason)
			if err != nil {
				return nil, xerrors.Errorf("invalid recovery reason: %w", err)
			}
			if len(payload) != binary.Size(RecoveryKey{}) {
				return nil, errors.New("invalid payload size")
			}
			var key RecoveryKey
			copy(key[:], payload)
			return &RecoveryActivationData{Key: key, Reason: RecoveryKeyUsageReason(n)}, nil
		default:
			return nil, errors.New("invalid description (unhandled type)")
		}
	}

	return nil, ErrNoActivationData
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
