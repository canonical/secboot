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

	"github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/snapd/osutil"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

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

// SnapModelChecker is used for verifying whether a Snap device model is
// authorized to access the data on a volume unlocked by this package.
type SnapModelChecker struct {
	volumeName string
	keyData    *KeyData
	auxKey     AuxiliaryKey
}

// IsModelAuthorized indicates whether the supplied Snap device model is
// authorized to access the data on the decrypted volume with the device
// mapper name returned by VolumeName.
func (c *SnapModelChecker) IsModelAuthorized(model SnapModel) (bool, error) {
	return c.keyData.IsSnapModelAuthorized(c.auxKey, model)
}

// VolumeName is the device mapper name of the volume associated with this
// SnapModelChecker.
func (c *SnapModelChecker) VolumeName() string {
	return c.volumeName
}

type activateWithKeyDataError struct {
	k   *KeyData
	err error
}

func (e *activateWithKeyDataError) Error() string {
	return fmt.Sprintf("%s: %v", e.k.ID(), e.err)
}

func (e *activateWithKeyDataError) Unwrap() error {
	return e.err
}

type keyDataAndError struct {
	*KeyData
	err error
}

type activateWithKeyDataState struct {
	volumeName       string
	sourceDevicePath string
	activateOptions  []string
	keyringPrefix    string

	keys []*keyDataAndError

	keyData *KeyData
	auxKey  AuxiliaryKey
}

func (s *activateWithKeyDataState) errors() (out []*activateWithKeyDataError) {
	for _, k := range s.keys {
		if k.err == nil {
			continue
		}
		out = append(out, &activateWithKeyDataError{k: k.KeyData, err: k.err})
	}
	return out
}

func (s *activateWithKeyDataState) snapModelChecker() *SnapModelChecker {
	return &SnapModelChecker{s.volumeName, s.keyData, s.auxKey}
}

func (s *activateWithKeyDataState) tryActivateWithRecoveredKey(keyData *KeyData, key DiskUnlockKey, auxKey AuxiliaryKey) error {
	if err := activate(s.volumeName, s.sourceDevicePath, key, s.activateOptions); err != nil {
		return xerrors.Errorf("cannot activate volume: %w", err)
	}

	s.keyData = keyData
	s.auxKey = auxKey

	if err := keyring.AddKeyToUserKeyring(key, s.sourceDevicePath, keyringPurposeDiskUnlock, s.keyringPrefix); err != nil {
		fmt.Fprintf(os.Stderr, "secboot: Cannot add key to user keyring: %v\n", err)
	}

	if err := keyring.AddKeyToUserKeyring(auxKey, s.sourceDevicePath, keyringPurposeAuxiliary, s.keyringPrefix); err != nil {
		fmt.Fprintf(os.Stderr, "secboot: Cannot add key to user keyring: %v\n", err)
	}

	return nil
}

func (s *activateWithKeyDataState) tryKeyDataAuthModeNone(k *KeyData) error {
	key, auxKey, err := k.RecoverKeys()
	if err != nil {
		return xerrors.Errorf("cannot recover key: %w", err)
	}

	return s.tryActivateWithRecoveredKey(k, key, auxKey)
}

func (s *activateWithKeyDataState) run() (success bool) {
	// Try keys that don't require any additional authentication first
	for _, k := range s.keys {
		if k.AuthMode() != AuthModeNone {
			continue
		}

		if err := s.tryKeyDataAuthModeNone(k.KeyData); err != nil {
			k.err = err
			continue
		}

		return true
	}

	// TODO: Passphrase support

	// We've failed at this point
	return false
}

func newActivateWithKeyDataState(volumeName, sourceDevicePath string, activateOptions []string, keyringPrefix string, keys []*KeyData) *activateWithKeyDataState {
	s := &activateWithKeyDataState{
		volumeName:       volumeName,
		sourceDevicePath: sourceDevicePath,
		activateOptions:  activateOptions,
		keyringPrefix:    keyringPrefixOrDefault(keyringPrefix)}
	for _, k := range keys {
		s.keys = append(s.keys, &keyDataAndError{KeyData: k})
	}
	return s
}

func activateWithRecoveryKey(volumeName, sourceDevicePath string, keyReader io.Reader, tries int, activateOptions []string, keyringPrefix string) error {
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

		if err := keyring.AddKeyToUserKeyring(key[:], sourceDevicePath, keyringPurposeDiskUnlock, keyringPrefixOrDefault(keyringPrefix)); err != nil {
			fmt.Fprintf(os.Stderr, "secboot: Cannot add key to user keyring: %v\n", err)
		}

		break
	}

	return lastErr
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

	// KeyringPrefix is the prefix used for the description of any
	// kernel keys created during activation.
	KeyringPrefix string
}

type activateVolumeWithKeyDataError struct {
	keyDataErrs         []error
	recoveryKeyUsageErr error
}

func (e *activateVolumeWithKeyDataError) Error() string {
	var s bytes.Buffer
	fmt.Fprintf(&s, "cannot activate with platform protected keys:")
	for _, err := range e.keyDataErrs {
		fmt.Fprintf(&s, "\n- %v", err)
	}
	fmt.Fprintf(&s, "\nand activation with recovery key failed: %v", e.recoveryKeyUsageErr)
	return s.String()
}

// ErrRecoveryKeyUsed is returned from ActivateVolumeWithKeyData and
// ActivateVolumeWithMultipleKeyData if the volume could not be activated with
// any platform protected keys but activation with the recovery key was
// successful.
var ErrRecoveryKeyUsed = errors.New("cannot activate with platform protected keys but activation with the recovery key was successful")

// ActivateVolumeWithKeyData attempts to activate the LUKS encrypted container at sourceDevicePath and create a
// mapping with the name volumeName, using the supplied KeyData objects to recover the disk unlock key from the
// platform's secure device. This makes use of systemd-cryptsetup.
//
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup.
//
// If activation with the supplied KeyData objects fails, this function will attempt to activate it with the fallback
// recovery key instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries
// field of options specifies how many attempts should be made to activate the volume with the recovery key before
// failing. If this is set to 0, then no attempts will be made to activate the encrypted volume with the fallback
// recovery key.
//
// If either the PassphraseTries or RecoveryKeyTries fields of options are less than zero, an error will be returned.
// If the ActivateOptions field of options contains the "tries=" option, then an error will be returned. This option
// cannot be used with this function.
//
// If activation with one of the supplied KeyData objects succeeds, a SnapModelChecker will be returned so that the
// caller can check whether a particular Snap device model has previously been authorized to access the data on this
// volume. If the fallback recovery key is used for successfully for activation, no SnapModelChecker will be
// returned and a ErrRecoveryKeyUsed error will be returned.
//
// If activation fails, an error will be returned.
func ActivateVolumeWithMultipleKeyData(volumeName, sourceDevicePath string, keys []*KeyData, options *ActivateVolumeOptions) (*SnapModelChecker, error) {
	if len(keys) == 0 {
		return nil, errors.New("no keys provided")
	}
	if options.PassphraseTries < 0 {
		return nil, errors.New("invalid PassphraseTries")
	}
	if options.RecoveryKeyTries < 0 {
		return nil, errors.New("invalid RecoveryKeyTries")
	}

	activateOptions, err := makeActivateOptions(options.ActivateOptions)
	if err != nil {
		return nil, err
	}

	s := newActivateWithKeyDataState(volumeName, sourceDevicePath, activateOptions, options.KeyringPrefix, keys)
	switch s.run() {
	case true: // success!
		return s.snapModelChecker(), nil
	default: // failed - try recovery key
		if rErr := activateWithRecoveryKey(volumeName, sourceDevicePath, nil, options.RecoveryKeyTries, activateOptions, options.KeyringPrefix); rErr != nil {
			// failed with recovery key - return errors
			var kdErrs []error
			for _, e := range s.errors() {
				kdErrs = append(kdErrs, e)
			}
			return nil, &activateVolumeWithKeyDataError{kdErrs, rErr}
		}
		// succeeded with recovery key
		return nil, ErrRecoveryKeyUsed
	}
}

// ActivateVolumeWithKeyData attempts to activate the LUKS encrypted container at sourceDevicePath and create a
// mapping with the name volumeName, using the supplied KeyData to recover the disk unlock key from the platform's
// secure device. This makes use of systemd-cryptsetup.
//
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup.
//
// If activation with the supplied KeyData fails, this function will attempt to activate it with the fallback recovery
// key instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of
// options specifies how many attempts should be made to activate the volume with the recovery key before failing.
// If this is set to 0, then no attempts will be made to activate the encrypted volume with the fallback recovery key.
//
// If either the PassphraseTries or RecoveryKeyTries fields of options are less than zero, an error will be returned.
// If the ActivateOptions field of options contains the "tries=" option, then an error will be returned. This option
// cannot be used with this function.
//
// If activation with the supplied KeyData succeeds, a SnapModelChecker will be returned so that the caller can check
// whether a particular Snap device model has previously been authorized to access the data on this volume. If the
// fallback recovery key is used for successfully for activation, no SnapModelChecker will be returned and a
// ErrRecoveryKeyUsed error will be returned.
//
// If activation fails, an error will be returned.
func ActivateVolumeWithKeyData(volumeName, sourceDevicePath string, key *KeyData, options *ActivateVolumeOptions) (*SnapModelChecker, error) {
	return ActivateVolumeWithMultipleKeyData(volumeName, sourceDevicePath, []*KeyData{key}, options)
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

	return activateWithRecoveryKey(volumeName, sourceDevicePath, keyReader, options.RecoveryKeyTries, activateOptions, options.KeyringPrefix)
}

// ActivateVolumeWithKey attempts to activate the LUKS encrypted volume at
// sourceDevicePath and create a mapping with the name volumeName, using the
// provided key. This makes use of systemd-cryptsetup.
//
// The ActivateOptions field of options can be used to specify additional
// options to pass to systemd-cryptsetup. All other fields are ignored.
//
// If the ActivateOptions field of options contains the "tries=" option, then an
// error will be returned. This option cannot be used with this function.
func ActivateVolumeWithKey(volumeName, sourceDevicePath string, key []byte, options *ActivateVolumeOptions) error {
	// do not be more strict about checking options to allow reusing it
	// across different calls
	activateOptions, err := makeActivateOptions(options.ActivateOptions)
	if err != nil {
		return err
	}

	return activate(volumeName, sourceDevicePath, key, activateOptions)
}

func setLUKS2KeyslotPreferred(devicePath string, slot int) error {
	cmd := exec.Command("cryptsetup", "config", "--priority", "prefer", "--key-slot", strconv.Itoa(slot), devicePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}

	return nil
}

// InitializeLUKS2ContainerOptions carries options for initializing LUKS2
// containers.
type InitializeLUKS2ContainerOptions struct {
	// MetadataKiBSize sets the size of the LUKS2 metadata (JSON) area,
	// expressed in multiples of 1024 bytes. The value includes 4096 bytes
	// for the binary metadata. According to LUKS2 specification and
	// cryptsetup(8), only these values are valid: 16, 32, 64, 128, 256,
	// 512, 1024, 2048 and 4096 KiB.
	MetadataKiBSize int
	// KeyslotsAreaSize sets the size of the LUKS2 binary keyslot area,
	// expressed in multiples of 1024 bytes. The value must be aligned to
	// 4096 bytes, with the maximum size of 128MB.
	KeyslotsAreaKiBSize int
}

func validateInitializeLUKS2Options(options *InitializeLUKS2ContainerOptions) error {
	if options == nil {
		return nil
	}

	if options.MetadataKiBSize != 0 {
		// metadata size is one of the allowed values (in kB)
		allowedSizesKB := []int{16, 32, 64, 128, 256, 512, 1024, 2048, 4096}
		found := false
		for _, sz := range allowedSizesKB {
			if options.MetadataKiBSize == sz {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("cannot set metadata size to %v KiB",
				options.MetadataKiBSize)
		}
	}
	if options.KeyslotsAreaKiBSize != 0 {
		// minimum size 4096 (4KiB), a multiple of 4096, max size 128MiB
		sizeValid := options.KeyslotsAreaKiBSize >= 4 &&
			options.KeyslotsAreaKiBSize <= 128*1024 &&
			options.KeyslotsAreaKiBSize%4 == 0
		if !sizeValid {
			return fmt.Errorf("cannot set keyslots area size to %v KiB",
				options.KeyslotsAreaKiBSize)
		}
	}
	return nil
}

// InitializeLUKS2Container will initialize the partition at the specified devicePath as a new LUKS2 container. This can only
// be called on a partition that isn't mapped. The label for the new LUKS2 container is provided via the label argument.
//
// The initial key used for unlocking the container is provided via the key argument, and must be a cryptographically secure
// random number of at least 32-bytes. The key should be encrypted by using SealKeyToTPM.
//
// The container will be configured to encrypt data with AES-256 and XTS block cipher mode.
//
// On failure, this will return an error containing the output of the cryptsetup command.
//
// WARNING: This function is destructive. Calling this on an existing LUKS container will make the data contained inside of it
// irretrievable.
func InitializeLUKS2Container(devicePath, label string, key []byte, options *InitializeLUKS2ContainerOptions) error {
	if len(key) < 32 {
		return fmt.Errorf("expected a key length of at least 256-bits (got %d)", len(key)*8)
	}
	if err := validateInitializeLUKS2Options(options); err != nil {
		return err
	}

	args := []string{
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
		// use argon2i as the KDF with reduced cost. This is done because the supplied input key has an
		// entropy of at least 32 bytes, and increased cost doesn't provide a security benefit because
		// this key and these settings are already more secure than the recovery key. Increased cost
		// here only slows down unlocking.
		"--pbkdf", "argon2i", "--iter-time", "100",
		// set LUKS2 label
		"--label", label,
	}
	if options != nil {
		if options.MetadataKiBSize != 0 {
			args = append(args,
				"--luks2-metadata-size", fmt.Sprintf("%dk", options.MetadataKiBSize))
		}
		if options.KeyslotsAreaKiBSize != 0 {
			args = append(args,
				"--luks2-keyslots-size", fmt.Sprintf("%dk", options.KeyslotsAreaKiBSize))
		}
	}
	args = append(args,
		// device to format
		devicePath)
	cmd := exec.Command("cryptsetup", args...)
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
	if len(key) < 32 {
		return fmt.Errorf("expected a key length of at least 256-bits (got %d)", len(key)*8)
	}

	cmd := exec.Command("cryptsetup", "luksKillSlot", "--key-file", "-", devicePath, "0")
	cmd.Stdin = bytes.NewReader(recoveryKey[:])
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}

	if err := addKeyToLUKS2Container(devicePath, recoveryKey[:], key, []string{
		// use argon2i as the KDF with reduced cost. This is done because the supplied input key has an
		// entropy of at least 32 bytes, and increased cost doesn't provide a security benefit because
		// this key and these settings are already more secure than the recovery key. Increased cost
		// here only slows down unlocking.
		"--pbkdf", "argon2i", "--iter-time", "100",
		// always have the main key in slot 0 for now
		"--key-slot", "0"}); err != nil {
		return err
	}

	return setLUKS2KeyslotPreferred(devicePath, 0)
}
