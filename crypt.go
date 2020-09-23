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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/snapcore/secboot/internal/luks2"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const userKeyring = -4

var (
	tokenType        = "secboot"         // The type used for all secboot tokens
	slotTypeKey      = "secboot-type"    // The key used to identify the type of secboot keyslot associated with a token
	masterSlotType   = "master-detached" // Used to idenfity a master keyslot with detached metadata
	recoverySlotType = "recovery"        // Used to identify a recovery keyslot
	tpmSlotType      = "tpm"

	luks2Activate = luks2.Activate
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

func isExitError(err error) bool {
	var e *exec.ExitError
	return xerrors.As(err, &e)
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

		if err := luks2Activate(volumeName, sourceDevicePath, key[:], activateOptions); err != nil {
			err = xerrors.Errorf("cannot activate volume: %w", err)
			if !isExitError(err) {
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

		k, err := ReadSealedKeyObjectFromFile(keyPath)
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

	if err := luks2Activate(volumeName, sourceDevicePath, key, activateOptions); err != nil {
		return xerrors.Errorf("cannot activate volume: %w", err)
	}

	return nil
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

	if err := activateWithTPMKey(tpm, volumeName, sourceDevicePath, keyPath, pinReader, options.PINTries, options.LockSealedKeyAccess, options.ActivateOptions); err != nil {
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
		case isExitError(err):
			// systemd-cryptsetup only provides 2 exit codes - success or fail - so we don't know the reason it failed yet. If activation
			// with the recovery key is successful, then it's safe to assume that it failed because the key unsealed from the TPM is incorrect.
			reason = RecoveryKeyUsageReasonInvalidKeyFile
		}
		rErr := activateWithRecoveryKey(volumeName, sourceDevicePath, nil, options.RecoveryKeyTries, reason, options.ActivateOptions)
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

	return activateWithRecoveryKey(volumeName, sourceDevicePath, keyReader, options.Tries, RecoveryKeyUsageReasonRequested, options.ActivateOptions)
}

func makeTokenForKeyslot(slotType string, slot int) *luks2.Token {
	return &luks2.Token{Type: tokenType, Keyslots: []int{slot}, Params: map[string]interface{}{slotTypeKey: slotType}}
}

// InitializeLUKS2Container will initialize the partition at the specified devicePath as a new LUKS2 container. This can only
// be called on a partition that isn't mapped. The label for the new LUKS2 container is provided via the label argument.
//
// The initial master key used for unlocking the container is provided via the key argument, and must be a cryptographically secure
// 64-byte random number. The key should be protected by a hardware backed keystore, such as a TPM by using SealKeyToTPM. Note that
// "master key" in this context refers to the main key used to activate the volume, and is not the same as the LUKS volume key
// although they must be the same size.
//
// The container will be configured to encrypt data with AES-256 and XTS block cipher mode.
//
// On failure, this will return an error containing the output of the cryptsetup command.
//
// WARNING: This function is destructive. Calling this on an existing LUKS container will make the data contained inside of it
// irretrievable.
func InitializeLUKS2Container(devicePath, label string, key []byte) error {
	releaseLock, err := luks2.AcquireLock(devicePath, luks2.LockModeExclusive)
	if err != nil {
		return xerrors.Errorf("cannot acquire lock: %w", err)
	}
	defer releaseLock()

	if err := luks2.Format(devicePath, label, key, &luks2.KDFOptions{Master: true}); err != nil {
		return xerrors.Errorf("cannot format device: %w", err)
	}

	if err := luks2.SetKeyslotPriority(devicePath, 0, "prefer"); err != nil {
		return xerrors.Errorf("cannot set keyslot priority: %w", err)
	}

	if err := luks2.ImportToken(devicePath, makeTokenForKeyslot(masterSlotType, 0)); err != nil {
		return xerrors.Errorf("cannot add token: %w", err)
	}

	return nil
}

func setLUKS2ContainerKey(devicePath string, existingKey, newKey []byte, slotType string, kdf *luks2.KDFOptions) (int, error) {
	startInfo, err := luks2.DecodeHdr(devicePath)
	if err != nil {
		return 0, xerrors.Errorf("cannot decode LUKS2 header: %w", err)
	}

	oldTokenId := -1
	for k, v := range startInfo.Metadata.Tokens {
		if v.Type != tokenType {
			continue
		}
		if s := v.Params[slotTypeKey]; s == slotType {
			oldTokenId = int(k)
			break
		}
	}

	if err := luks2.AddKey(devicePath, existingKey, newKey, kdf); err != nil {
		return 0, xerrors.Errorf("cannot add new keyslot: %w", err)
	}

	updatedInfo, err := luks2.DecodeHdr(devicePath)
	if err != nil {
		return 0, xerrors.Errorf("cannot decode updated LUKS2 header: %w", err)
	}

	newSlotId := -1
	for s := range updatedInfo.Metadata.Keyslots {
		if _, ok := startInfo.Metadata.Keyslots[s]; !ok {
			newSlotId = int(s)
			break
		}
	}

	if newSlotId == -1 {
		return 0, errors.New("cannot determine new keyslot ID")
	}

	if err := luks2.ImportToken(devicePath, makeTokenForKeyslot(slotType, newSlotId)); err != nil {
		return 0, xerrors.Errorf("cannot add new token: %w", err)
	}

	if oldTokenId == -1 {
		return newSlotId, nil
	}

	if len(startInfo.Metadata.Tokens[oldTokenId].Keyslots) > 0 {
		if err := luks2.KillSlot(devicePath, int(startInfo.Metadata.Tokens[oldTokenId].Keyslots[0]), newKey); err != nil {
			return 0, xerrors.Errorf("cannot delete old keyslot: %w", err)
		}
	}

	if err := luks2.RemoveToken(devicePath, oldTokenId); err != nil {
		return 0, xerrors.Errorf("cannot delete old token: %w", err)
	}

	return newSlotId, nil
}

// SetLUKS2ContainerRecoveryKey sets the fallback recovery key on an existing LUKS2 container created with InitializeLUKS2Container.
// The recovery key is intended to be provided manually as a fallback mechanism that operates independently of any hardware backed
// keystore in the event that the key normally used for unlocking the container cannot be recovered. The devicePath argument specifies
// the device that contains the LUKS2 container. An existing key or passphrase for the container must be provided via the existingKey
// argument.
//
// The recovery key is provided via the recoveryKey argument and must be a cryptographically secure 16-byte random number.
//
// If the container already has a recovery key defined, then this function will delete the old recovery key once the new one has been
// set.
func SetLUKS2ContainerRecoveryKey(devicePath string, existingKey []byte, recoveryKey RecoveryKey) error {
	releaseLock, err := luks2.AcquireLock(devicePath, luks2.LockModeExclusive)
	if err != nil {
		return xerrors.Errorf("cannot acquire lock: %w", err)
	}
	defer releaseLock()

	// Use a KDF with an increased cost for the recovery key.
	_, err = setLUKS2ContainerKey(devicePath, existingKey, recoveryKey[:], recoverySlotType, &luks2.KDFOptions{IterTime: 5 * time.Second})
	return err
}

// SetLUKS2ContainerMasterKey sets the master key that is normally used for unlocking the LUKS2 container at devicePath. This
// function is intended to be used after the container has had to be unlocked with the recovery key because the original master
// key could not be recovered from the hardware backed keystore that is protecting it. It can also be used to set the master key
// for a container that is normally unlocked with a passphrase. An existing key or passphrase for the container must be provided
// via the existingKey argument.
//
// The new key is provided via the key argument and must be a cryptographically secure 64-byte random number.
//
// If the container already has a master key defined, then this function will delete the old master key once the new one has been set.
func SetLUKS2ContainerMasterKey(devicePath string, existingKey, newKey []byte) error {
	releaseLock, err := luks2.AcquireLock(devicePath, luks2.LockModeExclusive)
	if err != nil {
		return xerrors.Errorf("cannot acquire lock: %w", err)
	}
	defer releaseLock()

	slotId, err := setLUKS2ContainerKey(devicePath, existingKey, newKey, masterSlotType, &luks2.KDFOptions{Master: true})
	if err != nil {
		return err
	}

	if err := luks2.SetKeyslotPriority(devicePath, slotId, "prefer"); err != nil {
		return xerrors.Errorf("cannot set priority of new keyslot: %w", err)
	}

	return nil
}

// SealLUKS2MasterKeyToTPM seals the supplied master key to the storage hierarchy of the TPM. The supplied key must match any existing
// master key that wasn't added by SetLUKS2ContainerRecovery key for the specified device. The sealed key object and associated
// metadata that is required during early boot in order to unseal the key again and unlock the encrypted volume is written to a LUKS2
// token for the corresponding keyslot on the specified device. Additional data that is required in order to update the authorization
// policy for the sealed key is written to a file at the path specified by policyUpdatePath. This file must live inside the encrypted
// volume.
//
// This function requires knowledge of the authorization value for the storage hierarchy, which must be provided by calling
// TPMConnection.OwnerHandleContext().SetAuthValue() prior to calling this function. If the provided authorization value is incorrect,
// a AuthFailError error will be returned.
//
// If the TPM is not correctly provisioned, a ErrTPMProvisioning error will be returned. In this case, ProvisionTPM must be called
// before proceeding.
//
// This function expects there to be no file at the specified path. If the path references a file that already exists, a wrapped
// *os.PathError error will be returned with an underlying error of syscall.EEXIST. A wrapped *os.PathError error will be returned if
// the file cannot be created and opened for writing.
//
// This function will create a NV index at the handle specified by the PINHandle field of the params argument. If the handle is already
// in use, a TPMResourceExistsError error will be returned. In this case, the caller will need to either choose a different handle or
// undefine the existing one. The handle must be a valid NV index handle (MSO == 0x01), and the choice of handle should take in to
// consideration the reserved indices from the "Registry of reserved TPM 2.0 handles and localities" specification. It is recommended
// that the handle is in the block reserved for owner objects (0x01800000 - 0x01bfffff).
//
// The key will be protected with a PCR policy computed from the PCRProtectionProfile supplied via the PCRProfile field of the params
// argument.
//
// If an existing keyslot is protected by a TPM sealed key and it is not the keyslot that is associated with the supplied key, this
// function will remove it.
func SealLUKS2MasterKeyToTPM(tpm *TPMConnection, devicePath string, key []byte, policyUpdatePath string, params *KeyCreationParams) error {
	releaseLock, err := luks2.AcquireLock(devicePath, luks2.LockModeExclusive)
	if err != nil {
		return xerrors.Errorf("cannot acquire lock: %w", err)
	}
	defer releaseLock()

	info, err := luks2.DecodeHdr(devicePath)
	if err != nil {
		return xerrors.Errorf("cannot decode LUKS2 header: %w", err)
	}

	targetTokenId := -1
	for k, v := range info.Metadata.Tokens {
		if v.Type != tokenType {
			continue
		}
		if s := v.Params[slotTypeKey]; s == recoverySlotType {
			continue
		}
		if len(v.Keyslots) > 0 {
			if err := luks2.TestPassphrase(devicePath, v.Keyslots[0], key); err == nil {
				targetTokenId = int(k)
				break
			}
		}
	}

	if targetTokenId == -1 {
		return errors.New("cannot find matching master key")
	}

	existingTpmTokenId := -1
	for k, v := range info.Metadata.Tokens {
		if v.Type != tokenType {
			continue
		}
		if s := v.Params[slotTypeKey]; s == tpmSlotType {
			existingTpmTokenId = int(k)
			break
		}
	}

	var sealedKeyObject bytes.Buffer

	succeeded := true
	var policyUpdateFile *os.File
	if policyUpdatePath != "" {
		var err error
		policyUpdateFile, err = os.OpenFile(policyUpdatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return xerrors.Errorf("cannot create private data file: %w", err)
		}
		defer func() {
			policyUpdateFile.Close()
			if succeeded {
				return
			}
			os.Remove(policyUpdatePath)
		}()
	}

	if err := sealKeyToTPMCommon(tpm, key, &sealedKeyObject, policyUpdateFile, params); err != nil {
		return err
	}

	token := makeTokenForKeyslot(tpmSlotType, info.Metadata.Tokens[targetTokenId].Keyslots[0])
	token.Params["secboot-tpm-data"] = sealedKeyObject.Bytes()

	if err := luks2.ImportToken(devicePath, token); err != nil {
		return xerrors.Errorf("cannot import new token: %w", err)
	}

	if err := luks2.RemoveToken(devicePath, targetTokenId); err != nil {
		return xerrors.Errorf("cannot delete old token: %w", err)
	}

	if existingTpmTokenId != -1 && existingTpmTokenId != targetTokenId {
		if err := luks2.RemoveToken(devicePath, existingTpmTokenId); err != nil {
			return xerrors.Errorf("cannot delete old token: %w", err)
		}

		if len(info.Metadata.Tokens[existingTpmTokenId].Keyslots) > 0 {
			if err := luks2.KillSlot(devicePath, info.Metadata.Tokens[existingTpmTokenId].Keyslots[0], key); err != nil {
				return xerrors.Errorf("cannot delete old TPM key slot: %w", err)
			}
		}
	}

	succeeded = true
	return nil
}
