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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/snapcore/snapd/asserts"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/secboot/internal/luks2"
)

var (
	// ErrMissingCryptsetupFeature is returned from some functions that make
	// use of the system's cryptsetup binary, if that binary is missing some
	// required features.
	ErrMissingCryptsetupFeature = luks2.ErrMissingCryptsetupFeature

	luks2Activate   = luks2.Activate
	luks2Deactivate = luks2.Deactivate
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

type activateWithKeyDataError struct {
	k   *KeyData
	err error
}

func (e *activateWithKeyDataError) Error() string {
	return fmt.Sprintf("%s: %v", e.k.ReadableName(), e.err)
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
	model            SnapModel
	keyringPrefix    string

	authRequestor   AuthRequestor
	kdf             KDF
	passphraseTries int

	keys []*keyDataAndError
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

func (s *activateWithKeyDataState) tryActivateWithRecoveredKey(keyData *KeyData, key DiskUnlockKey, auxKey AuxiliaryKey) error {
	if s.model != SkipSnapModelCheck {
		authorized, err := keyData.IsSnapModelAuthorized(auxKey, s.model)
		switch {
		case err != nil:
			return xerrors.Errorf("cannot check if snap model is authorized: %w", err)
		case !authorized:
			return errors.New("snap model is not authorized")
		}
	}

	if err := luks2Activate(s.volumeName, s.sourceDevicePath, key); err != nil {
		return xerrors.Errorf("cannot activate volume: %w", err)
	}

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

func (s *activateWithKeyDataState) tryKeyDataAuthModePassphrase(k *KeyData, passphrase string) error {
	key, auxKey, err := k.RecoverKeysWithPassphrase(passphrase, s.kdf)
	if err != nil {
		return xerrors.Errorf("cannot recover key: %w", err)
	}

	return s.tryActivateWithRecoveredKey(k, key, auxKey)
}

func (s *activateWithKeyDataState) run() (success bool, err error) {
	numPassphraseKeys := 0

	// Try keys that don't require any additional authentication first
	for _, k := range s.keys {
		if k.AuthMode()&AuthModePassphrase > 0 {
			numPassphraseKeys += 1
		}

		if k.AuthMode() != AuthModeNone {
			continue
		}

		if err := s.tryKeyDataAuthModeNone(k.KeyData); err != nil {
			k.err = err
			continue
		}

		return true, nil
	}

	// Try keys that require a passphrase
	tries := s.passphraseTries
	var passphraseErr error

	for tries > 0 && numPassphraseKeys > 0 {
		tries -= 1

		// Request a passphrase first and then try each key with it. One downside of
		// this approach is that if there are multiple keys with different passphrases
		// or the passphrase is wrong for all keys, this will accelerate the rate at
		// which dictionary attack protections kick in for platforms that support that.
		// This shouldn't be an issue for standard configurations where there would be
		// a maximum of 2 keys with passphrases enabled (Ubuntu Core based desktop on
		// a UEFI+TPM platform with run+recovery and recovery-only protectors for
		// ubuntu-data).
		passphrase, err := s.authRequestor.RequestPassphrase(s.volumeName, s.sourceDevicePath)
		if err != nil {
			passphraseErr = xerrors.Errorf("cannot obtain passphrase: %w", err)
			continue
		}

		for _, k := range s.keys {
			if k.AuthMode()&AuthModePassphrase == 0 {
				continue
			}

			if k.err != nil && !xerrors.Is(k.err, ErrInvalidPassphrase) {
				// Skip keys that failed for anything other than an invalid passphrase.
				continue
			}

			if err := s.tryKeyDataAuthModePassphrase(k.KeyData, passphrase); err != nil {
				if !xerrors.Is(err, ErrInvalidPassphrase) {
					numPassphraseKeys -= 1
				}
				k.err = err
				continue
			}

			return true, nil
		}
	}

	// We've failed at this point
	return false, passphraseErr
}

func newActivateWithKeyDataState(volumeName, sourceDevicePath string, keyringPrefix string, model SnapModel, keys []*KeyData, authRequestor AuthRequestor, kdf KDF, passphraseTries int) *activateWithKeyDataState {
	s := &activateWithKeyDataState{
		volumeName:       volumeName,
		sourceDevicePath: sourceDevicePath,
		keyringPrefix:    keyringPrefixOrDefault(keyringPrefix),
		model:            model,
		authRequestor:    authRequestor,
		kdf:              kdf,
		passphraseTries:  passphraseTries}
	for _, k := range keys {
		s.keys = append(s.keys, &keyDataAndError{KeyData: k})
	}
	return s
}

func activateWithRecoveryKey(volumeName, sourceDevicePath string, authRequestor AuthRequestor, tries int, keyringPrefix string) error {
	if tries == 0 {
		return errors.New("no recovery key tries permitted")
	}

	var lastErr error

	for ; tries > 0; tries-- {
		lastErr = nil

		key, err := authRequestor.RequestRecoveryKey(volumeName, sourceDevicePath)
		if err != nil {
			lastErr = xerrors.Errorf("cannot obtain recovery key: %w", err)
			continue
		}

		if err := luks2Activate(volumeName, sourceDevicePath, key[:]); err != nil {
			lastErr = xerrors.Errorf("cannot activate volume: %w", err)
			continue
		}

		if err := keyring.AddKeyToUserKeyring(key[:], sourceDevicePath, keyringPurposeDiskUnlock, keyringPrefixOrDefault(keyringPrefix)); err != nil {
			fmt.Fprintf(os.Stderr, "secboot: Cannot add key to user keyring: %v\n", err)
		}

		break
	}

	return lastErr
}

type nullSnapModel struct{}

func (_ nullSnapModel) Series() string            { return "" }
func (_ nullSnapModel) BrandID() string           { return "" }
func (_ nullSnapModel) Model() string             { return "" }
func (_ nullSnapModel) Grade() asserts.ModelGrade { return "" }
func (_ nullSnapModel) SignKeyID() string         { return "" }

// SkipSnapModelCheck provides a mechanism to skip the snap device model
// check when calling one of the ActivateVolumeWith* functions.
var SkipSnapModelCheck SnapModel = nullSnapModel{}

// ActivateVolumeOptions provides options to the ActivateVolumeWith*
// family of functions.
type ActivateVolumeOptions struct {
	// PassphraseTries specifies the maximum number of times
	// that activation with a user passphrase should be attempted
	// before failing with an error and falling back to activating
	// with the recovery key (see RecoveryKeyTries).
	//
	// Setting this to zero disables activation with a user
	// passphrase - in this case, any protected keys that require
	// a passphrase are ignored and activation will fall back to
	// requesting a recovery key.
	//
	// For each passphrase attempt, the supplied passphrase is
	// tested against every protected key that requires a passphrase.
	//
	// The actual number of available passphrase attempts may be
	// limited by the platform to a number that is lower than this
	// value (eg, in the TPM case because of the current auth fail
	// counter value which means the dictionary attack protection
	// might be triggered first).
	//
	// It is ignored by ActivateVolumeWithRecoveryKey.
	PassphraseTries int

	// RecoveryKeyTries specifies the maximum number of times that
	// activation with the fallback recovery key should be
	// attempted.
	//
	// It is used directly by ActivateVolumeWithRecoveryKey and
	// indirectly with other methods upon failure, for example
	// in the case where no other keys can be recovered.
	//
	// Setting this to zero will disable attempts to activate with
	// the fallback recovery key.
	RecoveryKeyTries int

	// KeyringPrefix is the prefix used for the description of any
	// kernel keys created during activation.
	KeyringPrefix string

	// Model is the snap device model that will access the data
	// on the encrypted container. The ActivateVolumeWith* functions
	// will check that this model is authorized via the KeyData
	// binding before unlocking the encrypted container.
	//
	// The caller of the ActivateVolumeWith* API is responsible for
	// validating the associated model assertion and snaps.
	//
	// Set this to SkipSnapModelCheck to skip the check. It cannot
	// be left set as nil.
	//
	// It is ignored by ActivateVolumeWithRecoveryKey, and it is
	// ok to leave it set as nil in this case.
	Model SnapModel
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

// ActivateVolumeWithKeyData attempts to activate the LUKS encrypted container at
// sourceDevicePath and create a mapping with the name volumeName, using the
// supplied KeyData objects to recover the disk unlock key from the platform's
// secure device. This makes use of systemd-cryptsetup.
//
// If activation with the supplied KeyData objects fails, this function will
// attempt to activate it with the fallback recovery key instead. The fallback
// recovery key is requested via the supplied authRequestor. If an AuthRequestor
// is not supplied, an error will be returned if the fallback recovery key is
// required. The RecoveryKeyTries field of options specifies how many attemps to
// request and use the recovery key will be made before failing. If it is set to
// 0, then no attempts will be made to request and use the fallback recovery key.
//
// If either the PassphraseTries or RecoveryKeyTries fields of options are less
// than zero, an error will be returned. If the Model field of options is nil,
// an error will be returned.
//
// If the fallback recovery key is used for successfully for activation, an
// ErrRecoveryKeyUsed error will be returned.
//
// If activation fails, an error will be returned.
//
// If activation with one of the supplied KeyData objects succeeds (ie, no error
// is returned), then the supplied SnapModel is authorized to access the data on
// this volume.
func ActivateVolumeWithMultipleKeyData(volumeName, sourceDevicePath string, keys []*KeyData, authRequestor AuthRequestor, kdf KDF, options *ActivateVolumeOptions) error {
	if len(keys) == 0 {
		return errors.New("no keys provided")
	}
	if options.PassphraseTries < 0 {
		return errors.New("invalid PassphraseTries")
	}
	if options.RecoveryKeyTries < 0 {
		return errors.New("invalid RecoveryKeyTries")
	}
	if options.Model == nil {
		return errors.New("nil Model")
	}

	if (options.PassphraseTries > 0 || options.RecoveryKeyTries > 0) && authRequestor == nil {
		return errors.New("nil authRequestor")
	}
	if options.PassphraseTries > 0 && kdf == nil {
		return errors.New("nil kdf")
	}

	s := newActivateWithKeyDataState(volumeName, sourceDevicePath, options.KeyringPrefix, options.Model, keys, authRequestor, kdf, options.PassphraseTries)
	success, err := s.run()
	switch {
	case success:
		return nil
	default: // failed - try recovery key
		if rErr := activateWithRecoveryKey(volumeName, sourceDevicePath, authRequestor, options.RecoveryKeyTries, options.KeyringPrefix); rErr != nil {
			// failed with recovery key - return errors
			var kdErrs []error
			for _, e := range s.errors() {
				kdErrs = append(kdErrs, e)
			}
			if err != nil {
				kdErrs = append(kdErrs, err)
			}
			return &activateVolumeWithKeyDataError{kdErrs, rErr}
		}
		// succeeded with recovery key
		return ErrRecoveryKeyUsed
	}
}

// ActivateVolumeWithKeyData attempts to activate the LUKS encrypted container at
// sourceDevicePath and create a mapping with the name volumeName, using the
// supplied KeyData to recover the disk unlock key from the platform's secure
// device. This makes use of systemd-cryptsetup.
//
// If activation with the supplied KeyData fails, this function will attempt to
// activate it with the fallback recovery key instead. The fallback recovery key is
// requested via the supplied authRequestor. If an AuthRequestor is not supplied,
// an error will be returned if the fallback recovery key is required. The
// RecoveryKeyTries field of options specifies how many attemps to request and use
// the recovery key will be made before failing. If it is set to 0, then no attempts
// will be made to request and use the fallback recovery key.
//
// If either the PassphraseTries or RecoveryKeyTries fields of options are less
// than zero, an error will be returned. If the Model field of options is nil,
// an error will be returned.
//
// If the fallback recovery key is used for successfully for activation, an
// ErrRecoveryKeyUsed error will be returned.
//
// If activation fails, an error will be returned.
//
// If activation with the supplied KeyData object succeeds (ie, no error is returned),
// then the supplied SnapModel is authorized to access the data on this volume.
func ActivateVolumeWithKeyData(volumeName, sourceDevicePath string, key *KeyData, authRequestor AuthRequestor, kdf KDF, options *ActivateVolumeOptions) error {
	return ActivateVolumeWithMultipleKeyData(volumeName, sourceDevicePath, []*KeyData{key}, authRequestor, kdf, options)
}

// ActivateVolumeWithRecoveryKey attempts to activate the LUKS encrypted volume at
// sourceDevicePath and create a mapping with the name volumeName, using the fallback
// recovery key. This makes use of systemd-cryptsetup.
//
// The recovery key is requested via the supplied AuthRequestor. If an AuthRequestor
// is not supplied, an error will be returned. The RecoveryKeyTries field of options
// specifies how many attempts to request and use the recovery key will be made before
// failing.
//
// If the RecoveryKeyTries field of options is less than zero, an error will be
// returned.
func ActivateVolumeWithRecoveryKey(volumeName, sourceDevicePath string, authRequestor AuthRequestor, options *ActivateVolumeOptions) error {
	if authRequestor == nil {
		return errors.New("nil authRequestor")
	}
	if options.RecoveryKeyTries < 0 {
		return errors.New("invalid RecoveryKeyTries")
	}

	return activateWithRecoveryKey(volumeName, sourceDevicePath, authRequestor, options.RecoveryKeyTries, options.KeyringPrefix)
}

// ActivateVolumeWithKey attempts to activate the LUKS encrypted volume at
// sourceDevicePath and create a mapping with the name volumeName, using the
// provided key. This makes use of systemd-cryptsetup.
func ActivateVolumeWithKey(volumeName, sourceDevicePath string, key []byte, options *ActivateVolumeOptions) error {
	return luks2Activate(volumeName, sourceDevicePath, key)
}

// DeactivateVolume attempts to deactivate the LUKS encrypted volumeName.
// This makes use of systemd-cryptsetup.
func DeactivateVolume(volumeName string) error {
	return luks2Deactivate(volumeName)
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

	// KDFOptions sets the KDF options for the initial keyslot. If this
	// is nil then the defaults are used.
	KDFOptions *KDFOptions
}

func (o *InitializeLUKS2ContainerOptions) formatOpts() *luks2.FormatOptions {
	return &luks2.FormatOptions{
		MetadataKiBSize:     o.MetadataKiBSize,
		KeyslotsAreaKiBSize: o.KeyslotsAreaKiBSize,
		KDFOptions:          o.KDFOptions.luksOpts()}
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

	// Simplify things a bit
	// Use a reduced cost for the KDF. This is done because we have a high entropy key rather
	// than a low entropy passphrase. Setting a higher cost provides no security benefit but
	// does slow down unlocking. If an adversary is going to attempt to brute force this key,
	// then they could instead turn their attention to one of the other keys involved in the
	// protection of this key, some of which can be verified without running a KDF. For
	// example, with a TPM sealed object, you can verify the parent storage key's seed by
	// computing the key object's HMAC key and verifying the integrity value on the outer wrapper.
	defaultKdfOptions := &KDFOptions{TargetDuration: 100 * time.Millisecond}
	if options == nil {
		options = &InitializeLUKS2ContainerOptions{KDFOptions: defaultKdfOptions}
	} else if options.KDFOptions == nil {
		options.KDFOptions = defaultKdfOptions
	}

	if err := validateInitializeLUKS2Options(options); err != nil {
		return err
	}

	if err := luks2.Format(devicePath, label, key, options.formatOpts()); err != nil {
		return xerrors.Errorf("cannot format %s: %w", err)
	}

	if err := luks2.SetSlotPriority(devicePath, 0, luks2.SlotPriorityHigh); err != nil {
		return xerrors.Errorf("cannot change keyslot priority: %w", err)
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
func AddRecoveryKeyToLUKS2Container(devicePath string, key []byte, recoveryKey RecoveryKey, options *KDFOptions) error {
	if options == nil {
		options = &KDFOptions{}
	}
	return luks2.AddKey(devicePath, key, recoveryKey[:],
		&luks2.AddKeyOptions{
			KDFOptions: options.luksOpts(),
			Slot:       luks2.AnySlot})
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

	if err := luks2.KillSlot(devicePath, 0, recoveryKey[:]); err != nil {
		return xerrors.Errorf("cannot kill existing slot: %w", err)
	}

	// Use a reduced cost for the KDF. This is done because we have a high entropy key rather
	// than a low entropy passphrase. Setting a higher cost provides no security benefit but
	// does slow down unlocking. If an adversary is going to attempt to brute force this key,
	// then they could instead turn their attention to one of the other keys involved in the
	// protection of this key, some of which can be verified without running a KDF. For
	// example, with a TPM sealed object, you can verify the parent storage key's seed by
	// computing the key object's HMAC key and verifying the integrity value on the outer wrapper.
	options := luks2.AddKeyOptions{
		KDFOptions: luks2.KDFOptions{TargetDuration: 100 * time.Millisecond},
		Slot:       0}
	if err := luks2.AddKey(devicePath, recoveryKey[:], key, &options); err != nil {
		return xerrors.Errorf("cannot add key: %w", err)
	}

	if err := luks2.SetSlotPriority(devicePath, 0, luks2.SlotPriorityHigh); err != nil {
		return xerrors.Errorf("cannot change keyslot priority: %w", err)
	}

	return nil
}
