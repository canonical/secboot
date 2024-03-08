// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2022 Canonical Ltd
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
	"io"
	"os"
	"strconv"

	"github.com/snapcore/snapd/asserts"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luksview"
)

var (
	// ErrMissingCryptsetupFeature is returned from some functions that make
	// use of the system's cryptsetup binary, if that binary is missing some
	// required features.
	ErrMissingCryptsetupFeature = luks2.ErrMissingCryptsetupFeature

	luks2Activate        = luks2.Activate
	luks2AddKey          = luks2.AddKey
	luks2Deactivate      = luks2.Deactivate
	luks2Format          = luks2.Format
	luks2ImportToken     = luks2.ImportToken
	luks2KillSlot        = luks2.KillSlot
	luks2RemoveToken     = luks2.RemoveToken
	luks2SetSlotPriority = luks2.SetSlotPriority

	newLUKSView = luksview.NewView

	osStderr io.Writer = os.Stderr
)

const (
	defaultKeyslotName         = "default"
	defaultRecoveryKeyslotName = "default-recovery"
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

type keyCandidate struct {
	*KeyData
	slot int
	err  error
}

type activateWithKeyDataState struct {
	volumeName       string
	sourceDevicePath string
	model            SnapModel
	keyringPrefix    string

	authRequestor   AuthRequestor
	kdf             KDF
	passphraseTries int

	keys []*keyCandidate
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

func (s *activateWithKeyDataState) tryActivateWithRecoveredKey(key DiskUnlockKey, slot int, keyData *KeyData, auxKey PrimaryKey) error {
	model := s.model
	// Snap model checking is skipped for generation 2 keys regardless of the model argument.
	// Although a gen 1 key could fake the generation field which is unprotected to also
	// bypass the model version check, that will result in an umarshalling error later on.
	switch keyData.Generation() {
	case 1:
		if model == nil {
			return errors.New("nil Model for generation 1 key")
		}
	default:
		// Model authorization checking is skipped for version 2 keys and
		// up as it is now responsibility of the platform to verify the model.
		model = SkipSnapModelCheck
	}

	if model != SkipSnapModelCheck {
		authorized, err := keyData.IsSnapModelAuthorized(auxKey, model)
		switch {
		case err != nil:
			return xerrors.Errorf("cannot check if snap model is authorized: %w", err)
		case !authorized:
			return errors.New("snap model is not authorized")
		}
	}

	if err := luks2Activate(s.volumeName, s.sourceDevicePath, key, slot); err != nil {
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

func (s *activateWithKeyDataState) tryKeyDataAuthModeNone(k *KeyData, slot int) error {
	key, auxKey, err := k.RecoverKeys()
	if err != nil {
		return xerrors.Errorf("cannot recover key: %w", err)
	}

	return s.tryActivateWithRecoveredKey(key, slot, k, auxKey)
}

func (s *activateWithKeyDataState) tryKeyDataAuthModePassphrase(k *KeyData, slot int, passphrase string) error {
	key, auxKey, err := k.RecoverKeysWithPassphrase(passphrase, s.kdf)
	if err != nil {
		return xerrors.Errorf("cannot recover key: %w", err)
	}

	return s.tryActivateWithRecoveredKey(key, slot, k, auxKey)
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

		if err := s.tryKeyDataAuthModeNone(k.KeyData, k.slot); err != nil {
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

			if err := s.tryKeyDataAuthModePassphrase(k.KeyData, k.slot, passphrase); err != nil {
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

func newActivateWithKeyDataState(volumeName, sourceDevicePath string, keyringPrefix string, model SnapModel, keys []*keyCandidate, authRequestor AuthRequestor, kdf KDF, passphraseTries int) *activateWithKeyDataState {
	return &activateWithKeyDataState{
		volumeName:       volumeName,
		sourceDevicePath: sourceDevicePath,
		keyringPrefix:    keyringPrefixOrDefault(keyringPrefix),
		model:            model,
		authRequestor:    authRequestor,
		kdf:              kdf,
		passphraseTries:  passphraseTries,
		keys:             keys}
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

		if err := luks2Activate(volumeName, sourceDevicePath, key[:], luks2.AnySlot); err != nil {
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
func (_ nullSnapModel) Classic() bool             { return false }
func (_ nullSnapModel) Grade() asserts.ModelGrade { return "" }
func (_ nullSnapModel) SignKeyID() string         { return "" }

// SkipSnapModelCheck provides a mechanism to skip the snap device model
// check when calling ActivateVolumeWithKeyData.
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
	// on the encrypted container. The ActivateVolumeWithKeyData
	// function will check that this model is authorized via the KeyData
	// binding before unlocking the encrypted container.
	//
	// The caller of the ActivateVolumeWithKeyData API is responsible
	// for validating the associated model assertion and snaps.
	//
	// Set this to SkipSnapModelCheck to skip the check. It cannot
	// be left set as nil when calling ActivateVolumeWithKeyData.
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

// ErrRecoveryKeyUsed is returned from ActivateVolumeWithKeyData if the
// volume could not be activated with any platform protected keys but
// activation with the recovery key was successful.
var ErrRecoveryKeyUsed = errors.New("cannot activate with platform protected keys but activation with the recovery key was successful")

// ActivateVolumeWithKeyData attempts to activate the LUKS encrypted container at
// sourceDevicePath and create a mapping with the name volumeName, using one of
// the KeyData objects stored in the container's metadata area to recover the
// disk unlock key from the platform's secure device. This makes use of
// systemd-cryptsetup.
//
// External KeyData objects can be supplied via the keys argument, and these
// will be attempted first.
//
// If activation with all of the KeyData objects fails, this function will
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
// If activation with one of the KeyData objects succeeds (ie, no error is
// returned), then the supplied SnapModel is authorized to access the data on
// this volume.
func ActivateVolumeWithKeyData(volumeName, sourceDevicePath string, authRequestor AuthRequestor, kdf KDF, options *ActivateVolumeOptions, keys ...*KeyData) error {
	if options.PassphraseTries < 0 {
		return errors.New("invalid PassphraseTries")
	}
	if options.RecoveryKeyTries < 0 {
		return errors.New("invalid RecoveryKeyTries")
	}
	if (options.PassphraseTries > 0 || options.RecoveryKeyTries > 0) && authRequestor == nil {
		return errors.New("nil authRequestor")
	}
	if options.PassphraseTries > 0 && kdf == nil {
		return errors.New("nil kdf")
	}

	var candidates []*keyCandidate
	for _, key := range keys {
		candidates = append(candidates, &keyCandidate{KeyData: key, slot: luks2.AnySlot})
	}

	view, err := newLUKSView(sourceDevicePath, luks2.LockModeBlocking)
	if err != nil {
		fmt.Fprintf(osStderr, "secboot: cannot obtain LUKS2 header view: %v\n", err)
	} else {
		tokens := view.KeyDataTokensByPriority()
		for _, token := range tokens {
			if token.Data == nil {
				// Skip uninitialized token
				continue
			}

			r := &LUKS2KeyDataReader{
				name:   sourceDevicePath + ":" + token.Name(),
				Reader: bytes.NewReader(token.Data)}
			kd, err := ReadKeyData(r)
			if err != nil {
				fmt.Fprintf(osStderr, "secboot: cannot read keydata from token %s: %v\n", token.Name(), err)
				continue
			}

			candidates = append(candidates, &keyCandidate{KeyData: kd, slot: token.Keyslots()[0]})
		}
	}

	s := newActivateWithKeyDataState(volumeName, sourceDevicePath, options.KeyringPrefix, options.Model, candidates, authRequestor, kdf, options.PassphraseTries)
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
	return luks2Activate(volumeName, sourceDevicePath, key, luks2.AnySlot)
}

// DeactivateVolume attempts to deactivate the LUKS encrypted volumeName.
// This makes use of systemd-cryptsetup.
func DeactivateVolume(volumeName string) error {
	return luks2Deactivate(volumeName)
}

// InitializeLUKS2ContainerOptions carries options for initializing LUKS2
// containers.
type InitializeLUKS2ContainerOptions struct {
	// MetadataKiBSize sets the size of the metadata area in KiB. This
	//
	// MetadataKiBSize sets the size of the metadata area in KiB. 4KiB of
	// this is used for the fixed-size binary header, with the remaining
	// space being used for the JSON area. Setting this to zero causes
	// the container to be initialized with the default metadata area size.
	// If set to a non zero value, it must be a power of 2 between 16KiB
	// and 4MiB.
	MetadataKiBSize uint32

	// KeyslotsAreaKiBSize sets the size of the binary keyslot area in KiB.
	// Setting this to zero causes the container to be initialized with
	// the default keyslots area size. If set to a non-zero value, the
	// value must be a multiple of 4KiB up to a maximum of 128MiB.
	KeyslotsAreaKiBSize uint32

	// InitialKeyslotName sets the name that will be used to identify
	// the initial keyslot. If this is empty, then the name will be
	// set to "default".
	InitialKeyslotName string

	// InlineCryptoEngine set flag if to use Inline Crypto Engine
	InlineCryptoEngine bool
}

func (o *InitializeLUKS2ContainerOptions) formatOpts() *luks2.FormatOptions {
	return &luks2.FormatOptions{
		MetadataKiBSize:     o.MetadataKiBSize,
		KeyslotsAreaKiBSize: o.KeyslotsAreaKiBSize,

		// Use a minimal KDF - this is the minimum recommended by SP800-132 and the minimum
		// supported by cryptsetup. We have a high entropy key rather than a low-entropy
		// passphrase - the input key has the same entropy as the derived key, so there is
		// no security benefit to the KDF here but it does slow down unlocking. There currently
		// isn't a way to disable it, but it would be disabled if there were. If an adversary is
		// going to attempt to brute force unlocking, they could just target other keys with the
		// same or lower entropy, such as:
		// - the derived key which has the same entropy, by decrypting the keyslot and testing it
		//   against the stored digest.
		// - for the TPM case, the storage key's seed which is 16 bytes, by computing the sealed
		//   object's HMAC and testing it against the stored one.
		KDFOptions: luks2.KDFOptions{
			Type:            luks2.KDFTypePBKDF2,
			ForceIterations: 1000,
			Hash:            luks2.HashSHA256,
		},

		InlineCryptoEngine: o.InlineCryptoEngine}
}

// InitializeLUKS2Container will initialize the partition at the specified devicePath
// as a new LUKS2 container. This can only be called on a partition that isn't mapped.
// The label for the new LUKS2 container is provided via the label argument.
//
// The container will be configured to encrypt data with AES-256 and XTS block cipher
// mode.
//
// The initial key used for unlocking the container is provided via the key argument,
// and must be a cryptographically secure random number of at least 32-bytes.
//
// The initial keyslot will be created with the name specified in the
// InitialKeyslotName field of options. If this is empty, "default" will be used.
//
// The initial key should be protected by some platform-specific mechanism in order
// to create a KeyData object. The KeyData object can be saved to the
// keyslot using LUKS2KeyDataWriter.
//
// On failure, this will return an error containing the output of the cryptsetup command.
//
// WARNING: This function is destructive. Calling this on an existing LUKS container
// will make the data contained inside of it irretrievable.
func InitializeLUKS2Container(devicePath, label string, key DiskUnlockKey, options *InitializeLUKS2ContainerOptions) error {
	if len(key) < 32 {
		return fmt.Errorf("expected a key length of at least 256-bits (got %d)", len(key)*8)
	}

	// Use a reduced cost for the KDF. This is done because we have a high entropy key rather
	// than a low entropy passphrase. Setting a higher cost provides no security benefit but
	// does slow down unlocking. If an adversary is going to attempt to brute force this key,
	// then they could instead turn their attention to one of the other keys involved in the
	// protection of this key, some of which can be verified without running a KDF. For
	// example, with a TPM sealed object, you can verify the parent storage key's seed by
	// computing the key object's HMAC key and verifying the integrity value on the outer wrapper.
	if options == nil {
		var defaultOptions InitializeLUKS2ContainerOptions
		options = &defaultOptions
	}

	initialKeyslotName := options.InitialKeyslotName
	if initialKeyslotName == "" {
		initialKeyslotName = defaultKeyslotName
	}

	if err := luks2Format(devicePath, label, key, options.formatOpts()); err != nil {
		return xerrors.Errorf("cannot format: %w", err)
	}

	token := luksview.KeyDataToken{
		TokenBase: luksview.TokenBase{
			TokenKeyslot: 0,
			TokenName:    initialKeyslotName}}
	if err := luks2ImportToken(devicePath, &token, nil); err != nil {
		return xerrors.Errorf("cannot import token: %w", err)
	}

	if err := luks2SetSlotPriority(devicePath, 0, luks2.SlotPriorityHigh); err != nil {
		return xerrors.Errorf("cannot change keyslot priority: %w", err)
	}

	return nil
}

func removeOrphanedTokens(devicePath string, view *luksview.View) {
	for _, id := range view.OrphanedTokenIds() {
		luks2RemoveToken(devicePath, id)
	}
}

func addLUKS2ContainerKey(devicePath, keyslotName string, existingKey, newKey DiskUnlockKey, options *luks2.KDFOptions,
	newToken func(base *luksview.TokenBase) luks2.Token, priority luks2.SlotPriority) error {
	view, err := newLUKSView(devicePath, luks2.LockModeBlocking)
	if err != nil {
		return xerrors.Errorf("cannot obtain LUKS header view: %w", err)
	}

	if _, _, exists := view.TokenByName(keyslotName); exists {
		return errors.New("the specified name is already in use")
	}

	removeOrphanedTokens(devicePath, view)

	freeSlot := 0
	for _, slot := range view.UsedKeyslots() {
		if slot != freeSlot {
			break
		}
		freeSlot++
	}

	if err := luks2AddKey(devicePath, existingKey, newKey, &luks2.AddKeyOptions{KDFOptions: *options, Slot: freeSlot}); err != nil {
		return xerrors.Errorf("cannot add key: %w", err)
	}

	// XXX: If we fail between AddKey and ImportToken, then we end up with a
	//  used keyslot that cannot be identified and no way to roll back the
	//  interrupted transaction safely. Ideally we'd be able to add a key and
	//  token in a single atomic operation, but this isn't even something that
	//  is possible with the libcryptsetup API.
	//
	//  I have an idea for how to make this more resilient and avoid ending up
	//  in this state in the event of an interruption, but it adds a bit more
	//  complexity and is for a future PR, as it's a bit of an edge case. But
	//  it's something like this:
	//  - Select an unused keyslot ID.
	//  - Add a transient token associated with an existing keyslot (there will
	//    always be at least one in this context. A token has to be associated
	//    with an active slot at import time). The new token will reference the
	//    selected unused keyslot ID in a new field.
	//  - Create the keyslot at the new keyslot ID.
	//  - Import the proper token associated with the new keyslot.
	//  - Delete the transient token.
	//
	//  This should ensure we can always roll back an interrupted operation to
	//  add a new key (or complete it if we've imported the proper token). It's
	//  not fully atomic (no transaction consisting of multiple cryptsetup
	//  operations is), but that's ok - on Ubuntu Core, all changes to the
	//  LUKS container should go through secboot. If we have multiple processes
	//  that could make changes (eg, snapd and a hypothetical fdectl or something),
	//  then we can add some locking to serialize transactions.
	//
	// Or, we could propose an API to libcrypsetup and the corresponding changes
	// to cryptsetup instead to support adding a keyslot with an initial token in
	// a single atomic transaction ¯\_(ツ)_/¯

	tokenBase := luksview.TokenBase{
		TokenName:    keyslotName,
		TokenKeyslot: freeSlot}
	if err := luks2ImportToken(devicePath, newToken(&tokenBase), nil); err != nil {
		return xerrors.Errorf("cannot import token: %w", err)
	}

	if err := luks2SetSlotPriority(devicePath, freeSlot, priority); err != nil {
		return xerrors.Errorf("cannot change keyslot priority: %w", err)
	}

	return nil
}

func listLUKS2ContainerKeyNames(devicePath string, tokenType luks2.TokenType) ([]string, error) {
	view, err := newLUKSView(devicePath, luks2.LockModeBlocking)
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain LUKS header view: %w", err)
	}

	var names []string
	for _, name := range view.TokenNames() {
		token, _, _ := view.TokenByName(name)
		if token.Type() != tokenType {
			continue
		}
		names = append(names, name)
	}

	return names, nil
}

// AddLUKS2ContainerUnlockKey creates a keyslot with the specified name on
// the LUKS2 container at the specified path, and uses it to protect the master
// key with the supplied key. The created keyslot is one that will normally be
// used for unlocking the specified LUKS2 container.
//
// If the specified name is empty, the name "default" will be used.
//
// The new key should be a cryptographically strong random number of at least
// 32-bytes.
//
// If a keyslot with the supplied name already exists, an error will be returned.
// The keyslot must first be deleted with DeleteLUKS2ContainerKey or renamed
// with RenameLUKS2ContainerKey.
//
// In order to perform this action, an existing key must be supplied.
//
// The new key should be protected by some platform-specific mechanism in
// order to create a KeyData object. The KeyData object can be saved to the
// keyslot using LUKS2KeyDataWriter.
func AddLUKS2ContainerUnlockKey(devicePath, keyslotName string, existingKey, newKey DiskUnlockKey) error {
	if len(newKey) < 32 {
		return fmt.Errorf("expected a key length of at least 256-bits (got %d)", len(newKey)*8)
	}

	if keyslotName == "" {
		keyslotName = defaultKeyslotName
	}

	// Use a minimal KDF - this is the minimum recommended by SP800-132 and the minimum
	// supported by cryptsetup. We have a high entropy key rather than a low-entropy
	// passphrase - the input key has the same entropy as the derived key, so there is
	// no security benefit to the KDF here but it does slow down unlocking. There currently
	// isn't a way to disable it, but it would be disabled if there were. If an adversary is
	// going to attempt to brute force unlocking, they could just target other keys with the
	// same or lower entropy, such as:
	// - the derived key which has the same entropy, by decrypting the keyslot and testing it
	//   against the stored digest.
	// - for the TPM case, the storage key's seed which is 16 bytes, by computing the sealed
	//   object's HMAC and testing it against the stored one.
	options := luks2.KDFOptions{
		Type:            luks2.KDFTypePBKDF2,
		ForceIterations: 1000,
		Hash:            luks2.HashSHA256,
	}
	return addLUKS2ContainerKey(devicePath, keyslotName, existingKey, newKey, &options, func(base *luksview.TokenBase) luks2.Token {
		return &luksview.KeyDataToken{TokenBase: *base}
	}, luks2.SlotPriorityHigh)
}

// ListLUKS2ContainerUnlockKeyNames lists the names of keyslots on the specified
// LUKS2 container configured as normal unlock slots (the keys associated with
// these should be protected by the platform's secure device).
func ListLUKS2ContainerUnlockKeyNames(devicePath string) ([]string, error) {
	return listLUKS2ContainerKeyNames(devicePath, luksview.KeyDataTokenType)
}

// AddLUKS2ContainerRecoveryKey creates a fallback recovery keyslot with the
// specified name on the LUKS2 container at the specified path and uses it to
// protect the LUKS master key with the supplied recovery key. The keyslot can
// be used to unlock the container in scenarios where it cannot be unlocked
// using a platform protected key.
//
// If the specified name is empty, the name "default-recovery" will be used.
//
// The recovery key must be generated by a cryptographically strong random
// number source.
//
// If a keyslot with the supplied name already exists, an error will be returned.
// The keyslot must first be deleted with DeleteLUKS2ContainerKey or renamed
// with RenameLUKS2ContainerKey.
//
// In order to perform this action, an existing key must be supplied.
func AddLUKS2ContainerRecoveryKey(devicePath, keyslotName string, existingKey DiskUnlockKey, recoveryKey RecoveryKey) error {
	if keyslotName == "" {
		keyslotName = defaultRecoveryKeyslotName
	}

	// Use PBKDF2 with the current OWASP recommendations - 600000 iterations
	// and SHA256. The recovery key has an entropy of 16 bytes which is strong
	// and this is overkill really - this could be knocked down to minimal settings
	// if we have a 32 byte recovery key.
	options := luks2.KDFOptions{
		Type:            luks2.KDFTypePBKDF2,
		ForceIterations: 600000,
		Hash:            luks2.HashSHA256,
	}
	return addLUKS2ContainerKey(devicePath, keyslotName, existingKey, recoveryKey[:], &options, func(base *luksview.TokenBase) luks2.Token {
		return &luksview.RecoveryToken{TokenBase: *base}
	}, luks2.SlotPriorityNormal)
}

// ListLUKS2ContainerRecoveryKeyNames lists the names of keyslots on the specified
// LUKS2 container configured as recovery slots.
func ListLUKS2ContainerRecoveryKeyNames(devicePath string) ([]string, error) {
	return listLUKS2ContainerKeyNames(devicePath, luksview.RecoveryTokenType)
}

// DeleteLUKS2ContainerKey deletes the keyslot with the specified name from the
// LUKS2 container at the specified path. This will return an error if the container
// only has a single keyslot remaining.
func DeleteLUKS2ContainerKey(devicePath, keyslotName string) error {
	view, err := newLUKSView(devicePath, luks2.LockModeBlocking)
	if err != nil {
		return xerrors.Errorf("cannot obtain LUKS header view: %w", err)
	}

	token, id, exists := view.TokenByName(keyslotName)
	if !exists {
		return errors.New("no key with the specified name exists")
	}

	if len(view.TokenNames()) == 1 {
		// This is stricter than not permitting the deletion of the last keyslot
		// - it intentionally does not permit deleting the last secboot named
		// keyslot, even if the container has other keyslots that might have
		// been created outside of this package.
		return errors.New("cannot kill last remaining slot")
	}

	removeOrphanedTokens(devicePath, view)

	slot := token.Keyslots()[0]
	if err := luks2KillSlot(devicePath, slot); err != nil {
		return xerrors.Errorf("cannot kill existing slot %d: %w", slot, err)
	}

	// KillSlot will clear the keyslot field from the associated token so
	// that we can identify it as orphaned and complete the transaction in
	// the future if we are interrupted between KillSlot and RemoveToken.

	if err := luks2RemoveToken(devicePath, id); err != nil {
		return xerrors.Errorf("cannot remove existing token %d: %w", id, err)
	}

	return nil
}

// RenameLUKS2Container key renames the keyslot with the specified oldName on
// the LUKS2 container at the specified path.
func RenameLUKS2ContainerKey(devicePath, oldName, newName string) error {
	view, err := newLUKSView(devicePath, luks2.LockModeBlocking)
	if err != nil {
		return xerrors.Errorf("cannot obtain LUKS header view: %w", err)
	}

	removeOrphanedTokens(devicePath, view)

	token, id, exists := view.TokenByName(oldName)
	if !exists {
		return errors.New("no key with the specified name exists")
	}

	if _, _, exists := view.TokenByName(newName); exists {
		return errors.New("the new name is already in use")
	}

	var newToken luks2.Token

	switch t := token.(type) {
	case *luksview.KeyDataToken:
		newToken = &luksview.KeyDataToken{
			TokenBase: luksview.TokenBase{
				TokenKeyslot: t.TokenKeyslot,
				TokenName:    newName},
			Priority: t.Priority,
			Data:     t.Data}
	case *luksview.RecoveryToken:
		newToken = &luksview.RecoveryToken{
			TokenBase: luksview.TokenBase{
				TokenKeyslot: t.TokenKeyslot,
				TokenName:    newName}}
	default:
		return errors.New("cannot rename key with unexpected token type")
	}

	if err := luks2ImportToken(devicePath, newToken, &luks2.ImportTokenOptions{Id: id, Replace: true}); err != nil {
		return xerrors.Errorf("cannot import new token: %w", err)
	}

	return nil
}
