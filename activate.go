// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/snapcore/secboot/internal/keyring"
	"golang.org/x/sys/unix"
)

var (
	// ErrCannotActivate is returned from ActivateContext.ActivateContainer
	// if a storage container cannot be activated because there are no valid
	// keyslots and / or there are no more passphrase, PIN or recovery key
	// attempts remaining.
	ErrCannotActivate = errors.New("cannot activate: no valid keyslots and / or no more passphrase, PIN or recovery key tries remaining")

	errInvalidPrimaryKey = errors.New("invalid primary key")
	errNoPrimaryKey      = errors.New("no primary key was obtained during activation")

	errInvalidRecoveryKey = errors.New("the supplied recovery key is incorrect")
)

// errorKeyslot is used to represent a Keyslot in a keyslotAttemptRecord
// in the case where StorageContainerReader.ReadKeyslot returns an error.
type errorKeyslot struct {
	slotType KeyslotType
	name     string
}

func (i *errorKeyslot) Type() KeyslotType {
	return i.slotType
}

func (i *errorKeyslot) Name() string {
	return i.name
}

func (i *errorKeyslot) Priority() int {
	return 0
}

func (i *errorKeyslot) Data() KeyDataReader {
	return nil
}

// keyslotAttemptRecord binds together information about a keyslot.
type keyslotAttemptRecord struct {
	slot      Keyslot  // The backend supplied Keyslot.
	data      *KeyData // A cache of the decoded KeyData for platform keys.
	err       error    // The first error that occurred with this keyslot.
	errNumber int      // The number of the error, used for ordering.
}

func (r *keyslotAttemptRecord) usable() bool {
	if r.err == nil {
		return true
	}

	// In general, a keyslot that has encountered an error becomes unusable,
	// with one exception being that if the error is a result of the user
	// supplying an incorrect credential (passphrase, PIN, or recovery key),
	// it should remain usable.
	// TODO: Uncomment this when passphrase support is added.
	//var expectedUserAuthErr error
	switch {
	// XXX: Keep this commented out for now because we don't check recovery
	// keyslot usability once we have built the initial list of them.
	//case r.slot.Type() == KeyslotTypeRecovery:
	//	// Recovery keyslot
	//	expectedUserAuthErr = errInvalidRecoveryKey
	// TODO: Enable this when passphrase support is added. This is just here
	// for now as a reminder - there will be a branch for PIN keyslots as well.
	//case r.slot.Type() == KeyslotTypePlatform && r.data != nil && r.data.AuthMode() == AuthModePassphrase:
	//	// Passphrase keyslot
	//	expectedUserAuthErr = ErrInvalidPassphrase
	default:
		// Any other type of keyslot is unusable with any error.
		return false
	}

	// TODO: Uncomment this when passphrase support is added.
	//return errors.Is(r.err, expectedUserAuthErr)
}

type keyslotAttemptRecordPrioritySlice []*keyslotAttemptRecord

func (s keyslotAttemptRecordPrioritySlice) Len() int {
	return len(s)
}

func (s keyslotAttemptRecordPrioritySlice) Less(i, j int) bool {
	switch {
	case s[i].slot.Priority() != s[j].slot.Priority():
		// Order higher priority keyslots first.
		return s[i].slot.Priority() > s[j].slot.Priority()
	default:
		// Order keyslots with the same priority in
		// name order.
		return s[i].slot.Name() < s[j].slot.Name()
	}
}

func (s keyslotAttemptRecordPrioritySlice) Swap(i, j int) {
	tmp := s[j]
	s[j] = s[i]
	s[i] = tmp
}

type keyslotAttemptRecordErrorSlice []*keyslotAttemptRecord

func (s keyslotAttemptRecordErrorSlice) Len() int {
	return len(s)
}

func (s keyslotAttemptRecordErrorSlice) Less(i, j int) bool {
	return s[i].errNumber < s[j].errNumber
}

func (s keyslotAttemptRecordErrorSlice) Swap(i, j int) {
	tmp := s[j]
	s[j] = s[i]
	s[i] = tmp
}

type activateOneContainerStateMachineFlags int

const (
	// activatePermitRecoveryKey allows recovery keyslots to be used.
	// Note that platform keyslots are always permitted to be used.
	activatePermitRecoveryKey activateOneContainerStateMachineFlags = 1 << iota

	// activateRequrePlatformProtectedByStorageContainer is used to
	// require that platform keyslots are protected by platforms registered
	// with the PlatformProtectedByStorageContainer flag in order to
	// be used.
	activateRequirePlatformKeyProtectedByStorageContainer

	// activateCrossCheckPrimaryKey is used to require that the
	// primary key recovered from a platform keyslot is cross-checked
	// against a previously used primary key before it can be used
	// for unlocking.
	activateCrossCheckPrimaryKey
)

// activateOneContainerStateMachineTask describes a state of
// the state machine, including a readable name and a callback function.
type activateOneContainerStateMachineTask struct {
	name string
	fn   func(context.Context) error
}

// activateOneContainerStateMachine is a state machine for activating
// a single StorageContainer.
type activateOneContainerStateMachine struct {
	container StorageContainer // The associated storage contaier.

	// cfg is the configuration for this activation, including those
	// supplied to NewActivateContext (which apply to all activations),
	// and those supplied to ActivateContext.ActivateContainer (which
	// inherits the global configuration).
	cfg ActivateConfigGetter

	primaryKey PrimaryKey // The primary key obtained from a previous activation
	flags      activateOneContainerStateMachineFlags

	stderr io.Writer // For writing error messages to.

	next activateOneContainerStateMachineTask // The next task to run.

	err                   error                            // The first fatal error for this statemachine
	status                ActivationStatus                 // Whether and how this container is activated.
	activationKeyslotName string                           // On successful activation, the name of the keyslot used.
	primaryKeyID          keyring.KeyID                    // If added to the keyring, the ID of the primary key.
	keyslotRecords        map[string]*keyslotAttemptRecord // Keyslot specific status, keyed by keyslot name.
	keyslotErrCount       int                              // The number of keyslot errors.
}

func newActivateOneContainerStateMachine(container StorageContainer, cfg ActivateConfigGetter, primaryKey PrimaryKey, flags activateOneContainerStateMachineFlags) *activateOneContainerStateMachine {
	// Check whether we have a custom stderr using WithStderrLogger
	stderr, exists := ActivateConfigGet[io.Writer](cfg, stderrLoggerKey)
	if !exists {
		stderr = osStderr
	}

	m := &activateOneContainerStateMachine{
		container:      container,
		cfg:            cfg,
		primaryKey:     primaryKey,
		flags:          flags,
		stderr:         stderr,
		keyslotRecords: make(map[string]*keyslotAttemptRecord),
	}
	m.next = activateOneContainerStateMachineTask{
		name: "init-external-key-attempts",
		fn:   m.initExternalKeyAttempts,
	}

	return m
}

func (m *activateOneContainerStateMachine) setKeyslotError(rec *keyslotAttemptRecord, err error) {
	rec.err = err
	rec.errNumber = m.keyslotErrCount
	m.keyslotErrCount += 1

	if errors.Is(err, errInvalidRecoveryKey) || errors.Is(err, ErrInvalidPassphrase) {
		return
	}

	fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", rec.slot.Name(), err)
}

func (m *activateOneContainerStateMachine) checkPrimaryKeyValid(primaryKey PrimaryKey) bool {
	if m.flags&activateCrossCheckPrimaryKey == 0 {
		return true
	}

	return subtle.ConstantTimeCompare(primaryKey, m.primaryKey) == 1
}

func (m *activateOneContainerStateMachine) addKeyslotRecord(name string, rec *keyslotAttemptRecord) error {
	if _, exists := m.keyslotRecords[name]; exists {
		return fmt.Errorf("duplicate keyslots with the name %q", name)
	}
	m.keyslotRecords[name] = rec
	if rec.err != nil {
		rec.errNumber = m.keyslotErrCount
		m.keyslotErrCount += 1
		fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", rec.slot.Name(), rec.err)
	}
	return nil
}

// collect externally provided KeyData supplied via WithExternalKeyData.
func (m *activateOneContainerStateMachine) initExternalKeyAttempts(ctx context.Context) error {
	m.next = activateOneContainerStateMachineTask{
		name: "init-keyslots-attemps",
		fn:   m.initKeyslotAttempts,
	}

	// Find external keys supplied via WithExternalKeyData.
	external, exists := ActivateConfigGet[[]*ExternalKeyData](m.cfg, externalKeyDataKey)
	if !exists {
		// Option not supplied.
		return nil
	}

	for _, data := range external {
		slot := newExternalKeyslot(data)
		kd, err := ReadKeyData(slot.Data())
		if err != nil {
			rec := &keyslotAttemptRecord{
				slot: slot,
				err:  &InvalidKeyDataError{err: err},
			}
			if err := m.addKeyslotRecord(slot.Name(), rec); err != nil {
				return fmt.Errorf("cannot add external key metadata %q: %w", slot.Name(), err)
			}

			continue
		}

		rec := &keyslotAttemptRecord{
			slot: slot,
			data: kd,
		}
		if err := m.addKeyslotRecord(slot.Name(), rec); err != nil {
			return fmt.Errorf("cannot add external key metadata %q: %w", slot.Name(), err)
		}
	}

	return nil
}

func (m *activateOneContainerStateMachine) initKeyslotAttempts(ctx context.Context) error {
	m.next = activateOneContainerStateMachineTask{
		name: "try-no-user-auth-keyslots",
		fn:   m.tryNoUserAuthKeyslots,
	}

	r, err := m.container.OpenRead(ctx)
	if err != nil {
		return fmt.Errorf("cannot open storage container for reading: %w", err)
	}
	defer r.Close()

	names, err := r.ListKeyslotNames(ctx)
	if err != nil {
		return fmt.Errorf("cannot list keyslot names from StorageContainer: %w", err)
	}

	for _, name := range names {
		slot, err := r.ReadKeyslot(ctx, name)
		if err != nil {
			rec := &keyslotAttemptRecord{
				slot: &errorKeyslot{
					slotType: KeyslotTypeUnknown,
					name:     name,
				},
				err: &InvalidKeyDataError{fmt.Errorf("cannot read keyslot: %w", err)},
			}
			if err := m.addKeyslotRecord(name, rec); err != nil {
				return fmt.Errorf("cannot add keyslot metadata %q: %w", name, err)
			}
			continue
		}

		rec := &keyslotAttemptRecord{
			slot: slot,
		}

		switch slot.Type() {
		case KeyslotTypePlatform:
			kd, err := ReadKeyData(slot.Data())
			if err != nil {
				rec.err = &InvalidKeyDataError{fmt.Errorf("cannot decode keyslot metadata: %w", err)}
			}
			rec.data = kd
		case KeyslotTypeRecovery:
			// Nothing to do here
		default:
			rec.err = &InvalidKeyDataError{fmt.Errorf("invalid type %q for keyslot metadata", slot.Type())}
		}

		if err := m.addKeyslotRecord(name, rec); err != nil {
			return fmt.Errorf("cannot add keyslot metadata %q: %w", name, err)
		}
	}

	return nil
}

func (m *activateOneContainerStateMachine) tryNoUserAuthKeyslots(ctx context.Context) error {
	var records keyslotAttemptRecordPrioritySlice
	for _, record := range m.keyslotRecords {
		if !record.usable() {
			// Skipping this unusable keyslot.
			continue
		}
		if record.slot.Type() != KeyslotTypePlatform {
			continue
		}
		if m.flags&activateRequirePlatformKeyProtectedByStorageContainer > 0 {
			_, flags, err := RegisteredPlatformKeyDataHandler(record.data.PlatformName())
			if err != nil {
				// No handler registered for this platform
				m.setKeyslotError(record, ErrNoPlatformHandlerRegistered)
				continue
			}
			if flags&PlatformProtectedByStorageContainer == 0 {
				// We require keyslots protected by platforms with
				// this flag, so skip this one.
				continue
			}
		}
		if record.data.AuthMode() != AuthModeNone {
			// This one requires user auth, so skip this one.
			continue
		}
		records = append(records, record)
	}
	// This sorts by keyslot priority.
	sort.Sort(records)

	for _, record := range records {
		unlockKey, primaryKey, err := record.data.RecoverKeys()
		if err != nil {
			m.setKeyslotError(record, fmt.Errorf("cannot recover keys from keyslot: %w", err))
			continue
		}

		if !m.checkPrimaryKeyValid(primaryKey) {
			m.setKeyslotError(record, &InvalidKeyDataError{errInvalidPrimaryKey})
			continue
		}

		if err := m.container.Activate(ctx, record.slot, unlockKey, m.cfg); err != nil {
			// XXX: This could fail for any number of reasons, such as invalid supplied parameters,
			// but the current API doesn't have a way of communicating this and in the luks2
			// backend, systemd-cryptsetup only gives us an exit code of 1 regardless of whether
			// the key is wrong or an already active volume name is supplied, so we just assume
			// invalid data for now. I'd really like to do better than this though and distinguish
			// between the key being wrong or the caller providing incorrect options. Given how
			// little of systemd-cryptsetup's functionality we use, perhaps in the future we could
			// replace it by a simple C application that makes use of libcryptsetup and returns
			// useful information back to us via a combination of JSON output on stdout and / or
			// exit codes.
			m.setKeyslotError(record, &InvalidKeyDataError{fmt.Errorf("cannot activate container with key recovered from keyslot metadata: %w", err)})
			continue
		}

		// We have unlocked successfully.
		m.status = ActivationSucceededWithPlatformKey
		m.activationKeyslotName = record.slot.Name()

		m.next = activateOneContainerStateMachineTask{
			name: "add-keyring-keys",
			fn: func(ctx context.Context) error {
				return m.addKeyringKeys(ctx, unlockKey, primaryKey)
			},
		}
		return nil
	}

	// We didn't unlock with any keyslots that require no user authentication,
	// so try those that require PINs or passphrases, and recovery keys next.
	m.next = activateOneContainerStateMachineTask{
		name: "try-with-user-auth-keyslots",
		fn:   m.tryWithUserAuthKeyslots,
	}
	return nil
}

func (m *activateOneContainerStateMachine) tryWithUserAuthKeyslots(ctx context.Context) error {
	// The caller must use WithAuthRequestor for this to work.
	authRequestor, exists := ActivateConfigGet[AuthRequestor](m.cfg, authRequestorKey)
	if !exists {
		// The caller didn't use WithAuthRequestor, so we're done now.
		fmt.Fprintln(m.stderr, "Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied")
		return ErrCannotActivate
	}

	var (
		// Keep separate slices for different authentication types.
		// XXX: Future PRs will add passphrase + PIN support.
		//passphraseSlotRecords keyslotAttemptRecordPrioritySlice
		//pinSlotRecords        keyslotAttemptRecordPrioritySlice
		recoverySlotRecords keyslotAttemptRecordPrioritySlice
	)

	// Gather keyslots
	for _, record := range m.keyslotRecords {
		if !record.usable() {
			// Skipping this unusable keyslot.
			continue
		}
		if record.slot.Type() == KeyslotTypeRecovery {
			// We've found a recovery key
			if m.flags&activatePermitRecoveryKey > 0 {
				recoverySlotRecords = append(recoverySlotRecords, record)
			}
			continue
		}
		if record.slot.Type() != KeyslotTypePlatform {
			// Skipping keyslot of unknown type. This should already
			// have an error set anyway.
			continue
		}
		// Look for keys that require a PIN or passphrase.
		switch record.data.AuthMode() {
		case AuthModeNone:
			// Skip as we've already tried these
		//case AuthModePassphrase:
		// XXX: A future PR will add passphrase support
		//case AuthModePIN:
		// XXX: A future PR will add PIN support
		default:
			m.setKeyslotError(record, &InvalidKeyDataError{fmt.Errorf("unknown user auth mode for keyslot: %s", record.data.AuthMode())})
		}
	}

	// Sort everything by priority.
	// XXX: Future PRs will add passphrase + PIN support.
	//sort.Sort(passphraseSlotRecords)
	//sort.Sort(pinSlotRecords)
	sort.Sort(recoverySlotRecords)

	// Get the value of WithAuthRequestorUserVisibleName, if used.
	name, _ := ActivateConfigGet[string](m.cfg, authRequestorUserVisibleNameKey)

	// Get the value of WithRecoveryKeyTries. This must be supplied and not zero
	// in order to use recovery keys.
	recoveryKeyTries, _ := ActivateConfigGet[uint](m.cfg, recoveryKeyTriesKey)
	// TODO: Get the equivalent values for PIN and passphrase.

	// TODO: Obtain values for PIN, passphrase ratelimiting from options when this
	// is implemented. Rate limiting is tricky because it relies on us temporarily
	// removing flags from the authType passed to AuthRequestor.RequestUserCredential,
	// and then adding them back when the rate limiting expires. Right now, any change
	// to authType requires us to restart systemd-ask-password (assuming the systemd
	// implementation of AuthRequestor is used), which won't be a great experience if,
	// eg, the user is in the middle of entering a recovery key having just entered an
	// incorred PIN, when PIN becomes available again, requiring us to add back
	// UserAuthTypePIN to authType and restarting systemd-ask-password in order to
	// update the prompt - the result will be that the update to the prompt will cause
	// the user to lose what they've entered so far.
	//
	// Maybe rate limiting will require us to replace systemd-ask-password with
	// something that fits this user experience better in the future.

	// Determine the available authentication types.
	var authType UserAuthType
	if len(recoverySlotRecords) > 0 {
		authType |= UserAuthTypeRecoveryKey
	}
	// TODO: Update authType for PIN / passphrase

	// XXX: When passphrase + PIN support lands, this will loop on available
	// PIN + passphrase tries as well.
	for recoveryKeyTries > 0 {
		// Update authType flags
		// XXX: This code will make more sense once support for passphrases and PINs is in,
		// as what we're doing here is removing an auth type once the number of tries has
		// expired so that the user prompt can be updated.
		if recoveryKeyTries == 0 {
			// No more recovery key tries are left,
			authType &^= UserAuthTypeRecoveryKey
		}

		if authType == UserAuthType(0) {
			break
		}

		cred, err := authRequestor.RequestUserCredential(ctx, name, m.container.Path(), authType)
		if err != nil {
			return fmt.Errorf("cannot request user credential: %w", err)
		}

		// We have a user credential.
		// 1) TODO: Try it against every keyslot with a passphrase.
		// 2) TODO: See if it decodes as a PIN and try it against every keyslot with a passphrase.
		// 3) See if it decodes as a recovery key, and try it against every recovery keyslot.
		//
		// XXX: Remember that for PIN and passphrase keyslots, a primary key check must be
		// performed.

		recoveryKey, err := ParseRecoveryKey(cred)
		switch {
		case err != nil && authType == UserAuthTypeRecoveryKey:
			// We are only expecting a recovery key and the user supplied a badly
			// formatted one. We can log this to stderr and allow them another
			// attempt.
			// XXX: Maybe display a notice in Plymouth for this case in the
			// future.
			fmt.Fprintf(m.stderr, "Cannot parse recovery key: %v\n", err)
		case err != nil:
			// The user supplied credential isn't a valid recovery key, but it
			// could be a valid PIN or passphrase, so ignore the error in this
			// case.
		default:
			// This is a valid recovery key
			recoveryKeyTries -= 1
			if slot := m.tryRecoveryKeyslotsHelper(ctx, recoverySlotRecords, recoveryKey); slot != nil {
				// Success!
				m.status = ActivationSucceededWithRecoveryKey
				m.activationKeyslotName = slot.Name()
			}

		}

		if m.status == activationIncomplete {
			// We haven't unlocked yet, so try again.
			continue
		}

		// We have unlocked successfully.
		m.next = activateOneContainerStateMachineTask{
			name: "add-keyring-keys",
			fn: func(ctx context.Context) error {
				return m.addKeyringKeys(ctx, DiskUnlockKey(recoveryKey[:]), PrimaryKey(nil))
			},
		}
		return nil
	}

	// We have failed to unlock
	m.next = activateOneContainerStateMachineTask{}

	return ErrCannotActivate
}

func (m *activateOneContainerStateMachine) tryRecoveryKeyslotsHelper(ctx context.Context, slotRecords keyslotAttemptRecordPrioritySlice, recoveryKey RecoveryKey) Keyslot {
	for _, record := range slotRecords {
		// XXX: Not sure what to do with errors from Activate yet. The most common error
		// will be because the recovery key is wrong, but we have no way to know. The API
		// doesn't provide a way of communicating this type of information, and
		// systemd-cryptsetup which is used by the luks2 backend returns exit code 1 for all
		// errors. Because of this, it's not appropriate to mark the keyslot with an error
		// that makes it unusable, and it's probably not appropriate to log to stderr either.
		//
		// As mentioned in another comment, perhaps rather than writing error messages to stderr
		// and having an option to customize where stderr messages go, it might be better for us
		// to provide an option that allows us to integrate with the callers logging framework,
		// which can allow us to write messages at different log levels.
		//
		// Note that we don't check if the keyslot is usable here (calling slot.usable()), as
		// we did that when building the list of recovery keys and nothing we do to the list
		// of recovery keys will make them unusable.
		if err := m.container.Activate(ctx, record.slot, recoveryKey[:], m.cfg); err == nil {
			// Unlocking succeeded with this keyslot.
			record.err = nil
			return record.slot
		}

		// The most likely failure here is an invalid key, so set the error for this keyslot
		// as such so that it will be communicated via ActivateState in the future.
		m.setKeyslotError(record, errInvalidRecoveryKey)
	}

	// We were unable to unlock with any recovery keyslot.
	return nil
}

func (m *activateOneContainerStateMachine) addKeyringKeys(ctx context.Context, unlockKey DiskUnlockKey, primaryKey PrimaryKey) error {
	m.next = activateOneContainerStateMachineTask{}

	// Get the value supplied by WithKeyringDescriptionPrefix.
	prefix, _ := ActivateConfigGet[string](m.cfg, keyringDescPrefixKey)
	prefix = keyringPrefixOrDefault(prefix)

	// We don't return an error if either of these fail because we don't
	// want failure to add keys to the keyring to mark activation of the
	// storage container as failed.
	if _, err := addKeyToUserKeyring(unlockKey, m.container, KeyringKeyPurposeUnlock, prefix); err != nil {
		fmt.Fprintln(m.stderr, "Cannot add unlock key to user keyring:", err)
	}
	if len(primaryKey) > 0 {
		id, err := addKeyToUserKeyring(primaryKey, m.container, KeyringKeyPurposePrimary, prefix)
		switch {
		case err != nil:
			fmt.Fprintln(m.stderr, fmt.Sprintf("Cannot add primary key to user keyring: %v", err))
		case len(m.primaryKey) == 0:
			// This is the first primary key from a keyslot that
			// was used to successfully unlock a storage container,
			// so retain it in order for it to be used for cross-checking
			// with other containers.
			m.primaryKeyID = id
			m.primaryKey = primaryKey
		}
	}

	legacyDescPaths, exists := ActivateConfigGet[[]string](m.cfg, legacyKeyringKeyDescPathsKey)
	if !exists {
		return nil
	}

	containerPath := m.container.Path()
	var containerSt unix.Stat_t
	err := unixStat(containerPath, &containerSt)
	switch {
	case errors.Is(err, os.ErrNotExist):
		fmt.Fprintln(m.stderr, "Ignoring WithLegacyKeyringDescriptionPaths because the container path does not refer to a filesystem object")
		return nil
	case err != nil:
		fmt.Fprintln(m.stderr, "Cannot use WithLegacyKeyringDescriptionPaths:", &os.PathError{Op: "stat", Path: containerPath, Err: err})
		return nil
	case containerSt.Mode&unix.S_IFMT != unix.S_IFBLK:
		fmt.Fprintln(m.stderr, "Ignoring WithLegacyKeyringDescriptionPaths because the container is not a block device")
		return nil
	}

	addLegacyKey := func(path string) {
		var st unix.Stat_t
		err := unixStat(path, &st)
		switch {
		case errors.Is(err, os.ErrNotExist):
			fmt.Fprintf(m.stderr, "Ignoring WithLegacyKeyringDescriptionPaths path %q which does not exist\n", path)
			return
		case err != nil:
			fmt.Fprintf(m.stderr, "Cannot use WithLegacyKeyringDescriptionPaths path %q: %v\n", path, &os.PathError{Op: "stat", Path: path, Err: err})
			return
		case st.Mode&unix.S_IFMT != unix.S_IFBLK:
			fmt.Fprintf(m.stderr, "Ignoring WithLegacyKeyringDescriptionPaths path %q because it is not a block device\n", path)
			return
		case st.Rdev != containerSt.Rdev:
			fmt.Fprintf(m.stderr, "Ignoring WithLegacyKeyringDescriptionPaths path %q because it does not refer to the container block device\n", path)
			return
		}

		if err := addKeyToUserKeyringLegacy(unlockKey, path, KeyringKeyPurposeUnlock, prefix); err != nil {
			fmt.Fprintf(m.stderr, "Cannot add unlock key to user keyring with legacy path description %q: %v\n", path, err)
		}
		if len(primaryKey) > 0 {
			if err := addKeyToUserKeyringLegacy(primaryKey, path, keyringKeyPurposeAuxiliary, prefix); err != nil {
				fmt.Fprintf(m.stderr, "Cannot add primary key to user keyring with legacy path description %q: %v\n", path, err)
			}
		}
	}

	for _, path := range legacyDescPaths {
		addLegacyKey(path)
	}

	return nil
}

func (m *activateOneContainerStateMachine) primaryKeyInfo() (PrimaryKey, keyring.KeyID, error) {
	if m.hasMoreWork() {
		return nil, 0, errors.New("state machine has not finished")
	}

	if m.status != ActivationSucceededWithPlatformKey {
		return nil, 0, errNoPrimaryKey
	}

	return m.primaryKey, m.primaryKeyID, nil
}

func (m *activateOneContainerStateMachine) activationState() (*ContainerActivateState, error) {
	if m.hasMoreWork() {
		return nil, errors.New("state machine has not finished")
	}

	state := &ContainerActivateState{
		Status:        m.status,
		KeyslotErrors: make(map[string]KeyslotErrorType),
	}

	// Did the caller use the WithActivateStateCustomData option?
	customData, exists := ActivateConfigGet[json.RawMessage](m.cfg, activateStateCustomDataKey)
	if exists {
		state.CustomData = customData
	}

	// If unlocked, retrieve the name of the keyslot used.
	if m.status == ActivationSucceededWithPlatformKey || m.status == ActivationSucceededWithRecoveryKey {
		state.Keyslot = m.activationKeyslotName
	}

	var slotRecords keyslotAttemptRecordErrorSlice
	for name, rec := range m.keyslotRecords {
		if rec.err == nil {
			// Don't add keyslots that have no error.
			continue
		}
		state.KeyslotErrors[name] = errorToKeyslotError(rec.err)
		slotRecords = append(slotRecords, rec)
	}

	sort.Sort(slotRecords)
	for _, rec := range slotRecords {
		state.KeyslotErrorsOrder = append(state.KeyslotErrorsOrder, rec.slot.Name())
	}

	return state, nil
}

func (m *activateOneContainerStateMachine) hasMoreWork() bool {
	return m.next.fn != nil && m.err == nil
}

func (m *activateOneContainerStateMachine) runNextTask(ctx context.Context) error {
	if m.err != nil {
		// A previous call to this state machine resulted in an unrecoverable error.
		return fmt.Errorf("error occurred during previous state: %w", m.err)
	}
	if m.next.fn == nil {
		return errors.New("no more work to do")
	}

	current := m.next
	if err := current.fn(ctx); err != nil {
		if !errors.Is(err, ErrCannotActivate) {
			err = fmt.Errorf("cannot complete state %q: %w", current.name, err)
		}
		m.err = err
		if m.status != activationIncomplete {
			panic(fmt.Sprintf("unexpected status %q on error %v", m.status, err))
		}
		m.status = ActivationFailed
	}

	return m.err
}

// ActivateContext maintains context related to [StorageContainer] activation
// during early boot. It is not safe to use from multiple goroutines.
type ActivateContext struct {
	state *ActivateState // used to track the status of activation
	cfg   activateConfig // a config built from the initial options

	stderr io.Writer

	primaryKey PrimaryKey
}

// NewActivateContext returns a new ActivateContext. The optional state argument
// makes it possible to perform activation in multiple processes, permitting them
// to share state. Note that ActivateContext usage must be serialized because state
// from the previous ActivateContext must propagate to the next one via the state
// argument. The caller can supply options that are common to all calls to
// [ActivateContext.ActivateContainer].
func NewActivateContext(ctx context.Context, state *ActivateState, opts ...ActivateContextOption) (*ActivateContext, error) {
	// state can be nil
	if state == nil {
		state = new(ActivateState)
	}
	if state.Activations == nil {
		state.Activations = make(map[string]*ContainerActivateState)
	}

	// Perform some sanity checks on the supplied state.
	switch state.TotalActivatedContainers() {
	case 0:
		if state.PrimaryKeyID != 0 {
			return nil, errors.New("invalid state: \"primary-key-id\" set with no activated containers")
		}
	default:
		switch state.NumActivatedContainersWithPlatformKey() {
		case 0:
			if state.PrimaryKeyID != 0 {
				return nil, errors.New("invalid state: \"primary-key-id\" set with no containers activated with a platform keyslot")
			}
			if state.NumActivatedContainersWithRecoveryKey() == 0 {
				panic("unexpected state: total activated containers > 0 but none activated with platform or recovery keyslot")
			}
		default:
			if state.PrimaryKeyID == 0 {
				return nil, errors.New("invalid state: \"primary-key-id\" unset with one or more containers activated with a platform keyslot")
			}
		}
	}

	// Fetch the primary key from the keyring using the ID supplied by the state.
	var primaryKey PrimaryKey
	if state.PrimaryKeyID != 0 {
		key, err := keyring.ReadKey(ctx, keyring.KeyID(state.PrimaryKeyID))
		if err != nil {
			return nil, fmt.Errorf("cannot obtain primary key from keyring: %w", err)
		}
		primaryKey = PrimaryKey(key)
	}

	// Process global options
	cfg := makeActivateConfig()
	for _, opt := range opts {
		opt.ApplyContextOptionToConfig(cfg)
	}

	// Check whether we have a custom stderr using WithStderrLogger
	stderr, exists := ActivateConfigGet[io.Writer](cfg, stderrLoggerKey)
	if !exists {
		stderr = osStderr
	}

	return &ActivateContext{
		state:      state,
		cfg:        cfg,
		stderr:     stderr,
		primaryKey: primaryKey,
	}, nil
}

func (c *ActivateContext) updateStateOnActivationAttempt(sm *activateOneContainerStateMachine) {
	if c.state.PrimaryKeyID == 0 {
		primaryKey, primaryKeyID, err := sm.primaryKeyInfo()
		switch {
		case errors.Is(err, errNoPrimaryKey):
			// The activation either failed or used a recovery key.
			// Don't log this.
		case err != nil:
			// Log an unexpected error.
			fmt.Fprintf(c.stderr, "Cannot obtain primary key information when unlocking %s: %v\n", sm.container.Path(), err)
		default:
			c.primaryKey = primaryKey
			c.state.PrimaryKeyID = int32(primaryKeyID)
		}
	}

	state, err := sm.activationState()
	if err != nil {
		fmt.Fprintf(c.stderr, "Cannot obtain activation state associated with unlocking %s: %v\n", sm.container.Path(), err)
		c.state.Activations[sm.container.CredentialName()] = &ContainerActivateState{
			Status: ActivationFailed,
		}
		return
	}
	c.state.Activations[sm.container.CredentialName()] = state
}

// ActivateContainer unlocks the supplied [StorageContainer]. The caller can supply options
// that are specific to this invocation, but which inherit from those options already supplied
// to [NewActivateContext].
//
// If there are no keyslots that can be used to unlock the storage container, a
// ErrCannotActivate error is returned.
//
// Note that it is important that all unlocked storage containers are part of the same install
// to prevent an attack where an adversary replaces a storage container with one that contains
// their own credentials, in order to use those credentials to gain access to confidential
// data on another storage container that has keyslots which unlock automatically.
// This "binding" is enforced using 1 of 2 mechanisms:
//  1. As the unlock key for each keyslot is derived from a primary key that is common for all
//     keyslots, and a keyslot unique key, there is a cryptographic binding between the unlock
//     key and the primary key. If a keyslot is used successfully, then verifying that the
//     primary key matches the primary key from keyslots used to unlock other containers is
//     sufficient to determine that the storage containers are related to the same install.
//     Where a previous storage container has been unlocked using a platform keyslot, any
//     keyslots that do not have a matching primary key will be dismissed as being unsuitable
//     for unlocking its associated storage container.
//  2. If the first container is unlocked using a recovery key, then there is no primary key
//     to which keyslots from subsequent containers can be compared. In this case, subsequent
//     containers must either be unlocked using a recovery key, or must be unlocked using a
//     platform keyslot protected by a platform that is registered with the
//     PlatformProtectedByStorageContainer flag (the "plainkey" platform is registered with
//     this), as these keyslots are protected using a key that must be stored inside the
//     first unlocked storage container. If unlocking succeeds using a keyslot protected by
//     a platform registered with this flag, then this is sufficient to determine that the
//     storage container is part of the same install as the first container. The recovered
//     primary key can be used to check the binding of subsequent storage containers using
//     the first method.
func (c *ActivateContext) ActivateContainer(ctx context.Context, container StorageContainer, opts ...ActivateOption) error {
	// Process options. These apply on top of those supplied to NewActivateContext.
	cfg := c.cfg.Clone()
	for _, opt := range opts {
		opt.ApplyOptionToConfig(cfg)
	}

	// Create and run a state machine for this activation
	var flags activateOneContainerStateMachineFlags
	switch {
	case c.state.TotalActivatedContainers() == 0:
		// If this is the first container to be activated, permit either
		// a platform or recovery keyslot to be used.
		flags = activatePermitRecoveryKey
	case c.state.NumActivatedContainersWithPlatformKey() == 0:
		// If all storage containers have been unlocked with recovery keys,
		// then permit either a platform or recovery keyslot to be used.
		// The platform keyslot must be protected with a platform registered
		// with the PlatformProtectedByStorageContainer flag, which binds it
		// to one of the already opened storage containers. The already opened
		// storage containers are bound by the fact that the user knows the
		// recovery keys to them.
		flags = activatePermitRecoveryKey | activateRequirePlatformKeyProtectedByStorageContainer
	case c.state.NumActivatedContainersWithRecoveryKey() > 0:
		// A mix of platform keyslots and recovery keys have been used to
		// unlock previous storage containers. As the binding between these
		// has already been proven, via a combination of platform keys
		// protected by a platform registered with the
		// PlatformProtectedByStorageContainer flag and by knowledge of
		// recovery keys, permit unlocking with any type of keyslot.
		flags = activatePermitRecoveryKey | activateCrossCheckPrimaryKey
	default:
		// All storage containers so far have been unlocked with platform
		// keys. It is no longer safe to permit the use of a recovery key
		// because it is not possible to associate the container with others
		// that are already activated in this case.
		//
		// TODO: What happens if we genuinely hit this case? The only safe
		// way to handle this would be to deactivate existing containers and
		// require everything to be unlocked using recovery keys. Will add
		// a way to handle this case in a follow-up PR.
		flags = activateCrossCheckPrimaryKey
	}
	sm := newActivateOneContainerStateMachine(container, cfg, c.primaryKey, flags)
	for sm.hasMoreWork() {
		if ctx.Err() != nil {
			// The supplied context is already canceled or expired in some way.
			// Mark this container as failed. We don't call updateState here
			// to avoid logging the error returned from sm.primaryKeyInfo to
			// stderr.
			c.state.Activations[sm.container.CredentialName()] = &ContainerActivateState{
				Status:        ActivationFailed,
				KeyslotErrors: make(map[string]KeyslotErrorType),
			}
			return ctx.Err()
		}
		if err := sm.runNextTask(ctx); err != nil {
			c.updateStateOnActivationAttempt(sm)
			return err
		}
	}
	c.updateStateOnActivationAttempt(sm)

	return nil
}

func (c *ActivateContext) updateStateOnDeactivation(container StorageContainer, reason DeactivationReason) {
	state, exists := c.state.Activations[container.CredentialName()]
	if !exists {
		state = new(ContainerActivateState)
		c.state.Activations[container.CredentialName()] = state
	}

	state.Status = ActivationDeactivated
	state.Keyslot = ""
	state.DeactivateReason = reason
}

// DeactivateContainer locks the supplied [StorageContainer]. The caller can supply a reason
// for the container being locked again which will be added to the state.
func (c *ActivateContext) DeactivateContainer(ctx context.Context, container StorageContainer, reason DeactivationReason) error {
	// TODO: This should remove any keys added to the keyring.

	if err := container.Deactivate(ctx); err != nil {
		return err
	}
	c.updateStateOnDeactivation(container, reason)

	return nil
}

// State returns a pointer to the current state. Note that this is a pointer
// to the state object used by this context, so it will be updated by calls
// to ActivateContainer and DeactivateContainer.
func (c *ActivateContext) State() *ActivateState {
	return c.state
}
