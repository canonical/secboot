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
)

var (
	// ErrCannotActivate is returned from ActivateContext.ActivatePath if
	// a storage container cannot be activated because there are no valid
	// keyslots and / or there are no more passphrase, PIN or recovery key
	// attempts remaining.
	ErrCannotActivate = errors.New("cannot activate: no valid keyslots and / or no more passphrase, PIN or recovery key tries remaining")

	// ErrContainerBindingFailure is returned from ActivateContext.ActivatePath
	// if the storage container is not related to previously unlocked storage
	// containers (ie, they are not from the same install). This may happen as
	// the result of an adversary tampering with the system in an attempt to
	// access confidential data - see the comment for ActivateContext.ActivatePath.
	ErrContainerBindingFailure = errors.New("the container is not associated with previously unlocked containers")

	errInvalidPrimaryKey = errors.New("invalid primary key")
	errNoPrimaryKey      = errors.New("no primary key was obtained during activation")

	errInvalidRecoveryKey = errors.New("the supplied recovery key is incorrect")
)

type errorKeyslotInfo struct {
	slotType KeyslotType
	name     string
}

func (i *errorKeyslotInfo) Type() KeyslotType {
	return i.slotType
}

func (i *errorKeyslotInfo) Name() string {
	return i.name
}

func (i *errorKeyslotInfo) Priority() int {
	return 0
}

func (i *errorKeyslotInfo) Data() KeyDataReader {
	return nil
}

// keyslotAttemptRecord binds together information about a keyslot.
type keyslotAttemptRecord struct {
	info     KeyslotInfo // The backend supplied KeyslotInfo.
	data     *KeyData    // A cache of the decoded KeyData for platform keys.
	external bool        // Whether the KeyData was supplied externally.
	err      error       // The first error that occurred with this keyslot.
}

func (r *keyslotAttemptRecord) usable() bool {
	if r.err == nil {
		return true
	}

	// In general, a keyslot that has encountered an error becomes unusable,
	// with one exception being that if the error is a result of the user
	// supplying an incorrect credential (passphrase, PIN, or recovery key),
	// it should remain usable.
	var expectedUserAuthErr error
	switch {
	case r.info.Type() == KeyslotTypeRecovery:
		// Recovery keyslot
		expectedUserAuthErr = errInvalidRecoveryKey
	case r.info.Type() == KeyslotTypePlatform && r.data != nil && r.data.AuthMode() == AuthModePassphrase:
		// Passphrase keyslot
		expectedUserAuthErr = ErrInvalidPassphrase
	case r.info.Type() == KeyslotTypePlatform && r.data != nil && r.data.AuthMode() == AuthModeNone:
		// Automatic keyslot requiring no credential is unusable with any error
		return false
	default:
		// XXX: We should never reach here - I'm not sure whether we
		// should return an error, panic with an error or write
		// something to stderr. For now, returning that the keyslot
		// is unusable is the safe thing to do.
		return false
	}

	return errors.Is(r.err, expectedUserAuthErr)
}

type keyslotAttemptRecordSlice []*keyslotAttemptRecord

func (s keyslotAttemptRecordSlice) Len() int {
	return len(s)
}

func (s keyslotAttemptRecordSlice) Less(i, j int) bool {
	ri := s[i]
	rj := s[j]

	switch {
	case ri.external && !ri.external:
		return true
	case !ri.external && rj.external:
		return false
	case ri.info.Priority() > rj.info.Priority():
		return true
	default:
		return false
	}
}

func (s keyslotAttemptRecordSlice) Swap(i, j int) {
	tmp := s[j]
	s[j] = s[i]
	s[i] = tmp
}

func (s keyslotAttemptRecordSlice) hasUsable() bool {
	for _, slot := range s {
		if slot.usable() {
			return true
		}
	}
	return false
}

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
	// and those supplied to ActivateContext.ActivatePath (which inherits
	// the global configuration).
	cfg activateConfig

	stderr     io.Writer // For writing error messages to.
	primaryKey PrimaryKey
	isFirst    bool

	next activateOneContainerStateMachineTask // The next task to run.

	err               error                            // The first fatal error for this statemachine
	status            ActivationStatus                 // Whether and how this container is activated.
	activationKeyslot KeyslotInfo                      // On successful activation, the keyslot used.
	primaryKeyID      keyring.KeyID                    // If added to the keyring, the ID of the primary key.
	keyslotRecords    map[string]*keyslotAttemptRecord // Keyslot specific status.
}

func newActivateOneContainerStateMachine(container StorageContainer, cfg activateConfig, stderr io.Writer, primaryKey PrimaryKey, isFirst bool) *activateOneContainerStateMachine {
	// Check whether we have a custom stderr using WithStderrLogger
	w, exists := ActivateConfigGet[io.Writer](cfg, stderrLoggerKey)
	if exists {
		stderr = w
	}

	m := &activateOneContainerStateMachine{
		container:  container,
		cfg:        cfg,
		stderr:     stderr,
		primaryKey: primaryKey,
		isFirst:    isFirst,
	}
	m.next.name = "init-external-key-attempts"
	m.next.fn = m.initExternalKeyAttempts

	return m
}

func (m *activateOneContainerStateMachine) isContainerBindingFailureFatal() bool {
	_, nonFatal := ActivateConfigGet[struct{}](m.cfg, nonFatalContainerBindingFailureKey)
	return !nonFatal
}

func (m *activateOneContainerStateMachine) checkPrimaryKeyValid(primaryKey PrimaryKey) bool {
	if len(m.primaryKey) == 0 {
		// We haven't saved a primary key from an activation yet, so consider
		// all primary keys valid for now.
		return true
	}

	return subtle.ConstantTimeCompare(primaryKey, m.primaryKey) == 0
}

func (m *activateOneContainerStateMachine) addKeyslotRecord(name string, rec *keyslotAttemptRecord) error {
	if _, exists := m.keyslotRecords[name]; exists {
		return fmt.Errorf("duplicate keyslots with the name %q", name)
	}
	m.keyslotRecords[name] = rec
	return nil
}

// collect externally provided KeyData supplied via WithExternalKeyData.
func (m *activateOneContainerStateMachine) initExternalKeyAttempts(ctx context.Context) error {
	m.next.name = "init-keyslots-attemps"
	m.next.fn = m.initKeyslotAttempts

	// Find external keys supplied via WithExternalKeyData.
	ekd, exists := ActivateConfigGet[[]*ExternalKeyData](m.cfg, externalKeyDataKey)
	if !exists {
		// Option not supplied.
		return nil
	}

	for _, kd := range ekd {
		ki, err := newExternalKeyslotInfo(kd)
		if err != nil {
			rec := &keyslotAttemptRecord{
				info: &errorKeyslotInfo{
					slotType: KeyslotTypePlatform,
					name:     kd.Name,
				},
				external: true,
				err:      &InvalidKeyDataError{err},
			}
			fmt.Fprintf(m.stderr, "Error with external key with name %q: %v\n", kd.Name, rec.err)
			continue

			if err := m.addKeyslotRecord(kd.Name, rec); err != nil {
				return fmt.Errorf("cannot add external key metadata %q: %w", kd.Name, err)
			}
			continue
		}

		rec := &keyslotAttemptRecord{
			info:     ki,
			data:     kd.Key,
			external: true,
		}
		if err := m.addKeyslotRecord(kd.Name, rec); err != nil {
			return fmt.Errorf("cannot add external key metadata %q: %w", kd.Name, err)
		}
	}

	return nil
}

func (m *activateOneContainerStateMachine) initKeyslotAttempts(ctx context.Context) error {
	m.next.name = "try-no-user-auth-keyslots"
	m.next.fn = m.tryNoUserAuthKeyslots

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
		ki, err := r.ReadKeyslot(ctx, name)
		if err != nil {
			rec := &keyslotAttemptRecord{
				info: &errorKeyslotInfo{
					slotType: KeyslotTypeUnknown,
					name:     name,
				},
				err: &InvalidKeyDataError{fmt.Errorf("cannot read keyslot info: %w", err)},
			}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, rec.err)
			continue

			if err := m.addKeyslotRecord(name, rec); err != nil {
				return fmt.Errorf("cannot add keyslot metadata %q: %w", name, err)
			}
			continue
		}

		rec := &keyslotAttemptRecord{
			info: ki,
		}

		switch ki.Type() {
		case KeyslotTypePlatform:
			kd, err := ReadKeyData(ki.Data())
			if err != nil {
				rec.err = &InvalidKeyDataError{fmt.Errorf("cannot decode keyslot metadata: %w", err)}
				fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, rec.err)
			}
			rec.data = kd
		case KeyslotTypeRecovery:
			// Nothing to do here
		default:
			rec.err = &InvalidKeyDataError{fmt.Errorf("invalid type %q for keyslot metadata", ki.Type())}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, rec.err)
		}

		if err := m.addKeyslotRecord(name, rec); err != nil {
			return fmt.Errorf("cannot add keyslot metadata %q: %w", name, err)
		}
	}

	return nil
}

func (m *activateOneContainerStateMachine) tryNoUserAuthKeyslots(ctx context.Context) error {
	// If this isn't the first container being unlocked and we don't
	// have a primary key, then require use of the "plainkey" platform.
	// This will happen if a recovery key is used to unlock the first
	// container. See the documentation for ActivatePath.
	requirePlainkey := len(m.primaryKey) == 0 && !m.isFirst

	var slots keyslotAttemptRecordSlice
	for _, slot := range m.keyslotRecords {
		if !slot.usable() {
			// Skipping this unusable keyslot.
			continue
		}
		if slot.info.Type() != KeyslotTypePlatform {
			continue
		}
		if requirePlainkey && slot.data.PlatformName() != "plainkey" {
			// We require "plainkey" keyslots, so skip this one.
			continue
		}
		if slot.data.AuthMode() != AuthModeNone {
			// This one requires user auth, so skip this one.
			continue
		}
		slots = append(slots, slot)
	}
	// This sorts by keyslot priority.
	sort.Sort(slots)

	for _, slot := range slots {
		name := slot.info.Name()

		unlockKey, primaryKey, err := slot.data.RecoverKeys()
		if err != nil {
			slot.err = fmt.Errorf("cannot recover keys from keyslot: %w", err)
			// XXX: Is it really appropriate to log this? Maybe as an alternative
			// to making it possible to override stderr, we should make it possible
			// for the application to provide a logger where we can log messages at
			// different levels.
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, slot.err)
			continue
		}

		if !m.checkPrimaryKeyValid(primaryKey) {
			slot.err = &InvalidKeyDataError{errInvalidPrimaryKey}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, slot.err)
			if m.isContainerBindingFailureFatal() {
				continue
			}
		}

		if err := m.container.Activate(ctx, slot.info, unlockKey, m.cfg); err != nil {
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
			slot.err = &InvalidKeyDataError{fmt.Errorf("cannot activate container with key recovered from keyslot metadata: %w", err)}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, slot.err)
			continue
		}

		// We have unlocked successfully.
		m.status = ActivationSucceededWithPlatformKey
		m.activationKeyslot = slot.info

		m.next.fn = func(ctx context.Context) error {
			return m.addKeyringKeys(ctx, unlockKey, primaryKey)
		}
		m.next.name = "add-keyring-keys"
		return nil
	}

	// We didn't unlock with any keyslots that require no user authentication,
	// so try those that require PINs or passphrases, and recovery keys next.
	m.next.name = "try-with-user-auth-keyslots"
	m.next.fn = func(ctx context.Context) error {
		return m.tryWithUserAuthKeyslots(ctx, requirePlainkey)
	}
	return nil
}

func (m *activateOneContainerStateMachine) tryWithUserAuthKeyslots(ctx context.Context, requirePlainkey bool) error {
	// The caller must use WithAuthRequestor for this to work.
	authRequestor, exists := ActivateConfigGet[AuthRequestor](m.cfg, authRequestorKey)
	if !exists {
		// The caller didn't use WithAuthRequestor, so we're done now.
		fmt.Fprintln(m.stderr, "Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied")
		return ErrCannotActivate
	}

	var (
		passphraseSlots keyslotAttemptRecordSlice
		pinSlots        keyslotAttemptRecordSlice
		recoverySlots   keyslotAttemptRecordSlice
	)

	// Gather keyslots
	for _, slot := range m.keyslotRecords {
		if !slot.usable() {
			// Skipping this unusable keyslot.
			continue
		}
		if slot.info.Type() == KeyslotTypeRecovery {
			// We've found a recovery key.
			recoverySlots = append(recoverySlots, slot)
			continue
		}
		if slot.info.Type() != KeyslotTypePlatform {
			// Skipping keyslot of unknown type. This should already
			// have an error set anyway.
			continue
		}
		if requirePlainkey {
			// "plainkey" keyslots do not support PINs or passphrases
			continue
		}
		// Look for keys that require a PIN or passphrase.
		switch slot.data.AuthMode() {
		case AuthModeNone:
			// Skip as we've already tried these
		case AuthModePassphrase:
			passphraseSlots = append(passphraseSlots, slot)
		case AuthModePIN:
			pinSlots = append(pinSlots, slot)
		default:
			slot.err = &InvalidKeyDataError{fmt.Errorf("unknown user auth mode for keyslot: %s", slot.data.AuthMode())}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", slot.info.Name(), slot.err)
		}
	}

	// Sort everything by priority.
	sort.Sort(passphraseSlots)
	sort.Sort(pinSlots)
	sort.Sort(recoverySlots)

	// Get the value of WithAuthRequestorUserVisibleName, if used.
	name, _ := ActivateConfigGet[string](m.cfg, authRequestorUserVisibleNameKey)

	// Get the permitted number of tries for each authentication type.
	passphraseTries, _ := ActivateConfigGet[uint](m.cfg, passphraseTriesKey)
	pinTries, _ := ActivateConfigGet[uint](m.cfg, pinTriesKey)
	recoveryKeyTries, _ := ActivateConfigGet[uint](m.cfg, recoveryKeyTriesKey)

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

	var authType UserAuthType
	if len(passphraseSlots) > 0 {
		authType |= UserAuthTypePassphrase
	}
	if len(pinSlots) > 0 {
		authType |= UserAuthTypePIN
	}
	if len(recoverySlots) > 0 {
		authType |= UserAuthTypeRecoveryKey
	}

	for passphraseTries > 0 || pinTries > 0 || recoveryKeyTries > 0 {
		// Don't try a method where there are no more usable keyslots.
		if !passphraseSlots.hasUsable() {
			passphraseTries = 0
		}
		if !pinSlots.hasUsable() {
			pinTries = 0
		}

		// Update authTypeFlags
		if passphraseTries == 0 {
			// No more passphrase key tries are left.
			authType &^= UserAuthTypePassphrase
		}
		if passphraseTries == 0 {
			// No more PIN key tries are left.
			authType &^= UserAuthTypePIN
		}
		if recoveryKeyTries == 0 {
			// No more recovery key tries are left.
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
		// 1) Try it against every keyslot with a passphrase.
		// 2) See if it decodes as a PIN and try it against every keyslot with a passphrase.
		// 3) See if it decodes as a recovery key, and try it against every recovery keyslot.

		var (
			unlockKey  DiskUnlockKey
			primaryKey PrimaryKey
		)

		if passphraseTries > 0 {
			passphraseTries -= 1
			if uk, pk, slot := m.tryPassphraseKeyslots(ctx, passphraseSlots, cred); slot != nil {
				// Success!
				m.status = ActivationSucceededWithPlatformKey
				m.activationKeyslot = slot

				unlockKey = uk
				primaryKey = pk
			}
		}

		if m.status == activationIncomplete && pinTries > 0 {
			pin, err := ParsePIN(cred)
			if err == nil {
				// This is a valid PIN
				pinTries -= 1
				if uk, pk, slot := m.tryPINKeyslots(ctx, pinSlots, pin); slot != nil {
					// Success!
					m.status = ActivationSucceededWithPlatformKey
					m.activationKeyslot = slot

					unlockKey = uk
					primaryKey = pk
				}
			}
		}

		if m.status == activationIncomplete && recoveryKeyTries > 0 {
			recoveryKey, err := ParseRecoveryKey(cred)
			if err == nil {
				// This is a valid recovery key
				recoveryKeyTries -= 1
				if slot := m.tryRecoveryKeyslots(ctx, recoverySlots, recoveryKey); slot != nil {
					// Success!
					m.status = ActivationSucceededWithRecoveryKey
					m.activationKeyslot = slot

					unlockKey = DiskUnlockKey(recoveryKey[:])
				}
			}
		}

		if m.status == activationIncomplete {
			// We haven't unlocked yet, so try again.
			continue
		}

		// We have unlocked successfully.
		m.next.fn = func(ctx context.Context) error {
			return m.addKeyringKeys(ctx, unlockKey, primaryKey)
		}
		m.next.name = "add-keyring-keys"
		return nil
	}

	// We have failed to unlock
	m.next.fn = nil
	m.next.name = ""

	return ErrCannotActivate
}

func (m *activateOneContainerStateMachine) tryPassphraseKeyslots(ctx context.Context, slots keyslotAttemptRecordSlice, passphrase string) (DiskUnlockKey, PrimaryKey, KeyslotInfo) {
	for _, slot := range slots {
		name := slot.info.Name()

		unlockKey, primaryKey, err := slot.data.RecoverKeysWithPassphrase(passphrase)
		if err != nil {
			slot.err = fmt.Errorf("cannot recover keys from keyslot: %w", err)
			// XXX: Is it really appropriate to log this? Maybe as an alternative
			// to making it possible to override stderr, we should make it possible
			// for the application to provide a logger where we can log messages at
			// different levels.
			if !errors.Is(slot.err, ErrInvalidPassphrase) {
				fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, slot.err)
			}
			continue
		}

		if !m.checkPrimaryKeyValid(primaryKey) {
			slot.err = &InvalidKeyDataError{errInvalidPrimaryKey}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, slot.err)
			if m.isContainerBindingFailureFatal() {
				continue
			}
		}

		if err := m.container.Activate(ctx, slot.info, unlockKey, m.cfg); err != nil {
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
			slot.err = &InvalidKeyDataError{fmt.Errorf("cannot activate container with key recovered from keyslot metadata: %w", err)}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, slot.err)
			continue
		}

		// Unlocking succeeded with this keyslot
		return unlockKey, primaryKey, slot.info
	}

	// We were unable to unlock with any passphrase keyslot
	return nil, nil, nil
}

func (m *activateOneContainerStateMachine) tryPINKeyslots(ctx context.Context, slots keyslotAttemptRecordSlice, pin PIN) (DiskUnlockKey, PrimaryKey, KeyslotInfo) {
	for _, slot := range slots {
		name := slot.info.Name()

		unlockKey, primaryKey, err := slot.data.RecoverKeysWithPIN(pin)
		if err != nil {
			slot.err = fmt.Errorf("cannot recover keys from keyslot: %w", err)
			// XXX: Is it really appropriate to log this? Maybe as an alternative
			// to making it possible to override stderr, we should make it possible
			// for the application to provide a logger where we can log messages at
			// different levels.
			if !errors.Is(slot.err, ErrInvalidPIN) {
				fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, slot.err)
			}
			continue
		}

		if !m.checkPrimaryKeyValid(primaryKey) {
			slot.err = &InvalidKeyDataError{errInvalidPrimaryKey}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, slot.err)
			if m.isContainerBindingFailureFatal() {
				continue
			}
		}

		if err := m.container.Activate(ctx, slot.info, unlockKey, m.cfg); err != nil {
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
			slot.err = &InvalidKeyDataError{fmt.Errorf("cannot activate container with key recovered from keyslot metadata: %w", err)}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, slot.err)
			continue
		}

		// Unlocking succeeded with this keyslot
		return unlockKey, primaryKey, slot.info
	}

	// We were unable to unlock with any passphrase keyslot
	return nil, nil, nil
}

func (m *activateOneContainerStateMachine) tryRecoveryKeyslots(ctx context.Context, slots keyslotAttemptRecordSlice, recoveryKey RecoveryKey) KeyslotInfo {
	for _, slot := range slots {
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
		if err := m.container.Activate(ctx, slot.info, recoveryKey[:], m.cfg); err == nil {
			// Unlocking succeeded with this keyslot.
			slot.err = nil
			return slot.info
		}

		// The most likely failure here is an invalid key, so set the error for this keyslot
		// as such so that it will be communicated via ActivateState in the future.
		slot.err = errInvalidRecoveryKey
	}

	// We were unable to unlock with any recovery keyslot.
	return nil
}

func (m *activateOneContainerStateMachine) addKeyringKeys(ctx context.Context, unlockKey DiskUnlockKey, primaryKey PrimaryKey) error {
	m.next.fn = nil
	m.next.name = ""

	// Get the value supplied by WithKeyringDescriptionPrefix.
	prefix, _ := ActivateConfigGet[string](m.cfg, keyringDescPrefixKey)

	// We don't return an error if either of these fail because we don't
	// want failure to add keys to the keyring to mark activation of the
	// storage container as failed.
	if _, err := addKeyToUserKeyring(unlockKey, m.container.Path(), KeyringKeyPurposeUnlock, prefix); err != nil {
		fmt.Fprintln(m.stderr, "Cannot add unlock key to user keyring: ", err)
	}
	if len(primaryKey) > 0 {
		id, err := addKeyToUserKeyring(unlockKey, m.container.Path(), KeyringKeyPurposePrimary, prefix)
		if err != nil {
			fmt.Fprintln(m.stderr, fmt.Sprintf("cannot add primary key to keyring: %v", err))
		} else {
			m.primaryKeyID = id
			if len(m.primaryKey) == 0 {
				// This is the first primary key from a keyslot that
				// was used to successfully unlock a storage container,
				// so retain it in order for it to be used for cross-checking
				// with other containers.
				m.primaryKey = primaryKey
			}
		}
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

func (m *activateOneContainerStateMachine) activationState() (ContainerActivateState, error) {
	if m.hasMoreWork() {
		return ContainerActivateState{}, errors.New("state machine has not finished")
	}

	state := ContainerActivateState{
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
		state.Keyslot = m.activationKeyslot.Name()
	}

	for name, rec := range m.keyslotRecords {
		state.KeyslotErrors[name] = errorToKeyslotError(rec.err)
	}

	return state, nil
}

func (m *activateOneContainerStateMachine) hasMoreWork() bool {
	return m.next.fn != nil && m.err == nil
}

func (m *activateOneContainerStateMachine) runNextTask(ctx context.Context) error {
	if ctx.Err() != nil {
		// The supplied context is already canceled or expired in some way.
		return ctx.Err()
	}
	if m.err != nil {
		// A previous call to this state machine resulted in an unrecoverable error.
		return fmt.Errorf("error occurred during previous state: %w", m.err)
	}
	if m.next.fn == nil {
		return errors.New("no more work to do")
	}

	current := m.next
	if err := current.fn(ctx); err != nil {
		err = fmt.Errorf("cannot complete state %q: %w", current.name, err)
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
	state  *ActivateState // used to track the status of activation
	cfg    activateConfig // a config built from the initial options
	stderr io.Writer      // Where to write errors to - os.Stderr but can be customized to go to an application logger.

	primaryKey PrimaryKey
}

// NewActivateContext returns a new ActivateContext. The optional state argument
// makes it possible to perform activation in multiple processes, permitting them
// to share state. Note that ActivateContext usage must be serialized because state
// from the previous ActivateContext must propagate to the next one via the state
// argument. The caller can also supply options that are common to all calls to
// [ActivateContext.ActivatePath].
func NewActivateContext(ctx context.Context, state *ActivateState, opts ...ActivateOption) (*ActivateContext, error) {
	// state can be nil
	if state == nil {
		state = new(ActivateState)
	}

	// Process global options
	cfg := makeActivateConfig()
	for i, opt := range opts {
		if opt.PerContainer() {
			return nil, fmt.Errorf("option %d supplied to NewActivateContext should only be supplied to ActivateContext.ActivatePath", i)
		}
		opt.ApplyToConfig(cfg)
	}

	out := &ActivateContext{
		state:  state,
		cfg:    cfg,
		stderr: os.Stderr,
	}

	// Check whether we have a custom stderr.
	w, exists := ActivateConfigGet[io.Writer](cfg, stderrLoggerKey)
	if exists {
		out.stderr = w
	}

	// Check whether the supplied state has a primary key.
	if state.PrimaryKeyID != 0 {
		key, err := keyring.ReadKey(ctx, keyring.KeyID(state.PrimaryKeyID))
		if err != nil {
			return nil, fmt.Errorf("cannot obtain primary key from keyring: %w", err)
		}
		out.primaryKey = PrimaryKey(key)
	}

	// Ensure we have a map of states for each storage container.
	if state.Activations == nil {
		state.Activations = make(map[string]ContainerActivateState)
	}

	return out, nil
}

func (c *ActivateContext) updateStateOnActivationAttempt(sm *activateOneContainerStateMachine) {
	// We don't return errors from here because if we get to this
	// point, we have already successfully unlocked the storage
	// container. If we experience an error here, all this means
	// is that we fail to populate the primary key on the context
	// which will force activation of subsequent containers to
	// only use a "plainkey" key slot (see the documentation for
	// ActivatePath).

	if len(c.primaryKey) == 0 {
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
			c.state.PrimaryKeyID = int(primaryKeyID)
		}
	}

	state, err := sm.activationState()
	if err != nil {
		fmt.Fprintf(c.stderr, "Cannot obtain activation state associated with unlocking %s: %v\n", sm.container.Path(), err)
	}
	c.state.Activations[sm.container.Path()] = state
}

// ActivatePath unlocks the [StorageContainer] at the specified path. The caller can
// supply options that are specific to this invocation, but which inherit from those
// options already supplied to [NewActivateContext].
//
// If there are no keyslots that can be used to unlock the storage container, a
// ErrCannotActivate error is returned.
//
// Note that it is important that all unlocked storage containers are part of the
// same install to prevent an attack where an adversary replaces one storage
// container with another that contains their own compromised credentials, in order
// to use those credentials to gain access to confidential data on other storage
// containers that have keyslots which unlock automatically. This "binding" is
// checked in 1 of 2 ways:
//  1. The unlock key for each keyslot is derived from a primary key that is common
//     for all keyslots, and a keyslot unique key. As there is a cryptographic
//     binding between the unlock key and the primary key, then checking that the
//     primary keys associated with keyslots used to unlock all storage containers
//     are the same is sufficient to deterine that all unlocked storage containers
//     are related to the same install. Any keyslots with an unexpected primary key
//     will be dismissed as being unsuitable for unlocking the related storage
//     container. If the [WithNonFatalContainerBindingFailure] option is supplied,
//     a keyslot with an unexpected primary key can be used for unlocking, but in
//     this case a ErrContainerBindingFailure error will be returned.
//  2. If the first container is unlocked with a recovery key, then we don't have
//     a primary key to which we can compare keyslots used to unlock subsequent
//     containers. In this case, subsequent containers must be unlocked using a
//     keyslot based on the "plainkey" platform, as these keyslots are protected
//     using a key that must be stored in the first unlocked container. If unlocking
//     succeeds using a keyslot based on the "plainkey" platform, then this is
//     sufficient to determine that the storage container is part of the same install
//     as the first storage container. Note that "plainkey" keyslots also contain a
//     primary key, which can be used for cross-checking of subsequent containers.
func (c *ActivateContext) ActivatePath(ctx context.Context, path string, opts ...ActivateOption) error {
	// Obtain a StorageContainer from whatever backend handles
	// the suppied path.
	container, err := NewStorageContainer(ctx, path)
	switch {
	case errors.Is(err, ErrNoStorageContainer):
		// Return this error unwrapped - it's likely this storage container
		// referenced by the supplied path is not handled by any registered backend.
		return ErrNoStorageContainer
	case err != nil:
		return fmt.Errorf("cannot create StorageContainer instance: %w", err)
	}

	// Process options. These apply on top of those supplied to NewActivateContext.
	cfg := c.cfg.Clone()
	for _, opt := range opts {
		opt.ApplyToConfig(cfg)
	}

	// Create and run a state machine for this activation
	isFirst := len(c.state.Activations) == 0
	sm := newActivateOneContainerStateMachine(container, cfg, c.stderr, c.primaryKey, isFirst)

	var activateErr error
	for sm.hasMoreWork() {
		activateErr = sm.runNextTask(ctx)
		if activateErr != nil {
			break
		}
	}

	c.updateStateOnActivationAttempt(sm)

	if activateErr != nil {
		return activateErr
	}

	if !sm.isContainerBindingFailureFatal() {
		// Make sure the activation keyslot didn't fail the
		// primary key cross-check.
		for _, slot := range sm.keyslotRecords {
			if slot.info != sm.activationKeyslot {
				// This isn't the activation keyslot.
				continue
			}

			// This is the activation keyslot
			if errors.Is(err, errInvalidPrimaryKey) {
				return ErrContainerBindingFailure
			}
			break
		}
	}

	return nil
}

func (c *ActivateContext) updateStateOnDeactivation(container StorageContainer, reason DeactivationReason) {
	state, exists := c.state.Activations[container.Path()]
	if !exists {
		fmt.Fprintf(c.stderr, "No state for previously activated container %q\n", container.Path())
		return
	}

	state.Status = ActivationDeactivated
	state.DeactivateReason = reason

	c.state.Activations[container.Path()] = state
}

func (c *ActivateContext) DeactivatePath(ctx context.Context, path string, reason DeactivationReason) error {
	// Obtain a StorageContainer from whatever backend handles
	// the suppied path.
	container, err := NewStorageContainer(ctx, path)
	switch {
	case errors.Is(err, ErrNoStorageContainer):
		// Return this error unwrapped - it's likely this storage container
		// referenced by the supplied path is not handled by any registered backend.
		return ErrNoStorageContainer
	case err != nil:
		return fmt.Errorf("cannot create StorageContainer instance: %w", err)
	}

	if err := container.Deactivate(ctx); err != nil {
		return fmt.Errorf("cannot deactivate container: %w", err)
	}
	c.updateStateOnDeactivation(container, reason)

	return nil
}

// State returns a pointer to the current state. Note that this is a pointer
// to the state object used by this context, so it will be updated by calls
// to ActivatePath and DeactivatePath.
func (c *ActivateContext) State() *ActivateState {
	return c.state
}
