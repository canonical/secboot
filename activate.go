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
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"golang.org/x/sys/unix"
)

// ErrCannotActivate is returned from ActivateContext.ActivateContainer
// if a storage container cannot be activated because there are no valid
// keyslots and / or there are no more passphrase, PIN or recovery key
// attempts remaining.
var ErrCannotActivate = errors.New("cannot activate: no valid keyslots and / or no more passphrase, PIN or recovery key tries remaining")

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
	slot Keyslot  // The backend supplied Keyslot.
	data *KeyData // A cache of the decoded KeyData for platform keys.
	err  error    // The first error that occurred with this keyslot.
}

func (r *keyslotAttemptRecord) usable() bool {
	if r.err == nil {
		return true
	}
	return errors.Is(r.err, ErrInvalidPassphrase)
}

type keyslotAttemptRecordSlice []*keyslotAttemptRecord

func (s keyslotAttemptRecordSlice) Len() int {
	return len(s)
}

func (s keyslotAttemptRecordSlice) Less(i, j int) bool {
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

func (s keyslotAttemptRecordSlice) Swap(i, j int) {
	tmp := s[j]
	s[j] = s[i]
	s[i] = tmp
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
	// and those supplied to ActivateContext.ActivateContainer (which
	// inherits the global configuration).
	cfg activateConfig

	stderr io.Writer // For writing error messages to.

	next activateOneContainerStateMachineTask // The next state to run.

	err            error                            // The first fatal error for this statemachine
	status         ActivationStatus                 // Whether and how this container is activated.
	keyslotRecords map[string]*keyslotAttemptRecord // Keyslot specific status.
}

func newActivateOneContainerStateMachine(container StorageContainer, cfg activateConfig) *activateOneContainerStateMachine {
	// Check whether we have a custom stderr using WithStderrLogger
	stderr, exists := ActivateConfigGet[io.Writer](cfg, stderrLoggerKey)
	if !exists {
		stderr = osStderr
	}

	m := &activateOneContainerStateMachine{
		container:      container,
		cfg:            cfg,
		stderr:         stderr,
		keyslotRecords: make(map[string]*keyslotAttemptRecord),
	}
	m.next = activateOneContainerStateMachineTask{
		name: "init-external-key-attempts",
		fn:   m.initExternalKeyAttempts,
	}

	return m
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
			fmt.Fprintf(m.stderr, "Error with external key metadata %q: %v\n", slot.Name(), rec.err)

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
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, rec.err)

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
				fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, rec.err)
			}
			rec.data = kd
		case KeyslotTypeRecovery:
			// Nothing to do here
		default:
			rec.err = &InvalidKeyDataError{fmt.Errorf("invalid type %q for keyslot metadata", slot.Type())}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", name, rec.err)
		}

		if err := m.addKeyslotRecord(name, rec); err != nil {
			return fmt.Errorf("cannot add keyslot metadata %q: %w", name, err)
		}
	}

	return nil
}

func (m *activateOneContainerStateMachine) tryNoUserAuthKeyslots(ctx context.Context) error {
	var records keyslotAttemptRecordSlice
	for _, record := range m.keyslotRecords {
		if !record.usable() {
			// Skipping this unusable keyslot.
			continue
		}
		if record.slot.Type() != KeyslotTypePlatform {
			continue
		}
		if record.data.AuthMode() != AuthModeNone {
			// Skip this one
			continue
		}
		records = append(records, record)
	}
	// This sorts by keyslot priority.
	sort.Sort(records)

	for _, record := range records {
		unlockKey, primaryKey, err := record.data.RecoverKeys()
		if err != nil {
			record.err = fmt.Errorf("cannot recover keys from keyslot: %w", err)
			// XXX: Is it really appropriate to log this? Maybe as an alternative
			// to making it possible to override stderr, we should make it possible
			// for the application to provide a logger where we can log messages at
			// different levels.
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", record.slot.Name(), record.err)
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
			record.err = &InvalidKeyDataError{fmt.Errorf("cannot activate container with key recovered from keyslot metadata: %w", err)}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", record.slot.Name(), record.err)
			continue
		}

		// We have unlocked successfully.
		m.status = ActivationSucceededWithPlatformKey
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
		//passphraseSlotRecords keyslotAttemptRecordSlice
		//pinSlotRecords        keyslotAttemptRecordSlice
		recoverySlotRecords keyslotAttemptRecordSlice
	)

	// Gather keyslots
	for _, record := range m.keyslotRecords {
		if !record.usable() {
			// Skipping this unusable keyslot.
			continue
		}
		if record.slot.Type() == KeyslotTypeRecovery {
			// We've found a recovery key
			recoverySlotRecords = append(recoverySlotRecords, record)
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
			record.err = &InvalidKeyDataError{fmt.Errorf("unknown user auth mode for keyslot: %s", record.data.AuthMode())}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", record.slot.Name(), record.err)
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

		cred, err := authRequestor.RequestUserCredential(ctx, name, m.container.Path(), authType)
		if err != nil {
			return fmt.Errorf("cannot request user credential: %w", err)
		}

		// We have a user credential.
		// 1) TODO: Try it against every keyslot with a passphrase.
		// 2) TODO: See if it decodes as a PIN and try it against every keyslot with a passphrase.
		// 3) See if it decodes as a recovery key, and try it against every recovery keyslot.

		recoveryKey, err := ParseRecoveryKey(cred)
		if err == nil {
			// This is a valid recovery key
			recoveryKeyTries -= 1
			if slot := m.tryRecoveryKeyslots(ctx, recoverySlotRecords, recoveryKey); slot != nil {
				// Success!
				m.status = ActivationSucceededWithRecoveryKey
			}

		}

		if m.status == ActivationIncomplete {
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

func (m *activateOneContainerStateMachine) tryRecoveryKeyslots(ctx context.Context, slotRecords keyslotAttemptRecordSlice, recoveryKey RecoveryKey) Keyslot {
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
		record.err = ErrInvalidPassphrase
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
	if err := addKeyToUserKeyring(unlockKey, m.container, KeyringKeyPurposeUnlock, prefix); err != nil {
		fmt.Fprintln(m.stderr, "Cannot add unlock key to user keyring:", err)
	}
	if len(primaryKey) > 0 {
		if err := addKeyToUserKeyring(primaryKey, m.container, KeyringKeyPurposePrimary, prefix); err != nil {
			fmt.Fprintln(m.stderr, "Cannot add primary key to user keyring:", err)
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

func (m *activateOneContainerStateMachine) hasMoreWork() bool {
	return m.next.fn != nil
}

func (m *activateOneContainerStateMachine) runNextState(ctx context.Context) error {
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
		if !errors.Is(err, ErrCannotActivate) {
			err = fmt.Errorf("cannot complete state %q: %w", current.name, err)
		}
		m.err = err
		if m.status != ActivationIncomplete {
			panic(fmt.Sprintf("unexpected status %q on error %v", m.status, err))
		}
		m.status = ActivationFailed
	}

	return m.err
}

// ActivateContext maintains context related to [StorageContainer] activation
// during early boot. it is not safe to use from multiple goroutines.
type ActivateContext struct {
	state *ActivateState // used to track the status of activation
	cfg   activateConfig // a config built from the initial options
}

// NewActivateContext returns a new ActivateContext. The optional state argument
// makes it possible to perform activation in multiple processes, permitting them
// to share state. The caller can supply options that are common to all calls to
// [ActivateContext.ActivateContainer].
func NewActivateContext(state *ActivateState, opts ...ActivateContextOption) *ActivateContext {
	// state can be nil
	if state == nil {
		state = new(ActivateState)
	}

	// Process global options
	cfg := makeActivateConfig()
	for _, opt := range opts {
		opt.ApplyContextOptionToConfig(cfg)
	}

	return &ActivateContext{
		state: state,
		cfg:   cfg,
	}
}

// ActivateContainer unlocks the supplied [StorageContainer]. The caller can supply options
// that are specific to this invocation, but which inherit from those options already supplied
// to [NewActivateContext].
func (c *ActivateContext) ActivateContainer(ctx context.Context, container StorageContainer, opts ...ActivateOption) error {
	// Procss options. These apply on top of those supplied to NewActivateContext.
	cfg := c.cfg.Clone()
	for _, opt := range opts {
		opt.ApplyOptionToConfig(cfg)
	}

	// TODO: When we retain activation state, make sure we obtain the activation
	// status and keyslot errors from the state machine before returning.

	// Create and run a state machine for this activation
	sm := newActivateOneContainerStateMachine(container, cfg)
	for sm.hasMoreWork() {
		if err := sm.runNextState(ctx); err != nil {
			return err
		}
	}

	return nil
}

// DeactivateContainer locks the supplied [StorageContainer]. The caller can supply a reason
// for the container being locked again which will be added to the state.
func (c *ActivateContext) DeactivateContainer(ctx context.Context, container StorageContainer, reason DeactivationReason) error {
	// TODO: When we retain activation state, mark the attempt for this storage
	// container as "deactivated" and record the supplied reason.

	// TODO: This should remove any keys added to the keyring.

	return container.Deactivate(ctx)
}
