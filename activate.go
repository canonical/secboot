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
)

// ErrCannotActivate is returned from ActivateContext.ActivatePath if
// a storage container cannot be activated because there are no valid
// keyslots and / or there are no more passphrase, PIN or recovery key
// attempts remaining.
var ErrCannotActivate = errors.New("cannot activate: no valid keyslots and / or no more passphrase, PIN or recovery key tries remaining")

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
	return errors.Is(r.err, ErrInvalidPassphrase)
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

// activateOneContainerStateMachineState describes a state of
// the state machine, including a readable name and a callback function.
type activateOneContainerStateMachineState struct {
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

	stderr io.Writer // For writing error messages to.

	next activateOneContainerStateMachineState // The next state to run.

	err            error                            // The first fatal error for this statemachine
	status         ActivationStatus                 // Whether and how this container is activated.
	keyslotRecords map[string]*keyslotAttemptRecord // Keyslot specific status.
}

func newActivateOneContainerStateMachine(container StorageContainer, cfg activateConfig, stderr io.Writer) *activateOneContainerStateMachine {
	// Check whether we have a custom stderr using WithStderrLogger
	w, exists := ActivateConfigGet[io.Writer](cfg, stderrLoggerKey)
	if exists {
		stderr = w
	}

	m := &activateOneContainerStateMachine{
		container: container,
		cfg:       cfg,
		stderr:    stderr,
	}
	m.next.name = "init-external-key-attempts"
	m.next.fn = m.initExternalKeyAttempts

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
	var slots keyslotAttemptRecordSlice
	for _, slot := range m.keyslotRecords {
		if !slot.usable() {
			// Skipping this unusable keyslot.
			continue
		}
		if slot.info.Type() != KeyslotTypePlatform {
			continue
		}
		if slot.data.AuthMode() != AuthModeNone {
			// Skip this one
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
		m.next.fn = func(ctx context.Context) error {
			return m.addKeyringKeys(ctx, unlockKey, primaryKey)
		}
		m.next.name = "add-keyring-keys"
		return nil
	}

	// We didn't unlock with any keyslots that require no user authentication,
	// so try those that require PINs or passphrases, and recovery keys next.
	m.next.name = "try-with-user-auth-keyslots"
	m.next.fn = m.tryWithUserAuthKeyslots

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
		//passphraseSlots keyslotAttemptRecordSlice
		//pinSlots        keyslotAttemptRecordSlice
		recoverySlots keyslotAttemptRecordSlice
	)

	// Gather keyslots
	for _, slot := range m.keyslotRecords {
		if !slot.usable() {
			// Skipping this unusable keyslot.
			continue
		}
		if slot.info.Type() == KeyslotTypeRecovery {
			// We've found a recovery key
			recoverySlots = append(recoverySlots, slot)
			continue
		}
		if slot.info.Type() != KeyslotTypePlatform {
			// Skipping keyslot of unknown type. This should already
			// have an error set anyway.
			continue
		}

		// Look for keys that require a PIN or passphrase.
		switch slot.data.AuthMode() {
		case AuthModeNone:
			// Skip as we've already tried these
		//case AuthModePassphrase:
		// TODO: passphrase support
		//case AuthModePIN:
		// TODO: PIN support
		default:
			slot.err = &InvalidKeyDataError{fmt.Errorf("unknown user auth mode for keyslot: %s", slot.data.AuthMode())}
			fmt.Fprintf(m.stderr, "Error with keyslot %q: %v\n", slot.info.Name(), slot.err)
		}
	}

	// Sort everything by priority.
	//sort.Sort(passphraseSlots)
	//sort.Sort(pinSlots)
	sort.Sort(recoverySlots)

	// Get the value of WithAuthRequestorUserVisibleName, if used.
	name, _ := ActivateConfigGet[string](m.cfg, authRequestorUserVisibleNameKey)

	// Get the value of WithRecoveryKeyTries. This must be supplied and not zero
	// in order to use recovery keys.
	recoveryKeyTries, _ := ActivateConfigGet[uint](m.cfg, recoveryKeyTriesKey)
	// TODO: Get the equivalent values for PIN and passphrase

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
	if len(recoverySlots) > 0 {
		authType |= UserAuthTypeRecoveryKey
	}
	// TODO: Update authType for PIN / passphrase

	for recoveryKeyTries > 0 {
		// Update authTypeFlags
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
			if slot := m.tryRecoveryKeyslots(ctx, recoverySlots, recoveryKey); slot != nil {
				// Success!
				m.status = ActivationSucceededWithRecoveryKey
			}

		}

		if m.status == ActivationIncomplete {
			// We haven't unlocked yet, so try again.
			continue
		}

		// We have unlocked successfully.
		m.next.fn = func(ctx context.Context) error {
			return m.addKeyringKeys(ctx, DiskUnlockKey(recoveryKey[:]), PrimaryKey(nil))
		}
		m.next.name = "add-keyring-keys"
		return nil
	}

	// We have failed to unlock
	m.next.fn = nil
	m.next.name = ""

	return ErrCannotActivate
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
		slot.err = ErrInvalidPassphrase
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
		if _, err := addKeyToUserKeyring(unlockKey, m.container.Path(), KeyringKeyPurposePrimary, prefix); err != nil {
			fmt.Fprintln(m.stderr, "Cannot add primary key to user keyring: ", err)
		}
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
		err = fmt.Errorf("cannot complete state %q: %w", current.name, err)
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
	state  *ActivateState // used to track the status of activation
	cfg    activateConfig // a config built from the initial options
	stderr io.Writer      // Where to write errors to - os.Stderr but can be customized to go to an application logger.
}

// NewActivateContext returns a new ActivateContext. The optional state argument
// makes it possible to perform activation in multiple processes, permitting them
// to share state. The caller can supply options that are common to all calls to
// [ActivateContext.ActivatePath].
func NewActivateContext(state *ActivateState, opts ...ActivateOption) (*ActivateContext, error) {
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

	return out, nil
}

// ActivatePath unlocks the [StorageContainer] at the specified path. The caller can
// supply options that are specific to this invocation, but which inherit from those
// options already supplied to [NewActivateContext].
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

	// Procss options. These apply on top of those supplied to NewActivateContext.
	cfg := c.cfg.Clone()
	for _, opt := range opts {
		opt.ApplyToConfig(cfg)
	}

	// Create and run a state machine for this activation
	sm := newActivateOneContainerStateMachine(container, cfg, c.stderr)
	for sm.hasMoreWork() {
		if err := sm.runNextState(ctx); err != nil {
			return err
		}
	}

	return nil
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

	// TODO: When we retain activation state, mark the attempt for this storage
	// container as "deactivated" and record the supplied reason.

	return container.Deactivate(ctx)
}
