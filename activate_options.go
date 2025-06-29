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
	"encoding/json"
	"io"
)

// ActivateConfigGetter provides read-only access to configuration options
// that were added to [ActivateConfig] from [ActivateOption]s.
type ActivateConfigGetter interface {
	// Get is used to get the value of the specified key, if one exists.
	Get(key any) (value any, exists bool)
}

// ActivateConfig is used for gathering configuration options from [ActivateOption]s
// supplied to [NewActivateContext] or [ActivateContext.ActivatePath].
type ActivateConfig interface {
	ActivateConfigGetter

	// Set is used to set the value of the specified key to the specified value.
	// If value is nil, the key is erased from the config.
	Set(key, value any)
}

// ActivateOption represents an option that can be supplied to [NewActivateContext]
// or [ActivateContext.ActivatePath].
type ActivateOption interface {
	// ApplyToConfig is called to make changes to the supplied ActivateConfig
	ApplyToConfig(ActivateConfig)

	// PerContainer indicates whether this ActivateOption is only valid for
	// ActivateContext.ActivatePath.
	PerContainer() bool
}

type activateConfig map[any]any

func makeActivateConfig() activateConfig {
	return make(activateConfig)
}

func (c activateConfig) Clone() activateConfig {
	out := makeActivateConfig()
	for k, v := range c {
		out[k] = v
	}
	return out
}

// Get implements [ActivateConfig.Get], and returns the value of the specified key,
// which must be a comparable type. If a value for the specified key doesn't exist,
// (nil, false) will be returned.
func (c activateConfig) Get(key any) (val any, exists bool) {
	val, exists = c[key]
	return val, exists
}

// Set implements [ActivateConfig.Set]. The supplied key must be a comparable type,
// else it will panic. If the value is nil, the key will be deleted from the config.
// If the value is not nil, the supplied value will overwrite any existing one.
func (c activateConfig) Set(key, val any) {
	if val == nil {
		delete(c, key)
		return
	}
	c[key] = val
}

func zero[T any]() T {
	var z T
	return z
}

// ActivateConfigGet is a generic implementation of [ActivateConfig.Get]. If a value
// for the specified key doesn't exist, the zero value is returned along with false.
// If a value for the specified key exists but it is of the wrong type, this function
// will panic.
func ActivateConfigGet[V any, K comparable](c ActivateConfigGetter, key K) (val V, exists bool) {
	v, exists := c.Get(key)
	if !exists {
		return zero[V](), false
	}
	return v.(V), true
}

// activateConfigKey is the type of keys added to activateConfig by this package.
type activateConfigKey string

const (
	// activateStateCustomDataKey is used by WithActivateStateCustomData to
	// provide a way for the user of the activation API to supply arbitrary
	// JSON data.
	activateStateCustomDataKey activateConfigKey = "activate-state-custom-data"

	// externalKeyDataKey is used by WithExternalKeyDataOption to supply extra
	// key metadata that isn't part of the container header
	authRequestorKey activateConfigKey = "auth-requestor"

	// authRequestorUserVisibleNameKey is used by WithAuthRequestorUserVisibleName
	// to customize the name argument passed to AuthRequestor.RequestUserCredential.
	authRequestorUserVisibleNameKey activateConfigKey = "auth-requestor-user-visible-name"

	// externalKeyDataKey is used by WithExternalKeyDataOption to supply extra
	// key metadata that isn't part of the container header
	externalKeyDataKey activateConfigKey = "external-key-data"

	// keyringDescPrefixKey is used by WithKeyringDescriptionPrefix to customize the
	// prefix of the description for keys added to the kernel keyring during storage
	// container unlocking.
	keyringDescPrefixKey activateConfigKey = "keyring-desc-prefix"

	// nonFatalContainerBindingKey is used by WithNonFatalContainerBindingFailure.
	nonFatalContainerBindingFailureKey = "non-fatal-container-binding-failure"

	passphraseTriesKey  activateConfigKey = "passphrase-tries"
	pinTriesKey         activateConfigKey = "pin-tries"
	recoveryKeyTriesKey activateConfigKey = "recovery-key-tries"

	// stderrLoggerKey is used by WithStderrLogger to provide a way to override
	// os.Stderr so that anything normally logged to this descriptor can be
	// handled by the applications logging framework
	stderrLoggerKey activateConfigKey = "stderr-logger"
)

type genericOption[T any] struct {
	key          activateConfigKey
	val          T
	perContainer bool
}

func (o *genericOption[T]) ApplyToConfig(config ActivateConfig) {
	config.Set(o.key, o.val)
}

func (o *genericOption[T]) PerContainer() bool {
	return o.perContainer
}

// WithActivateStateCustomData can be supplied to [ActivateContext.ActivatePath] to
// permit the caller to supply arbitrary data that will appear in the
// [ContainerActivateState] associated with an activation.
func WithActivateStateCustomData(data json.RawMessage) ActivateOption {
	return &genericOption[json.RawMessage]{
		key:          activateStateCustomDataKey,
		val:          data,
		perContainer: true,
	}
}

type withAuthRequestorOption struct {
	req AuthRequestor
}

func (o *withAuthRequestorOption) ApplyToConfig(config ActivateConfig) {
	config.Set(authRequestorKey, o.req)
}

func (*withAuthRequestorOption) PerContainer() bool {
	return false
}

// WithAuthRequestor allows the caller to specify an instance of [AuthRequestor]
// when using the [ActivateContext] API. Without this, functionality that requires
// asking for user credentials will not work.
func WithAuthRequestor(req AuthRequestor) ActivateOption {
	return &withAuthRequestorOption{req: req}
}

// WithAuthRequestorUserVisibleName allows the caller to customize the
// name passed to AuthRequestor.RequestUserCredential. It can only be
// supplied as a per container option (to [ActivateContext.ActivatePath]).
func WithAuthRequestorUserVisibleName(name string) ActivateOption {
	return &genericOption[string]{
		key:          authRequestorUserVisibleNameKey,
		val:          name,
		perContainer: true,
	}
}

type withExternalKeyDataOption []*ExternalKeyData

func (o withExternalKeyDataOption) ApplyToConfig(config ActivateConfig) {
	config.Set(externalKeyDataKey, []*ExternalKeyData(o))
}

func (withExternalKeyDataOption) PerContainer() bool {
	return true
}

// WithExternalKeyData makes it possible for callers to [ActivateContext.ActivatePath]
// to supply extra key metadata that is not part of the associated [StorageContainer].
func WithExternalKeyData(keys ...*ExternalKeyData) ActivateOption {
	return withExternalKeyDataOption(keys)
}

// WithNonFatalContainerBindingFailure can be passed to [ActivateContext.ActivatePath]
// in order to permit unlocking of storage containers that are not "bound" as part of
// the same install. In this case, the container will be unlocked but a
// ErrContainerBindingFailure error will be returned.
//
// This option must not be used in run mode.
//
// It may be useful in a recovery mode, but if the ErrContainerBindingFailure error
// is returned from [ActivateContext.ActivatePath], then credentials that permit
// access to the system must not be trusted by the recovery system.
func WithNonFatalContainerBindingFailure() ActivateOption {
	return &genericOption[struct{}]{
		key:          nonFatalContainerBindingFailureKey,
		perContainer: true,
	}
}

// WithKeyringDescriptionPrefix permits the prefix in the description for keys
// added to the kernel keyring during storage container activation to be customized.
// The API that the OS uses to retrieve these keys [GetKeyFromKernel] searches for
// keys with a specific description format, and part of that description includes a
// prefix that can be customized using this option. Without this option, the default
// prefix is "ubuntu-fde".
//
// In order for the OS to be able to retrieve keys added during early boot, the prefix
// passed to [GetKeyFromKernel] must match the prefix passed to this option (or be
// empty if this option isn't used, in which case, the default prefix value is used).
func WithKeyringDescriptionPrefix(prefix string) ActivateOption {
	return &genericOption[string]{
		key: keyringDescPrefixKey,
		val: prefix,
	}
}

type withStderrLoggerOption struct {
	io.Writer
}

func (o *withStderrLoggerOption) ApplyToConfig(config ActivateConfig) {
	config.Set(stderrLoggerKey, o.Writer)
}

func (*withStderrLoggerOption) PerContainer() bool {
	return false
}

// WithStderrLogger allows the caller to customize the default [io.Writer]
// for which to log errors to (in this case, these are errors that aren't
// fatal enough to give up with the activation and return an error to the
// caller). The calling application can use this to integrate it with its
// standard logging framework.
//
// Note that writes to the supplied writer may happen from multiple
// gorountines. XXX(chrisccoulson) - should we serialize access to this
// rather than requiring the application to do it? In the normal case,
// were the stderr io.Wrtier is the default [os.File], then there is no
// locking to serialize the logging of messages, resulting in logging
// output that can be a bit of a mess.
func WithStderrLogger(w io.Writer) ActivateOption {
	return &withStderrLoggerOption{Writer: w}
}

// WithDiscardStderrLogger is a shortcut for WithStderrLogger(io.Discard).
func WithDiscardStderrLogger() ActivateOption {
	return WithStderrLogger(io.Discard)
}

// WithPassphraseTries defines how many attempts the user has to enter a
// correct passphrase.
func WithPassphraseTries(n uint) ActivateOption {
	return &genericOption[uint]{
		key: passphraseTriesKey,
		val: n,
	}
}

// WithPINTries defines how many attempts the user has to enter a correct PIN.
func WithPINTries(n uint) ActivateOption {
	return &genericOption[uint]{
		key: pinTriesKey,
		val: n,
	}
}

// WithRecoveryKeyTries defines how many attempts the user has to enter a
// correct recovery key.
func WithRecoveryKeyTries(n uint) ActivateOption {
	return &genericOption[uint]{
		key: recoveryKeyTriesKey,
		val: n,
	}
}
