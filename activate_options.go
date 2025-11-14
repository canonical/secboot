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
// that were added to a [ActivateConfig].
type ActivateConfigGetter interface {
	// Get is used to get the value of the specified key, if one exists.
	Get(key any) (value any, exists bool)
}

// ActivateConfig is used for gathering configuration options from
// [ActivateContextOption]s supplied to [NewActivateContext] or [ActivateOption]s
// supplied to [ActivateContext.ActivateContainer].
type ActivateConfig interface {
	ActivateConfigGetter

	// Set is used to set the value of the specified key to the specified value.
	// If value is nil, the key is erased from the config.
	Set(key, value any)
}

// ActivateOption represents an option that can be supplied to
// [ActivateContext.ActivateContainer].
type ActivateOption interface {
	// ApplyOptionToConfig is called to make changes to the supplied ActivateConfig.
	ApplyOptionToConfig(ActivateConfig)
}

// ActivateContextOption represents an option that can be supplied to
// [NewActivateContext] or [ActivateContext.ActivateContainer].
type ActivateContextOption interface {
	ActivateOption

	// ApplyContextOptionToConfig is called to make changes to the supplied ActivateConfig.
	ApplyContextOptionToConfig(ActivateConfig)
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

	// authRequestorKey is used by WithAuthRequestor to supply an AuthRequestor
	// implementation.
	authRequestorKey activateConfigKey = "auth-requestor"

	// authRequestorUserVisibleNameKey is used by WithAuthRequestorUserVisibleName
	// to customize the name argument passed to AuthRequestor.RequestUserCredential.
	authRequestorUserVisibleNameKey activateConfigKey = "auth-requestor-user-visible-name"

	// externalKeyData is used by WithExternalKeyData and WithExternalKeyDataFromReader
	// to supply extra key metadata that isn't part of the container header.
	externalKeyDataKey activateConfigKey = "external-key-data"

	// externalUnlockKey is used by WithExternalUnlockKey to supply an externally
	// recovered unlock key that can be used to unlock a container.
	externalUnlockKeyKey activateConfigKey = "external-unlock-key"

	// keyringDescPrefixKey is used by WithKeyringDescriptionPrefix to customize the
	// prefix of the description for keys added to the kernel keyring during storage
	// container unlocking.
	keyringDescPrefixKey activateConfigKey = "keyring-desc-prefix"

	// legacyKeyringKeyDescPathsKey is used by WithLegacyKeyringKeyDescriptionPaths
	// to specify block device paths to use to add legacy keyring keys to maintain
	// compatibility with older snapd versions.
	legacyKeyringKeyDescPathsKey activateConfigKey = "legacy-keyring-key-desc-paths"

	// passphraseTriesKey is used by WithPassphraseTries to specify the maximum
	// number of passphrase attempts.
	passphraseTriesKey activateConfigKey = "passphrase-tries"

	// recoveryKeyTriesKey is used by WithRecoveryKeyTries to specify the maximum
	// number of recovery key attempts.
	recoveryKeyTriesKey activateConfigKey = "recovery-key-tries"

	// stderrLoggerKey is used by WithStderrLogger to provide a way to override
	// os.Stderr so that anything normally logged to this descriptor can be
	// handled by the applications logging framework
	stderrLoggerKey activateConfigKey = "stderr-logger"
)

type flagOption bool

func (o *flagOption) ApplyOptionToConfig(config ActivateConfig) {
	config.Set(o, struct{}{})
}

type genericOption[T any] struct {
	key activateConfigKey
	val T
}

func (o *genericOption[T]) ApplyOptionToConfig(config ActivateConfig) {
	config.Set(o.key, o.val)
}

type genericContextOption[T any] struct {
	genericOption[T]
}

func (o *genericContextOption[T]) ApplyContextOptionToConfig(config ActivateConfig) {
	config.Set(o.key, o.val)
}

type genericSliceOption[T any] struct {
	key activateConfigKey
	val T
}

func (o *genericSliceOption[T]) ApplyOptionToConfig(config ActivateConfig) {
	var current []T
	if val, exists := config.Get(o.key); exists {
		current = val.([]T)
	}
	config.Set(o.key, append(current, o.val))
}

var willCheckStorageContainerBindingOption flagOption

// WillCheckStorageContainerBinding indicates that the caller will verify that a
// storage container is bound to those that have already been unlocked, rather than
// relying on this to be performed by cross checking the primary key.
//
// Note that this disables the primary key check performed by [ActivateContext]. This
// should only be used when it is known that unlocking will happen with a [KeyData]
// with a generation older than 2. It should not be used in any other circumstance.
// When used, the caller must take steps to verify that the storage container being
// unlocked is bound to those that have already been unlocked (XXX: This doesn't apply
// if a recovery key is used - the [ActivateContext.ActivateContainer] API will be
// updated in another PR to indicate what type of key was used).
//
// If the external binding check fails, the unlocked storage container must be locked
// again. The caller can then repeat the attempt without this option.
func WillCheckStorageContainerBinding() ActivateOption {
	return &willCheckStorageContainerBindingOption
}

// WithActivateStateCustomData can be supplied to [ActivateContext.ActivatePath] to
// permit the caller to supply arbitrary data that will appear in the
// [ContainerActivateState] associated with an activation.
func WithActivateStateCustomData(data json.RawMessage) ActivateOption {
	return &genericOption[json.RawMessage]{
		key: activateStateCustomDataKey,
		val: data,
	}
}

// WithAuthRequestor allows the caller to specify an instance of [AuthRequestor]
// when using the [ActivateContext] API. Without this, functionality that requires
// asking for user credentials will not work.
func WithAuthRequestor(req AuthRequestor) ActivateContextOption {
	return &genericContextOption[AuthRequestor]{
		genericOption: genericOption[AuthRequestor]{
			key: authRequestorKey,
			val: req,
		},
	}
}

// WithAuthRequestorUserVisibleName allows the caller to customize the
// name passed to AuthRequestor.RequestUserCredential.
func WithAuthRequestorUserVisibleName(name string) ActivateOption {
	return &genericOption[string]{
		key: authRequestorUserVisibleNameKey,
		val: name,
	}
}

// WithExternalKeyData makes it possible for callers of [ActivateContext.ActivateContainer]
// to supply extra key metadata that is not part of the associated [StorageContainer]. These
// keys have a hardcoded priority of 100 so that they are tried before [StorageContainer]
// keyslots with the default priority (0). External keys are tried in order of name.
// This option can be supplied multiple times.
func WithExternalKeyData(name string, data *KeyData) ActivateOption {
	return &genericSliceOption[*externalKeyData]{
		key: externalKeyDataKey,
		val: &externalKeyData{
			name: name,
			data: data,
		},
	}
}

// WithExternalKeyDataFromReader makes it possible for callers of
// [ActivateContext.ActivateContainer] to supply extra key metadata that is not part of the
// associated [StorageContainer]. These keys have a hardcoded priority of 100 so that they
// are tried before [StorageContainer] keyslots with the default priority (0). External
// keys are tried in order of name. Note that the [KeyDataReader] argument will eventually
// be replaced by [io.Reader]. This option can be supplied multiple times.
func WithExternalKeyDataFromReader(name string, r KeyDataReader) ActivateOption {
	return &genericSliceOption[*externalKeyData]{
		key: externalKeyDataKey,
		val: &externalKeyData{
			name: name,
			r:    r,
		},
	}
}

// ExternalUnlockKeySource provides a hint about where a key supplied to
// [WithExternalUnlockKey] comes from.
type ExternalUnlockKeySource int

const (
	// ExternalUnlockKeyFromPlatformDevice indicates that a key was recovered
	// from some platform device.
	ExternalUnlockKeyFromPlatformDevice ExternalUnlockKeySource = iota

	// ExternalUnlockKeyFromStorageContainer indicates that a key was recovered
	// from some encrypted storage container.
	ExternalUnlockKeyFromStorageContainer
)

// WithExternalUnlockKey makesit possible for callers of [ActivateContext.ActivateContainer]
// to supply plain unlock keys that can be used to try to unlock the storage container. These
// keys have a hardcoded priority of 100 so that they are tried before [StorageContainer]
// keyslots with the default priority (0) and no user authentication. External keys are tried
// in order of name. This option can be supplied multiple times.
func WithExternalUnlockKey(name string, key DiskUnlockKey, src ExternalUnlockKeySource) ActivateOption {
	return &genericSliceOption[*externalUnlockKey]{
		key: externalUnlockKeyKey,
		val: &externalUnlockKey{
			name: name,
			key:  key,
			src:  src,
		},
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
func WithKeyringDescriptionPrefix(prefix string) ActivateContextOption {
	return &genericContextOption[string]{
		genericOption: genericOption[string]{
			key: keyringDescPrefixKey,
			val: prefix,
		},
	}
}

// WithLegacyKeyringKeyDescriptionPaths tells [ActivateContext.ActivateContainer]
// to add keys to the kernel keyrings with descriptions derived from the
// supplied paths, emulating the legacy behaviour associated with the older
// activation API in order to maintain compatibility with older versions of
// snapd.
//
// If the [StorageContainer] being activated isn't a block device, this option
// will be ignored. If any of the supplied paths do not point to the same
// block device as the [StorageContainer], they will be ignored.
func WithLegacyKeyringKeyDescriptionPaths(paths ...string) ActivateOption {
	return &genericOption[[]string]{
		key: legacyKeyringKeyDescPathsKey,
		val: paths,
	}
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
func WithStderrLogger(w io.Writer) ActivateContextOption {
	return &genericContextOption[io.Writer]{
		genericOption: genericOption[io.Writer]{
			key: stderrLoggerKey,
			val: w,
		},
	}
}

// WithDiscardStderrLogger is a shortcut for WithStderrLogger(io.Discard).
func WithDiscardStderrLogger() ActivateContextOption {
	return WithStderrLogger(io.Discard)
}

// WithPassphraseTries defines how many attempts the user has to enter a
// correct passphrase.
func WithPassphraseTries(n uint) ActivateContextOption {
	return &genericContextOption[uint]{
		genericOption: genericOption[uint]{
			key: passphraseTriesKey,
			val: n,
		},
	}
}

// WithRecoveryKeyTries defines how many attempts the user has to enter a
// correct recovery key.
func WithRecoveryKeyTries(n uint) ActivateContextOption {
	return &genericContextOption[uint]{
		genericOption: genericOption[uint]{
			key: recoveryKeyTriesKey,
			val: n,
		},
	}
}
