// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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
	"crypto"
	"fmt"
	"sort"
)

// PlatformHandlerErrorType indicates the type of error that
// PlatformHandlerError is associated with.
type PlatformHandlerErrorType int

const (
	// PlatformHandlerErrorInvalidData indicates that an action could not be
	// performed by PlatformKeyDataHandler because the supplied key data is
	// invalid.
	PlatformHandlerErrorInvalidData PlatformHandlerErrorType = iota + 1

	// PlatformHandlerErrorUninitialized indicates that an action could not
	// be performed by PlatformKeyDataHandler because the platform's secure
	// device is not properly initialized.
	PlatformHandlerErrorUninitialized

	// PlatformHandlerErrorUnavailable indicates that an action could not be
	// be performed by PlatformKeyDataHandler because the platform's secure
	// device is unavailable.
	PlatformHandlerErrorUnavailable

	// PlatformHandlerErrorInvalidAuthKey indicates that an action could not
	// be performed by PlatformKeyDataHandler because the supplied
	// authorization key was incorrect.
	PlatformHandlerErrorInvalidAuthKey
)

// PlatformHandlerError is returned from a PlatformKeyDataHandler implementation when
// the type of error can be categorized as one of the types supported by
// PlatformHandlerErrorType.
type PlatformHandlerError struct {
	Type PlatformHandlerErrorType // type of the error
	Err  error                    // underlying error
}

func (e *PlatformHandlerError) Error() string {
	return e.Err.Error()
}

func (e *PlatformHandlerError) Unwrap() error {
	return e.Err
}

// PlatformKeyData represents the data exchanged between this package and
// platform implementations via the PlatformKeyDataHandler.
type PlatformKeyData struct {
	Generation    int
	EncodedHandle []byte // The JSON encoded platform handle
	Role          string
	KDFAlg        crypto.Hash

	AuthMode AuthMode
}

// PlatformKeyDataHandlerFlags can be used to describe features supported
// by a registered platform.
//
// The lower 40 bits are for use and defined by the platform, and the
// platform can choose to use them however it wants to (eg, it may use some
// bits as a version number). This package does not use or interpret these
// 40 bits.
//
// The upper 24 bits are reserved for common flags defined by this package,
// although there aren't any defined right now.
type PlatformKeyDataHandlerFlags uint64

const (
	platformKeyDataHandlerCommonFlagsMask uint64 = 0xffffff0000000000

	// PlatformProtectedByStorageContainer indicates that a platform protects
	// its keys inside an encrypted storage container rather than a hardware
	// device.
	PlatformProtectedByStorageContainer PlatformKeyDataHandlerFlags = 1 << 40
)

// AddPlatformFlags adds the platform defined flags to the common flags,
// returning a new flags value. This package doesn't define the meaning of
// the specified flags and it does not use or interpret them in any way.
//
// This will panic if it uses any of the upper 24 bits reserved for common
// flags defined by this package.
func (f PlatformKeyDataHandlerFlags) AddPlatformFlags(flags uint64) PlatformKeyDataHandlerFlags {
	if flags&platformKeyDataHandlerCommonFlagsMask > 0 {
		panic(fmt.Sprintf("platform is using flag bits reserved for common flags: %#x", flags&platformKeyDataHandlerCommonFlagsMask))
	}
	return f | PlatformKeyDataHandlerFlags(flags)
}

type platformKeyDataHandlerInfo struct {
	handler PlatformKeyDataHandler
	flags   PlatformKeyDataHandlerFlags
}

// PlatormKeyDataHandler is the interface that this go package uses to
// interact with a platform's secure device for the purpose of recovering keys.
type PlatformKeyDataHandler interface {
	// RecoverKeys attempts to recover the cleartext keys from the supplied encrypted
	// payload using this platform's secure device.
	RecoverKeys(data *PlatformKeyData, encryptedPayload []byte) ([]byte, error)

	// RecoverKeysWithAuthKey attempts to recover the cleartext keys from the
	// encrypted payload using this platform's secure device. The key parameter
	// is a passphrase derived key to enable passphrase support to be integrated
	// with the secure device. The platform implementation doesn't provide the primary
	// mechanism of protecting keys with a passphrase - this is done in the platform
	// agnostic API. Some devices (such as TPMs) support this integration natively. For
	// other devices, the integration should provide a way of validating the key in
	// a way that requires the use of the secure device (eg, such as computing a HMAC of
	// it using a hardware backed key).
	RecoverKeysWithAuthKey(data *PlatformKeyData, encryptedPayload, key []byte) ([]byte, error)

	// ChangeAuthKey is called to notify the platform implementation that the
	// passphrase is being changed. The old and new parameters are passphrase derived
	// keys. Either value can be nil if passphrase authentication is being enabled (
	// where old will be nil) or disabled (where new will be nil).
	//
	// The use of the context argument isn't defined here - it's passed during
	// key construction and the platform is free to use it however it likes.
	//
	// On success, it should return an updated handle.
	ChangeAuthKey(data *PlatformKeyData, old, new []byte, context any) ([]byte, error)
}

var keyDataHandlers = make(map[string]platformKeyDataHandlerInfo)

// RegisterPlatformKeyDataHandler registers a handler for the specified platform name.
// The platform can also specify a set of feature flags.
//
// Supplying a nil handler will unregister the handler for the specified platform name,
// if one exists.
func RegisterPlatformKeyDataHandler(name string, handler PlatformKeyDataHandler, flags PlatformKeyDataHandlerFlags) {
	if handler == nil {
		delete(keyDataHandlers, name)
		return
	}

	keyDataHandlers[name] = platformKeyDataHandlerInfo{
		handler: handler,
		flags:   flags,
	}
}

// RegisteredPlatformKeyDataHandler returns the handler and its flags, for the
// specified platform name.
//
// If no platform with the specified name is registered, a ErrNoPlatformHandlerRegistered
// error will be returned.
func RegisteredPlatformKeyDataHandler(name string) (handler PlatformKeyDataHandler, flags PlatformKeyDataHandlerFlags, err error) {
	handlerInfo, exists := keyDataHandlers[name]
	if !exists {
		return nil, 0, ErrNoPlatformHandlerRegistered
	}
	return handlerInfo.handler, handlerInfo.flags, nil
}

// ListRegisteredKeyDataPlatforms returns a list of the names of all
// of the registered PlatformKeyDataHandlers.
func ListRegisteredKeyDataPlatforms() []string {
	var platforms []string
	for k := range keyDataHandlers {
		platforms = append(platforms, k)
	}
	sort.Strings(platforms)
	return platforms
}
