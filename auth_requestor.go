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
	"context"
	"fmt"
	"strings"
)

// UserAuthType describes a user authentication type that can be
// requested via [AuthRequestor].
type UserAuthType int

const (
	// UserAuthTypePassphrase indicates that a passphase is
	// being requested.
	UserAuthTypePassphrase UserAuthType = 1 << iota

	// UserAuthTypePIN indicates that a PIN is being requested.
	UserAuthTypePIN

	// UserAuthTypeRecoveryKey indicates that a recovery key
	// is being requesteed.
	UserAuthTypeRecoveryKey
)

func formatUserAuthTypeString(authTypes UserAuthType) string {
	var s []string
	if authTypes&UserAuthTypePassphrase > 0 {
		s = append(s, "passphrase")
	}
	if authTypes&UserAuthTypePIN > 0 {
		s = append(s, "PIN")
	}
	if authTypes&UserAuthTypeRecoveryKey > 0 {
		s = append(s, "recovery key")
	}

	switch len(s) {
	case 0:
		return ""
	case 1:
		return s[0]
	default:
		return fmt.Sprintf("%s or %s", strings.Join(s[0:len(s)-1], ", "), s[len(s)-1])
	}
}

// UserAuthResult indicates the result of a user auth attempt.
type UserAuthResult int

const (
	// UserAuthResultSuccess indicates that an authentication attempt
	// was successful.
	UserAuthResultSuccess UserAuthResult = iota

	// UserAuthResultFailed indicates that an authentication attempt failed.
	UserAuthResultFailed

	// UserAuthResultInvalidFormat indicates that authentication
	// could not be attempted because the supplied credential was formatted
	// incorrectly for the type.
	UserAuthResultInvalidFormat
)

// AuthRequestor is an interface for requesting credentials.
type AuthRequestor interface {
	// RequestUserCredential is used to request a user credential that is
	// required to unlock the container at the specified path. The optional
	// name argument permits the caller to supply a more human friendly name,
	// and can be supplied via the ActivateContext API using the
	// WithAuthRequestorUserVisibleName option. The authTypes argument is used
	// to indicate what types of credential are being requested.
	//
	// The implementation returns the requested credential and its type, which
	// may be a subset of the requested credential types.
	RequestUserCredential(ctx context.Context, name, path string, authTypes UserAuthType) (string, UserAuthType, error)

	// NotifyUserAuthResult is used to inform the user about the result of an
	// authentication attempt.
	//
	// If the result is UserAuthResultSuccess, the supplied authTypes argument
	// indicates the credential type that was successfully used. The
	// exhaustedAuthTypes argument is unused.
	//
	// If the result is UserAuthResultFailed, the supplied authTypes argument
	// indicates the credential types that were attempted but failed. The
	// exhaustedAuthTypes argument indicates the credential types that
	// will no longer be available following the last attempt because there are
	// no more tries permitted.
	//
	// If the result is UserAuthResultInvalidFormat, the supplied
	// authTypes argument indicates the credential types that the user supplied
	// credential was badly formatted for. The exhaustedAuthTypes argument
	// is unused.
	NotifyUserAuthResult(ctx context.Context, result UserAuthResult, authTypes, exhaustedAuthTypes UserAuthType) error
}
