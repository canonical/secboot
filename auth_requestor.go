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

import "context"

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

// AuthRequestor is an interface for requesting credentials.
type AuthRequestor interface {
	// RequestUserCredential is used to request a user credential that is
	// required to unlock the container at the specified path. The optional
	// name argument permits the caller to supply a more human friendly name,
	// and can be supplied via the ActivateContext API using the
	// WithAuthRequestorUserVisibleName option. The authTypes argument is used
	// to indicate what types of credential are being requested.
	// The implementation returns the requested credential and its type, which
	// may be a subset of the requested credential types.
	RequestUserCredential(ctx context.Context, name, path string, authTypes UserAuthType) (string, UserAuthType, error)
}
