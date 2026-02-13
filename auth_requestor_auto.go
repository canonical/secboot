// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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
)

var (
	newPlymouthAuthRequestor = NewPlymouthAuthRequestor
	newSystemdAuthRequestor  = NewSystemdAuthRequestor
)

// AutoAuthRequestorStringer is used by the auto selecting implementation
// of [AuthRequestor] to obtain translated strings.
type AutoAuthRequestorStringer interface {
	// RequestUserCredentialString returns messages used by RequestUserCredential.
	RequestUserCredentialString(name, path string, authTypes UserAuthType) (string, error)

	// NotifyUserAuthResultString returns messages used by NotifyUserAuthResult.
	NotifyUserAuthResultString(name, path string, result UserAuthResult, authTypes, exhaustedAuthTypes UserAuthType) (string, error)
}

type autoAuthRequestor struct {
	requestors []AuthRequestor
	lastUsed   AuthRequestor
}

func (r *autoAuthRequestor) RequestUserCredential(ctx context.Context, name, path string, authTypes UserAuthType) (string, UserAuthType, error) {
	for _, req := range r.requestors {
		switch cred, credType, err := req.RequestUserCredential(ctx, name, path, authTypes); {
		case err == nil:
			r.lastUsed = req
			fallthrough
		case !errors.Is(err, ErrAuthRequestorNotAvailable):
			return cred, credType, err
		}
	}

	return "", 0, ErrAuthRequestorNotAvailable
}

func (r *autoAuthRequestor) NotifyUserAuthResult(ctx context.Context, result UserAuthResult, authTypes, exhaustedAuthTypes UserAuthType) error {
	if r.lastUsed == nil {
		return errors.New("no user credential requested yet")
	}
	return r.lastUsed.NotifyUserAuthResult(ctx, result, authTypes, exhaustedAuthTypes)
}

// NewAutoAuthRequestor creates an implementation of AuthRequestor that automatically
// selects the first available implementation in the following order:
// - Plymouth.
// - systemd-ask-password.
//
// The caller supplies an implementation of AutoAuthRequestorStringer that returns messages.
// The console argument is used by the systemd-ask-password implementation of
// [AuthRequestor.NotifyUserAuthResult] where result is not [UserAuthResultSuccess]. If not
// provided, it defaults to [os.Stderr].
func NewAutoAuthRequestor(stderr io.Writer, stringer AutoAuthRequestorStringer) (AuthRequestor, error) {
	var requestors []AuthRequestor
	switch ply, err := newPlymouthAuthRequestor(stringer); {
	case errors.Is(err, ErrAuthRequestorNotAvailable):
		// ignore
	case err != nil:
		return nil, fmt.Errorf("cannot create Plymouth AuthRequestor: %w", err)
	default:
		requestors = append(requestors, ply)
	}

	switch sd, err := newSystemdAuthRequestor(stderr, func(name, path string, authTypes UserAuthType) (string, error) {
		return stringer.RequestUserCredentialString(name, path, authTypes)
	}); {
	case errors.Is(err, ErrAuthRequestorNotAvailable):
		// ignore
	case err != nil:
		return nil, fmt.Errorf("cannot create systemd AuthRequestor: %w", err)
	default:
		requestors = append(requestors, sd)
	}

	if len(requestors) == 0 {
		return nil, ErrAuthRequestorNotAvailable
	}

	return &autoAuthRequestor{requestors: requestors}, nil
}
