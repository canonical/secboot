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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

// PlymouthAuthRequestorStringer is used by the Plymouth implementation
// of [AuthRequestor] to obtain translated strings.
type PlymouthAuthRequestorStringer interface {
	// RequestUserCredentialString returns messages used by RequestUserCredential. The
	// name is a string supplied via the WithAuthRequestorUserVisibleName option, and the
	// path is the storage container path.
	RequestUserCredentialString(name, path string, authTypes UserAuthType) (string, error)

	// NotifyUserAuthResultString returns messages used by NotifyUserAuthResult.
	NotifyUserAuthResultString(name, path string, result UserAuthResult, authTypes, exhaustedAuthTypes UserAuthType) (string, error)
}

type plymouthRequestUserCredentialContext struct {
	Name string
	Path string
}

type plymouthAuthRequestor struct {
	stringer PlymouthAuthRequestorStringer

	lastRequestUserCredentialCtx plymouthRequestUserCredentialContext
}

func (r *plymouthAuthRequestor) ping(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "plymouth", "--ping")
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ErrAuthRequestorNotAvailable
		}
		return fmt.Errorf("cannot execute plymouth --ping: %w", err)
	}
	return nil
}

func (r *plymouthAuthRequestor) RequestUserCredential(ctx context.Context, name, path string, authTypes UserAuthType) (string, UserAuthType, error) {
	if err := r.ping(ctx); err != nil {
		return "", 0, err
	}

	msg, err := r.stringer.RequestUserCredentialString(name, path, authTypes)
	if err != nil {
		return "", 0, fmt.Errorf("cannot request message string: %w", err)
	}

	cmd := exec.CommandContext(
		ctx, "plymouth", "ask-for-password",
		"--prompt", msg)
	out := new(bytes.Buffer)
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("cannot execute plymouth ask-for-password: %w", err)
	}
	result, err := io.ReadAll(out)
	if err != nil {
		// The only error returned from bytes.Buffer.Read should be io.EOF,
		// which io.ReadAll filters out.
		return "", 0, fmt.Errorf("unexpected error: %w", err)
	}

	r.lastRequestUserCredentialCtx = plymouthRequestUserCredentialContext{
		Name: name,
		Path: path,
	}

	return string(result), authTypes, nil
}

func (r *plymouthAuthRequestor) NotifyUserAuthResult(ctx context.Context, result UserAuthResult, authTypes, exhaustedAuthTypes UserAuthType) error {
	if err := r.ping(ctx); err != nil {
		return err
	}

	msg, err := r.stringer.NotifyUserAuthResultString(r.lastRequestUserCredentialCtx.Name, r.lastRequestUserCredentialCtx.Path, result, authTypes, exhaustedAuthTypes)
	if err != nil {
		return fmt.Errorf("cannot request message string: %w", err)
	}

	cmd := exec.CommandContext(
		ctx, "plymouth", "display-message",
		"--text", msg)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot execute plymouth display-message: %w", err)
	}

	r.lastRequestUserCredentialCtx = plymouthRequestUserCredentialContext{}
	return nil
}

// NewPlymouthAuthRequestor creates an implementation of AuthRequestor that
// communicates directly with Plymouth.
func NewPlymouthAuthRequestor(stringer PlymouthAuthRequestorStringer) (AuthRequestor, error) {
	if _, err := exec.LookPath("plymouth"); err != nil {
		return nil, ErrAuthRequestorNotAvailable
	}

	if stringer == nil {
		return nil, errors.New("must supply an implementation of PlymouthAuthRequestorStringer")
	}
	return &plymouthAuthRequestor{
		stringer: stringer,
	}, nil
}
