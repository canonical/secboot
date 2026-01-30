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
	"os"
	"os/exec"
)

// PlymouthAuthRequestorStringer is used by the Plymouth implementation
// of [AuthRequestor] to obtain translated strings.
type PlymouthAuthRequestorStringer interface {
	// RequestUserCredentialString returns messages used by RequestUserCredential.
	RequestUserCredentialString(name, path string, authTypes UserAuthType) (string, error)
}

type plymouthAuthRequestor struct {
	stringer PlymouthAuthRequestorStringer
}

func (r *plymouthAuthRequestor) RequestUserCredential(ctx context.Context, name, path string, authTypes UserAuthType) (string, UserAuthType, error) {
	msg, err := r.stringer.RequestUserCredentialString(name, path, authTypes)
	if err != nil {
		return "", 0, fmt.Errorf("cannot request message string: %w", err)
	}

	cmd := exec.CommandContext(
		ctx, "plymouth", "ask-for-password",
		"--prompt", msg)
	out := new(bytes.Buffer)
	cmd.Stdout = out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("cannot execute plymouth ask-for-password: %w", err)
	}
	result, err := io.ReadAll(out)
	if err != nil {
		// The only error returned from bytes.Buffer.Read should be io.EOF,
		// which io.ReadAll filters out.
		return "", 0, fmt.Errorf("unexpected error: %w", err)
	}
	return string(result), authTypes, nil
}

// NewPlymouthAuthRequestor creates an implementation of AuthRequestor that
// communicates directly with Plymouth.
func NewPlymouthAuthRequestor(stringer PlymouthAuthRequestorStringer) (AuthRequestor, error) {
	if stringer == nil {
		return nil, errors.New("must supply an implementation of PlymouthAuthRequestorStringer")
	}
	return &plymouthAuthRequestor{
		stringer: stringer,
	}, nil
}
