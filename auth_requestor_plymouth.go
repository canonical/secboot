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
	// RequestUserCredentialFormatString returns a format string used by
	// RequestUserCredential to construct a message that is used to request
	// credentials with the supplied auth types. The returned format string
	// is interpreted with the following parameters:
	// - %[1]s: A human readable name for the storage container.
	// - %[2]s: The path of the encrypted storage container.
	RequestUserCredentialFormatString(authTypes UserAuthType) (string, error)
}

type plymouthAuthRequestor struct {
	stringer PlymouthAuthRequestorStringer
}

func (r *plymouthAuthRequestor) RequestUserCredential(ctx context.Context, name, path string, authTypes UserAuthType) (string, error) {
	fmtString, err := r.stringer.RequestUserCredentialFormatString(authTypes)
	if err != nil {
		return "", fmt.Errorf("cannot request format string for requested auth types: %w", err)
	}
	msg := fmt.Sprintf(fmtString, name, path)

	cmd := exec.CommandContext(
		ctx, "plymouth", "ask-for-password",
		"--prompt", msg)
	out := new(bytes.Buffer)
	cmd.Stdout = out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cannot execute plymouth ask-for-password: %w", err)
	}
	result, err := io.ReadAll(out)
	if err != nil {
		// The only error returned from bytes.Buffer.Read should be io.EOF,
		// which io.ReadAll filters out.
		return "", fmt.Errorf("unexpected error: %w", err)
	}
	return string(result), nil
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
