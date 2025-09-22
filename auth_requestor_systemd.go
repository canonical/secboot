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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type systemdAuthRequestor struct {
	formatStringFn func(UserAuthType) (string, error)
}

func (r *systemdAuthRequestor) RequestUserCredential(ctx context.Context, name, path string, authTypes UserAuthType) (string, error) {
	fmtString, err := r.formatStringFn(authTypes)
	if err != nil {
		return "", fmt.Errorf("cannot request format string for requested auth types: %w", err)
	}
	msg := fmt.Sprintf(fmtString, name, path)

	cmd := exec.CommandContext(
		ctx, "systemd-ask-password",
		"--icon", "drive-harddisk",
		"--id", filepath.Base(os.Args[0])+":"+path,
		msg)
	out := new(bytes.Buffer)
	cmd.Stdout = out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cannot execute systemd-ask-password: %w", err)
	}
	result, err := out.ReadString('\n')
	if err != nil {
		// The only error returned from bytes.Buffer.ReadString is io.EOF.
		return "", errors.New("systemd-ask-password output is missing terminating newline")
	}
	return strings.TrimRight(result, "\n"), nil
}

// NewSystemdAuthRequestor creates an implementation of AuthRequestor that
// delegates to the systemd-ask-password binary. The caller supplies a map
// of user auth type combinations to format strings that are used to construct
// messages. The format strings are interpreted with the following parameters:
// - %[1]s: A human readable name for the storage container.
// - %[2]s: The path of the encrypted storage container.
func NewSystemdAuthRequestor(formatStringFn func(UserAuthType) (string, error)) (AuthRequestor, error) {
	if formatStringFn == nil {
		return nil, errors.New("must supply a callback to obtain format strings for requesting user credentials")
	}
	return &systemdAuthRequestor{
		formatStringFn: formatStringFn,
	}, nil
}
