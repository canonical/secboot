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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SystemdAuthRequestorStringFn is a callback used to supply translated messages
// to the systemd implementation of AuthRequestor.RequestUserCredential. The name
// is a string supplied via the [WithAuthRequestorUserVisibleName] option, and the
// path is the storage container path.
type SystemdAuthRequestorStringFn func(name, path string, authTypes UserAuthType) (string, error)

type systemdAuthRequestor struct {
	console  io.Writer
	stringFn SystemdAuthRequestorStringFn

	lastRequestUserCredentialPath string
}

func (r *systemdAuthRequestor) RequestUserCredential(ctx context.Context, name, path string, authTypes UserAuthType) (string, UserAuthType, error) {
	msg, err := r.stringFn(name, path, authTypes)
	if err != nil {
		return "", 0, fmt.Errorf("cannot request message string: %w", err)
	}

	cmd := exec.CommandContext(
		ctx, "systemd-ask-password",
		"--icon", "drive-harddisk",
		"--id", filepath.Base(os.Args[0])+":"+path,
		msg)
	out := new(bytes.Buffer)
	cmd.Stdout = out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("cannot execute systemd-ask-password: %w", err)
	}
	result, err := out.ReadString('\n')
	if err != nil {
		// The only error returned from bytes.Buffer.ReadString is io.EOF.
		return "", 0, errors.New("systemd-ask-password output is missing terminating newline")
	}

	r.lastRequestUserCredentialPath = path

	return strings.TrimRight(result, "\n"), authTypes, nil
}

func (r *systemdAuthRequestor) NotifyUserAuthResult(ctx context.Context, result UserAuthResult, authTypes, exhaustedAuthTypes UserAuthType) error {
	switch result {
	case UserAuthResultFailed:
		fmt.Fprintf(r.console, "Incorrect %s for %s\n", formatUserAuthTypeString(authTypes), r.lastRequestUserCredentialPath)
		if exhaustedAuthTypes != UserAuthType(0) {
			fmt.Fprintf(r.console, "No more %s tries remaining\n", formatUserAuthTypeString(exhaustedAuthTypes))
		}
	case UserAuthResultInvalidFormat:
		fmt.Fprintf(r.console, "Incorrectly formatted %s\n", formatUserAuthTypeString(authTypes))
	}

	r.lastRequestUserCredentialPath = ""
	return nil
}

// NewSystemdAuthRequestor creates an implementation of AuthRequestor that
// delegates to the systemd-ask-password binary. The caller supplies a callback
// to supply messages for user auth requests. The console argument is used by
// the implementation of [AuthRequestor.NotifyUserAuthResult] where result is
// not [UserAuthResultSuccess]. If not provided, it defaults to [os.Stderr].
func NewSystemdAuthRequestor(console io.Writer, stringFn SystemdAuthRequestorStringFn) (AuthRequestor, error) {
	if console == nil {
		console = os.Stderr
	}
	if stringFn == nil {
		return nil, errors.New("must supply a SystemdAuthRequestorStringFn")
	}
	return &systemdAuthRequestor{
		console:  console,
		stringFn: stringFn,
	}, nil
}
