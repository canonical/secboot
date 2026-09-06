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
	"os"
	"path/filepath"
	"strings"
)

type systemdCredsRequestUserCredentialContext struct {
	Path     string
	CredPath string
}

type systemdCredsAuthRequestor struct {
	console  io.Writer
	prefix   string
	credsDir string

	lastRequestUserCredentialCtx systemdCredsRequestUserCredentialContext
}

func (r *systemdCredsAuthRequestor) RequestUserCredential(ctx context.Context, name, path string, authTypes UserAuthType) (string, UserAuthType, error) {
	pathStr := strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "-")

	for _, info := range []struct {
		authTypeStr string
		authType    UserAuthType
	}{
		{authTypeStr: "passphrase", authType: UserAuthTypePassphrase},
		{authTypeStr: "pin", authType: UserAuthTypePIN},
		{authTypeStr: "recoverykey", authType: UserAuthTypeRecoveryKey},
	} {
		if info.authType&authTypes == 0 {
			continue
		}

		credPath := filepath.Join(r.credsDir, fmt.Sprintf("%s.%s.%s", r.prefix, pathStr, info.authTypeStr))
		data, err := os.ReadFile(credPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", 0, fmt.Errorf("cannot read credential from %s: %w", path, err)
		}

		r.lastRequestUserCredentialCtx = systemdCredsRequestUserCredentialContext{
			Path:     path,
			CredPath: credPath,
		}
		return string(data), info.authType, nil
	}

	return "", 0, ErrAuthRequestorNotAvailable
}

func (r *systemdCredsAuthRequestor) NotifyUserAuthResult(ctx context.Context, result UserAuthResult, authTypes, exhaustedAuthTypes UserAuthType) error {
	switch result {
	case UserAuthResultFailed:
		fmt.Fprintf(r.console, "Incorrect %s from credential %s for %s\n", formatUserAuthTypeString(authTypes), r.lastRequestUserCredentialCtx.CredPath, r.lastRequestUserCredentialCtx.Path)
	case UserAuthResultInvalidFormat:
		fmt.Fprintf(r.console, "Incorrectly formatted %s from credential %s\n", formatUserAuthTypeString(authTypes), r.lastRequestUserCredentialCtx.CredPath)
	}

	r.lastRequestUserCredentialCtx = systemdCredsRequestUserCredentialContext{}
	return nil
}

// NewSystemdCredsAuthRequestor creates an implementation of AuthRequestor that
// returns credentials from systemd credentials. The console argument is used by
// the implementation of [AuthRequestor.NotifyUserAuthResult] where result is
// not [UserAuthResultSuccess]. If not provided, it defaults to [os.Stderr].
// The prefix argument can be used to customize the prefix used for looking up
// credentials. It defaults to "ubuntu-fde" if not provided.
//
// Credentials can be provided by using the following format for their name:
// <prefix>.<path>.<type>
// ... where <path> is the path with the leading separator removed and remaining
// separators replaced with '-', and <type> is one of "passphrase", "pin" or
// "recoverykey".
//
// This will return [ErrAuthRequestorNotAvailable] if the CREDENTIALS_DIRECTORY
// environment variable is not set.
func NewSystemdCredsAuthRequestor(console io.Writer, prefix string) (AuthRequestor, error) {
	dir, exists := os.LookupEnv("CREDENTIALS_DIRECTORY")
	if !exists {
		return nil, ErrAuthRequestorNotAvailable
	}

	if console == nil {
		console = os.Stderr
	}
	if prefix == "" {
		prefix = "ubuntu-fde"
	}

	return &systemdCredsAuthRequestor{
		console:  console,
		prefix:   prefix,
		credsDir: dir,
	}, nil
}
