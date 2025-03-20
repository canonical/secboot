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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

type systemdAuthRequestor struct {
	passphraseTmpl  string
	recoveryKeyTmpl string
}

func (r *systemdAuthRequestor) askPassword(sourceDevicePath, msg string) (string, error) {
	cmd := exec.Command(
		"systemd-ask-password",
		"--icon", "drive-harddisk",
		"--id", filepath.Base(os.Args[0])+":"+sourceDevicePath,
		msg)
	out := new(bytes.Buffer)
	cmd.Stdout = out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return "", xerrors.Errorf("cannot execute systemd-ask-password: %v", err)
	}
	result, err := out.ReadString('\n')
	if err != nil {
		// The only error returned from bytes.Buffer.ReadString is io.EOF.
		return "", errors.New("systemd-ask-password output is missing terminating newline")
	}
	return strings.TrimRight(result, "\n"), nil
}

func (r *systemdAuthRequestor) RequestPassphrase(volumeName, sourceDevicePath string) (string, error) {
	msg := fmt.Sprintf(r.passphraseTmpl, volumeName, sourceDevicePath)
	return r.askPassword(sourceDevicePath, msg)
}

func (r *systemdAuthRequestor) RequestRecoveryKey(volumeName, sourceDevicePath string) (RecoveryKey, error) {
	msg := fmt.Sprintf(r.recoveryKeyTmpl, volumeName, sourceDevicePath)
	passphrase, err := r.askPassword(sourceDevicePath, msg)
	if err != nil {
		return RecoveryKey{}, err
	}

	key, err := ParseRecoveryKey(passphrase)
	if err != nil {
		return RecoveryKey{}, xerrors.Errorf("cannot parse recovery key: %w", err)
	}

	return key, nil
}

// NewSystemdAuthRequestor creates an implementation of AuthRequestor that
// delegates to the systemd-ask-password binary. The supplied foramt strings are
// used to compose the messages that will be displayed when requesting a
// credential. The format strings will be interpreted with the following parameters:
// - %[1]s: The name that the LUKS container will be mapped to.
// - %[2]s: The device path of the LUKS container.
func NewSystemdAuthRequestor(passphraseTmpl, recoveryKeyTmpl string) AuthRequestor {
	return &systemdAuthRequestor{
		passphraseTmpl:  passphraseTmpl,
		recoveryKeyTmpl: recoveryKeyTmpl}
}
