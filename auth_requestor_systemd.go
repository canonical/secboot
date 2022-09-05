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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"golang.org/x/xerrors"
)

type askPasswordMsgParams struct {
	VolumeName       string
	SourceDevicePath string
	// PartLabel string
	// LUKS2Label string
}

type systemdAuthRequestor struct {
	passphraseTmpl  *template.Template
	recoveryKeyTmpl *template.Template
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
	params := askPasswordMsgParams{
		VolumeName:       volumeName,
		SourceDevicePath: sourceDevicePath}

	msg := new(bytes.Buffer)
	if err := r.passphraseTmpl.Execute(msg, params); err != nil {
		return "", xerrors.Errorf("cannot execute message template: %w", err)
	}

	return r.askPassword(sourceDevicePath, msg.String())
}

func (r *systemdAuthRequestor) RequestRecoveryKey(volumeName, sourceDevicePath string) (RecoveryKey, error) {
	params := askPasswordMsgParams{
		VolumeName:       volumeName,
		SourceDevicePath: sourceDevicePath}

	msg := new(bytes.Buffer)
	if err := r.recoveryKeyTmpl.Execute(msg, params); err != nil {
		return RecoveryKey{}, xerrors.Errorf("cannot execute message template: %w", err)
	}

	passphrase, err := r.askPassword(sourceDevicePath, msg.String())
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
// delegates to the systemd-ask-password binary. The supplied templates are
// used to compose the messages that will be displayed when requesting a
// credential. The template will be executed with the following parameters:
// - .VolumeName: The name that the LUKS container will be mapped to.
// - .SourceDevicePath: The device path of the LUKS container.
func NewSystemdAuthRequestor(passphraseTmpl, recoveryKeyTmpl string) (AuthRequestor, error) {
	pt, err := template.New("passphraseMsg").Parse(passphraseTmpl)
	if err != nil {
		return nil, xerrors.Errorf("cannot parse passphrase message template: %w", err)
	}

	rkt, err := template.New("recoveryKeyMsg").Parse(recoveryKeyTmpl)
	if err != nil {
		return nil, xerrors.Errorf("cannot parse recovery key message template: %w", err)
	}

	return &systemdAuthRequestor{
		passphraseTmpl:  pt,
		recoveryKeyTmpl: rkt}, nil
}
