// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package luks2

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"golang.org/x/xerrors"
)

var (
	systemdCryptsetupPath = "/lib/systemd/systemd-cryptsetup"
)

// Activate unlocks the LUKS device at sourceDevicePath using systemd-cryptsetup and creates a device
// mapping with the supplied volumeName. The device is unlocked using the supplied key.
//
// This will return a *os.ExitError error in the event that systemd-cryptsetup fails.
func Activate(volumeName, sourceDevicePath string, key []byte) error {
	cmd := exec.Command(systemdCryptsetupPath, "attach", volumeName, sourceDevicePath, "/dev/stdin", "luks,tries=1")
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "SYSTEMD_LOG_TARGET=console")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return xerrors.Errorf("cannot create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return xerrors.Errorf("cannot create stderr pipe: %w", err)
	}

	cmd.Stdin = bytes.NewReader(key)

	if err := cmd.Start(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		rd := bufio.NewScanner(stdout)
		for rd.Scan() {
			fmt.Printf("systemd-cryptsetup: %s\n", rd.Text())
		}
		wg.Done()
	}()
	go func() {
		rd := bufio.NewScanner(stderr)
		for rd.Scan() {
			fmt.Fprintf(os.Stderr, "systemd-cryptsetup: %s\n", rd.Text())
		}
		wg.Done()
	}()

	wg.Wait()

	return cmd.Wait()
}
