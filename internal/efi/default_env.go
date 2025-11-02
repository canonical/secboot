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

package efi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	"github.com/snapcore/secboot/internal/tpm2_device"
)

var (
	tpm2_deviceDefaultDevice = tpm2_device.DefaultDevice

	eventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements" // Path of the TCG event log for the default TPM, in binary form
	sysfsPath    = "/sys"
)

type defaultEnvImpl struct{}

// VarContext implements [HostEnvironmentEFI.VarContext].
func (defaultEnvImpl) VarContext(parent context.Context) context.Context {
	return efi.WithDefaultVarsBackend(parent)
}

// ReadEventLog implements [HostEnvironmentEFI.ReadEventLog].
func (defaultEnvImpl) ReadEventLog() (*tcglog.Log, error) {
	f, err := os.Open(eventLogPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return tcglog.ReadLog(f, &tcglog.LogOptions{})
}

// TPMDevice implements [HostEnvironment.TPMDevice].
func (defaultEnvImpl) TPMDevice() (tpm2_device.TPMDevice, error) {
	return tpm2_deviceDefaultDevice(tpm2_device.DeviceModeTryResourceManaged)
}

// DetectVirtMode implements [HostEnvironment.DetectVirtMode].
func (defaultEnvImpl) DetectVirtMode(mode DetectVirtMode) (string, error) {
	var extraArgs []string
	switch mode {
	case DetectVirtModeAll:
		// no extra args
	case DetectVirtModeContainer:
		extraArgs = []string{"--container"}
	case DetectVirtModeVM:
		extraArgs = []string{"--vm"}
	default:
		panic("not reached")
	}

	output, err := exec.Command("systemd-detect-virt", extraArgs...).Output()
	virt := string(bytes.TrimSpace(output)) // The stdout is newline terminated
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok && virt == VirtModeNone {
			// systemd-detect-virt returns non zero exit code if no virtualization is detected
			return virt, nil
		}
		return "", err
	}
	return virt, nil
}

type defaultEnvSysfsDevice struct {
	name      string
	path      string
	subsystem string
}

// Name implements [SysfsDevice.Name].
func (d *defaultEnvSysfsDevice) Name() string {
	return d.name
}

// Path implements [SysfsDevice.Path].
func (d *defaultEnvSysfsDevice) Path() string {
	return d.path
}

// Subsystem implements [SysfsDevice.Subsystem].
func (d *defaultEnvSysfsDevice) Subsystem() string {
	return d.subsystem
}

// AttributeReader implements [SysfsDevice.AttributeReader].
func (d *defaultEnvSysfsDevice) AttributeReader(attr string) (rc io.ReadCloser, err error) {
	if attr == "uevent" {
		return nil, ErrNoDeviceAttribute
	}

	f, err := os.Open(filepath.Join(d.path, attr))
	switch {
	case os.IsNotExist(err):
		return nil, ErrNoDeviceAttribute
	case err != nil:
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		f.Close()
	}()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, ErrNoDeviceAttribute
	}

	return f, nil
}

// DeviceForClass implements [HostEnvironment.DevicesForClass].
func (defaultEnvImpl) DevicesForClass(class string) ([]SysfsDevice, error) {
	classPath := filepath.Join(sysfsPath, "class", class)
	f, err := os.Open(classPath)
	switch {
	case os.IsNotExist(err):
		// it's ok to have no devices for the specified class
		return nil, nil
	case err != nil:
		return nil, err
	}
	defer f.Close()

	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	var out []SysfsDevice
	for _, entry := range entries {
		path, err := filepath.EvalSymlinks(filepath.Join(classPath, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("cannot resolve path for %s: %w", entry.Name(), err)
		}
		subsystem, err := filepath.EvalSymlinks(filepath.Join(path, "subsystem"))
		if err != nil {
			return nil, fmt.Errorf("cannot resolve subsystem for %s: %w", entry.Name(), err)
		}
		out = append(out, &defaultEnvSysfsDevice{
			name:      entry.Name(),
			path:      path,
			subsystem: filepath.Base(subsystem),
		})
	}
	return out, nil
}

// DefaultEnv corresponds to the environment associated with the host
// machine.
var DefaultEnv = defaultEnvImpl{}
