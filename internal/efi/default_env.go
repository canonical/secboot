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
	"github.com/pilebones/go-udev/crawler"
	"github.com/pilebones/go-udev/netlink"
	"github.com/snapcore/secboot/internal/tpm2_device"
)

var (
	crawlerExistingDevices   = crawler.ExistingDevices
	osOpen                   = os.Open
	osReadFile               = os.ReadFile
	osReadlink               = os.Readlink
	tpm2_deviceDefaultDevice = tpm2_device.DefaultDevice

	eventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements" // Path of the TCG event log for the default TPM, in binary form
)

// decodeKernelUeventParams decodes the uevent attribute for the device associated
// with the supplied sysfs path, and returns a map of variables.
//
// XXX: This is duplicated in luks2/dm_helper.go. A future PR may move device
// enumeration into a separate internal package.
func decodeKernelUeventParams(path string) (map[string]string, error) {
	data, err := osReadFile(filepath.Join(path, "uevent"))
	if err != nil {
		return nil, err
	}

	entries := bytes.Split(data, []byte("\n"))

	env := make(map[string]string)
	for i, entry := range entries[:len(entries)-1] {
		v := bytes.Split(entry, []byte("="))
		if len(v) != 2 {
			return nil, fmt.Errorf("invalid entry %d: %q", i, entry)
		}
		env[string(v[0])] = string(v[1])
	}

	return env, nil
}

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
	path      string
	props     map[string]string
	subsystem string
}

// Path implements [SysfsDevice.Path].
func (d *defaultEnvSysfsDevice) Path() string {
	return d.path
}

// Properties implements [SysfsDevice.Properties].
func (d *defaultEnvSysfsDevice) Properties() map[string]string {
	return d.props
}

// Subsystem implements [SysfsDevice.Subsystem].
func (d *defaultEnvSysfsDevice) Subsystem() string {
	return d.subsystem
}

func (d *defaultEnvSysfsDevice) Parent() (SysfsDevice, error) {
	path := d.path
	for {
		path = filepath.Dir(path)
		if path == crawler.BASE_DEVPATH {
			return nil, nil
		}
		props, err := decodeKernelUeventParams(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("cannot decode kernel uevent properties for %s: %w", path, err)
		}

		subsystem, err := osReadlink(filepath.Join(path, "subsystem"))
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("cannot resolve subsystem for %s: %w", path, err)
		}

		return &defaultEnvSysfsDevice{
			path:      path,
			props:     props,
			subsystem: filepath.Base(subsystem),
		}, nil
	}
}

// AttributeReader implements [SysfsDevice.AttributeReader].
func (d *defaultEnvSysfsDevice) AttributeReader(attr string) (rc io.ReadCloser, err error) {
	if attr == "uevent" {
		return nil, ErrNoDeviceAttribute
	}

	f, err := osOpen(filepath.Join(d.path, attr))
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

// EnumerateDevices implements [HostEnvironment.EnumerateDevices].
func (defaultEnvImpl) EnumerateDevices(matcher netlink.Matcher) ([]SysfsDevice, error) {
	queue := make(chan crawler.Device)
	errs := make(chan error)
	crawlerExistingDevices(queue, errs, matcher)

	var devices []SysfsDevice

	for {
		select {
		case dev, more := <-queue:
			if !more {
				return devices, nil
			}
			devices = append(devices, &defaultEnvSysfsDevice{
				path:      dev.KObj,
				props:     dev.Env,
				subsystem: dev.Env["SUBSYSTEM"],
			})
			delete(dev.Env, "SUBSYSTEM")
		case err := <-errs:
			return nil, err
		}
	}
}

// DefaultEnv corresponds to the environment associated with the host
// machine.
var DefaultEnv = defaultEnvImpl{}
