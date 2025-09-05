// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	errNotDMBlockDevice      = errors.New("path does not correspond to a device mapper block device")
	errUnsupportedTargetType = errors.New("unsupported target type")
)

// decodeKernelSysfsUeventAttr decodes the uevent attributes for the device associated
// with the supplied sysfs path (which will be relative to sysfsRoot), and returns a
// map of variables.
func decodeKernelSysfsUeventAttr(devPath string) (env map[string]string, err error) {
	data, err := os.ReadFile(filepath.Join(sysfsRoot, devPath, "uevent"))
	if err != nil {
		return nil, err
	}

	entries := bytes.Split(data, []byte("\n"))

	env = make(map[string]string)
	for i, entry := range entries[:len(entries)-1] {
		v := bytes.Split(entry, []byte("="))
		if len(v) != 2 {
			return nil, fmt.Errorf("invalid entry %d: %q", i, entry)
		}
		env[string(v[0])] = string(v[1])
	}

	return env, nil
}

// sourceDeviceFromDMDevice obtains the path of the source device that backs
// the supplied DM device, if the supplied path references a DM device. If
// the supplied path is not a DM device or block device, this function returns
// ("", nil). It only supports walking linear and crypt tables, which should be
// sufficient for our requirements for now.
//
// TODO: Make sure that this works with the layout of DM devices that we have
// during re-encryption.
//
// TODO: Replace this with a package that talks directly to /dev/mapper/control.
// It has an easy to use, well-documented ioctl based API and is preferable to
// parsing the output of dmsetup.
var sourceDeviceFromDMDevice = func(ctx context.Context, path string) (string, error) {
	// Is the supplied path a block device?
	var st unix.Stat_t
	if err := unixStat(path, &st); err != nil {
		return "", &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFBLK == 0 {
		// Ignore paths that aren't block devices - another backend
		// might handle this.
		return "", errNotDMBlockDevice
	}

	// Is the supplied block device path a DM device. It should have a "dm"
	// directory in /sys/dev/block/<major>:<minor>
	if _, err := osStat(filepath.Join(sysfsRoot, "dev/block", fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev)), "dm")); err != nil {
		if os.IsNotExist(err) {
			// This is not a DM device. Ignore it because another
			// backend might handle it.
			return "", errNotDMBlockDevice
		}
		return "", err
	}

	// The supplied path is a device mapper device. Obtain the table using dmsetup.
	cmd := exec.CommandContext(ctx, "dmsetup", "table", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cannot obtain dm table for %s: %w", path, err)
	}

	// We have a table that we can split by whitespace. The table format is:
	// <logical_start_sector> <num_sectors> <target_type> <target_args>...
	tbl := strings.Split(string(out), " ")
	if len(tbl) < 3 {
		return "", fmt.Errorf("invalid dm table: unexpected number of arguments (%d) - expected at least 3", len(tbl))
	}

	var dev string

	targetType := tbl[2]
	switch targetType {
	case "crypt":
		// For crypt device, we expect the following extra args:
		// <cipher> <key> <iv_offset> <device> <offset> <features>...
		if len(tbl) < 8 {
			return "", fmt.Errorf("invalid dm table: unexpected number of arguments (%d) for device with crypt target: expected at least 8", len(tbl))
		}

		dev = tbl[6]
	case "linear":
		// For linear device, we expect the following extra args:
		// <device> <offset>
		if len(tbl) < 5 {
			return "", fmt.Errorf("invalid dm table: unexpected number of arguments (%d) for device with linear target: expected at least 5", len(tbl))
		}

		dev = tbl[3]
	default:
		return "", errUnsupportedTargetType
	}

	// XXX: Is the device always identified by device number? Can it be referenced
	// by its device node path (in which case, this code needs some readjustment)?
	devPath := filepath.Join("dev/block", dev)
	env, err := decodeKernelSysfsUeventAttr(devPath)
	if err != nil {
		return "", fmt.Errorf("cannot decode uevent attrs for %s: %w", devPath, err)
	}

	// Obtain the DEVNAME variable
	devName, exists := env["DEVNAME"]
	if !exists {
		return "", fmt.Errorf("no DEVNAME variable for %s", devPath)
	}

	// Return the device node path.
	return filepath.Join(devRoot, devName), nil
}
