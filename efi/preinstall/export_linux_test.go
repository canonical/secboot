//go:build linux

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

package preinstall

import (
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/ppi"
)

var (
	ObtainTPMDevicePPILinux = obtainTPMDevicePPILinux
)

func MockLinuxRawDevicePhysicalPresenceInterface(fn func(*linux.RawDevice) (ppi.PPI, error)) (restore func()) {
	orig := linuxRawDevicePhysicalPresenceInterface
	linuxRawDevicePhysicalPresenceInterface = fn
	return func() {
		linuxRawDevicePhysicalPresenceInterface = orig
	}
}

func MockLinuxRMDeviceRawDevice(fn func(*linux.RMDevice) *linux.RawDevice) (restore func()) {
	orig := linuxRMDeviceRawDevice
	linuxRMDeviceRawDevice = fn
	return func() {
		linuxRMDeviceRawDevice = orig
	}
}
