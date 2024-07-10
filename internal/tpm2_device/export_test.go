// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package tpm2_device

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/ppi"
)

func MockLinuxDefaultTPM2Device(fn func() (*linux.RawDevice, error)) (restore func()) {
	orig := linuxDefaultTPM2Device
	linuxDefaultTPM2Device = fn
	return func() {
		linuxDefaultTPM2Device = orig
	}
}

func MockLinuxRawDeviceResourceManagedDevice(fn func(*linux.RawDevice) (*linux.RMDevice, error)) (restore func()) {
	orig := linuxRawDeviceResourceManagedDevice
	linuxRawDeviceResourceManagedDevice = fn
	return func() {
		linuxRawDeviceResourceManagedDevice = orig
	}
}

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

func NewTPMDevice(dev tpm2.TPMDevice, mode DeviceMode, ppi ppi.PPI, ppiErr error) TPMDevice {
	return &tpmDevice{
		TPMDevice: dev,
		mode:      mode,
		ppi:       ppi,
		ppiErr:    ppiErr,
	}
}
