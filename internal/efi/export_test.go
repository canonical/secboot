// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2024 Canonical Ltd
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
	"github.com/canonical/go-tpm2/linux"
	. "gopkg.in/check.v1"
)

func MockEventLogPath(path string) (restore func()) {
	origPath := eventLogPath
	eventLogPath = path
	return func() {
		eventLogPath = origPath
	}
}

func MockLinuxDefaultTPM2Device(dev *linux.RawDevice, err error) (restore func()) {
	orig := linuxDefaultTPM2Device
	linuxDefaultTPM2Device = func() (*linux.RawDevice, error) {
		return dev, err
	}
	return func() {
		linuxDefaultTPM2Device = orig
	}
}

func MockLinuxRawDeviceResourceManagedDevice(c *C, expectedDev *linux.RawDevice, dev *linux.RMDevice, err error) (restore func()) {
	orig := linuxRawDeviceResourceManagedDevice
	linuxRawDeviceResourceManagedDevice = func(device *linux.RawDevice) (*linux.RMDevice, error) {
		c.Check(device, Equals, expectedDev)
		return dev, err
	}
	return func() {
		linuxRawDeviceResourceManagedDevice = orig
	}
}

func MockSysfsPath(path string) (restore func()) {
	orig := sysfsPath
	sysfsPath = path
	return func() {
		sysfsPath = orig
	}
}
