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
	"errors"

	"github.com/canonical/go-tpm2/linux"
)

var (
	linuxDefaultTPM2Device                  = linux.DefaultTPM2Device
	linuxRawDeviceResourceManagedDevice     = (*linux.RawDevice).ResourceManagedDevice
	linuxRawDevicePhysicalPresenceInterface = (*linux.RawDevice).PhysicalPresenceInterface
	linuxRMDeviceRawDevice                  = (*linux.RMDevice).RawDevice
)

func newTpmDeviceDirect(dev *linux.RawDevice) TPMDevice {
	ppi, err := linuxRawDevicePhysicalPresenceInterface(dev)
	if errors.Is(err, linux.ErrNoPhysicalPresenceInterface) {
		err = nil
	}
	return &tpmDevice{
		TPMDevice: dev,
		mode:      DeviceModeDirect,
		ppi:       ppi,
		ppiErr:    err,
	}
}

func newTpmDeviceRM(dev *linux.RMDevice) TPMDevice {
	ppi, err := linuxRawDevicePhysicalPresenceInterface(linuxRMDeviceRawDevice(dev))
	if errors.Is(err, linux.ErrNoPhysicalPresenceInterface) {
		err = nil
	}
	return &tpmDevice{
		TPMDevice: dev,
		mode:      DeviceModeResourceManaged,
		ppi:       ppi,
		ppiErr:    err,
	}
}

func init() {
	DefaultDevice = func(mode DeviceMode) (TPMDevice, error) {
		rawDev, err := linuxDefaultTPM2Device()
		switch {
		case errors.Is(err, linux.ErrDefaultNotTPM2Device) || errors.Is(err, linux.ErrNoTPMDevices):
			// Either there are no TPM devices or the default device is a TPM1.2 device
			return nil, ErrNoTPM2Device
		case err != nil:
			return nil, err
		}

		if mode == DeviceModeDirect {
			// Return the direct device
			return newTpmDeviceDirect(rawDev), nil
		}

		rmDev, err := linuxRawDeviceResourceManagedDevice(rawDev)
		switch {
		case errors.Is(err, linux.ErrNoResourceManagedDevice) && mode == DeviceModeTryResourceManaged:
			// No in-kernel resource manager, but the mode allows us to return the direct device
			return newTpmDeviceDirect(rawDev), nil
		case errors.Is(err, linux.ErrNoResourceManagedDevice):
			// No in-kernel resource manager, return an error
			return nil, ErrNoResourceManagedTPM2Device
		case err != nil:
			return nil, err
		}

		// Return the resource managed device
		return newTpmDeviceRM(rmDev), nil
	}
}
