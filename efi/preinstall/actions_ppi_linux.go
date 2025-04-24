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

package preinstall

import (
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/ppi"
)

func init() {
	obtainTPMDevicePPI = obtainTPMDevicePPILinux
}

var (
	linuxRawDevicePhysicalPresenceInterface = (*linux.RawDevice).PhysicalPresenceInterface
	linuxRMDeviceRawDevice                  = (*linux.RMDevice).RawDevice
)

func obtainTPMDevicePPILinux(dev tpm2.TPMDevice) (ppi.PPI, error) {
	var ppi ppi.PPI
	var err error
	switch d := dev.(type) {
	case *linux.RawDevice:
		ppi, err = linuxRawDevicePhysicalPresenceInterface(d)
	case *linux.RMDevice:
		ppi, err = linuxRawDevicePhysicalPresenceInterface(linuxRMDeviceRawDevice(d))
	default:
		return nil, errors.New("not a linux tpm2.TPMDevice")
	}

	switch {
	case errors.Is(err, linux.ErrNoPhysicalPresenceInterface):
		return nil, nil
	case err != nil:
		return nil, err
	default:
		return ppi, nil
	}
}
