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

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/ppi"
)

// DeviceMode describes the mode to select the default device.
type DeviceMode int

const (
	// DeviceModeDirect requests the most direct TPM2 device, without
	// the use of a resource manager. These devices cannot be opened more
	// than once and don't permit the TPM to be shared.
	DeviceModeDirect DeviceMode = iota

	// DeviceModeResourceManaged requests a resource managed TPM2 device.
	// These devices can be opened more than once and shared, relying on
	// the resource manager to handle context switching between users
	// (although they can't be shared with a direct device).
	DeviceModeResourceManaged

	// DeviceModeTryResourceManaged is like DeviceModeResourceManaged except
	// it will return a direct device if a resource managed device is not
	// available. Some older linux kernels do not support an in-kernel resource
	// manager.
	DeviceModeTryResourceManaged
)

var (
	// ErrNoTPM2Device indicates that no TPM2 device is available.
	ErrNoTPM2Device = errors.New("no TPM2 device is available")

	// ErrNoResourceManagedTPM2Device indicates that there is no resource
	// managed TPM2 device option available.
	ErrNoResourceManagedTPM2Device = errors.New("no resource managed TPM2 device available")

	// ErrNoPPI indicates that no physical presence interface is available.
	ErrNoPPI = errors.New("no physical presence interface available")
)

type tpmDevice struct {
	tpm2.TPMDevice

	mode DeviceMode

	ppi    ppi.PPI
	ppiErr error
}

func (d *tpmDevice) Mode() DeviceMode {
	return d.mode
}

func (d *tpmDevice) PPI() (ppi.PPI, error) {
	if d.ppiErr != nil {
		return nil, d.ppiErr
	}
	if d.ppi == nil {
		return nil, ErrNoPPI
	}
	return d.ppi, nil
}

// TPMDevice corresponds to a [tpm2.TPMDevice] with some extra features.
type TPMDevice interface {
	tpm2.TPMDevice
	Mode() DeviceMode      // either DeviceModeDirect or DeviceModeResourceManaged
	PPI() (ppi.PPI, error) // provide access to the physical presence interface
}

// DefaultDevice returns the default TPM device. The specified mode controls what kind
// of device to return, if available.
var DefaultDevice = func(DeviceMode) (TPMDevice, error) {
	return nil, ErrNoTPM2Device
}
