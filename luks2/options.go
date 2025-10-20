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
	"github.com/snapcore/secboot"
)

// activateConfigKey is the type of keys added to a [secboot.ActivateConfig] implementation
// by this package.
type activateConfigKey string

const (
	// volumeNameKey is used by WithVolumeName to specify the volume name
	// for the newly mapped dm-crypt device.
	volumeNameKey activateConfigKey = "volume-name"
)

type volumeNameOption string

// ApplyToConfig implements [secboot.ActivateOption.ApplyOptionToConfig].
func (o volumeNameOption) ApplyOptionToConfig(config secboot.ActivateConfig) {
	config.Set(volumeNameKey, string(o))
}

// WithVolumeName is used to specify the volume name used to create the
// DM device when unlocking a LUKS2 container. It can be supplied to
// the [secboot.ActivateContext.ActivateContainer] API.
//
// XXX: It is mandatory for now for any [StorageContainer] managed by this
// package. A future revision may relax this requirement and support a
// mode where the volume name is created automatically, perhaps based on
// the UUID of the LUKS2 container. An automatically generated volume name
// can be retrieved afterwards using [StorageContainer.ActiveVolumeName].
func WithVolumeName(name string) secboot.ActivateOption {
	return volumeNameOption(name)
}
