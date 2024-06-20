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

package internal

import (
	"fmt"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-efilib/guids"
	"github.com/canonical/tcglog-parser"
)

// IsAbsoluteAgentLaunch returns true if the supplied event corresponds to the launch of an
// application that is associated with the Absolute (formerly Computrace) endpoint management
// firmware. This will return false if the event is not associated with an application launch,
// or the launch is not from a firmware volume, or the launch is from a firmware volume with
// a filename that is not known to be Absolute.
//
// It will return an error if the event data is badly formed, ie, it doesn't decode properly
// to the EFI_IMAGE_LOAD_EVENT structure, there is an empty device path or a badly formed
// firmware device path that begins with a firmware volume that is not followed by a single
// firmware volume filename.
func IsAbsoluteAgentLaunch(ev *tcglog.Event) (bool, error) {
	if ev.EventType != tcglog.EventTypeEFIBootServicesApplication {
		// Wrong event type
		return false, nil
	}
	data, ok := ev.Data.(*tcglog.EFIImageLoadEvent)
	if !ok {
		// the data resulting from decode errors is guaranteed to implement the error interface
		return false, fmt.Errorf("%s event has wrong data format: %w", tcglog.EventTypeEFIBootServicesApplication, ev.Data.(error))
	}
	if len(data.DevicePath) == 0 {
		return false, fmt.Errorf("%s event has empty device path", tcglog.EventTypeEFIBootServicesApplication)
	}

	if _, isFv := data.DevicePath[0].(efi.MediaFvDevicePathNode); !isFv {
		// Not loaded from a flash volume, so this isn't Absolute
		return false, nil
	}

	// The image is loaded from a flash volume - we should have a path of the form "Fv()\FvFile()".
	if len(data.DevicePath) != 2 {
		return false, fmt.Errorf("invalid firmware volume device path (%v): invalid length (expected 2 components)", data.DevicePath)
	}

	// The second component should be the filename in the firmware volume (both firmware volumes and the names
	// of files inside those volumes are identified with a GUID, for which there is a public database of well
	// known GUIDs).
	fvf, isFvf := data.DevicePath[1].(efi.MediaFvFileDevicePathNode)
	if !isFvf {
		// The second component is not a firmware volume filename
		return false, fmt.Errorf("invalid firmware volume device path (%v): doesn't terminate with FvFile", data.DevicePath)
	}

	// We have a complete firmware volume file path. The Absolute installer application has 2 well
	// known names. We can match directly by GUID or do a lookup using data in the public database.
	name, known := guids.FileOrVolumeNameString(efi.GUID(fvf))
	if !known {
		// This is not a well known GUID and is not Absolute.
		return false, nil
	}
	switch name {
	case "AbsoluteAbtInstaller", "AbsoluteComputraceInstaller":
		return true, nil
	default:
		return false, nil
	}
}
