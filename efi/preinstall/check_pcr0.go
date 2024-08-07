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
	"fmt"

	"github.com/canonical/tcglog-parser"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// checkPlatformFirmwareMeasurements checks measurements related to platform firmware in PCR0,
// including that measurements are of expected types, and that no measurements are made during
// the OS-present phase.
func checkPlatformFirmwareMeasurements(log *tcglog.Log) error {
	// Iterate over the log until OS-present and make sure that we have expected
	// event types
	phaseTracker := newTcgLogPhaseTracker()
NextEvent:
	for _, ev := range log.Events {
		phase, err := phaseTracker.processEvent(ev)
		if err != nil {
			return err
		}

		switch phase {
		case tcglogPhasePreOSMeasureSecureBootConfig, tcglogPhasePreOS:
			if ev.PCRIndex != internal_efi.PlatformFirmwarePCR {
				// Not PCR0
				continue NextEvent
			}

			switch ev.EventType {
			case tcglog.EventTypePostCode, tcglog.EventTypeEFIPlatformFirmwareBlob:
				// Platform firmware blobs - deprecated.
				// EV_POST_CODE should contain a non-NULL terminated string or a
				// UEFI_PLATFORM_FIRMWARE_BLOB structure. EV_EFI_PLATFORM_FIRMWARE_BLOB
				// should contain a UEFI_PLATFORM_FIRMWARE_BLOB structure.
			case tcglog.EventTypeNoAction:
				// Information, not measured
			case tcglog.EventTypeSCRTMContents, tcglog.EventTypeSCRTMVersion:
				// SCRTM measurements. EV_S_SCRTM_CONTENTS should either contain a
				// UEFI_PLATFORM_FIRMWARE_BLOB or UEFI_PLATFORM_FIRMWARE_BLOB2 structure,
				// or it can contain a NULL terminated ASCII string if measured by a H-CRTM
				// event. EV_S_CRTM_VERSION should contain a NULL terminated UCS2 string or
				// a EFI_GUID.
				//
				// We don't make any special accommodations for these when measured as part
				// of a H-CRTM sequence, so it's possible we already mis-predicted PCR0 and
				// marked it invalid before getting to this point.
				//
				// EV_S_CRTM_VERSION is not informational but we don't check that the data matches
				// the event digests because we don't do any prediction for this value.
			case tcglog.EventTypeNonhostCode, tcglog.EventTypeNonhostInfo:
				// Non-host platform code running on an embedded controller. The second one is used
				// if the host platform cannot reliably measure the non-host code. The event data is
				// determined by the platform manufacturer.
			case tcglog.EventTypePostCode2, tcglog.EventTypeEFIPlatformFirmwareBlob2:
				// Platform firmware blobs.
				// EV_POST_CODE2 should contain a non-NULL terminated string or a
				// UEFI_PLATFORM_FIRMWARE_BLOB2 structure. EV_EFI_PLATFORM_FIRMWARE_BLOB
				// should contain a EF_EFI_PLATFORM_FIRMWARE_BLOB2 structure.
			case tcglog.EventTypeEFIBootServicesDriver, tcglog.EventTypeEFIRuntimeServicesDriver:
				// Platform firmware blobs as PE images and loaded via the LoadImage API.
				// We don't check the digests here because it's likely that the device path
				// takes us to something we can't read, and we don't do any prediction here
				// yet either.
			case tcglog.EventTypeEFIHCRTMEvent:
				// a H-CRTM sequence that occurred before TPM2_Startup. There may be more than
				// one of these.
				// There should be a corresponding EV_NO_ACTION event indicating that the startup
				// locality is 4, and there may be other EV_NO_ACTION events containing
				// TCG_HCRTMComponentEvent structures.
			case tcglog.EventTypeEFISPDMFirmwareBlob:
				// Firmware of a component that supports SPDM "GET_MEASUREMENTS".
				// Note that this is very new (only in the TCG PFP spec v1.06)
			default:
				return fmt.Errorf("unexpected pre-OS log event type %v", ev.EventType)
			}
		case tcglogPhaseOSPresent:
			// Nothing should measure to PCR0 outside of pre-OS - we'll generate an invalid profile
			// if it does.
			if ev.PCRIndex == internal_efi.PlatformFirmwarePCR {
				return errors.New("firmware measures events as part of the OS-present environment")
			}
		}
	}
	return nil
}
