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

type driversAndAppsResultFlags int

const (
	driversAndAppsDriversPresent driversAndAppsResultFlags = 1 << iota
)

// checkDriversAndAppsMeasurements checks measurements related to addon code from value-added-retailer
// hardware, such as option ROMs and UEFI drivers in PCR2, including that measurements are of expected
// types, and that no measurements are made during the OS-present phase. This returns an indication of
// whether addon code is present during the current boot.
func checkDriversAndAppsMeasurements(log *tcglog.Log) (result driversAndAppsResultFlags, err error) {
	// Iterate over the log until OS-present and make sure that we have expected
	// event types
	phaseTracker := newTcgLogPhaseTracker()
NextEvent:
	for _, ev := range log.Events {
		phase, err := phaseTracker.processEvent(ev)
		if err != nil {
			return 0, err
		}

		switch phase {
		case tcglogPhasePreOSMeasureSecureBootConfig, tcglogPhasePreOS:
			if ev.PCRIndex != internal_efi.DriversAndAppsPCR {
				// Not PCR2
				continue NextEvent
			}

			switch ev.EventType {
			case tcglog.EventTypeAction, tcglog.EventTypeEFIAction:
				// Some sort of action. The event data is a non-NULL terminated ASCII string.
				// The data in these events is not informational (the event digests are the tagged
				// hashes of the event data), but we don't verify that the event data is consistent
				// with the digests yet because we don't do any prediction here.
			case tcglog.EventTypeNonhostCode, tcglog.EventTypeNonhostInfo:
				// Non-host platform code running on an embedded controller. The second one is used
				// if the host platform cannot reliably measure the non-host code. The event data is
				// determined by the platform manufacturer and is purely informational.
			case tcglog.EventTypeEFIBootServicesApplication, tcglog.EventTypeEFIBootServicesDriver, tcglog.EventTypeEFIRuntimeServicesDriver:
				// Code from value-added-retailer component loaded via the LoadImage API.
				// We don't check the digests here because it's likely that the device path
				// takes us to something we can't read, and we don't do any prediction here
				// yet either.
				result |= driversAndAppsDriversPresent
			case tcglog.EventTypeEFIPlatformFirmwareBlob:
				// Code blob from value-added-retailer component - deprecated. Event data should
				// contain a UEFI_PLATFORM_FIRMWARE_BLOB structure.
				result |= driversAndAppsDriversPresent
			case tcglog.EventTypeEFIPlatformFirmwareBlob2:
				// Code blob from value-added-retailer component. Event data should contain a
				// UEFI_PLATFORM_FIRMWARE_BLOB2 structure.
				result |= driversAndAppsDriversPresent
			case tcglog.EventTypeEFISPDMFirmwareBlob:
				// Firmware of a component that supports SPDM "GET_MEASUREMENTS".
				// Note that this is very new (only in the TCG PFP spec v1.06)
				result |= driversAndAppsDriversPresent
			default:
				return 0, fmt.Errorf("unexpected pre-OS log event type %v", ev.EventType)
			}
		case tcglogPhaseOSPresent:
			// Nothing should measure to PCR2outside of pre-OS - we'll generate an invalid profile
			// if it does.
			if ev.PCRIndex == internal_efi.DriversAndAppsPCR {
				return 0, errors.New("firmware measures events as part of the OS-present environment")
			}
		}
	}
	return result, nil
}
