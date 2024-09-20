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
	"github.com/canonical/tcglog-parser"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

type checkDriversAndAppsMeasurementsResult int

const (
	noDriversAndAppsPresent checkDriversAndAppsMeasurementsResult = iota
	driversAndAppsPresent
)

// checkDriversAndAppsMeasurements performs minimal checks on PCR 2, which is where
// addon code from value-added-retailer components such as option ROMs and UEFI
// drivers are measured.
//
// It returns whether the PCR indicates that there is code from value-added-retailer
// components executing.
//
// As efi.WithDriversAndAppsProfile just copies events from the log and does no
// prediction for this PCR, this function doesn't do any more extensive testing, such
// as ensuring that the PCR only contains events of the expected type, the event data
// for each event is of an expected type, and for events where the digest is a tagged
// hash of the event data, that the digest is consistent with the event data.
func checkDriversAndAppsMeasurements(log *tcglog.Log) (checkDriversAndAppsMeasurementsResult, error) {
	// Iterate over the log until OS-present and check if there are any
	// drivers or applications loaded
	phaseTracker := newTcgLogPhaseTracker()
	for _, ev := range log.Events {
		phase, err := phaseTracker.processEvent(ev)
		if err != nil {
			return noDriversAndAppsPresent, err
		}

		if phase >= tcglogPhaseTransitioningToOSPresent {
			return noDriversAndAppsPresent, nil
		}

		if ev.PCRIndex != internal_efi.DriversAndAppsPCR {
			// Not PCR2
			continue
		}

		switch ev.EventType {
		case tcglog.EventTypeEFIBootServicesApplication, tcglog.EventTypeEFIBootServicesDriver, tcglog.EventTypeEFIRuntimeServicesDriver,
			tcglog.EventTypeEFIPlatformFirmwareBlob, tcglog.EventTypeEFIPlatformFirmwareBlob2, tcglog.EventTypeEFISPDMFirmwareBlob:
			return driversAndAppsPresent, nil
		}
	}

	panic("not reached")
}
