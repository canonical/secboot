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
	"context"
	"errors"
	"fmt"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// checkDriversAndAppsMeasurements performs minimal checks on PCR 2, which is where
// addon code from value-added-retailer components such as option ROMs and UEFI
// drivers are measured.
//
// It returns information about any addon drivers that are detected.
//
// As efi.WithDriversAndAppsProfile just copies events from the log and does no
// prediction for this PCR, this function doesn't do any more extensive testing, such
// as ensuring that the PCR only contains events of the expected type, the event data
// for each event is of an expected type, and for events where the digest is a tagged
// hash of the event data, that the digest is consistent with the event data. It may be
// extended to in the future.
//
// This function expects that the supplied log has already been tested to be valid (eg,
// with checkFirmwareLogAndChoosePCRBank), and will panic if it isn't
func checkDriversAndAppsMeasurements(ctx context.Context, env internal_efi.HostEnvironment, log *tcglog.Log, pcrAlg tpm2.HashAlgorithmId) ([]*LoadedImageInfo, error) {
	varCtx := env.VarContext(ctx)

	// Obtain the list of DriverXXXX load options for drivers that are started
	// from BDS rather than from an option ROM.
	driverLoadOpts, driverLoadOrder, err := readOrderedLoadOptionVariables(varCtx, efi.LoadOptionClassDriver)
	if err != nil && !errors.Is(err, efi.ErrVarNotExist) {
		return nil, fmt.Errorf("cannot read driver load option variables: %w", err)
	}

	var addonDrivers []*LoadedImageInfo

	// Iterate over the log until OS-present and check if there are any
	// drivers or applications loaded
	phaseTracker := newTcgLogPhaseTracker()
	for _, ev := range log.Events {
		phase, err := phaseTracker.processEvent(ev)
		if err != nil {
			return nil, err
		}

		if phase >= tcglogPhaseTransitioningToOSPresent {
			return addonDrivers, nil
		}

		if ev.PCRIndex != internal_efi.DriversAndAppsPCR {
			// Not PCR2
			continue
		}

		switch ev.EventType {
		case tcglog.EventTypeEFIBootServicesApplication, tcglog.EventTypeEFIBootServicesDriver, tcglog.EventTypeEFIRuntimeServicesDriver:
			data, ok := ev.Data.(*tcglog.EFIImageLoadEvent)
			if !ok {
				return nil, fmt.Errorf("invalid %v event data: %w", ev.EventType, ev.Data.(error))
			}
			opt, n, err := matchLaunchToLoadOption(ev, driverLoadOrder, driverLoadOpts...)
			if err != nil {
				return nil, fmt.Errorf("cannot match %v event for %v to a driver load option: %w", ev.EventType, data.DevicePath, err)
			}
			var (
				description    string
				loadOptionName string
			)
			if opt != nil {
				description = opt.Description
				loadOptionName = efi.FormatLoadOptionVariableName(efi.LoadOptionClassDriver, n)
			}
			addonDrivers = append(addonDrivers, &LoadedImageInfo{
				Format:         LoadedImageFormatPE,
				Description:    description,
				LoadOptionName: loadOptionName,
				DevicePath:     data.DevicePath,
				DigestAlg:      pcrAlg,
				Digest:         ev.Digests[pcrAlg],
			})
		case tcglog.EventTypeEFIPlatformFirmwareBlob:
			addonDrivers = append(addonDrivers, &LoadedImageInfo{
				Format:    LoadedImageFormatBlob,
				DigestAlg: pcrAlg,
				Digest:    ev.Digests[pcrAlg],
			})
		case tcglog.EventTypeEFIPlatformFirmwareBlob2:
			data, ok := ev.Data.(*tcglog.EFIPlatformFirmwareBlob2)
			if !ok {
				return nil, fmt.Errorf("invalid EV_EFI_PLATFORM_FIRMWARE_BLOB2 event data: %w", ev.Data.(error))
			}
			addonDrivers = append(addonDrivers, &LoadedImageInfo{
				Format:      LoadedImageFormatBlob,
				Description: data.BlobDescription,
				DigestAlg:   pcrAlg,
				Digest:      ev.Digests[pcrAlg],
			})
		}
	}

	return nil, errors.New("reached end of log before encountering transition to OS-present")
}
