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
	"bytes"
	"fmt"

	"github.com/canonical/tcglog-parser"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// checkForKernelIOMMU checks that the kernel has enabled some sort of DMA protection.
// On Intel devices, the domains are defined by the DMAR ACPI table. The check is quite
// simple, and based on the fwupd HSI checks.
// XXX: Figure out whether this is genuinely sufficient, eg:
//   - Should we only mandate this if there are externally facing ports, or internal ports
//     that are accessible to the user
//   - Are all externally facing ports protected?
//   - Are internal ports accessible to the user protected?
//   - Are all addon devices with embedded controllers protected?
//
// This function is going to need some additional work later on.
func checkForKernelIOMMU(env internal_efi.HostEnvironment) error {
	devices, err := env.DevicesForClass("iommu")
	switch {
	case err != nil:
		return err
	case len(devices) == 0:
		return ErrNoKernelIOMMU
	}

	for _, device := range devices {
		if device.Subsystem() == "iommu" {
			return nil
		}
	}
	return ErrNoKernelIOMMU
}

// checkSecureBootPolicyPCRForDegradedFirmwareSettings checks PCR7 for the indication of degraded
// firmware settings:
//   - Whether a debugging endpoint is enabled, via the presence of a EV_EFI_ACTION event with the
//     "UEFI Debug Mode" string. This is defined in the TCG PC-Client PFP spec.
//   - Whether DMA protection was disabled at some point, via the presence of a EV_EFI_ACTION event
//     with the "DMA Protection Disabled" string. This is a Windows requirement.
func checkSecureBootPolicyPCRForDegradedFirmwareSettings(log *tcglog.Log) error {
	events := log.Events
	for len(events) > 0 {
		// Pop next event
		event := events[0]
		events = events[1:]

		if event.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}

		switch event.EventType {
		case tcglog.EventTypeEFIAction:
			if event.Data == tcglog.FirmwareDebuggerEvent {
				// Debugger enabled
				return ErrUEFIDebuggingEnabled
			}
			if event.Data == tcglog.DMAProtectionDisabled {
				// DMA protection was disabled bt the firmware at some point
				return ErrInsufficientDMAProtection
			}
			// XXX: My Dell NULL terminates this string which causes decoding to fail,
			//  as the TCG PC Client Platform Firmware Profile spec says that the event
			//  data in EV_EFI_ACTION events should not be NULL terminated.
			if bytes.Equal(event.Data.Bytes(), append([]byte(tcglog.DMAProtectionDisabled), 0x00)) {
				// DMA protection was disabled bt the firmware at some point
				return ErrInsufficientDMAProtection
			}
			// Unexpected data
			return fmt.Errorf("unexpected EV_EFI_ACTION event data in PCR7 event: %q", event.Data)
		case tcglog.EventTypeEFIVariableDriverConfig, tcglog.EventTypeSeparator:
			// ok
		case tcglog.EventTypeEFIVariableAuthority:
			return nil
		default:
			// Unexpected event type
			return fmt.Errorf("unexpected event type (%v) in PCR7", event.EventType)
		}
	}

	// This could only happen if there are no events in PCR7, but checkFirmwareLogAndChoosePCRBank
	// verifies that there is a separator in all TCG defined PCRs.
	panic("not reached")
}
