// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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

package efi

import (
	"bytes"
	"errors"
	"fmt"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
)

const hpPreBootDMAConfigEventData = `"SVM CPU Virtualization":"Enable";"DMA protection":"Enable";"Pre-boot DMA protection":"All PCIe devices";`

// AMDTSMEConfigEventType is the vendor-defined event type used by AMD AGESA
// to measure the TSME status.
const AMDTSMEConfigEventType tcglog.EventType = 0x00008401

// IsVendorEventType indicates whether the supplied event type is vendor
// defined. Officially, this applies to any event type that is not within the
// range of TCG reserved types (0x00000000-0x0000ffff and 0x80000000-0x8000ffff),
// however, this also considers event types between 0x00008000-0x0000ffff to be
// vendor defined because AMD firmware is using these and it's unlikely that
// these types are going to be used by the TCG.
func IsVendorEventType(t tcglog.EventType) bool {
	switch {
	case t&0x80000000 > 0:
		return t > 0x8000ffff
	default:
		return t > 0x7fff
	}
}

// AMDTSMEConfigEventData returns the event data measured by AMD AGESA for the
// supplied TSME status.
func AMDTSMEConfigEventData(enabled bool) []byte {
	if enabled {
		return []byte{1}
	}
	return []byte{0}
}

// IsAMDTSMEConfigEvent indicates whether the supplied event is an AMD AGESA
// TSME status measurement. AGESA measures this to PCR2 and, when TSME is
// disabled, may additionally measure it to PCR7.
func IsAMDTSMEConfigEvent(ev *tcglog.Event) bool {
	return (ev.PCRIndex == DriversAndAppsPCR || ev.PCRIndex == SecureBootPolicyPCR) &&
		ev.EventType == AMDTSMEConfigEventType
}

// HPPreBootDMAConfigEventData returns the expected event data for HP's
// enabled SVM and DMA protection configuration.
func HPPreBootDMAConfigEventData() string {
	return hpPreBootDMAConfigEventData
}

// IsHPPreBootDMAConfigEvent indicates whether the supplied event is the exact
// virtualization and pre-boot DMA configuration measurement produced by HP
// firmware when "Measure Additional DMA Settings" is directed to PCR7.
func IsHPPreBootDMAConfigEvent(ev *tcglog.Event) bool {
	return ev.PCRIndex == SecureBootPolicyPCR &&
		ev.EventType == tcglog.EventTypeEFIAction &&
		bytes.Equal(ev.Data.Bytes(), []byte(hpPreBootDMAConfigEventData))
}

// IsLaunchedFromFirmwareVolume indicates that the supplied event is associated
// with an image launch from a firmware volume.
func IsLaunchedFromFirmwareVolume(ev *tcglog.Event) (yes bool, err error) {
	// The caller should check this.
	switch ev.EventType {
	case tcglog.EventTypeEFIBootServicesDriver, tcglog.EventTypeEFIRuntimeServicesDriver, tcglog.EventTypeEFIBootServicesApplication:
		// ok
	default:
		return false, fmt.Errorf("unexpected event type %v", ev.EventType)
	}

	data, ok := ev.Data.(*tcglog.EFIImageLoadEvent)
	if !ok {
		return false, fmt.Errorf("event has invalid event data: %w", ev.Data.(error))
	}

	if len(data.DevicePath) == 0 {
		return false, errors.New("empty device path")
	}

	return data.DevicePath[0].CompoundType() == efi.DevicePathNodeFwVolType, nil
}
