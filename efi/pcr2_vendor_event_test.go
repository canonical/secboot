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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package efi_test

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

func newLogWithPostSeparatorPCR2Event(c *C, insertedEvent *tcglog.Event) *tcglog.Log {
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})

	var events []*tcglog.Event
	inserted := false
	for _, event := range log.Events {
		events = append(events, event)
		if event.PCRIndex == internal_efi.PlatformManufacturerPCR &&
			event.EventType == tcglog.EventTypeSeparator {
			events = append(events, insertedEvent)
			inserted = true
		}
	}
	c.Assert(inserted, Equals, true)
	log.Events = events
	return log
}

func newLogWithPCR2EventAfterOSBoundary(c *C, opts *efitest.LogOptions, insertedEvent *tcglog.Event) *tcglog.Log {
	log := efitest.NewLog(c, opts)

	var events []*tcglog.Event
	seenPCR2Separator := false
	inserted := false
	for _, event := range log.Events {
		events = append(events, event)

		if event.PCRIndex == internal_efi.DriversAndAppsPCR &&
			event.EventType == tcglog.EventTypeSeparator {
			seenPCR2Separator = true
			continue
		}
		if !seenPCR2Separator || inserted {
			continue
		}

		if (event.PCRIndex == internal_efi.SecureBootPolicyPCR &&
			event.EventType == tcglog.EventTypeEFIVariableAuthority) ||
			(event.PCRIndex == internal_efi.BootManagerCodePCR &&
				event.EventType == tcglog.EventTypeEFIBootServicesApplication) {
			events = append(events, insertedEvent)
			inserted = true
		}
	}
	c.Assert(inserted, Equals, true)
	log.Events = events
	return log
}

// TestMeasureImageStartDriversAndAppsIncludesPostSeparatorVendorEvent
// reproduces the event ordering from the HP ZBook Ultra G1a firmware:
//
//	PCR2 EV_SEPARATOR
//	...
//	PCR2 vendor event 0x00008401 with data 0x01
//	...
//	PCR7 EV_EFI_VARIABLE_AUTHORITY
//	PCR4 EV_EFI_BOOT_SERVICES_APPLICATION
//
// The event digest must be retained in the generated PCR2 profile because the
// firmware extends it into the TPM before launching the OS.
func (s *fwLoadHandlerSuite) TestMeasureImageStartDriversAndAppsIncludesPostSeparatorVendorEvent(c *C) {
	vendorDigest := testutil.DecodeHexString(c, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a")
	log := newLogWithPostSeparatorPCR2Event(c, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: 0x00008401,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: vendorDigest,
		},
		Data: tcglog.OpaqueEventData{0x01},
	})

	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		log:  log,
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.DriversAndAppsPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 2, eventType: mockPcrBranchResetEvent},
			{pcr: 2, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
			{pcr: 2, eventType: mockPcrBranchExtendEvent, digest: vendorDigest},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartDriversAndAppsRejectsPostSeparatorStandardEvent(c *C) {
	log := newLogWithPostSeparatorPCR2Event(c, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: tcglog.EventTypeEFIAction,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
		},
		Data: tcglog.OpaqueEventData{0x01},
	})

	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(nil, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.DriversAndAppsPCR),
	}, nil, collector.Next())

	handler := NewFwLoadHandler(log)
	c.Check(
		handler.MeasureImageStart(ctx),
		ErrorMatches,
		`cannot measure drivers and apps: unexpected post-separator event type EV_EFI_ACTION found in PCR 2`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartDriversAndAppsRejectsMissingOSBoundary(c *C) {
	log := newLogWithPostSeparatorPCR2Event(c, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: 0x00008401,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
		},
		Data: tcglog.OpaqueEventData{0x01},
	})

	truncated := false
	for i, event := range log.Events {
		if (event.PCRIndex == internal_efi.SecureBootPolicyPCR &&
			event.EventType == tcglog.EventTypeEFIVariableAuthority) ||
			(event.PCRIndex == internal_efi.BootManagerCodePCR &&
				event.EventType == tcglog.EventTypeEFIBootServicesApplication) {
			log.Events = log.Events[:i]
			truncated = true
			break
		}
	}
	c.Assert(truncated, Equals, true)

	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(nil, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.DriversAndAppsPCR),
	}, nil, collector.Next())

	handler := NewFwLoadHandler(log)
	c.Check(
		handler.MeasureImageStart(ctx),
		ErrorMatches,
		`cannot measure drivers and apps: reached end of log before encountering initial OS authorization or launch`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartDriversAndAppsStopsAtVariableAuthorityBoundary(c *C) {
	vendorDigest := testutil.DecodeHexString(c, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a")
	log := newLogWithPCR2EventAfterOSBoundary(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	}, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: 0x00008401,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: vendorDigest,
		},
		Data: tcglog.OpaqueEventData{0x01},
	})

	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		log:  log,
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.DriversAndAppsPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 2, eventType: mockPcrBranchResetEvent},
			{pcr: 2, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartDriversAndAppsStopsAtImageLaunchBoundary(c *C) {
	vendorDigest := testutil.DecodeHexString(c, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a")
	log := newLogWithPCR2EventAfterOSBoundary(c, &efitest.LogOptions{
		Algorithms:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		SecureBootDisabled: true,
	}, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: 0x00008401,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: vendorDigest,
		},
		Data: tcglog.OpaqueEventData{0x01},
	})

	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		log:  log,
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.DriversAndAppsPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 2, eventType: mockPcrBranchResetEvent},
			{pcr: 2, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}
