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

package preinstall_test

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
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

func newLogWithPCR2EventAfterOSBoundary(c *C, insertedEvent *tcglog.Event) *tcglog.Log {
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})

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
		if event.PCRIndex == internal_efi.SecureBootPolicyPCR &&
			event.EventType == tcglog.EventTypeEFIVariableAuthority {
			events = append(events, insertedEvent)
			inserted = true
		}
	}
	c.Assert(inserted, Equals, true)
	log.Events = events
	return log
}

func newLogWithPCR2AsFinalSeparator(c *C, insertedEvent *tcglog.Event) *tcglog.Log {
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})

	var (
		events        []*tcglog.Event
		pcr2Separator *tcglog.Event
		inserted      bool
	)
	for _, event := range log.Events {
		if event.PCRIndex == internal_efi.DriversAndAppsPCR &&
			event.EventType == tcglog.EventTypeSeparator {
			pcr2Separator = event
			continue
		}

		events = append(events, event)
		if event.PCRIndex == internal_efi.PlatformManufacturerPCR &&
			event.EventType == tcglog.EventTypeSeparator {
			c.Assert(pcr2Separator, NotNil)
			events = append(events, pcr2Separator, insertedEvent)
			inserted = true
		}
	}
	c.Assert(inserted, Equals, true)
	log.Events = events
	return log
}

// TestCheckDriversAndAppsMeasurementsAcceptsPostSeparatorVendorEvent confirms
// that the PCR2 preinstall check accepts the HP vendor event before the OS
// launch boundary.
func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsAcceptsPostSeparatorVendorEvent(c *C) {
	log := newLogWithPostSeparatorPCR2Event(c, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: 0x00008401,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
		},
		Data: tcglog.OpaqueEventData{0x01},
	})

	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, IsNil)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsAcceptsPCR2AsFinalSeparator(c *C) {
	log := newLogWithPCR2AsFinalSeparator(c, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: 0x00008401,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
		},
		Data: tcglog.OpaqueEventData{0x01},
	})

	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, IsNil)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsRejectsLatePCR2Separator(c *C) {
	log := newLogWithPostSeparatorPCR2Event(c, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: tcglog.EventTypeSeparator,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"),
		},
		Data: &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventNormalValue},
	})

	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `unexpected post-separator event type EV_SEPARATOR found in PCR 2`)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsRejectsMissingOSBoundary(c *C) {
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

	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `reached end of log before encountering initial OS authorization or launch`)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsRejectsPostSeparatorStandardEvent(c *C) {
	log := newLogWithPostSeparatorPCR2Event(c, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: tcglog.EventTypeEFIAction,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
		},
		Data: tcglog.OpaqueEventData{0x01},
	})

	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `unexpected post-separator event type EV_EFI_ACTION found in PCR 2`)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsStopsAtOSBoundary(c *C) {
	log := newLogWithPCR2EventAfterOSBoundary(c, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: tcglog.EventTypeEFIAction,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
		},
		Data: tcglog.OpaqueEventData{0x01},
	})

	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, IsNil)
}
