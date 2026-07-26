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
 */

package efi_test

import (
	"crypto"

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"

	. "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

const hpPreBootDMAConfigEventData = `"SVM CPU Virtualization":"Enable";"DMA protection":"Enable";"Pre-boot DMA protection":"All PCIe devices";`

func newLogWithHPPreBootDMAConfigEvent(c *C) *tcglog.Log {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	data := tcglog.StringEventData(hpPreBootDMAConfigEventData)
	event := &tcglog.Event{
		PCRIndex:  internal_efi.SecureBootPolicyPCR,
		EventType: tcglog.EventTypeEFIAction,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: tcglog.ComputeStringEventDigest(crypto.SHA256, hpPreBootDMAConfigEventData),
		},
		Data: data,
	}

	var events []*tcglog.Event
	added := false
	for _, ev := range log.Events {
		if ev.PCRIndex == internal_efi.SecureBootPolicyPCR &&
			ev.EventType == tcglog.EventTypeEFIVariableDriverConfig &&
			!added {
			events = append(events, event)
			added = true
		}
		events = append(events, ev)
	}
	c.Assert(added, testutil.IsTrue)
	log.Events = events
	return log
}

func measureSecureBootPolicyProfileError(c *C, log *tcglog.Log) error {
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
	}, nil, collector.Next())
	return NewFwLoadHandler(log).MeasureImageStart(ctx)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileWithHPPreBootDMAConfig(c *C) {
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		log:  newLogWithHPPreBootDMAConfigEvent(c),
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "102a994acb0172f38fada0319cea1a2964ad15fcdb54216bcd3a0b821c8612ee")},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileRejectsHPPreBootDMAConfigWithWrongDigest(c *C) {
	log := newLogWithHPPreBootDMAConfigEvent(c)
	for _, ev := range log.Events {
		if internal_efi.IsHPPreBootDMAConfigEvent(ev) {
			ev.Digests[tpm2.HashAlgorithmSHA256] = make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size())
		}
	}

	err := measureSecureBootPolicyProfileError(c, log)
	c.Check(err, ErrorMatches, `cannot measure secure boot policy: invalid digest for HP pre-boot DMA configuration event`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileRejectsDuplicateHPPreBootDMAConfig(c *C) {
	log := newLogWithHPPreBootDMAConfigEvent(c)
	var events []*tcglog.Event
	for _, ev := range log.Events {
		events = append(events, ev)
		if internal_efi.IsHPPreBootDMAConfigEvent(ev) {
			events = append(events, ev)
		}
	}
	log.Events = events

	err := measureSecureBootPolicyProfileError(c, log)
	c.Check(err, ErrorMatches, `cannot measure secure boot policy: unexpected event type \(EV_EFI_ACTION\) found in log, before config`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileRejectsMisplacedHPPreBootDMAConfig(c *C) {
	log := newLogWithHPPreBootDMAConfigEvent(c)
	var (
		events  []*tcglog.Event
		hpEvent *tcglog.Event
		added   bool
	)
	for _, ev := range log.Events {
		if internal_efi.IsHPPreBootDMAConfigEvent(ev) {
			hpEvent = ev
			continue
		}
		events = append(events, ev)
		if ev.PCRIndex == internal_efi.SecureBootPolicyPCR &&
			ev.EventType == tcglog.EventTypeEFIVariableDriverConfig &&
			!added {
			events = append(events, hpEvent)
			added = true
		}
	}
	c.Assert(hpEvent, NotNil)
	c.Assert(added, testutil.IsTrue)
	log.Events = events

	err := measureSecureBootPolicyProfileError(c, log)
	c.Check(err, ErrorMatches, `cannot measure secure boot policy: unexpected event type \(EV_EFI_ACTION\) found in log`)
}
