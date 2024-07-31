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

package preinstall_test

import (
	"errors"
	"io"

	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type tcglogSuite struct {
	tpm2_testutil.TPMSimulatorTest
}

var _ = Suite(&tcglogSuite{})

func (s *tcglogSuite) resetTPMAndReplayLog(c *C, log *tcglog.Log, algs ...tpm2.HashAlgorithmId) {
	s.ResetTPMSimulatorNoStartup(c) // Shutdown and reset the simulator to reset the PCRs back to their reset values.
	// Don't immediately call TPM2_Startup in case the log indicates we need to change localities.
	started := false
	for _, ev := range log.Events {
		if ev.EventType == tcglog.EventTypeNoAction {
			// EV_NO_ACTION events are informational and not measured
			if startupLocalityData, isStartupLocality := ev.Data.(*tcglog.StartupLocalityEventData); isStartupLocality {
				c.Assert(ev.PCRIndex, Equals, internal_efi.PlatformFirmwarePCR)
				c.Assert(started, testutil.IsFalse)

				switch startupLocalityData.StartupLocality {
				case 0:
					// do nothing
				case 3:
					s.Mssim(c).SetLocality(3)
					c.Assert(s.TPM.Startup(tpm2.StartupClear), IsNil)
					s.Mssim(c).SetLocality(0)
					started = true
				default:
					c.Fatal("TPM2_Startup can only be called from localities 0 or 3")
				}
			}
			continue
		}

		if !started {
			// Our first actual measurement and we haven't called TPM2_Startup yet
			c.Assert(s.TPM.Startup(tpm2.StartupClear), IsNil)
			started = true
		}

		var digests tpm2.TaggedHashList
		for _, alg := range algs {
			digest, ok := ev.Digests[alg]
			c.Assert(ok, testutil.IsTrue)
			digests = append(digests, tpm2.MakeTaggedHash(alg, tpm2.Digest(digest)))
		}
		c.Assert(s.TPM.PCRExtend(s.TPM.PCRHandleContext(int(ev.PCRIndex)), digests, nil), IsNil)
	}
}

func (s *tcglogSuite) allocatePCRBanks(c *C, algs ...tpm2.HashAlgorithmId) {
	current, err := s.TPM.GetCapabilityPCRs()
	c.Assert(err, IsNil)

	pcrs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}

	// Iterate over the returned PCR selections first
	for i, selection := range current {
		found := false
		for _, alg := range algs {
			if selection.Hash == alg {
				found = true // An algorithm we want to enable already appears in the TPML_PCR_SELECTION
				break
			}
		}
		switch found {
		case true:
			// Enable this bank
			current[i].Select = pcrs
		case false:
			current[i].Select = nil // Disable this bank by clearing the selection
		}
	}

	// We might need to enable PCR banks by adding extra TPMS_PCR_SELECTION structures
	for _, alg := range algs {
		found := false
		for _, selection := range current {
			if selection.Hash == alg {
				// We enabled this one earlier
				found = true
				break
			}
		}
		if found {
			continue
		}
		// We haven't enabled this one yet, so append a new TPMS_PCR_SELECTION
		current = append(current, tpm2.PCRSelection{Hash: alg, Select: pcrs})
	}

	// Set the PCR allocation
	success, _, _, _, err := s.TPM.PCRAllocate(s.TPM.PlatformHandleContext(), current, nil)
	c.Assert(err, IsNil)
	c.Assert(success, testutil.IsTrue)

	s.ResetTPMSimulator(c)
}

type testCheckFirmwareLogAndChoosePCRBankParams struct {
	enabledBanks    []tpm2.HashAlgorithmId
	logAlgs         []tpm2.HashAlgorithmId
	startupLocality uint8
	replayAlgs      []tpm2.HashAlgorithmId
	mandatoryPcrs   tpm2.HandleList

	expectedAlg tpm2.HashAlgorithmId
}

func (s *tcglogSuite) testCheckFirmwareLogAndChoosePCRBank(c *C, params *testCheckFirmwareLogAndChoosePCRBankParams) {
	s.allocatePCRBanks(c, params.enabledBanks...)

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:      params.logAlgs,
		StartupLocality: params.startupLocality,
	})
	s.resetTPMAndReplayLog(c, log, params.replayAlgs...)
	result, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, params.mandatoryPcrs)
	c.Assert(err, IsNil)
	c.Check(result.Alg, Equals, params.expectedAlg)
	c.Check(result.StartupLocality, Equals, params.startupLocality)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankSHA256(c *C) {
	s.testCheckFirmwareLogAndChoosePCRBank(c, &testCheckFirmwareLogAndChoosePCRBankParams{
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		logAlgs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		replayAlgs:   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		mandatoryPcrs: tpm2.HandleList{
			internal_efi.PlatformFirmwarePCR,
			internal_efi.PlatformFirmwareConfigPCR,
			internal_efi.DriversAndAppsPCR,
			internal_efi.DriversAndAppsConfigPCR,
			internal_efi.BootManagerCodePCR,
			internal_efi.BootManagerCodeConfigPCR,
			internal_efi.PlatformManufacturerPCR,
			internal_efi.SecureBootPolicyPCR,
		},
		expectedAlg: tpm2.HashAlgorithmSHA256,
	})
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankSHA384(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)
	s.testCheckFirmwareLogAndChoosePCRBank(c, &testCheckFirmwareLogAndChoosePCRBankParams{
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA384},
		logAlgs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA384},
		replayAlgs:   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA384},
		mandatoryPcrs: tpm2.HandleList{
			internal_efi.PlatformFirmwarePCR,
			internal_efi.PlatformFirmwareConfigPCR,
			internal_efi.DriversAndAppsPCR,
			internal_efi.DriversAndAppsConfigPCR,
			internal_efi.BootManagerCodePCR,
			internal_efi.BootManagerCodeConfigPCR,
			internal_efi.PlatformManufacturerPCR,
			internal_efi.SecureBootPolicyPCR,
		},
		expectedAlg: tpm2.HashAlgorithmSHA384,
	})
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankSHA512(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA512)
	s.testCheckFirmwareLogAndChoosePCRBank(c, &testCheckFirmwareLogAndChoosePCRBankParams{
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA512},
		logAlgs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA512},
		replayAlgs:   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA512},
		mandatoryPcrs: tpm2.HandleList{
			internal_efi.PlatformFirmwarePCR,
			internal_efi.PlatformFirmwareConfigPCR,
			internal_efi.DriversAndAppsPCR,
			internal_efi.DriversAndAppsConfigPCR,
			internal_efi.BootManagerCodePCR,
			internal_efi.BootManagerCodeConfigPCR,
			internal_efi.PlatformManufacturerPCR,
			internal_efi.SecureBootPolicyPCR,
		},
		expectedAlg: tpm2.HashAlgorithmSHA512,
	})
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankMultipleSHA384(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)
	s.testCheckFirmwareLogAndChoosePCRBank(c, &testCheckFirmwareLogAndChoosePCRBankParams{
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		logAlgs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		replayAlgs:   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		mandatoryPcrs: tpm2.HandleList{
			internal_efi.PlatformFirmwarePCR,
			internal_efi.PlatformFirmwareConfigPCR,
			internal_efi.DriversAndAppsPCR,
			internal_efi.DriversAndAppsConfigPCR,
			internal_efi.BootManagerCodePCR,
			internal_efi.BootManagerCodeConfigPCR,
			internal_efi.PlatformManufacturerPCR,
			internal_efi.SecureBootPolicyPCR,
		},
		expectedAlg: tpm2.HashAlgorithmSHA384,
	})
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankSHA256WithEmptySHA384Bank(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)
	s.testCheckFirmwareLogAndChoosePCRBank(c, &testCheckFirmwareLogAndChoosePCRBankParams{
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		logAlgs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		replayAlgs:   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		mandatoryPcrs: tpm2.HandleList{
			internal_efi.PlatformFirmwarePCR,
			internal_efi.PlatformFirmwareConfigPCR,
			internal_efi.DriversAndAppsPCR,
			internal_efi.DriversAndAppsConfigPCR,
			internal_efi.BootManagerCodePCR,
			internal_efi.BootManagerCodeConfigPCR,
			internal_efi.PlatformManufacturerPCR,
			internal_efi.SecureBootPolicyPCR,
		},
		expectedAlg: tpm2.HashAlgorithmSHA256,
	})
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankSHA256StartupLocality3(c *C) {
	s.testCheckFirmwareLogAndChoosePCRBank(c, &testCheckFirmwareLogAndChoosePCRBankParams{
		enabledBanks:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		logAlgs:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		startupLocality: 3,
		replayAlgs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		mandatoryPcrs: tpm2.HandleList{
			internal_efi.PlatformFirmwarePCR,
			internal_efi.PlatformFirmwareConfigPCR,
			internal_efi.DriversAndAppsPCR,
			internal_efi.DriversAndAppsConfigPCR,
			internal_efi.BootManagerCodePCR,
			internal_efi.BootManagerCodeConfigPCR,
			internal_efi.PlatformManufacturerPCR,
			internal_efi.SecureBootPolicyPCR,
		},
		expectedAlg: tpm2.HashAlgorithmSHA256,
	})
}

// TODO(chrisccoulson): github.com/canonical/go-tpm2/mssim needs support for sending H-CRTM
//  event sequences to the simulator in order to run this test, which is relatively non-trivial
//  to add - see https://github.com/canonical/go-tpm2/issues/18
//func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankSHA256WithHCRTM(c *C) {
//	s.testCheckFirmwareLogAndChoosePCRBank(c, &testCheckFirmwareLogAndChoosePCRBankParams{
//		enabledBanks:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
//		logAlgs:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
//		startupLocality: 4,
//		replayAlgs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
//		mandatoryPcrs: tpm2.HandleList{
//			internal_efi.PlatformFirmwarePCR,
//			internal_efi.PlatformFirmwareConfigPCR,
//			internal_efi.DriversAndAppsPCR,
//			internal_efi.DriversAndAppsConfigPCR,
//			internal_efi.BootManagerCodePCR,
//			internal_efi.BootManagerCodeConfigPCR,
//			internal_efi.PlatformManufacturerPCR,
//			internal_efi.SecureBootPolicyPCR,
//		},
//		expectedAlg: tpm2.HashAlgorithmSHA256,
//	})
//}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankMultipleSHA384StartupLocality3(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)
	s.testCheckFirmwareLogAndChoosePCRBank(c, &testCheckFirmwareLogAndChoosePCRBankParams{
		enabledBanks:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		logAlgs:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		startupLocality: 3,
		replayAlgs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		mandatoryPcrs: tpm2.HandleList{
			internal_efi.PlatformFirmwarePCR,
			internal_efi.PlatformFirmwareConfigPCR,
			internal_efi.DriversAndAppsPCR,
			internal_efi.DriversAndAppsConfigPCR,
			internal_efi.BootManagerCodePCR,
			internal_efi.BootManagerCodeConfigPCR,
			internal_efi.PlatformManufacturerPCR,
			internal_efi.SecureBootPolicyPCR,
		},
		expectedAlg: tpm2.HashAlgorithmSHA384,
	})
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankUnexpectedStartupLocality(c *C) {
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256)

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		StartupLocality: 3,
	})
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256)

	// Move the startup locality event to PCR 1

	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex != internal_efi.PlatformFirmwarePCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeNoAction {
			continue
		}
		if _, isStartupLocality := ev.Data.(*tcglog.StartupLocalityEventData); !isStartupLocality {
			continue
		}

		ev.PCRIndex = internal_efi.PlatformFirmwareConfigPCR
		break
	}

	_, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, tpm2.HandleList{
		internal_efi.PlatformFirmwarePCR,
	})
	c.Check(err, ErrorMatches, `no suitable PCR algorithm available:
- TPM_ALG_SHA512: digest algorithm not present in log.
- TPM_ALG_SHA384: digest algorithm not present in log.
- TPM_ALG_SHA256\(PCR0\): PCR value mismatch \(actual from TPM 0xb0d6d5f50852be1524306ad88b928605c14338e56a1b8c0dc211a144524df2ef, reconstructed from log 0xa6602a7a403068b5556e78cc3f5b00c9c76d33d514093ca9b584dce7590e6c69\).
- TPM_ALG_SHA256\(PCR1\): unexpected StartupLocality event \(should be in PCR0\).
`)
	var e *NoSuitablePCRAlgorithmError
	c.Check(errors.As(err, &e), testutil.IsTrue)

	// Test that we can access individual errors.
	c.Check(e.UnwrapBankError(tpm2.HashAlgorithmSHA512), ErrorMatches, `digest algorithm not present in log`)
	c.Check(e.UnwrapBankError(tpm2.HashAlgorithmSHA384), ErrorMatches, `digest algorithm not present in log`)
	c.Check(e.UnwrapPCRError(tpm2.HashAlgorithmSHA384, internal_efi.PlatformFirmwarePCR), IsNil)
	c.Check(e.UnwrapBankError(tpm2.HashAlgorithmSHA256), IsNil)
	c.Check(e.UnwrapPCRError(tpm2.HashAlgorithmSHA256, internal_efi.PlatformFirmwarePCR), ErrorMatches, `PCR value mismatch \(actual from TPM 0xb0d6d5f50852be1524306ad88b928605c14338e56a1b8c0dc211a144524df2ef, reconstructed from log 0xa6602a7a403068b5556e78cc3f5b00c9c76d33d514093ca9b584dce7590e6c69\)`)
	c.Check(e.UnwrapPCRError(tpm2.HashAlgorithmSHA256, internal_efi.PlatformFirmwareConfigPCR), ErrorMatches, `unexpected StartupLocality event \(should be in PCR0\)`)
	c.Check(e.UnwrapPCRError(tpm2.HashAlgorithmSHA256, internal_efi.DriversAndAppsPCR), IsNil)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankOutOfPlaceStartupLocality(c *C) {
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256)

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		StartupLocality: 3,
	})
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256)

	// Move the startup locality event after the first EV_NO_ACTION event in PCR 0
	var slEvent *tcglog.Event      // the startup locality event
	events := log.Events           // the current events
	var eventsCopy []*tcglog.Event // a copy of the events

	// Find the startup locality event, omitting it from the copy of events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]
		eventsCopy = append(eventsCopy, ev)

		if ev.PCRIndex != internal_efi.PlatformFirmwarePCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeNoAction {
			continue
		}
		if _, isStartupLocality := ev.Data.(*tcglog.StartupLocalityEventData); !isStartupLocality {
			continue
		}

		slEvent = ev
		eventsCopy = eventsCopy[:len(eventsCopy)-1] // truncate the copy of events by 1
		break
	}

	c.Assert(slEvent, NotNil)

	// Find the first non EV_NO_ACTION event in PCR 0 and move the startup locality event after it
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]
		eventsCopy = append(eventsCopy, ev)

		if ev.PCRIndex == internal_efi.PlatformFirmwarePCR &&
			ev.EventType != tcglog.EventTypeNoAction && slEvent != nil {
			eventsCopy = append(eventsCopy, slEvent)
			slEvent = nil
		}
	}

	// Swap the log over
	log.Events = eventsCopy

	_, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, tpm2.HandleList{
		internal_efi.PlatformFirmwarePCR,
	})
	c.Check(err, ErrorMatches, `no suitable PCR algorithm available:
- TPM_ALG_SHA512: digest algorithm not present in log.
- TPM_ALG_SHA384: digest algorithm not present in log.
- TPM_ALG_SHA256\(PCR0\): unexpected StartupLocality event after measurements already made.
`)
	var e *NoSuitablePCRAlgorithmError
	c.Check(errors.As(err, &e), testutil.IsTrue)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankInvalidStartupLocality(c *C) {
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256)

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		StartupLocality: 3,
	})
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256)

	// Change the startup locality to 2

	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex != internal_efi.PlatformFirmwarePCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeNoAction {
			continue
		}
		if _, isStartupLocality := ev.Data.(*tcglog.StartupLocalityEventData); !isStartupLocality {
			continue
		}

		ev.Data = &tcglog.StartupLocalityEventData{StartupLocality: 2}
		break
	}

	_, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, tpm2.HandleList{
		internal_efi.PlatformFirmwarePCR,
	})
	c.Check(err, ErrorMatches, `no suitable PCR algorithm available:
- TPM_ALG_SHA512: digest algorithm not present in log.
- TPM_ALG_SHA384: digest algorithm not present in log.
- TPM_ALG_SHA256\(PCR0\): invalid StartupLocality value 2 - TPM2_Startup is only permitted from locality 0 or 3, or PCR0 can be initialized from locality 4 by a H-CRTM event before TPM2_Startup is called.
`)
	var e *NoSuitablePCRAlgorithmError
	c.Check(errors.As(err, &e), testutil.IsTrue)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankPCRMismatchMandatory(c *C) {
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256)

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		StartupLocality: 3,
	})
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256)

	// This will make the PCR 0 calculation wrong
	log = efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})
	_, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, tpm2.HandleList{
		internal_efi.PlatformFirmwarePCR,
	})
	c.Check(err, ErrorMatches, `no suitable PCR algorithm available:
- TPM_ALG_SHA512: digest algorithm not present in log.
- TPM_ALG_SHA384: digest algorithm not present in log.
- TPM_ALG_SHA256\(PCR0\): PCR value mismatch \(actual from TPM 0xb0d6d5f50852be1524306ad88b928605c14338e56a1b8c0dc211a144524df2ef, reconstructed from log 0xa6602a7a403068b5556e78cc3f5b00c9c76d33d514093ca9b584dce7590e6c69\).
`)
	var e *NoSuitablePCRAlgorithmError
	c.Check(errors.As(err, &e), testutil.IsTrue)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankPCRMismatchNonMandatory(c *C) {
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256)

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		StartupLocality: 3,
	})
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256)

	// This will make the PCR 0 calculation wrong
	log = efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})
	results, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log,
		tpm2.HandleList{
			internal_efi.PlatformFirmwareConfigPCR,
			internal_efi.DriversAndAppsPCR,
			internal_efi.DriversAndAppsConfigPCR,
			internal_efi.BootManagerCodePCR,
			internal_efi.BootManagerCodeConfigPCR,
			internal_efi.PlatformManufacturerPCR,
			internal_efi.SecureBootPolicyPCR,
		},
	)
	c.Assert(err, IsNil)
	c.Check(results.Alg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(results.Ok(), Equals, true)
	c.Check(results.Lookup(internal_efi.PlatformFirmwarePCR).Ok(), Equals, false)
	c.Check(results.Lookup(internal_efi.PlatformFirmwarePCR).Err(), ErrorMatches, `PCR value mismatch \(actual from TPM 0xb0d6d5f50852be1524306ad88b928605c14338e56a1b8c0dc211a144524df2ef, reconstructed from log 0xa6602a7a403068b5556e78cc3f5b00c9c76d33d514093ca9b584dce7590e6c69\)`)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankPCRMismatchMandatoryInOneBank(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384)

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		StartupLocality: 3,
	})
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384)

	for i, ev := range log.Events {
		if ev.PCRIndex != internal_efi.BootManagerCodePCR {
			continue
		}
		if ev.EventType == tcglog.EventTypeEFIAction {
			log.Events[i].Digests[tpm2.HashAlgorithmSHA384] = make(tpm2.Digest, tpm2.HashAlgorithmSHA384.Size())
		}
	}

	results, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log,
		tpm2.HandleList{
			internal_efi.PlatformFirmwarePCR,
			internal_efi.PlatformFirmwareConfigPCR,
			internal_efi.DriversAndAppsPCR,
			internal_efi.DriversAndAppsConfigPCR,
			internal_efi.BootManagerCodePCR,
			internal_efi.BootManagerCodeConfigPCR,
			internal_efi.PlatformManufacturerPCR,
			internal_efi.SecureBootPolicyPCR,
		},
	)
	c.Assert(err, IsNil)
	c.Check(results.Alg, Equals, tpm2.HashAlgorithmSHA256)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankPCRMismatchNonMandatoryInOneBank(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384)

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		StartupLocality: 3,
	})
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384)

	for i, ev := range log.Events {
		if ev.PCRIndex != internal_efi.BootManagerCodePCR {
			continue
		}
		if ev.EventType == tcglog.EventTypeEFIAction {
			log.Events[i].Digests[tpm2.HashAlgorithmSHA384] = make(tpm2.Digest, tpm2.HashAlgorithmSHA384.Size())
		}
	}

	results, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log,
		tpm2.HandleList{
			internal_efi.PlatformFirmwarePCR,
			internal_efi.PlatformFirmwareConfigPCR,
			internal_efi.DriversAndAppsPCR,
			internal_efi.DriversAndAppsConfigPCR,
			internal_efi.BootManagerCodeConfigPCR,
			internal_efi.PlatformManufacturerPCR,
			internal_efi.SecureBootPolicyPCR,
		},
	)
	c.Assert(err, IsNil)
	c.Check(results.Alg, Equals, tpm2.HashAlgorithmSHA384)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankBadSpec(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})
	log.Spec = tcglog.Spec{
		PlatformType: tcglog.PlatformTypeEFI,
		Major:        1,
		Minor:        2,
		Errata:       0,
	}
	_, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, nil)
	c.Check(err, ErrorMatches, `invalid log spec`)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankPreOSMeasurementToNonTCGPCR(c *C) {
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256)
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})

	var eventsCopy []*tcglog.Event
	events := log.Events
	added := false
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex >= internal_efi.PlatformFirmwarePCR && ev.PCRIndex <= internal_efi.PlatformManufacturerPCR && ev.EventType == tcglog.EventTypeSeparator && !added {
			eventsCopy = append(eventsCopy, &tcglog.Event{
				PCRIndex:  8,
				EventType: tcglog.EventTypeEventTag,
				Data:      &tcglog.TaggedEvent{EventID: 10, Data: []byte{1, 2, 3, 4}},
				Digests:   tcglog.DigestMap{tpm2.HashAlgorithmSHA256: make([]byte, 32)},
			})
			added = true
		}

		eventsCopy = append(eventsCopy, ev)
	}
	log.Events = eventsCopy
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256)

	_, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, nil)
	c.Check(err, ErrorMatches, `measurements were made by firmware from pre-OS environment to non-TCG defined PCR 8`)
}

type invalidEventData struct {
	err error
}

func (e *invalidEventData) String() string        { return "invalid event data: " + e.err.Error() }
func (*invalidEventData) Bytes() []byte           { return nil }
func (*invalidEventData) Write(w io.Writer) error { return errors.New("not supported") }
func (e *invalidEventData) Error() string         { return e.err.Error() }

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankSeparatorDecodeError(c *C) {
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256)
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.EventType != tcglog.EventTypeSeparator {
			continue
		}

		ev.Data = &invalidEventData{errors.New("some error")}
		break
	}
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256)

	_, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, nil)
	c.Check(err, ErrorMatches, `invalid event data for EV_SEPARATOR event in PCR 7: some error`)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankSeparatorError(c *C) {
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256)
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.EventType != tcglog.EventTypeSeparator {
			continue
		}

		ev.Data = &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventErrorValue, ErrorInfo: []byte{1, 2, 3, 4}}
		break
	}
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256)

	_, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, nil)
	c.Check(err, ErrorMatches, `EV_SEPARATOR event for PCR 7 indicates an error occurred \(error code in log: 67305985\)`)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankMissingSeparators(c *C) {
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256)
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})
	var eventsCopy []*tcglog.Event
	skippedOneSeparator := false
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.EventType != tcglog.EventTypeSeparator || skippedOneSeparator {
			eventsCopy = append(eventsCopy, ev)
			continue
		}

		skippedOneSeparator = true
	}
	log.Events = eventsCopy
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256)

	_, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, nil)
	c.Check(err, ErrorMatches, `unexpected event type EV_EFI_VARIABLE_AUTHORITY after beginning transition to OS-present phase \(expected EV_SEPARATOR\)`)
}

func (s *tcglogSuite) TestCheckFirmwareLogAndChoosePCRBankMultipleSeparatorsForSamePCR(c *C) {
	s.allocatePCRBanks(c, tpm2.HashAlgorithmSHA256)
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})
	var eventsCopy []*tcglog.Event
	copiedEvent := false
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		eventsCopy = append(eventsCopy, ev)
		if !copiedEvent && ev.EventType == tcglog.EventTypeSeparator {
			eventsCopy = append(eventsCopy, ev)
			copiedEvent = true
		}
	}
	log.Events = eventsCopy
	s.resetTPMAndReplayLog(c, log, tpm2.HashAlgorithmSHA256)

	_, err := CheckFirmwareLogAndChoosePCRBank(s.TPM, log, nil)
	c.Check(err, ErrorMatches, `more than one EV_SEPARATOR event exists for PCR 7`)
}
