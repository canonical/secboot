// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package efi_test

import (
	"errors"
	"fmt"
	"io"

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"

	. "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type fwLoadHandlerSuite struct {
	mockImageLoadHandlerMap
}

func (s *fwLoadHandlerSuite) SetUpTest(c *C) {
	s.mockImageLoadHandlerMap = make(mockImageLoadHandlerMap)
}

var _ = Suite(&fwLoadHandlerSuite{})

type testFwMeasureImageStartData struct {
	vars           efitest.MockVars
	logOptions     *efitest.LogOptions
	alg            tpm2.HashAlgorithmId
	pcrs           PcrFlags
	expectedEvents []*mockPcrBranchEvent
}

func (s *fwLoadHandlerSuite) testMeasureImageStart(c *C, data *testFwMeasureImageStartData) *FwContext {
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(data.vars, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  data.alg,
		pcrs: data.pcrs}, nil, collector.Next())

	handler := NewFwLoadHandler(efitest.NewLog(c, data.logOptions))
	c.Check(handler.MeasureImageStart(ctx), IsNil)
	c.Check(ctx.events, DeepEquals, data.expectedEvents)
	for _, event := range ctx.events {
		c.Logf("pcr:%d, type:%v, digest:%#x", event.pcr, event.eventType, event.digest)
	}
	c.Check(collector.More(), testutil.IsFalse)
	return ctx.FwContext()
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfile(c *C) {
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars:       vars,
		logOptions: &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}},
		alg:        tpm2.HashAlgorithmSHA256,
		pcrs:       MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileSecureBootDisabled(c *C) {
	// Verify that we generate a profile that requires secure boot regardless of the state of
	// the current environment.
	vars := makeMockVars(c, withMsSecureBootConfig(), withSecureBootDisabled())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			SecureBootDisabled: true,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileIncludeDriverLaunch(c *C) {
	// Verify the events associated with a driver launch are included in the profile
	vars := makeMockVars(c, withMsSecureBootConfig())
	verificationDigest := testutil.DecodeHexString(c, "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9")
	fc := s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			IncludeDriverLaunch: true,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
		},
	})
	c.Check(fc.HasVerificationEvent(verificationDigest), testutil.IsTrue)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartBootManagerCodeProfile(c *C) {
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars:       vars,
		logOptions: &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}},
		alg:        tpm2.HashAlgorithmSHA256,
		pcrs:       MakePcrFlags(internal_efi.BootManagerCodePCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartBootManagerCodeProfileWithoutCallingEFIActionEvent(c *C) {
	// Verify the profile is correct if the log doesn't contain the "Calling EFI Application"
	// EV_EFI_ACTION event
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			NoCallingEFIApplicationEvent: true,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.BootManagerCodePCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartBootManagerCodeProfileIncludeSysPrepAppLaunch(c *C) {
	// Verify the events associated with a sysprep application launch are included in the profile
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			IncludeSysPrepAppLaunch: true,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.BootManagerCodePCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartBootManagerCodeProfileIncludeAbsoluteAbtInstaller(c *C) {
	// Verify the events associated with the "AbsoluteAbtInstaller" application contained in the firmware
	// that loads as part of the OS-present.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.BootManagerCodePCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "59b1f92051a43fea7ac3a846f2714c3e041a4153d581acd585914bcff2ad2781")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartBootManagerCodeProfileIncludeAbsoluteComputraceInstaller(c *C) {
	// Verify the events associated with the "AbsoluteComputraceInstaller" application contained in the firmware
	// that loads as part of the OS-present.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x8feeecf1, 0xbcfd, 0x4a78, 0x9231, [...]byte{0x48, 0x01, 0x56, 0x6b, 0x35, 0x67}),
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.BootManagerCodePCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "e58b9aa46c99806ce57c805a78d8224dd174743341e03e8a68b13a0071785295")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartBootManagerCodeProfileIgnoreUnknownFirmwareAgentLaunch(c *C) {
	// Verify that the profile ignores any firmware application launch that isn't "AbsoluteAbtInstaller" or
	// "AbsoluteComputraceInstaller". This will generate an invalid profile, but will be detected by the
	// pre-install checks.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0xee993080, 0x5197, 0x4d4e, 0xb63c, [...]byte{0xf1, 0xf7, 0x41, 0x3e, 0x33, 0xce}),
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.BootManagerCodePCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyAndBootManagerCodeProfile(c *C) {
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars:       vars,
		logOptions: &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}},
		alg:        tpm2.HashAlgorithmSHA256,
		pcrs:       MakePcrFlags(internal_efi.BootManagerCodePCR, internal_efi.SecureBootPolicyPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartPlatformFirmwareProfile(c *C) {
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		logOptions: &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}},
		alg:        tpm2.HashAlgorithmSHA256,
		pcrs:       MakePcrFlags(internal_efi.PlatformFirmwarePCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 0, eventType: mockPcrBranchResetEvent},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "d0ff5974b6aa52cf562bea5921840c032a860a91a3512f7fe8f768f6bbe005f6")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "aef237d4703e8936530141636186a9f249fa39e194f02f668cd328bd5902cf03")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "8b0eec99d3cccc081edb98c3a2aa74b99a02b785bd74513e1cf7401e99121e80")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartPlatformFirmwareProfileSL3(c *C) {
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		logOptions: &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}, StartupLocality: 3},
		alg:        tpm2.HashAlgorithmSHA256,
		pcrs:       MakePcrFlags(internal_efi.PlatformFirmwarePCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 0, eventType: mockPcrBranchResetCRTMPCREvent, locality: 3},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "d0ff5974b6aa52cf562bea5921840c032a860a91a3512f7fe8f768f6bbe005f6")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "aef237d4703e8936530141636186a9f249fa39e194f02f668cd328bd5902cf03")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "8b0eec99d3cccc081edb98c3a2aa74b99a02b785bd74513e1cf7401e99121e80")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartDriversAndAppsProfile(c *C) {
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		logOptions: &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}},
		alg:        tpm2.HashAlgorithmSHA256,
		pcrs:       MakePcrFlags(internal_efi.DriversAndAppsPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 2, eventType: mockPcrBranchResetEvent},
			{pcr: 2, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartDriversAndAppsProfile2(c *C) {
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		logOptions: &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}, IncludeDriverLaunch: true},
		alg:        tpm2.HashAlgorithmSHA256,
		pcrs:       MakePcrFlags(internal_efi.DriversAndAppsPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 2, eventType: mockPcrBranchResetEvent},
			{pcr: 2, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6")},
			{pcr: 2, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogPCR7_1(c *C) {
	// Insert a second EV_SEPARATOR event into PCR7
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
	for i, event := range log.Events {
		if event.PCRIndex == 7 && event.EventType == tcglog.EventTypeSeparator {
			events := log.Events[:i+1]
			events = append(events, event)
			if len(log.Events) > i+1 {
				events = append(events, log.Events[i+1:]...)
			}
			log.Events = events
			break
		}
	}

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure secure boot policy: unexpected separator`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogPCR7_2(c *C) {
	// Prepend a verification event into PCR7 before the EV_SEPARATOR
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
	for i, event := range log.Events {
		if event.PCRIndex == 7 && event.EventType == tcglog.EventTypeSeparator {
			events := log.Events[:i]
			events = append(events, &tcglog.Event{
				PCRIndex:  7,
				EventType: tcglog.EventTypeEFIVariableAuthority})
			events = append(events, event)
			if len(log.Events) > i+1 {
				events = append(events, log.Events[i+1:]...)
			}
			log.Events = events
			break
		}
	}

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure secure boot policy: unexpected verification event`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogPCR7_3(c *C) {
	// Append a configuration event into PCR7 after the EV_SEPARATOR
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
	for i, event := range log.Events {
		if event.PCRIndex == 7 && event.EventType == tcglog.EventTypeSeparator {
			events := log.Events[:i]
			events = append(events, event)
			events = append(events, &tcglog.Event{
				PCRIndex:  7,
				EventType: tcglog.EventTypeEFIVariableDriverConfig})
			if len(log.Events) > i+1 {
				events = append(events, log.Events[i+1:]...)
			}
			log.Events = events
			break
		}
	}

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure secure boot policy: unexpected configuration event`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogPCR7_4(c *C) {
	// Insert an unexpected event type into PCR7
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
	for i, event := range log.Events {
		if event.PCRIndex == 7 && event.EventType == tcglog.EventTypeSeparator {
			events := log.Events[:i]
			events = append(events, event)
			events = append(events, &tcglog.Event{
				PCRIndex:  7,
				EventType: tcglog.EventTypeEFIBootServicesApplication})
			if len(log.Events) > i+1 {
				events = append(events, log.Events[i+1:]...)
			}
			log.Events = events
			break
		}
	}

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure secure boot policy: unexpected event type \(EV_EFI_BOOT_SERVICES_APPLICATION\) found in log`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogPCR0_1(c *C) {
	// Insert an invalid StartupLocality event data into the log
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(nil, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.PlatformFirmwarePCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		StartupLocality: 3})
	for i, event := range log.Events {
		if event.PCRIndex == 0 && event.EventType == tcglog.EventTypeNoAction {
			if _, isLoc := event.Data.(*tcglog.StartupLocalityEventData); !isLoc {
				continue
			}
			// Overwrite the event data with a mock error event
			log.Events[i].Data = &mockErrLogData{fmt.Errorf("cannot decode StartupLocality data: %w", io.ErrUnexpectedEOF)}
			break
		}
	}

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure platform firmware: cannot decode EV_NO_ACTION event data: cannot decode StartupLocality data: unexpected EOF`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogPCR0_2(c *C) {
	// Insert an extra StartupLocality event data into the log
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(nil, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.PlatformFirmwarePCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		StartupLocality: 3})
	for i, event := range log.Events {
		if event.PCRIndex == 0 && event.EventType == tcglog.EventTypeNoAction {
			if _, isLoc := event.Data.(*tcglog.StartupLocalityEventData); !isLoc {
				continue
			}
			events := log.Events[:i]
			events = append(events, event, event)
			if len(log.Events) > i+1 {
				events = append(events, log.Events[i+1:]...)
			}
			log.Events = events
			break
		}
	}

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure platform firmware: log for PCR0 has an unexpected StartupLocality event`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogPCR4_1(c *C) {
	// Insert an unexpected event type in the OS-present phase
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(nil, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.BootManagerCodePCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d})})
	for i, event := range log.Events {
		if event.PCRIndex == 4 && event.EventType == tcglog.EventTypeEFIBootServicesApplication {
			log.Events[i].EventType = tcglog.EventTypeAction
			break
		}
	}

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure boot manager code: unexpected OS-present event type: EV_ACTION`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogPCR4_2(c *C) {
	// Insert invalid event data in the OS-present phase so that internal_efi.IsAbsoluteAgentLaunch returns an error
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(nil, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.BootManagerCodePCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d})})
	for i, event := range log.Events {
		if event.PCRIndex == 4 && event.EventType == tcglog.EventTypeEFIBootServicesApplication {
			data, ok := event.Data.(*tcglog.EFIImageLoadEvent)
			c.Assert(ok, testutil.IsTrue)
			data.DevicePath = efi.DevicePath{}
			log.Events[i].Data = data
			break
		}
	}

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure boot manager code: encountered an error determining whether an OS-present launch is related to Absolute: EV_EFI_BOOT_SERVICES_APPLICATION event has empty device path`)
}

func (s *fwLoadHandlerSuite) testMeasureImageStartErrBadLogSeparatorError(c *C, pcr tpm2.Handle) error {
	// Insert an invalid error separator event into the log for the specified pcr
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(nil, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(pcr)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
	for i, event := range log.Events {
		if event.PCRIndex == pcr && event.EventType == tcglog.EventTypeSeparator {
			// Overwrite the event data with a mock error event
			log.Events[i].Data = &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventErrorValue, ErrorInfo: []byte{0x50, 0x10, 0x00, 0x00}}
			break
		}
	}

	handler := NewFwLoadHandler(log)
	return handler.MeasureImageStart(ctx)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogSeparatorErrorPCR0(c *C) {
	err := s.testMeasureImageStartErrBadLogSeparatorError(c, 0)
	c.Check(err, ErrorMatches, `cannot measure platform firmware: separator indicates that a firmware error occurred \(error code from log: 4176\)`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogSeparatorErrorPCR2(c *C) {
	err := s.testMeasureImageStartErrBadLogSeparatorError(c, 2)
	c.Check(err, ErrorMatches, `cannot measure drivers and apps: separator indicates that a firmware error occurred \(error code from log: 4176\)`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogSeparatorErrorPCR4(c *C) {
	err := s.testMeasureImageStartErrBadLogSeparatorError(c, 4)
	c.Check(err, ErrorMatches, `cannot measure boot manager code: separator indicates that a firmware error occurred \(error code from log: 4176\)`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogSeparatorErrorPCR7(c *C) {
	err := s.testMeasureImageStartErrBadLogSeparatorError(c, 7)
	c.Check(err, ErrorMatches, `cannot measure secure boot policy: separator indicates that a firmware error occurred \(error code from log: 4176\)`)
}

func (s *fwLoadHandlerSuite) testMeasureImageStartErrBadLogInvalidSeparator(c *C, pcr tpm2.Handle) error {
	// Insert an invalid separator event into the log for the specified PCR
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(nil, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(pcr)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
	for i, event := range log.Events {
		if event.PCRIndex == pcr && event.EventType == tcglog.EventTypeSeparator {
			// Overwrite the event data with a mock error event
			log.Events[i].Data = &mockErrLogData{errors.New("data is the wrong size")}
			break
		}
	}

	handler := NewFwLoadHandler(log)
	return handler.MeasureImageStart(ctx)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogInvalidSeparatorPCR0(c *C) {
	err := s.testMeasureImageStartErrBadLogInvalidSeparator(c, 0)
	c.Check(err, ErrorMatches, `cannot measure platform firmware: cannot measure invalid separator event: data is the wrong size`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogInvalidSeparatorPCR2(c *C) {
	err := s.testMeasureImageStartErrBadLogInvalidSeparator(c, 2)
	c.Check(err, ErrorMatches, `cannot measure drivers and apps: cannot measure invalid separator event: data is the wrong size`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogInvalidSeparatorPCR4(c *C) {
	err := s.testMeasureImageStartErrBadLogInvalidSeparator(c, 4)
	c.Check(err, ErrorMatches, `cannot measure boot manager code: cannot measure invalid separator event: data is the wrong size`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogInvalidSeparatorPCR7(c *C) {
	err := s.testMeasureImageStartErrBadLogInvalidSeparator(c, 7)
	c.Check(err, ErrorMatches, `cannot measure secure boot policy: cannot measure invalid separator event: data is the wrong size`)
}

func (s *fwLoadHandlerSuite) testMeasureImageStartErrBadLogMissingSeparator(c *C, pcr tpm2.Handle) error {
	// Remove the separator from the specified PCR
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(nil, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(pcr)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
	for i, event := range log.Events {
		if event.PCRIndex == pcr && event.EventType == tcglog.EventTypeSeparator {
			events := log.Events[:i]
			if len(log.Events) > i+1 {
				events = append(events, log.Events[i+1:]...)
			}
			log.Events = events
			break
		}
	}

	handler := NewFwLoadHandler(log)
	return handler.MeasureImageStart(ctx)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogMissingSeparatorPCR0(c *C) {
	err := s.testMeasureImageStartErrBadLogMissingSeparator(c, 0)
	c.Check(err, ErrorMatches, `cannot measure platform firmware: missing separator`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogMissingSeparatorPCR2(c *C) {
	err := s.testMeasureImageStartErrBadLogMissingSeparator(c, 2)
	c.Check(err, ErrorMatches, `cannot measure drivers and apps: missing separator`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogMissingSeparatorPCR4(c *C) {
	err := s.testMeasureImageStartErrBadLogMissingSeparator(c, 4)
	c.Check(err, ErrorMatches, `cannot measure boot manager code: missing separator`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogMissingSeparatorPCR7(c *C) {
	err := s.testMeasureImageStartErrBadLogMissingSeparator(c, 7)
	c.Check(err, ErrorMatches, `cannot measure secure boot policy: unexpected verification event`)
}

type testFwMeasureImageLoadData struct {
	alg                tpm2.HashAlgorithmId
	pcrs               PcrFlags
	db                 efi.SignatureDatabase
	fc                 *FwContext
	image              *mockImage
	expectedEvents     []*mockPcrBranchEvent
	verificationDigest tpm2.Digest
}

func (s *fwLoadHandlerSuite) testMeasureImageLoad(c *C, data *testFwMeasureImageLoadData) {
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:      data.alg,
		pcrs:     data.pcrs,
		handlers: s,
	}, nil, nil)
	if data.fc != nil {
		ctx.fc = data.fc
	}
	ctx.FwContext().Db = &SecureBootDB{
		Name:     Db,
		Contents: data.db,
	}

	s.mockImageLoadHandlerMap[data.image] = newMockLoadHandler()

	handler := NewFwLoadHandler(nil)
	childHandler, err := handler.MeasureImageLoad(ctx, data.image.newPeImageHandle())
	c.Check(err, IsNil)
	c.Check(childHandler, Equals, s.mockImageLoadHandlerMap[data.image])
	c.Check(ctx.events, DeepEquals, data.expectedEvents)
	if len(data.verificationDigest) > 0 {
		c.Check(ctx.FwContext().HasVerificationEvent(data.verificationDigest), testutil.IsTrue)
	}
}

func (s *fwLoadHandlerSuite) TestMeasureImageLoadSecureBootPolicyProfile(c *C) {
	verificationDigest := testutil.DecodeHexString(c, "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9")

	s.testMeasureImageLoad(c, &testFwMeasureImageLoadData{
		alg:   tpm2.HashAlgorithmSHA256,
		pcrs:  MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		db:    msDb(c),
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
		},
		verificationDigest: verificationDigest,
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageLoadSecureBootPolicyProfileExistingDigest(c *C) {
	// Test that a verification digest isn't added more than once
	verificationDigest := testutil.DecodeHexString(c, "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9")
	fc := new(FwContext)
	fc.AppendVerificationEvent(verificationDigest)

	s.testMeasureImageLoad(c, &testFwMeasureImageLoadData{
		alg:   tpm2.HashAlgorithmSHA256,
		pcrs:  MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		db:    msDb(c),
		fc:    fc,
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)),
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageLoadBootManagerCodeProfile1(c *C) {
	s.testMeasureImageLoad(c, &testFwMeasureImageLoadData{
		alg:   tpm2.HashAlgorithmSHA256,
		pcrs:  MakePcrFlags(internal_efi.BootManagerCodePCR),
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "bf6b6dfdb1f6435a81e4808db7f846d86d170566e4753d4384fdab6504be4fb9")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageLoadBootManagerCodeProfile2(c *C) {
	s.testMeasureImageLoad(c, &testFwMeasureImageLoadData{
		alg:   tpm2.HashAlgorithmSHA256,
		pcrs:  MakePcrFlags(internal_efi.BootManagerCodePCR),
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "dbffd70a2c43fd2c1931f18b8f8c08c5181db15f996f747dfed34def52fad036")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageLoadSecureBootPolicyAndBootManagerCodeProfile(c *C) {
	verificationDigest := testutil.DecodeHexString(c, "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9")

	s.testMeasureImageLoad(c, &testFwMeasureImageLoadData{
		alg:   tpm2.HashAlgorithmSHA256,
		pcrs:  MakePcrFlags(internal_efi.BootManagerCodePCR, internal_efi.SecureBootPolicyPCR),
		db:    msDb(c),
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "bf6b6dfdb1f6435a81e4808db7f846d86d170566e4753d4384fdab6504be4fb9")},
		},
		verificationDigest: verificationDigest,
	})
}
