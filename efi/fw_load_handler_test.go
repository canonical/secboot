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
	log            *tcglog.Log
	alg            tpm2.HashAlgorithmId
	pcrs           PcrFlags
	expectedEvents []*mockPcrBranchEvent
	loadParams     *LoadParams
}

func (s *fwLoadHandlerSuite) testMeasureImageStart(c *C, data *testFwMeasureImageStartData) *FwContext {
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(data.vars, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  data.alg,
		pcrs: data.pcrs}, data.loadParams, collector.Next())

	log := data.log
	switch {
	case log != nil:
		c.Assert(data.logOptions, IsNil)
	default:
		log = efitest.NewLog(c, data.logOptions)
	}

	handler := NewFwLoadHandler(log)
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
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileSecureBootSeparatorAfterPreOS(c *C) {
	// Verify the event ordering when the log indicates that the EV_SEPARATOR in PCR7
	// is measured as part of the transition to OS-present. The ordering has no effect
	// in this case because there are no events asssociated with verification of
	// third-party pre-OS images.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:               []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			SecureBootSeparatorOrder: efitest.SecureBootSeparatorAfterPreOS,
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
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
		},
	})
	c.Check(fc.HasVerificationEvent(verificationDigest), testutil.IsTrue)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileIncludeDriverLaunchAndSecureBootSeparatorAfterPreOS(c *C) {
	// Verify the events associated with a driver launch are included in the profile, and
	// that the event ordering is preserved in the case where the EV_SEPARATOR event in
	// PCR7 is measured as part of the transition to OS-present.
	vars := makeMockVars(c, withMsSecureBootConfig())
	verificationDigest := testutil.DecodeHexString(c, "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9")
	fc := s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:               []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			SecureBootSeparatorOrder: efitest.SecureBootSeparatorAfterPreOS,
			IncludeDriverLaunch:      true,
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
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
	c.Check(fc.HasVerificationEvent(verificationDigest), testutil.IsTrue)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileAllowInsufficientDMAProtection(c *C) {
	// Verify that the EV_EFI_ACTION "DMA Protection Disabled" event can be permitted.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DMAProtection: efitest.DMAProtectionDisabled,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": false,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileIncludeInsufficientDMAProtection(c *C) {
	// Verify that the EV_EFI_ACTION "DMA Protection Disabled" event can be permitted
	// and included in the emitted profile.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DMAProtection: efitest.DMAProtectionDisabled,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": true,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "019537eeff4f1858181e09d26faa59a5ad3a9d8eef3d1bbbb35288e0e16d656c")}, // "DMA Protection Disabled"
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileIncludeInsufficientDMAProtectionNul(c *C) {
	// Verify that the EV_EFI_ACTION "DMA Protection Disabled" event can be permitted
	// and included in the emitted profile, and that it handles the case where the
	// event data is NULL terminated.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventNullTerminated,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": true,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "5b2b1f0c5470397d4efa2fe23110c8b6f61e299b9fa2c098f834ff06416196c3")}, // "DMA Protection Disabled\0"
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileIncludeInsufficientDMAProtectionAndDriverLaunch(c *C) {
	// Verify that the EV_EFI_ACTION "DMA Protection Disabled" event can be permitted
	// and included in the emitted profile, and that the original event ordering is
	// retained - in this case, the event is immediately after the secure boot config
	// measurements, with the separator in PCR7 dividing the secure boot configuration
	// and image verification events. There is also a driver launch.
	vars := makeMockVars(c, withMsSecureBootConfig())
	verificationDigest := testutil.DecodeHexString(c, "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9")
	fc := s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DMAProtection:       efitest.DMAProtectionDisabled,
			IncludeDriverLaunch: true,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": true,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "019537eeff4f1858181e09d26faa59a5ad3a9d8eef3d1bbbb35288e0e16d656c")}, // "DMA Protection Disabled"
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
		},
	})
	c.Check(fc.HasVerificationEvent(verificationDigest), testutil.IsTrue)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileIncludeInsufficientDMAProtectionAndDriverLaunchWithSeparatorAfterPreOS(c *C) {
	// Verify that the EV_EFI_ACTION "DMA Protection Disabled" event can be permitted
	// and included in the emitted profile, and that the original event ordering is
	// retained - in this case, the event is immediately after the secure boot config
	// measurements, with the separator in PCR7 being measured as part of the transition
	// to OS-present. There is also a driver launch.
	vars := makeMockVars(c, withMsSecureBootConfig())
	verificationDigest := testutil.DecodeHexString(c, "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9")
	fc := s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:               []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DMAProtection:            efitest.DMAProtectionDisabled,
			SecureBootSeparatorOrder: efitest.SecureBootSeparatorAfterPreOS,
			IncludeDriverLaunch:      true,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": true,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "019537eeff4f1858181e09d26faa59a5ad3a9d8eef3d1bbbb35288e0e16d656c")}, // "DMA Protection Disabled"
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
	c.Check(fc.HasVerificationEvent(verificationDigest), testutil.IsTrue)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileIncludeInsufficientDMAProtectionAfterSeparator(c *C) {
	// Verify that the EV_EFI_ACTION "DMA Protection Disabled" event can be permitted
	// and included in the emitted profile, and that the original event ordering is
	// retained - in this case, the event is immediately after the secure boot separator,
	// with the separator in PCR7 dividing the secure boot configuration events and the
	// secure boot image verification events.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventOrderAfterSeparator,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": true,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "019537eeff4f1858181e09d26faa59a5ad3a9d8eef3d1bbbb35288e0e16d656c")}, // "DMA Protection Disabled"
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileIncludeInsufficientDMAProtectionAfterSeparatorWithDriverLaunch(c *C) {
	// Verify that the EV_EFI_ACTION "DMA Protection Disabled" event can be permitted
	// and included in the emitted profile, and that the original event ordering is
	// retained - in this case, the event is immediately after the secure boot separator,
	// with the separator in PCR7 dividing the secure boot configuration events and the
	// secure boot image verification events. There is also a driver launch.
	vars := makeMockVars(c, withMsSecureBootConfig())
	verificationDigest := testutil.DecodeHexString(c, "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9")
	fc := s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DMAProtection:       efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventOrderAfterSeparator,
			IncludeDriverLaunch: true,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": true,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "019537eeff4f1858181e09d26faa59a5ad3a9d8eef3d1bbbb35288e0e16d656c")}, // "DMA Protection Disabled"
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
		},
	})
	c.Check(fc.HasVerificationEvent(verificationDigest), testutil.IsTrue)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileAllowInsufficientDMAProtectionBeforeConfig(c *C) {
	// Verify that the EV_EFI_ACTION "DMA Protection Disabled" event can be permitted,
	// and that the original event ordering is retained - in this case, the event is
	// before the secure boot configuration measurements.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventOrderBeforeConfig,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": false,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileIncludeInsufficientDMAProtectionBeforeConfig(c *C) {
	// Verify that the EV_EFI_ACTION "DMA Protection Disabled" event can be permitted
	// and included in the emitted profile, and that the original event ordering is
	// retained - in this case, the event is before the secure boot configuration
	// measurements.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventOrderBeforeConfig,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": true,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "019537eeff4f1858181e09d26faa59a5ad3a9d8eef3d1bbbb35288e0e16d656c")}, // "DMA Protection Disabled"
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileIncludeInsufficientDMAProtectionNulBeforeConfig(c *C) {
	// Verify that the EV_EFI_ACTION "DMA Protection Disabled" event can be permitted
	// and included in the emitted profile, and that it handles the case where the
	// event data is NULL terminated.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventNullTerminated | efitest.DMAProtectionDisabledEventOrderBeforeConfig,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": true,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "5b2b1f0c5470397d4efa2fe23110c8b6f61e299b9fa2c098f834ff06416196c3")}, // "DMA Protection Disabled\0"
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileWithVendorEventBeforeConfig(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	added := false
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex == internal_efi.SecureBootPolicyPCR && !added {
			eventsCopy = append(eventsCopy, &tcglog.Event{
				PCRIndex:  internal_efi.SecureBootPolicyPCR,
				EventType: 0x8041,
				Digests: tcglog.DigestMap{
					tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
				},
				Data: tcglog.OpaqueEventData{0},
			})
			added = true
		}

		eventsCopy = append(eventsCopy, ev)
	}
	log.Events = eventsCopy

	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		log:  log,
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")}, // vendor event
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileWithVendorEventWithConfig(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	added := false
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex == internal_efi.SecureBootPolicyPCR && ev.EventType == tcglog.EventTypeSeparator && !added {
			eventsCopy = append(eventsCopy, &tcglog.Event{
				PCRIndex:  internal_efi.SecureBootPolicyPCR,
				EventType: 0x8041,
				Digests: tcglog.DigestMap{
					tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
				},
				Data: tcglog.OpaqueEventData{0},
			})
			added = true
		}

		eventsCopy = append(eventsCopy, ev)
	}
	log.Events = eventsCopy

	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		log:  log,
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")}, // vendor event
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileWithVendorEventWithVerification(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	added := false
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		eventsCopy = append(eventsCopy, ev)

		if ev.PCRIndex == internal_efi.SecureBootPolicyPCR && ev.EventType == tcglog.EventTypeSeparator && !added {
			eventsCopy = append(eventsCopy, &tcglog.Event{
				PCRIndex:  internal_efi.SecureBootPolicyPCR,
				EventType: 0x8041,
				Digests: tcglog.DigestMap{
					tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
				},
				Data: tcglog.OpaqueEventData{0},
			})
			added = true
		}
	}
	log.Events = eventsCopy

	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		log:  log,
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")}, // vendor event
		},
	})
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
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartBootManagerCodeProfileHP(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	// XXX: It would be good to have this sort of thing in internal/efitest
	var eventsCopy []*tcglog.Event
	for _, ev := range log.Events {
		eventsCopy = append(eventsCopy, ev)

		if ev.PCRIndex == internal_efi.SecureBootPolicyPCR && ev.EventType == tcglog.EventTypeSeparator {
			// Add HP events to PCR4
			addEvent := func(guid efi.GUID, digest tpm2.Digest) {
				eventsCopy = append(eventsCopy, &tcglog.Event{
					PCRIndex:  internal_efi.BootManagerCodePCR,
					EventType: tcglog.EventTypeEFIBootServicesApplication,
					Digests: tcglog.DigestMap{
						tpm2.HashAlgorithmSHA256: digest,
					},
					Data: &tcglog.EFIImageLoadEvent{
						DevicePath: efi.DevicePath{
							efi.MediaFvDevicePathNode(efi.MakeGUID(0xcdbb7b35, 0x6833, 0x4ed6, 0x9ab2, [...]uint8{0x57, 0xd2, 0xac, 0xdd, 0xf6, 0xf0})),
							efi.MediaFvFileDevicePathNode(guid),
						},
					},
				})
			}

			addEvent(efi.MakeGUID(0xb1dac9bd, 0x132e, 0x4f9f, 0xb2ca, [...]byte{0x14, 0xfd, 0xc6, 0x5b, 0xd6, 0x61}), testutil.DecodeHexString(c, "f407e3fd9a46e946d91522880ab771bce2fe08d1410bd1f10dab99ab2ec3d6c5"))
			addEvent(efi.MakeGUID(0x9d8243e8, 0x8381, 0x453d, 0xaceb, [...]byte{0xc3, 0x50, 0xee, 0x77, 0x57, 0xca}), testutil.DecodeHexString(c, "3cfb0e1a22e6e1a203d3382e00db516107cbf948708befe8b1e7c79e5fb0455c")) // StartupMenuApp
			addEvent(efi.MakeGUID(0x96d0626b, 0x71d5, 0x4001, 0xac71, [...]byte{0xe0, 0x5B, 0x10, 0x3b, 0xd4, 0x5d}), testutil.DecodeHexString(c, "ae1d24af29d3a27d49da12ad98b64e6072ad3e1786186dfe5e23b1001671b858")) // F10App
			addEvent(efi.MakeGUID(0xeb6b71c3, 0x0659, 0x4a8a, 0x8ae1, [...]byte{0xda, 0xd2, 0xf5, 0x19, 0x2c, 0x62}), testutil.DecodeHexString(c, "ccf5d88d928171a2af8d0fec99fe142aa75684a49dda5c5db2feae19085a7a6b")) // BootMenuApp
			addEvent(efi.MakeGUID(0xaf8898c9, 0x9b92, 0x4556, 0x8318, [...]byte{0xe4, 0x25, 0xc9, 0xde, 0x0a, 0x65}), testutil.DecodeHexString(c, "43099125543e0647d3918e5e06239e940157c42a881eed8d854f230beb96951b")) // F2App
			addEvent(efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}), testutil.DecodeHexString(c, "6a8138a15c60aca1bfe06914987e3e2ea9a243b2e055e5c903482cea5b3893bc")) // AbsoluteAbtInstaller
			addEvent(efi.MakeGUID(0xc988bded, 0x6977, 0x464d, 0xb714, [...]byte{0xe6, 0x1d, 0xeb, 0xd2, 0xde, 0x97}), testutil.DecodeHexString(c, "953e26aeecfea145f82a2be73674af76e54850387e5bdcb9e540ef01e51b145e"))
			addEvent(efi.MakeGUID(0x4ea97c46, 0x7491, 0x4dfd, 0xb542, [...]byte{0x74, 0x70, 0x10, 0xf3, 0xce, 0x7f}), testutil.DecodeHexString(c, "63040d9100b9fdfd849c06d13bbfddc5eb08131a6c18f0e0aef7a46ccfb92630")) // HPNetworkTransferWorker
			addEvent(efi.MakeGUID(0x8224846e, 0x6d50, 0x453d, 0xb7c2, [...]byte{0x3e, 0x7e, 0xd7, 0xd0, 0x0d, 0x52}), testutil.DecodeHexString(c, "445a4fe85fa4b48f4eb7a86e92b89a2f4ceb1c9a1a849c3b808226ac45039a17"))
			addEvent(efi.MakeGUID(0xf02313f7, 0x581f, 0x4f31, 0xb09c, [...]byte{0xc1, 0xba, 0x2f, 0xc5, 0x87, 0x13}), testutil.DecodeHexString(c, "dd42008bac6b5c4c07919921ec21f39176811b597b3a7553badfa30c4e3dfe8a")) // HPDriveWipe

			// HP systems seem to measure this twice
			addEvent(efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}), testutil.DecodeHexString(c, "6a8138a15c60aca1bfe06914987e3e2ea9a243b2e055e5c903482cea5b3893bc")) // AbsoluteAbtInstaller
		}
	}
	log.Events = eventsCopy

	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		log:  log,
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.BootManagerCodePCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "f407e3fd9a46e946d91522880ab771bce2fe08d1410bd1f10dab99ab2ec3d6c5")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3cfb0e1a22e6e1a203d3382e00db516107cbf948708befe8b1e7c79e5fb0455c")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "ae1d24af29d3a27d49da12ad98b64e6072ad3e1786186dfe5e23b1001671b858")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "ccf5d88d928171a2af8d0fec99fe142aa75684a49dda5c5db2feae19085a7a6b")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "43099125543e0647d3918e5e06239e940157c42a881eed8d854f230beb96951b")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "6a8138a15c60aca1bfe06914987e3e2ea9a243b2e055e5c903482cea5b3893bc")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "953e26aeecfea145f82a2be73674af76e54850387e5bdcb9e540ef01e51b145e")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "63040d9100b9fdfd849c06d13bbfddc5eb08131a6c18f0e0aef7a46ccfb92630")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "445a4fe85fa4b48f4eb7a86e92b89a2f4ceb1c9a1a849c3b808226ac45039a17")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "dd42008bac6b5c4c07919921ec21f39176811b597b3a7553badfa30c4e3dfe8a")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "6a8138a15c60aca1bfe06914987e3e2ea9a243b2e055e5c903482cea5b3893bc")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartBootManagerCodeProfileIncludeAbsoluteAbtInstallerPreOS(c *C) {
	// Verify the events associated with the "AbsoluteAbtInstaller" application contained in the firmware
	// that loads as part of pre-OS.
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:                    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			IncludePreOSFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.BootManagerCodePCR),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "59b1f92051a43fea7ac3a846f2714c3e041a4153d581acd585914bcff2ad2781")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "cd1137dfa2bfba51973100d73d78d9f496e089fd246fe980fadc668b4efc9443")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "5ca5e6acb83d626a42b53ddc5a2fe04d6a4b2f045bb07f6d9baf0e82900d7bbe")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "aef237d4703e8936530141636186a9f249fa39e194f02f668cd328bd5902cf03")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "8b0eec99d3cccc081edb98c3a2aa74b99a02b785bd74513e1cf7401e99121e80")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "cd1137dfa2bfba51973100d73d78d9f496e089fd246fe980fadc668b4efc9443")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "5ca5e6acb83d626a42b53ddc5a2fe04d6a4b2f045bb07f6d9baf0e82900d7bbe")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "aef237d4703e8936530141636186a9f249fa39e194f02f668cd328bd5902cf03")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "8b0eec99d3cccc081edb98c3a2aa74b99a02b785bd74513e1cf7401e99121e80")},
			{pcr: 0, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 2, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
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
			{pcr: 2, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrDisallowDMAProtectionDisabled(c *C) {
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		DMAProtection: efitest.DMAProtectionDisabled,
	})

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure secure boot policy: unexpected event type \(EV_EFI_ACTION\) found in log`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrDisallowDMAProtectionDisabledNul(c *C) {
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventNullTerminated,
	})

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure secure boot policy: unexpected event type \(EV_EFI_ACTION\) found in log`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrDisallowDMAProtectionDisabledBeforeConfig(c *C) {
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventOrderBeforeConfig,
	})

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure secure boot policy: unexpected event type \(EV_EFI_ACTION\) found in log, before config`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrDisallowDMAProtectionDisabledNulBeforeConfig(c *C) {
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventNullTerminated | efitest.DMAProtectionDisabledEventOrderBeforeConfig,
	})

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure secure boot policy: unexpected event type \(EV_EFI_ACTION\) found in log, before config`)
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
			events := append([]*tcglog.Event(nil), log.Events[:i+1]...)
			events = append(events, event)
			if len(log.Events) > i+1 {
				events = append(events, log.Events[i+1:]...)
			}
			log.Events = events
			break
		}
	}

	handler := NewFwLoadHandler(log)
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure secure boot policy: unexpected event type \(EV_SEPARATOR\) found in log`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogPCR7_2(c *C) {
	// Append a configuration event into PCR7 after the EV_SEPARATOR
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
	for i, event := range log.Events {
		if event.PCRIndex == 7 && event.EventType == tcglog.EventTypeSeparator {
			events := append([]*tcglog.Event(nil), log.Events[:i]...)
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
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `cannot measure secure boot policy: unexpected event type \(EV_EFI_VARIABLE_DRIVER_CONFIG\) found in log`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogPCR7_3(c *C) {
	// Insert an unexpected event type into PCR7
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR)}, nil, collector.Next())

	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
	for i, event := range log.Events {
		if event.PCRIndex == 7 && event.EventType == tcglog.EventTypeSeparator {
			events := append([]*tcglog.Event(nil), log.Events[:i]...)
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
			events := append([]*tcglog.Event(nil), log.Events[:i]...)
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
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil))
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
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil))
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
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil))
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
	c.Check(err, ErrorMatches, `cannot measure platform firmware: missing separator in log`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogMissingSeparatorPCR2(c *C) {
	err := s.testMeasureImageStartErrBadLogMissingSeparator(c, 2)
	c.Check(err, ErrorMatches, `cannot measure drivers and apps: missing separator in log`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogMissingSeparatorPCR4(c *C) {
	err := s.testMeasureImageStartErrBadLogMissingSeparator(c, 4)
	c.Check(err, ErrorMatches, `cannot measure boot manager code: missing separator in log`)
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartErrBadLogMissingSeparatorPCR7(c *C) {
	err := s.testMeasureImageStartErrBadLogMissingSeparator(c, 7)
	c.Check(err, ErrorMatches, `cannot measure secure boot policy: missing separator in log`)
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

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileUserMode(c *C) {
	vars := makeMockVars(c, withMsSecureBootConfig(), withDeployedModeDisabled())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DisableDeployedMode: true,
		},
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		loadParams: &LoadParams{
			"include_secure_boot_user_mode": true,
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "AuditMode", GUID: efi.GlobalVariable}, varData: []byte{0x00}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "DeployedMode", GUID: efi.GlobalVariable}, varData: []byte{0x00}},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileUserModeNotIncluded(c *C) {
	vars := makeMockVars(c, withMsSecureBootConfig(), withDeployedModeDisabled())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars: vars,
		logOptions: &efitest.LogOptions{
			Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			DisableDeployedMode: true,
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
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")}, // EV_SEPARATOR
		},
	})
}
