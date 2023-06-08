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
	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"

	. "github.com/snapcore/secboot/efi"
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
	flags          PcrProfileFlags
	expectedEvents []*mockPcrBranchEvent
}

func (s *fwLoadHandlerSuite) testMeasureImageStart(c *C, data *testFwMeasureImageStartData) *FwContext {
	collector := NewRootVarsCollector(efitest.NewMockHostEnvironment(data.vars, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:   data.alg,
		flags: data.flags}, collector.Next())

	handler := NewFwLoadHandler(efitest.NewLog(c, data.logOptions))
	c.Check(handler.MeasureImageStart(ctx), IsNil)
	c.Check(ctx.events, DeepEquals, data.expectedEvents)
	c.Check(collector.More(), testutil.IsFalse)
	return ctx.FwContext()
}

func (s *fwLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfile(c *C) {
	vars := makeMockVars(c, withMsSecureBootConfig())
	s.testMeasureImageStart(c, &testFwMeasureImageStartData{
		vars:       vars,
		logOptions: &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}},
		alg:        tpm2.HashAlgorithmSHA256,
		flags:      SecureBootPolicyProfile,
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
		alg:   tpm2.HashAlgorithmSHA256,
		flags: SecureBootPolicyProfile,
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
		alg:   tpm2.HashAlgorithmSHA256,
		flags: SecureBootPolicyProfile,
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
		flags:      BootManagerCodeProfile,
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
		alg:   tpm2.HashAlgorithmSHA256,
		flags: BootManagerCodeProfile,
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
		alg:   tpm2.HashAlgorithmSHA256,
		flags: BootManagerCodeProfile,
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4")},
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
		flags:      BootManagerCodeProfile | SecureBootPolicyProfile,
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchResetEvent},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable}, varData: []byte{0x01}},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: PK, varData: vars[PK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: KEK, varData: vars[KEK].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Db, varData: vars[Db].Payload},
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: Dbx, varData: vars[Dbx].Payload},
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
			{pcr: 4, eventType: mockPcrBranchResetEvent},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
		},
	})
}

type testFwMeasureImageLoadData struct {
	alg                tpm2.HashAlgorithmId
	flags              PcrProfileFlags
	db                 efi.SignatureDatabase
	fc                 *FwContext
	image              *mockImage
	expectedEvents     []*mockPcrBranchEvent
	verificationDigest tpm2.Digest
}

func (s *fwLoadHandlerSuite) testMeasureImageLoad(c *C, data *testFwMeasureImageLoadData) {
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:      data.alg,
		flags:    data.flags,
		handlers: s,
	}, nil)
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
		flags: SecureBootPolicyProfile,
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
		flags: SecureBootPolicyProfile,
		db:    msDb(c),
		fc:    fc,
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)),
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageLoadBootManagerCodeProfile1(c *C) {
	s.testMeasureImageLoad(c, &testFwMeasureImageLoadData{
		alg:   tpm2.HashAlgorithmSHA256,
		flags: BootManagerCodeProfile,
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "bf6b6dfdb1f6435a81e4808db7f846d86d170566e4753d4384fdab6504be4fb9")},
		},
	})
}

func (s *fwLoadHandlerSuite) TestMeasureImageLoadBootManagerCodeProfile2(c *C) {
	s.testMeasureImageLoad(c, &testFwMeasureImageLoadData{
		alg:   tpm2.HashAlgorithmSHA256,
		flags: BootManagerCodeProfile,
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
		flags: BootManagerCodeProfile | SecureBootPolicyProfile,
		db:    msDb(c),
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "bf6b6dfdb1f6435a81e4808db7f846d86d170566e4753d4384fdab6504be4fb9")},
		},
		verificationDigest: verificationDigest,
	})
}
