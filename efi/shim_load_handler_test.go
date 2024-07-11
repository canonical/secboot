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
	"crypto/x509"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type shimLoadHandlerSuite struct {
	mockShimImageHandleMixin
	mockImageLoadHandlerMap
}

func (s *shimLoadHandlerSuite) SetUpTest(c *C) {
	s.mockShimImageHandleMixin.SetUpTest(c)
	s.mockImageLoadHandlerMap = make(mockImageLoadHandlerMap)
}

var _ = Suite(&shimLoadHandlerSuite{})

func (s *shimLoadHandlerSuite) TestNewShimLoadHandler15_7(c *C) {
	image := newMockUbuntuShimImage15_7(c)

	handler, err := NewShimLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec|ShimVendorCertContainsDb|ShimHasSbatRevocationManagement)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "MokListRT", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, ShimGuid)},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"), []byte("sbat,1,2022052400\ngrub,2\n")})

	var v VendorAuthorityGetter
	c.Assert(handler, Implements, &v)
	certs, err := handler.(VendorAuthorityGetter).VendorAuthorities()
	c.Check(err, IsNil)
	c.Check(certs, DeepEquals, []*x509.Certificate{testutil.ParseCertificate(c, canonicalCACert)})
}

func (s *shimLoadHandlerSuite) TestNewShimLoadHandler15_6(c *C) {
	vendorDb := efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})}
	sbatLevel := ShimSbatLevel{[]byte("sbat,1,2022052400\nshim,2\ngrub,2\n"), []byte("sbat,1,2021030218\n")}

	image := newMockImage().
		withShimVersion(MustParseShimVersion("15.6")).
		withShimVendorDb(vendorDb, ShimVendorCertIsX509)

	handler, err := NewShimLoadHandlerConstructor().WithSbatLevel(sbatLevel).New(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec|ShimHasSbatRevocationManagement)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: vendorDb,
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, sbatLevel)

	var v VendorAuthorityGetter
	c.Assert(handler, Implements, &v)
	certs, err := handler.(VendorAuthorityGetter).VendorAuthorities()
	c.Check(err, IsNil)
	c.Check(certs, DeepEquals, []*x509.Certificate{testutil.ParseCertificate(c, canonicalCACert)})
}

func (s *shimLoadHandlerSuite) TestNewShimLoadHandler15_3(c *C) {
	vendorDb := efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})}
	sbatLevel := ShimSbatLevel{[]byte("sbat,1,2021030218\n"), []byte("sbat,1,2021030218\n")}

	image := newMockImage().
		withShimVersion(MustParseShimVersion("15.3")).
		withShimVendorDb(vendorDb, ShimVendorCertIsX509)

	handler, err := NewShimLoadHandlerConstructor().WithSbatLevel(sbatLevel).New(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: vendorDb,
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, sbatLevel)

	var v VendorAuthorityGetter
	c.Assert(handler, Implements, &v)
	certs, err := handler.(VendorAuthorityGetter).VendorAuthorities()
	c.Check(err, IsNil)
	c.Check(certs, DeepEquals, []*x509.Certificate{testutil.ParseCertificate(c, canonicalCACert)})
}

func (s *shimLoadHandlerSuite) TestNewShimLoadHandler15_2(c *C) {
	vendorDb := efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})}

	image := newMockImage().
		withShimVersion(MustParseShimVersion("15.2")).
		withShimVendorDb(vendorDb, ShimVendorCertIsX509)

	handler, err := NewShimLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimFlags(0))
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: vendorDb,
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{})

	var v VendorAuthorityGetter
	c.Assert(handler, Implements, &v)
	certs, err := handler.(VendorAuthorityGetter).VendorAuthorities()
	c.Check(err, IsNil)
	c.Check(certs, DeepEquals, []*x509.Certificate{testutil.ParseCertificate(c, canonicalCACert)})
}

func (s *shimLoadHandlerSuite) TestNewShimLoadHandler15(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15"))

	_, err := NewShimLoadHandler(image.newPeImageHandle())
	c.Assert(err, ErrorMatches, "unsupported shim version < 15.2")
}

func (s *shimLoadHandlerSuite) TestNewShimLoadHandler15Ubuntu(c *C) {
	image := newMockUbuntuShimImage15a(c)

	handler, err := NewShimLoadHandlerConstructor().WithVersion(MustParseShimVersion("15.2")).New(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimFlags(0))
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{})

	var v VendorAuthorityGetter
	c.Assert(handler, Implements, &v)
	certs, err := handler.(VendorAuthorityGetter).VendorAuthorities()
	c.Check(err, IsNil)
	c.Check(certs, DeepEquals, []*x509.Certificate{testutil.ParseCertificate(c, canonicalCACert)})
}

func (s *shimLoadHandlerSuite) TestNewShimLoadHandlerWithVendorDb15_7(c *C) {
	vendorDb := efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, testOwnerGuid)}
	sbatLevel := ShimSbatLevel{[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"), []byte("sbat,1,2022052400\ngrub,2\n")}

	image := newMockImage().
		withShimVersion(MustParseShimVersion("15.7")).
		withShimVendorDb(vendorDb, ShimVendorCertIsDb).
		withShimSbatLevel(sbatLevel)

	handler, err := NewShimLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec|ShimVendorCertContainsDb|ShimHasSbatRevocationManagement)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "vendor_db", GUID: efi.ImageSecurityDatabaseGuid},
		Contents: vendorDb,
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, sbatLevel)

	var v VendorAuthorityGetter
	c.Assert(handler, Implements, &v)
	certs, err := handler.(VendorAuthorityGetter).VendorAuthorities()
	c.Check(err, IsNil)
	c.Check(certs, DeepEquals, []*x509.Certificate{testutil.ParseCertificate(c, canonicalCACert)})
}

func (s *shimLoadHandlerSuite) TestNewShimLoadHandlerWithVendorDb15_6(c *C) {
	vendorDb := efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, testOwnerGuid)}
	sbatLevel := ShimSbatLevel{[]byte("sbat,1,2022052400\nshim,2\ngrub,2\n"), []byte("sbat,1,2021030218\n")}

	image := newMockImage().
		withShimVersion(MustParseShimVersion("15.6")).
		withShimVendorDb(vendorDb, ShimVendorCertIsDb)

	handler, err := NewShimLoadHandlerConstructor().WithSbatLevel(sbatLevel).New(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec|ShimVendorCertContainsDb|ShimHasSbatRevocationManagement)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "vendor_db", GUID: efi.ImageSecurityDatabaseGuid},
		Contents: vendorDb,
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, sbatLevel)

	var v VendorAuthorityGetter
	c.Assert(handler, Implements, &v)
	certs, err := handler.(VendorAuthorityGetter).VendorAuthorities()
	c.Check(err, IsNil)
	c.Check(certs, DeepEquals, []*x509.Certificate{testutil.ParseCertificate(c, canonicalCACert)})
}

type testShimMeasureImageStartData struct {
	alg            tpm2.HashAlgorithmId
	pcrs           PcrFlags
	vars           efitest.MockVars
	shimFlags      ShimFlags
	vendorDb       *SecureBootDB
	sbatLevel      ShimSbatLevel
	expectedEvents []*mockPcrBranchEvent
}

func (s *shimLoadHandlerSuite) testMeasureImageStart(c *C, data *testShimMeasureImageStartData) (PcrBranchContext, *VariableSetCollector) {
	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(data.vars, nil))
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{alg: data.alg, pcrs: data.pcrs}, nil, collector.Next())

	handler := &ShimLoadHandler{
		Flags:     data.shimFlags,
		VendorDb:  data.vendorDb,
		SbatLevel: data.sbatLevel,
	}
	c.Check(handler.MeasureImageStart(ctx), IsNil)
	c.Check(ctx.events, DeepEquals, data.expectedEvents)
	c.Check(ctx.ShimContext().Flags, Equals, handler.Flags)
	c.Check(ctx.ShimContext().VendorDb, DeepEquals, handler.VendorDb)

	return ctx, collector
}

func (s *shimLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfile15_6(c *C) {
	_, collector := s.testMeasureImageStart(c, &testShimMeasureImageStartData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrs:      MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		vars:      makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2021030218\n"))),
		shimFlags: ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimHasSbatRevocationManagement,
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
		},
		sbatLevel: ShimSbatLevel{[]byte("sbat,1,2022052400\ngrub,2\n"), []byte("sbat,1,2021030218\n")},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SbatLevel", GUID: ShimGuid}, varData: []byte("sbat,1,2021030218\n")},
		},
	})
	c.Check(collector.More(), testutil.IsFalse)
}

func (s *shimLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileApplySbatLatest15_6(c *C) {
	// Verify MeasureImageStart produces the correct digest if this image will apply a SBAT update
	// because of the current policy, and verify that we get new sets of initial variables to rerun
	// the profile with.
	ctx, collector := s.testMeasureImageStart(c, &testShimMeasureImageStartData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrs:      MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		vars:      makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2021030218\n")), withSbatPolicy(ShimSbatPolicyLatest)),
		shimFlags: ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimHasSbatRevocationManagement,
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
		},
		sbatLevel: ShimSbatLevel{[]byte("sbat,1,2022052400\ngrub,2\n"), []byte("sbat,1,2021030218\n")},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SbatLevel", GUID: ShimGuid}, varData: []byte("sbat,1,2022052400\ngrub,2\n")},
		},
	})

	// Verify that this branch's variables were updated
	data, _, err := ctx.Vars().ReadVar("SbatLevelRT", ShimGuid)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("sbat,1,2022052400\ngrub,2\n"))
	data, _, err = ctx.Vars().ReadVar("SbatPolicy", ShimGuid)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{uint8(ShimSbatPolicyPrevious)})

	// Verify that we get additional sets of variables to run the profile against
	c.Assert(collector.More(), testutil.IsTrue)
	vars := collector.Next()

	data, _, err = vars.ReadVar("SbatLevelRT", ShimGuid)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("sbat,1,2021030218\n"))
	data, _, err = vars.ReadVar("SbatPolicy", ShimGuid)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{uint8(ShimSbatPolicyPrevious)})

	c.Assert(collector.More(), testutil.IsTrue)
	vars = collector.Next()

	data, _, err = vars.ReadVar("SbatLevelRT", ShimGuid)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("sbat,1,2022052400\ngrub,2\n"))
	data, _, err = vars.ReadVar("SbatPolicy", ShimGuid)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{uint8(ShimSbatPolicyPrevious)})

	c.Check(collector.More(), testutil.IsFalse)
}

func (s *shimLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfileUpgrade15_6To15_7(c *C) {
	// Verify MeasureImageStart produces the correct digest if this image will apply a SBAT update,
	// and verify that we get new sets of initial variables to rerun the profile with.
	ctx, collector := s.testMeasureImageStart(c, &testShimMeasureImageStartData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrs:      MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		vars:      makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2021030218\n"))),
		shimFlags: ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimVendorCertContainsDb | ShimHasSbatRevocationManagement,
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "MokListRT", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, ShimGuid)},
		},
		sbatLevel: ShimSbatLevel{[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"), []byte("sbat,1,2022052400\ngrub,2\n")},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SbatLevel", GUID: ShimGuid}, varData: []byte("sbat,1,2022052400\ngrub,2\n")},
		},
	})

	// Verify that this branch's variables were updated
	data, _, err := ctx.Vars().ReadVar("SbatLevelRT", ShimGuid)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("sbat,1,2022052400\ngrub,2\n"))

	// Verify that we get additional sets of variables to run the profile against
	c.Assert(collector.More(), testutil.IsTrue)
	vars := collector.Next()

	data, _, err = vars.ReadVar("SbatLevelRT", ShimGuid)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("sbat,1,2022052400\ngrub,2\n"))

	c.Check(collector.More(), testutil.IsFalse)
}

func (s *shimLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfile15_7To15_4(c *C) {
	// Verify MeasureImageStart produces the correct digest if this image preserves the
	// current SbatLevel.
	_, collector := s.testMeasureImageStart(c, &testShimMeasureImageStartData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrs:      MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		vars:      makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2022052400\ngrub,2\n"))),
		shimFlags: ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec,
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
		},
		sbatLevel: ShimSbatLevel{[]byte("sbat,1,2021030218\n"), []byte("sbat,1,2021030218\n")},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SbatLevel", GUID: ShimGuid}, varData: []byte("sbat,1,2022052400\ngrub,2\n")},
		},
	})
	c.Check(collector.More(), testutil.IsFalse)
}

func (s *shimLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfile15_2(c *C) {
	// Test MeasureImageStart on a pre-SBAT shim
	_, collector := s.testMeasureImageStart(c, &testShimMeasureImageStartData{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		vars: makeMockVars(c, withMsSecureBootConfig()),
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
		},
	})
	c.Check(collector.More(), testutil.IsFalse)
}

func (s *shimLoadHandlerSuite) TestMeasureImageStartSecureBootPolicyProfile15_2To15_6(c *C) {
	// Test MeasureImageStart produces the correct digest when upgrading from a pre-SBAT shim,
	// and verify we get new sets of initial variables to rerun the profile with.
	ctx, collector := s.testMeasureImageStart(c, &testShimMeasureImageStartData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrs:      MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		vars:      makeMockVars(c, withMsSecureBootConfig()),
		shimFlags: ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimHasSbatRevocationManagement,
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
		},
		sbatLevel: ShimSbatLevel{[]byte("sbat,1,2022052400\ngrub,2\n"), []byte("sbat,1,2021030218\n")},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchMeasureVariableEvent, varName: efi.VariableDescriptor{Name: "SbatLevel", GUID: ShimGuid}, varData: []byte("sbat,1,2021030218\n")},
		},
	})

	// Verify that this branch's variables were updated
	data, _, err := ctx.Vars().ReadVar("SbatLevelRT", ShimGuid)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("sbat,1,2021030218\n"))

	// Verify that we get additional sets of variables to run the profile against
	c.Assert(collector.More(), testutil.IsTrue)
	vars := collector.Next()

	data, _, err = vars.ReadVar("SbatLevelRT", ShimGuid)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("sbat,1,2021030218\n"))

	c.Check(collector.More(), testutil.IsFalse)
}

func (s *shimLoadHandlerSuite) TestMeasureImageStartBootManagerCodeProfile(c *C) {
	_, collector := s.testMeasureImageStart(c, &testShimMeasureImageStartData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrs:      MakePcrFlags(internal_efi.BootManagerCodePCR),
		vars:      makeMockVars(c, withMsSecureBootConfig()),
		shimFlags: ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimHasSbatRevocationManagement,
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
		},
		sbatLevel: ShimSbatLevel{[]byte("sbat,1,2022052400\ngrub,2\n"), []byte("sbat,1,2021030218\n")},
	})
	c.Check(collector.More(), testutil.IsFalse)
}

type testShimMeasureImageLoadData struct {
	alg                tpm2.HashAlgorithmId
	pcrs               PcrFlags
	db                 efi.SignatureDatabase
	shimFlags          ShimFlags
	vendorDb           *SecureBootDB
	image              *mockImage
	expectedEvents     []*mockPcrBranchEvent
	verificationDigest tpm2.Digest
}

func (s *shimLoadHandlerSuite) testMeasureImageLoad(c *C, data *testShimMeasureImageLoadData) {
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:      data.alg,
		pcrs:     data.pcrs,
		handlers: s,
	}, nil, nil)
	ctx.FwContext().Db = &SecureBootDB{
		Name:     Db,
		Contents: data.db,
	}
	ctx.ShimContext().Flags = data.shimFlags
	ctx.ShimContext().VendorDb = data.vendorDb

	s.mockImageLoadHandlerMap[data.image] = newMockLoadHandler()

	handler := &ShimLoadHandler{
		Flags:    ctx.ShimContext().Flags,
		VendorDb: ctx.ShimContext().VendorDb,
	}
	childHandler, err := handler.MeasureImageLoad(ctx, data.image.newPeImageHandle())
	c.Check(err, IsNil)
	c.Check(childHandler, Equals, s.mockImageLoadHandlerMap[data.image])
	c.Check(ctx.events, DeepEquals, data.expectedEvents)
	if len(data.verificationDigest) > 0 {
		c.Check(ctx.ShimContext().HasVerificationEvent(data.verificationDigest), testutil.IsTrue)
	}
}

func (s *shimLoadHandlerSuite) TestMeasureImageLoadSecureBootPolicyProfile15_7(c *C) {
	verificationDigest := testutil.DecodeHexString(c, "68bdff38e48c399326ca7356eb992693d13301f3925caf10e7b39dc9240789cd")

	s.testMeasureImageLoad(c, &testShimMeasureImageLoadData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrs:      MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		db:        msDb(c),
		shimFlags: ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimVendorCertContainsDb | ShimHasSbatRevocationManagement,
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "MokListRT", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, ShimGuid)},
		},
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
		},
		verificationDigest: verificationDigest,
	})
}

func (s *shimLoadHandlerSuite) TestMeasureImageLoadSecureBootPolicyProfile15_6(c *C) {
	verificationDigest := testutil.DecodeHexString(c, "5e19450c7a75acd95f6af49d0e32b74142972d9dd4c1b8068450653683a13016")

	s.testMeasureImageLoad(c, &testShimMeasureImageLoadData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrs:      MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		db:        msDb(c),
		shimFlags: ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimHasSbatRevocationManagement,
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
		},
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
		},
		verificationDigest: verificationDigest,
	})
}

func (s *shimLoadHandlerSuite) TestMeasureImageLoadSecureBootPolicyProfileVendorDb15_6(c *C) {
	verificationDigest := testutil.DecodeHexString(c, "0215d3be0866e20cbcd1816645436caed77de45cadd2790c1b20220df775a412")

	s.testMeasureImageLoad(c, &testShimMeasureImageLoadData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrs:      MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		db:        msDb(c),
		shimFlags: ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimVendorCertContainsDb | ShimHasSbatRevocationManagement,
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, testOwnerGuid)},
		},
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
		},
		verificationDigest: verificationDigest,
	})
}

func (s *shimLoadHandlerSuite) TestMeasureImageLoadSecureBootPolicyProfileVerifyFromDb15_6(c *C) {
	verificationDigest := testutil.DecodeHexString(c, "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9")

	s.testMeasureImageLoad(c, &testShimMeasureImageLoadData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrs:      MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		db:        msDb(c),
		shimFlags: ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimHasSbatRevocationManagement,
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
		},
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
		},
		verificationDigest: verificationDigest,
	})
}

func (s *shimLoadHandlerSuite) TestMeasureImageLoadSecureBootPolicyProfileVerifyFromDb15_2(c *C) {
	verificationDigest := testutil.DecodeHexString(c, "533f27695c8a3bdf2994bdca61291ae5edf781da051f592649270e82d7c95dc1")

	s.testMeasureImageLoad(c, &testShimMeasureImageLoadData{
		alg:  tpm2.HashAlgorithmSHA256,
		pcrs: MakePcrFlags(internal_efi.SecureBootPolicyPCR),
		db:   msDb(c),
		vendorDb: &SecureBootDB{
			Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
			Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
		},
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: verificationDigest},
		},
		verificationDigest: verificationDigest,
	})
}

func (s *shimLoadHandlerSuite) TestMeasureImageLoadBootManagerCodeProfile1(c *C) {
	s.testMeasureImageLoad(c, &testShimMeasureImageLoadData{
		alg:   tpm2.HashAlgorithmSHA256,
		pcrs:  MakePcrFlags(internal_efi.BootManagerCodePCR),
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3709c5a882490fa5b9b7a471f3466341da4267060419491954324d3bfb6aa0c6")},
		},
	})
}

func (s *shimLoadHandlerSuite) TestMeasureImageLoadBootManagerCodeProfile2(c *C) {
	s.testMeasureImageLoad(c, &testShimMeasureImageLoadData{
		alg:   tpm2.HashAlgorithmSHA256,
		pcrs:  MakePcrFlags(internal_efi.BootManagerCodePCR),
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig2)),
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 4, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "6f007fb8b3a8397bbbe5aa4d64ad2624c2cfb7cd5fa18d51bfbb0f27d1d62b89")},
		},
	})
}
