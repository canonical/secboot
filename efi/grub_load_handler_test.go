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
	"github.com/snapcore/secboot/efi/internal"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type grubLoadHandlerSuite struct {
	mockImageLoadHandlerMap
}

func (s *grubLoadHandlerSuite) SetUpTest(c *C) {
	s.mockImageLoadHandlerMap = make(mockImageLoadHandlerMap)
}

var _ = Suite(&grubLoadHandlerSuite{})

func (s *grubLoadHandlerSuite) TestMeasureImageLoadUbuntuUsesShim15_7(c *C) {
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		pcrs:     MakePcrFlags(internal.SecureBootPolicyPCR),
		handlers: s,
	}, nil, nil)
	ctx.FwContext().Db = &SecureBootDB{
		Name:     Db,
		Contents: msDb(c),
	}
	ctx.ShimContext().Flags = ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimVendorCertContainsDb | ShimHasSbatRevocationManagement
	ctx.ShimContext().VendorDb = &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "MokListRT", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, ShimGuid)},
	}

	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, kernelUbuntuSig3))
	s.mockImageLoadHandlerMap[image] = newMockLoadHandler()

	handler := &GrubLoadHandler{Flags: GrubChainloaderUsesShimProtocol}
	childHandler, err := handler.MeasureImageLoad(ctx, image.newPeImageHandle())
	c.Check(err, IsNil)
	c.Check(childHandler, Equals, s.mockImageLoadHandlerMap[image])
	c.Check(ctx.events, DeepEquals, []*mockPcrBranchEvent{
		{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "68bdff38e48c399326ca7356eb992693d13301f3925caf10e7b39dc9240789cd")},
	})
	c.Check(ctx.ShimContext().HasVerificationEvent(ctx.events[0].digest), testutil.IsTrue)
}

func (s *grubLoadHandlerSuite) TestMeasureImageLoadUbuntuUsesShim15_6(c *C) {
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		pcrs:     MakePcrFlags(internal.SecureBootPolicyPCR),
		handlers: s,
	}, nil, nil)
	ctx.FwContext().Db = &SecureBootDB{
		Name:     Db,
		Contents: msDb(c),
	}
	ctx.ShimContext().Flags = ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimHasSbatRevocationManagement
	ctx.ShimContext().VendorDb = &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	}

	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, kernelUbuntuSig3))
	s.mockImageLoadHandlerMap[image] = newMockLoadHandler()

	handler := &GrubLoadHandler{Flags: GrubChainloaderUsesShimProtocol}
	childHandler, err := handler.MeasureImageLoad(ctx, image.newPeImageHandle())
	c.Check(err, IsNil)
	c.Check(childHandler, Equals, s.mockImageLoadHandlerMap[image])
	c.Check(ctx.events, DeepEquals, []*mockPcrBranchEvent{
		{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "5e19450c7a75acd95f6af49d0e32b74142972d9dd4c1b8068450653683a13016")},
	})
	c.Check(ctx.ShimContext().HasVerificationEvent(ctx.events[0].digest), testutil.IsTrue)
}

func (s *grubLoadHandlerSuite) TestMeasureImageLoadNoShim(c *C) {
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		pcrs:     MakePcrFlags(internal.SecureBootPolicyPCR),
		handlers: s,
	}, nil, nil)
	ctx.FwContext().Db = &SecureBootDB{
		Name:     Db,
		Contents: append(msDb(c), efitest.NewSignatureListX509(c, canonicalCACert, testOwnerGuid)),
	}
	ctx.ShimContext().Flags = ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimHasSbatRevocationManagement
	ctx.ShimContext().VendorDb = &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	}

	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, kernelUbuntuSig3))
	s.mockImageLoadHandlerMap[image] = newMockLoadHandler()

	handler := &GrubLoadHandler{}
	childHandler, err := handler.MeasureImageLoad(ctx, image.newPeImageHandle())
	c.Check(err, IsNil)
	c.Check(childHandler, Equals, s.mockImageLoadHandlerMap[image])
	c.Check(ctx.events, DeepEquals, []*mockPcrBranchEvent{
		{pcr: 7, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "8c06c18055bc8f82df1405ae0fe80f64bc9b444ba82b2879acc113b9c751f6fb")},
	})
	c.Check(ctx.FwContext().HasVerificationEvent(ctx.events[0].digest), testutil.IsTrue)
}

func (s *grubLoadHandlerSuite) TestMeasureImageLoadNoShimError(c *C) {
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		pcrs:     MakePcrFlags(internal.SecureBootPolicyPCR),
		handlers: s,
	}, nil, nil)
	ctx.FwContext().Db = &SecureBootDB{
		Name:     Db,
		Contents: msDb(c),
	}
	ctx.ShimContext().Flags = ShimHasSbatVerification | ShimFixVariableAuthorityEventsMatchSpec | ShimHasSbatRevocationManagement
	ctx.ShimContext().VendorDb = &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	}

	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, kernelUbuntuSig3))
	s.mockImageLoadHandlerMap[image] = newMockLoadHandler()

	handler := &GrubLoadHandler{}
	_, err := handler.MeasureImageLoad(ctx, image.newPeImageHandle())
	c.Check(err, ErrorMatches, "cannot measure image: cannot measure secure boot event: cannot determine authority")
}
