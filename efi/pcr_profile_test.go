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
	"crypto"
	"errors"
	"fmt"
	"io"
	"strconv"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"
	"github.com/canonical/tcglog-parser"
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

type pcrProfileMockedSuite struct {
	restoreMakeImageLoadHandlerMap func()
	restoreNewFwLoadHandler        func()
	mockNewFwLoadHandler           func(*tcglog.Log) ImageLoadHandler
	mockImageHandleMixin
	mockImageLoadHandlerMap
}

func (s *pcrProfileMockedSuite) SetUpSuite(c *C) {
	s.restoreMakeImageLoadHandlerMap = MockMakeImageLoadHandlerMap(func() ImageLoadHandlerMap {
		return s
	})
	s.restoreNewFwLoadHandler = MockNewFwLoadHandler(func(log *tcglog.Log) ImageLoadHandler {
		return newMockLoadHandler().withMeasureVariableOnImageStart(0, testGuid1, "foo")
	})
}

func (s *pcrProfileMockedSuite) SetUpTest(c *C) {
	s.mockImageHandleMixin.SetUpTest(c)
	s.mockNewFwLoadHandler = nil
	s.mockImageLoadHandlerMap = make(mockImageLoadHandlerMap)
}

func (s *pcrProfileMockedSuite) TearDownSuite(c *C) {
	if s.restoreNewFwLoadHandler != nil {
		s.restoreNewFwLoadHandler()
	}
	if s.restoreMakeImageLoadHandlerMap != nil {
		s.restoreMakeImageLoadHandlerMap()
	}
}

var _ = Suite(&pcrProfileMockedSuite{})

func (s *pcrProfileMockedSuite) TestPcrProfileGeneratorPCRAlg(c *C) {
	gen := NewPcrProfileGenerator(tpm2.HashAlgorithmSHA256, NewImageLoadSequences())
	c.Check(gen.PCRAlg(), Equals, tpm2.HashAlgorithmSHA256)
}

func (s *pcrProfileMockedSuite) TestPcrProfileGeneratorPCRAlgSHA1(c *C) {
	gen := NewPcrProfileGenerator(tpm2.HashAlgorithmSHA1, NewImageLoadSequences())
	c.Check(gen.PCRAlg(), Equals, tpm2.HashAlgorithmSHA1)
}

func (s *pcrProfileMockedSuite) TestWithSecureBootPolicyProfile(c *C) {
	gen := NewPcrProfileGenerator(tpm2.HashAlgorithmSHA256, NewImageLoadSequences(), WithSecureBootPolicyProfile())
	c.Check(gen.PCRs(), Equals, PcrFlags(1<<SecureBootPolicyPCR))
}

func (s *pcrProfileMockedSuite) TestWithBootManagerCodeProfile(c *C) {
	gen := NewPcrProfileGenerator(tpm2.HashAlgorithmSHA256, NewImageLoadSequences(), WithBootManagerCodeProfile())
	c.Check(gen.PCRs(), Equals, PcrFlags(1<<BootManagerCodePCR))
}

func (s *pcrProfileMockedSuite) TestPcrProfileGeneratorImageLoadHandlers(c *C) {
	gen := NewPcrProfileGenerator(tpm2.HashAlgorithmSHA256, NewImageLoadSequences())
	c.Check(gen.ImageLoadHandlerMap(), Equals, s)
}

func (s *pcrProfileMockedSuite) TestAddPCRProfileLog(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	sequences := NewImageLoadSequences()
	expectedLog := new(tcglog.Log)

	restore := MockNewFwLoadHandler(func(log *tcglog.Log) ImageLoadHandler {
		c.Check(log, Equals, expectedLog)
		return newMockLoadHandler()
	})
	defer restore()

	c.Check(AddPCRProfile(tpm2.HashAlgorithmSHA256, profile.RootBranch(), sequences,
		WithHostEnvironment(efitest.NewMockHostEnvironment(efitest.MockVars{}, expectedLog)),
		WithSecureBootPolicyProfile(),
	), IsNil)
}

func (s *pcrProfileMockedSuite) TestAddPCRProfileSimple(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()

	var digests tpm2.DigestList
	for i := 0; i <= 2; i++ {
		h := crypto.SHA256.New()
		io.WriteString(h, strconv.Itoa(i))
		digests = append(digests, h.Sum(nil))
	}

	images := []Image{newMockImage(), newMockImage(), newMockImage()}
	s.mockImageLoadHandlerMap[images[0]] = newMockLoadHandler().withExtendPCROnImageLoads(0, digests[0])
	s.mockImageLoadHandlerMap[images[1]] = newMockLoadHandler().withExtendPCROnImageLoads(0, digests[1])
	s.mockImageLoadHandlerMap[images[2]] = newMockLoadHandler()

	sequences := NewImageLoadSequences().Append(
		NewImageLoadActivity(images[0]).Loads(
			NewImageLoadActivity(images[1]).Loads(
				NewImageLoadActivity(images[2]),
			),
		),
	)
	c.Check(AddPCRProfile(tpm2.HashAlgorithmSHA256, profile.RootBranch(), sequences,
		WithHostEnvironment(efitest.NewMockHostEnvironment(efitest.MockVars{
			{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, new(tcglog.Log))),
		WithSecureBootPolicyProfile(),
	), IsNil)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 ExtendPCR(TPM_ALG_SHA256, 0, 00f324751003eb79761fe622189096b3da044ff2333d02d8845d73704a7182b4)
 ExtendPCR(TPM_ALG_SHA256, 0, %x)
 ExtendPCR(TPM_ALG_SHA256, 0, %x)
`, digests[0], digests[1]))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "e9281e0f25468a6d97696917babda2393f5c8dceb9514fa0f10a6d9689521771"),
	})
}

func (s *pcrProfileMockedSuite) TestAddPCRProfileSimpleWithLeafBranches(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()

	var digests tpm2.DigestList
	for i := 0; i <= 3; i++ {
		h := crypto.SHA256.New()
		io.WriteString(h, strconv.Itoa(i))
		digests = append(digests, h.Sum(nil))
	}

	images := []Image{newMockImage(), newMockImage(), newMockImage(), newMockImage()}
	s.mockImageLoadHandlerMap[images[0]] = newMockLoadHandler().withExtendPCROnImageLoads(0, digests[0])
	s.mockImageLoadHandlerMap[images[1]] = newMockLoadHandler().withExtendPCROnImageLoads(0, digests[1], digests[2])
	s.mockImageLoadHandlerMap[images[2]] = newMockLoadHandler()
	s.mockImageLoadHandlerMap[images[3]] = newMockLoadHandler()

	sequences := NewImageLoadSequences().Append(
		NewImageLoadActivity(images[0]).Loads(
			NewImageLoadActivity(images[1]).Loads(
				NewImageLoadActivity(images[2]),
				NewImageLoadActivity(images[3]),
			),
		),
	)
	c.Check(AddPCRProfile(tpm2.HashAlgorithmSHA256, profile.RootBranch(), sequences,
		WithHostEnvironment(efitest.NewMockHostEnvironment(efitest.MockVars{
			{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, new(tcglog.Log))),
		WithSecureBootPolicyProfile(),
	), IsNil)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 ExtendPCR(TPM_ALG_SHA256, 0, 00f324751003eb79761fe622189096b3da044ff2333d02d8845d73704a7182b4)
 ExtendPCR(TPM_ALG_SHA256, 0, %x)
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
   }
 )
`, digests[0], digests[1], digests[2]))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "e9281e0f25468a6d97696917babda2393f5c8dceb9514fa0f10a6d9689521771"),
		testutil.DecodeHexString(c, "f631cf82c3008d65649c3b04cfe028a72deff3279532dd36b69abb89e17aa547"),
	})
}

func (s *pcrProfileMockedSuite) TestAddPCRProfileSimpleWithBranches(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()

	var digests tpm2.DigestList
	for i := 0; i <= 3; i++ {
		h := crypto.SHA256.New()
		io.WriteString(h, strconv.Itoa(i))
		digests = append(digests, h.Sum(nil))
	}

	images := []Image{newMockImage(), newMockImage(), newMockImage(), newMockImage()}
	s.mockImageLoadHandlerMap[images[0]] = newMockLoadHandler().withExtendPCROnImageLoads(0, digests[0], digests[1])
	s.mockImageLoadHandlerMap[images[1]] = newMockLoadHandler().withExtendPCROnImageLoads(0, digests[2])
	s.mockImageLoadHandlerMap[images[2]] = newMockLoadHandler().withExtendPCROnImageLoads(0, digests[2])
	s.mockImageLoadHandlerMap[images[3]] = newMockLoadHandler()

	sequences := NewImageLoadSequences().Append(
		NewImageLoadActivity(images[0]).Loads(
			NewImageLoadActivity(images[1]).Loads(
				NewImageLoadActivity(images[3]),
			),
			NewImageLoadActivity(images[2]).Loads(
				NewImageLoadActivity(images[3]),
			),
		),
	)
	c.Check(AddPCRProfile(tpm2.HashAlgorithmSHA256, profile.RootBranch(), sequences,
		WithHostEnvironment(efitest.NewMockHostEnvironment(efitest.MockVars{
			{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, new(tcglog.Log))),
		WithSecureBootPolicyProfile(),
	), IsNil)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 ExtendPCR(TPM_ALG_SHA256, 0, 00f324751003eb79761fe622189096b3da044ff2333d02d8845d73704a7182b4)
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 0, %[3]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
    ExtendPCR(TPM_ALG_SHA256, 0, %[3]x)
   }
 )
`, digests[0], digests[1], digests[2]))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "f631cf82c3008d65649c3b04cfe028a72deff3279532dd36b69abb89e17aa547"),
		testutil.DecodeHexString(c, "2fc157356e099c7d21ce49567bc9d228cf59726a60208348243fe231bb0cd19f"),
	})
}

func (s *pcrProfileMockedSuite) TestAddPCRProfileWithParams1(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()

	var digests tpm2.DigestList
	for i := 0; i <= 2; i++ {
		h := crypto.SHA256.New()
		io.WriteString(h, strconv.Itoa(i))
		digests = append(digests, h.Sum(nil))
	}

	images := []Image{newMockImage(), newMockImage(), newMockImage()}
	params := []*LoadParams{{KernelCommandline: "foo"}, {KernelCommandline: "bar"}}

	s.mockImageLoadHandlerMap[images[0]] = newMockLoadHandler().withExtendPCROnImageLoads(0, digests[0], digests[0])
	s.mockImageLoadHandlerMap[images[1]] = newMockLoadHandler().
		withExtendPCROnImageLoads(0, digests[1], digests[1]).
		withCheckParamsOnImageStarts(c, params...)
	s.mockImageLoadHandlerMap[images[2]] = newMockLoadHandler().withCheckParamsOnImageStarts(c, params...)

	sequences := NewImageLoadSequences().Append(
		NewImageLoadActivity(images[0]).Loads(
			NewImageLoadActivity(images[1], KernelCommandlineParams("foo", "bar")).Loads(
				NewImageLoadActivity(images[2]),
			),
		),
	)
	c.Check(AddPCRProfile(tpm2.HashAlgorithmSHA256, profile.RootBranch(), sequences,
		WithHostEnvironment(efitest.NewMockHostEnvironment(efitest.MockVars{
			{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, new(tcglog.Log))),
		WithSecureBootPolicyProfile(),
	), IsNil)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 ExtendPCR(TPM_ALG_SHA256, 0, 00f324751003eb79761fe622189096b3da044ff2333d02d8845d73704a7182b4)
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
   }
 )
`, digests[0], digests[1]))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "e9281e0f25468a6d97696917babda2393f5c8dceb9514fa0f10a6d9689521771"),
	})
}

func (s *pcrProfileMockedSuite) TestAddPCRProfileWithParams2(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()

	var digests tpm2.DigestList
	for i := 0; i <= 2; i++ {
		h := crypto.SHA256.New()
		io.WriteString(h, strconv.Itoa(i))
		digests = append(digests, h.Sum(nil))
	}

	images := []Image{newMockImage(), newMockImage(), newMockImage()}
	params := []*LoadParams{{KernelCommandline: "foo"}, {KernelCommandline: "bar"}}

	s.mockImageLoadHandlerMap[images[0]] = newMockLoadHandler().withExtendPCROnImageLoads(0, digests[0])
	s.mockImageLoadHandlerMap[images[1]] = newMockLoadHandler().
		withExtendPCROnImageLoads(0, digests[1], digests[1]).
		withCheckParamsOnImageStarts(c, new(LoadParams))
	s.mockImageLoadHandlerMap[images[2]] = newMockLoadHandler().withCheckParamsOnImageStarts(c, params...)

	sequences := NewImageLoadSequences().Append(
		NewImageLoadActivity(images[0]).Loads(
			NewImageLoadActivity(images[1]).Loads(
				NewImageLoadActivity(images[2], KernelCommandlineParams("foo", "bar")),
			),
		),
	)
	c.Check(AddPCRProfile(tpm2.HashAlgorithmSHA256, profile.RootBranch(), sequences,
		WithHostEnvironment(efitest.NewMockHostEnvironment(efitest.MockVars{
			{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, new(tcglog.Log))),
		WithSecureBootPolicyProfile(),
	), IsNil)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 ExtendPCR(TPM_ALG_SHA256, 0, 00f324751003eb79761fe622189096b3da044ff2333d02d8845d73704a7182b4)
 ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
   }
 )
`, digests[0], digests[1]))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "e9281e0f25468a6d97696917babda2393f5c8dceb9514fa0f10a6d9689521771"),
	})
}

func (s *pcrProfileMockedSuite) TestAddPCRProfileWithRootParams(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()

	var digests tpm2.DigestList
	for i := 0; i <= 2; i++ {
		h := crypto.SHA256.New()
		io.WriteString(h, strconv.Itoa(i))
		digests = append(digests, h.Sum(nil))
	}

	images := []Image{newMockImage(), newMockImage(), newMockImage()}
	params := []*LoadParams{{KernelCommandline: "foo"}, {KernelCommandline: "bar"}}

	s.mockImageLoadHandlerMap[images[0]] = newMockLoadHandler().
		withExtendPCROnImageLoads(0, digests[0], digests[0]).
		withCheckParamsOnImageStarts(c, params...)
	s.mockImageLoadHandlerMap[images[1]] = newMockLoadHandler().
		withExtendPCROnImageLoads(0, digests[1], digests[1]).
		withCheckParamsOnImageStarts(c, params...)
	s.mockImageLoadHandlerMap[images[2]] = newMockLoadHandler().withCheckParamsOnImageStarts(c, params...)

	sequences := NewImageLoadSequences(KernelCommandlineParams("foo", "bar")).Append(
		NewImageLoadActivity(images[0]).Loads(
			NewImageLoadActivity(images[1]).Loads(
				NewImageLoadActivity(images[2]),
			),
		),
	)
	c.Check(AddPCRProfile(tpm2.HashAlgorithmSHA256, profile.RootBranch(), sequences,
		WithHostEnvironment(efitest.NewMockHostEnvironment(efitest.MockVars{
			{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, new(tcglog.Log))),
		WithSecureBootPolicyProfile(),
	), IsNil)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, 00f324751003eb79761fe622189096b3da044ff2333d02d8845d73704a7182b4)
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, 00f324751003eb79761fe622189096b3da044ff2333d02d8845d73704a7182b4)
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
   }
 )
`, digests[0], digests[1]))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "e9281e0f25468a6d97696917babda2393f5c8dceb9514fa0f10a6d9689521771"),
	})
}

func (s *pcrProfileMockedSuite) TestAddPCRProfileWithVariableUpdate(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()

	var digests tpm2.DigestList
	for i := 0; i <= 2; i++ {
		h := crypto.SHA256.New()
		io.WriteString(h, strconv.Itoa(i))
		digests = append(digests, h.Sum(nil))
	}

	images := []Image{newMockImage(), newMockImage(), newMockImage()}
	s.mockImageLoadHandlerMap[images[0]] = newMockLoadHandler().
		withExtendPCROnImageLoads(0, digests[0], digests[0]).
		withCheckVarOnImageStarts(c, "foo", testGuid1, []byte{1}, []byte{2}).
		withSetVarOnImageStart("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})
	s.mockImageLoadHandlerMap[images[1]] = newMockLoadHandler().
		withExtendPCROnImageLoads(0, digests[1], digests[1]).
		withCheckVarOnImageStarts(c, "foo", testGuid1, []byte{2}, []byte{2})
	s.mockImageLoadHandlerMap[images[2]] = newMockLoadHandler().withCheckVarOnImageStarts(c, "foo", testGuid1, []byte{2}, []byte{2})

	sequences := NewImageLoadSequences().Append(
		NewImageLoadActivity(images[0]).Loads(
			NewImageLoadActivity(images[1]).Loads(
				NewImageLoadActivity(images[2]),
			),
		),
	)
	c.Check(AddPCRProfile(tpm2.HashAlgorithmSHA256, profile.RootBranch(), sequences,
		WithHostEnvironment(efitest.NewMockHostEnvironment(efitest.MockVars{
			{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, new(tcglog.Log))),
		WithSecureBootPolicyProfile(),
	), IsNil)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, 00f324751003eb79761fe622189096b3da044ff2333d02d8845d73704a7182b4)
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, 65e90a2a01829ea74d2e7526f14f269ad7ae806c48fd867d2f0aa1216f9193ca)
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
   }
 )
`, digests[0], digests[1]))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "e9281e0f25468a6d97696917babda2393f5c8dceb9514fa0f10a6d9689521771"),
		testutil.DecodeHexString(c, "7169ed6086c3f082f17769c7bd2152febe0e12c207e99186c4d8922f81dc7793"),
	})
}

func (s *pcrProfileMockedSuite) TestAddPCRProfileWithVariableModifier(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()

	var digests tpm2.DigestList
	for i := 0; i <= 2; i++ {
		h := crypto.SHA256.New()
		io.WriteString(h, strconv.Itoa(i))
		digests = append(digests, h.Sum(nil))
	}

	images := []Image{new(mockImage), new(mockImage), new(mockImage)}

	s.mockImageLoadHandlerMap[images[0]] = newMockLoadHandler().
		withExtendPCROnImageLoads(0, digests[0], digests[0]).
		withCheckVarOnImageStarts(c, "foo", testGuid1, []byte{1}, []byte{2})
	s.mockImageLoadHandlerMap[images[1]] = newMockLoadHandler().
		withExtendPCROnImageLoads(0, digests[1], digests[1]).
		withCheckVarOnImageStarts(c, "foo", testGuid1, []byte{1}, []byte{2})
	s.mockImageLoadHandlerMap[images[2]] = newMockLoadHandler().withCheckVarOnImageStarts(c, "foo", testGuid1, []byte{1}, []byte{2})

	sequences := NewImageLoadSequences().Append(
		NewImageLoadActivity(images[0]).Loads(
			NewImageLoadActivity(images[1]).Loads(
				NewImageLoadActivity(images[2]),
			),
		),
	)
	c.Check(AddPCRProfile(tpm2.HashAlgorithmSHA256, profile.RootBranch(), sequences,
		WithHostEnvironment(efitest.NewMockHostEnvironment(efitest.MockVars{
			{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, new(tcglog.Log))),
		WithSecureBootPolicyProfile(),
		WithMockRootVarsModifierOption(func(vars *RootVarsCollector) error {
			c.Check(vars.PeekAll()[0].WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)
			return nil
		}),
	), IsNil)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, 00f324751003eb79761fe622189096b3da044ff2333d02d8845d73704a7182b4)
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, 65e90a2a01829ea74d2e7526f14f269ad7ae806c48fd867d2f0aa1216f9193ca)
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
   }
 )
`, digests[0], digests[1]))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "e9281e0f25468a6d97696917babda2393f5c8dceb9514fa0f10a6d9689521771"),
		testutil.DecodeHexString(c, "7169ed6086c3f082f17769c7bd2152febe0e12c207e99186c4d8922f81dc7793"),
	})
}

func (s *pcrProfileMockedSuite) TestAddPCRProfileWithVariableModifierErr(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()

	images := []Image{new(mockImage), new(mockImage), new(mockImage)}

	s.mockImageLoadHandlerMap[images[0]] = newMockLoadHandler()
	s.mockImageLoadHandlerMap[images[1]] = newMockLoadHandler()
	s.mockImageLoadHandlerMap[images[2]] = newMockLoadHandler()

	sequences := NewImageLoadSequences().Append(
		NewImageLoadActivity(images[0]).Loads(
			NewImageLoadActivity(images[1]).Loads(
				NewImageLoadActivity(images[2]),
			),
		),
	)
	c.Check(AddPCRProfile(tpm2.HashAlgorithmSHA256, profile.RootBranch(), sequences,
		WithHostEnvironment(efitest.NewMockHostEnvironment(efitest.MockVars{
			{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, new(tcglog.Log))),
		WithSecureBootPolicyProfile(),
		WithMockRootVarsModifierOption(func(vars *RootVarsCollector) error {
			return errors.New("some error")
		}),
	), ErrorMatches, `cannot process host variable modifier 0: some error`)
}

type pcrProfileSuite struct {
	restoreNewShimImageHandle func()
	mockImageHandleMixin
	mockShimImageHandleMixin
	mockGrubImageHandleMixin
}

func (s *pcrProfileSuite) SetUpTest(c *C) {
	s.mockImageHandleMixin.SetUpTest(c)
	s.mockShimImageHandleMixin.SetUpTest(c)
	s.mockGrubImageHandleMixin.SetUpTest(c)
}

func (s *pcrProfileSuite) TearDownTest(c *C) {
	s.mockImageHandleMixin.TearDownTest(c)
	s.mockShimImageHandleMixin.TearDownTest(c)
	s.mockGrubImageHandleMixin.TearDownTest(c)
}

var _ = Suite(&pcrProfileSuite{})

type testAddPCRProfileData struct {
	vars          efitest.MockVars
	log           *tcglog.Log
	alg           tpm2.HashAlgorithmId
	profile       *secboot_tpm2.PCRProtectionProfile
	branch        *secboot_tpm2.PCRProtectionProfileBranch
	loadSequences *ImageLoadSequences
	expected      []tpm2.PCRValues
}

func (s *pcrProfileSuite) testAddPCRProfile(c *C, data *testAddPCRProfileData, options ...PCRProfileOption) error {
	profile := data.profile
	branch := data.branch
	switch {
	case profile == nil:
		c.Assert(branch, IsNil)
		profile = secboot_tpm2.NewPCRProtectionProfile()
		branch = profile.RootBranch()
	case branch == nil:
		branch = profile.RootBranch()
	}

	var expectedPcrs tpm2.PCRSelectionList
	var expectedDigests tpm2.DigestList
	for i, v := range data.expected {
		pcrs, digest, err := util.ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA256, v)
		c.Assert(err, IsNil)
		if i == 0 {
			expectedPcrs = pcrs
		} else {
			c.Assert(pcrs, tpm2_testutil.TPMValueDeepEquals, expectedPcrs)
		}
		expectedDigests = append(expectedDigests, digest)
	}

	err := AddPCRProfile(data.alg, branch, data.loadSequences, append([]PCRProfileOption{WithHostEnvironment(efitest.NewMockHostEnvironment(data.vars, data.log))}, options...)...)
	if err != nil {
		return err
	}

	pcrs, digests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	c.Check(pcrs, tpm2_testutil.TPMValueDeepEquals, expectedPcrs)
	c.Check(digests, DeepEquals, expectedDigests)
	if c.Failed() {
		c.Logf("Profile:\n%s", profile)
		c.Logf("Values:\n%s", tpm2test.FormatPCRValuesFromPCRProtectionProfile(profile, nil))
	}

	return nil
}

func (s *pcrProfileSuite) TestAddPCRProfileUC20(c *C) {
	// Test with a standard UC20 profile
	shim := newMockUbuntuShimImage15_7(c)
	grub := newMockUbuntuGrubImage3(c)
	recoverKernel := newMockUbuntuKernelImage2(c)
	runKernel := newMockUbuntuKernelImage3(c)

	err := s.testAddPCRProfile(c, &testAddPCRProfileData{
		vars: makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2022052400\ngrub,2\n"))),
		log: efitest.NewLog(c, &efitest.LogOptions{
			Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		}),
		alg: tpm2.HashAlgorithmSHA256,
		loadSequences: NewImageLoadSequences(
			SnapModelParams(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")),
		).Append(
			NewImageLoadActivity(shim).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(runKernel),
					),
					NewImageLoadActivity(recoverKernel),
				),
			),
		),
		expected: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "bec6121586508581e08a41244944292ef452879f8e19c7f93d166e912c6aac5e"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "c731a39b7fc6475c7d8a9264e704902157c7cee40c22f59fa1690ea99ff70c67"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
		},
	}, WithSecureBootPolicyProfile(), WithBootManagerCodeProfile(), WithKernelConfigProfile())
	c.Check(err, IsNil)
}

func (s *pcrProfileSuite) TestAddPCRProfileUC20WithExtraProfiles(c *C) {
	// Test with a standard UC20 profile
	shim := newMockUbuntuShimImage15_7(c)
	grub := newMockUbuntuGrubImage3(c)
	recoverKernel := newMockUbuntuKernelImage2(c)
	runKernel := newMockUbuntuKernelImage3(c)

	err := s.testAddPCRProfile(c, &testAddPCRProfileData{
		vars: makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2022052400\ngrub,2\n"))),
		log: efitest.NewLog(c, &efitest.LogOptions{
			Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		}),
		alg: tpm2.HashAlgorithmSHA256,
		loadSequences: NewImageLoadSequences(
			SnapModelParams(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")),
		).Append(
			NewImageLoadActivity(shim).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(runKernel),
					),
					NewImageLoadActivity(recoverKernel),
				),
			),
		),
		expected: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					0:  testutil.DecodeHexString(c, "3d2b11b4c5cb623acbde6d14205217e47ebd368eab861e4fed782bb99be4598a"),
					2:  testutil.DecodeHexString(c, "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
					4:  testutil.DecodeHexString(c, "bec6121586508581e08a41244944292ef452879f8e19c7f93d166e912c6aac5e"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					0:  testutil.DecodeHexString(c, "3d2b11b4c5cb623acbde6d14205217e47ebd368eab861e4fed782bb99be4598a"),
					2:  testutil.DecodeHexString(c, "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
					4:  testutil.DecodeHexString(c, "c731a39b7fc6475c7d8a9264e704902157c7cee40c22f59fa1690ea99ff70c67"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
		},
	}, WithPlatformFirmwareProfile(), WithDriversAndAppsProfile(), WithSecureBootPolicyProfile(), WithBootManagerCodeProfile(), WithKernelConfigProfile())
	c.Check(err, IsNil)
}

func (s *pcrProfileSuite) TestAddPCRProfileUC20WithPlatformFirmwareProfileSL3(c *C) {
	// Test with a standard UC20 profile
	shim := newMockUbuntuShimImage15_7(c)
	grub := newMockUbuntuGrubImage3(c)
	recoverKernel := newMockUbuntuKernelImage2(c)
	runKernel := newMockUbuntuKernelImage3(c)

	err := s.testAddPCRProfile(c, &testAddPCRProfileData{
		vars: makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2022052400\ngrub,2\n"))),
		log: efitest.NewLog(c, &efitest.LogOptions{
			Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
			StartupLocality: 3,
		}),
		alg: tpm2.HashAlgorithmSHA256,
		loadSequences: NewImageLoadSequences(
			SnapModelParams(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")),
		).Append(
			NewImageLoadActivity(shim).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(runKernel),
					),
					NewImageLoadActivity(recoverKernel),
				),
			),
		),
		expected: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					0:  testutil.DecodeHexString(c, "25a58800ba22dff433a8bb1b5084a53ddf02dc71f204053b38036fe1c0f146e2"),
					2:  testutil.DecodeHexString(c, "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
					4:  testutil.DecodeHexString(c, "bec6121586508581e08a41244944292ef452879f8e19c7f93d166e912c6aac5e"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					0:  testutil.DecodeHexString(c, "25a58800ba22dff433a8bb1b5084a53ddf02dc71f204053b38036fe1c0f146e2"),
					2:  testutil.DecodeHexString(c, "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
					4:  testutil.DecodeHexString(c, "c731a39b7fc6475c7d8a9264e704902157c7cee40c22f59fa1690ea99ff70c67"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
		},
	}, WithPlatformFirmwareProfile(), WithDriversAndAppsProfile(), WithSecureBootPolicyProfile(), WithBootManagerCodeProfile(), WithKernelConfigProfile())
	c.Check(err, IsNil)
}

func (s *pcrProfileSuite) TestAddPCRProfileUC20WithTryKernel(c *C) {
	// Test with a standard UC20 profile that includes a try kernel
	shim := newMockUbuntuShimImage15_7(c)
	grub := newMockUbuntuGrubImage3(c)
	recoverKernel := newMockUbuntuKernelImage2(c)
	runKernel1 := newMockUbuntuKernelImage3(c)
	runKernel2 := newMockUbuntuKernelImage4(c)

	err := s.testAddPCRProfile(c, &testAddPCRProfileData{
		vars: makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2022052400\ngrub,2\n"))),
		log: efitest.NewLog(c, &efitest.LogOptions{
			Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		}),
		alg: tpm2.HashAlgorithmSHA256,
		loadSequences: NewImageLoadSequences(
			SnapModelParams(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")),
		).Append(
			NewImageLoadActivity(shim).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(runKernel1),
						NewImageLoadActivity(runKernel2),
					),
					NewImageLoadActivity(recoverKernel),
				),
			),
		),
		expected: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "bec6121586508581e08a41244944292ef452879f8e19c7f93d166e912c6aac5e"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "407f697575347ec33bd66d5a6311e994de513abc28bebe8e4cfae5c20fe67e38"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "c731a39b7fc6475c7d8a9264e704902157c7cee40c22f59fa1690ea99ff70c67"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
		},
	}, WithSecureBootPolicyProfile(), WithBootManagerCodeProfile(), WithKernelConfigProfile())
	c.Check(err, IsNil)
}

func (s *pcrProfileSuite) TestAddPCRProfileUC20ShimUpdate(c *C) {
	// Test with a standard UC20 profile that includes a shim 15.4 -> shim 15.7
	// upgrade. The 15.7 branch applies a SBAT update and this should produce a
	// profile that contains a branch that works with 15.4 after booting 15.7 so
	// that the profile is compatible with A/B updating shim.
	shim1 := newMockUbuntuShimImage15_4(c)
	shim2 := newMockUbuntuShimImage15_7(c)
	grub := newMockUbuntuGrubImage3(c)
	recoverKernel := newMockUbuntuKernelImage2(c)
	runKernel := newMockUbuntuKernelImage3(c)

	err := s.testAddPCRProfile(c, &testAddPCRProfileData{
		vars: makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2021030218\n"))),
		log: efitest.NewLog(c, &efitest.LogOptions{
			Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		}),
		alg: tpm2.HashAlgorithmSHA256,
		loadSequences: NewImageLoadSequences(
			SnapModelParams(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")),
		).Append(
			NewImageLoadActivity(shim1).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(runKernel),
					),
					NewImageLoadActivity(recoverKernel),
				),
			),
			NewImageLoadActivity(shim2).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(runKernel),
					),
					NewImageLoadActivity(recoverKernel),
				),
			),
		),
		expected: []tpm2.PCRValues{
			// Shim 15.4 branches
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "d196042b85e14fd009817abda16522e1fb32b19617e68d4688d0d435b24b5d02"),
					7:  testutil.DecodeHexString(c, "98f515726b235c9226a5c0d4cc2d421e6ce22f35b6652b2fbf9005fc12202d66"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "96c0ede7bb07853e327c4eaf64ec4341d4eeaa833c80ae1ed865fba4cde43ba7"),
					7:  testutil.DecodeHexString(c, "98f515726b235c9226a5c0d4cc2d421e6ce22f35b6652b2fbf9005fc12202d66"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
			// Shim 15.7 branches
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "bec6121586508581e08a41244944292ef452879f8e19c7f93d166e912c6aac5e"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "c731a39b7fc6475c7d8a9264e704902157c7cee40c22f59fa1690ea99ff70c67"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
			// Shim 15.4 branches after applying SBAT update from shim 15.7 - note that PCR4 values are identical but
			// PCR7 is updated because the value of SbatLevel changes. These branches facilitate potential A/B updating shim
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "d196042b85e14fd009817abda16522e1fb32b19617e68d4688d0d435b24b5d02"),
					7:  testutil.DecodeHexString(c, "6fc916d63dbb2efa1d6179fc105ae48451ad5d09218312157762eced9d1bdfbb"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "96c0ede7bb07853e327c4eaf64ec4341d4eeaa833c80ae1ed865fba4cde43ba7"),
					7:  testutil.DecodeHexString(c, "6fc916d63dbb2efa1d6179fc105ae48451ad5d09218312157762eced9d1bdfbb"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
		},
	}, WithSecureBootPolicyProfile(), WithBootManagerCodeProfile(), WithKernelConfigProfile())
	c.Check(err, IsNil)
}

func (s *pcrProfileSuite) TestAddPCRProfileUC20ShimUpdateFromPreSbat(c *C) {
	// Test with a standard UC20 profile that includes a shim 15 -> shim 15.4
	// upgrade, assuming that the host SbatLevel is currently unset.
	shim1 := newMockUbuntuShimImage15b(c)
	shim2 := newMockUbuntuShimImage15_4(c)
	grub := newMockUbuntuGrubImage3(c)
	recoverKernel := newMockUbuntuKernelImage2(c)
	runKernel := newMockUbuntuKernelImage3(c)

	err := s.testAddPCRProfile(c, &testAddPCRProfileData{
		vars: makeMockVars(c, withMsSecureBootConfig()),
		log: efitest.NewLog(c, &efitest.LogOptions{
			Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		}),
		alg: tpm2.HashAlgorithmSHA256,
		loadSequences: NewImageLoadSequences(
			SnapModelParams(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")),
		).Append(
			NewImageLoadActivity(shim1).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(runKernel),
					),
					NewImageLoadActivity(recoverKernel),
				),
			),
			NewImageLoadActivity(shim2).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(runKernel),
					),
					NewImageLoadActivity(recoverKernel),
				),
			),
		),
		expected: []tpm2.PCRValues{
			// Shim 15
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "68e3d6ce7f8bf9f647629bd926486a0309b28efcb2e74c2bb517ee45dd0081ca"),
					7:  testutil.DecodeHexString(c, "65df349cba09824e925f4563877f2e0b145ce929db0cc1d8a665014857e9e7e9"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "42eeb4127f3732e54119df9a6c0383b63fbca39bc715edefc4bebdc62bbe0f7b"),
					7:  testutil.DecodeHexString(c, "65df349cba09824e925f4563877f2e0b145ce929db0cc1d8a665014857e9e7e9"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
			// Shim 15.4 branches
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "d196042b85e14fd009817abda16522e1fb32b19617e68d4688d0d435b24b5d02"),
					7:  testutil.DecodeHexString(c, "98f515726b235c9226a5c0d4cc2d421e6ce22f35b6652b2fbf9005fc12202d66"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "96c0ede7bb07853e327c4eaf64ec4341d4eeaa833c80ae1ed865fba4cde43ba7"),
					7:  testutil.DecodeHexString(c, "98f515726b235c9226a5c0d4cc2d421e6ce22f35b6652b2fbf9005fc12202d66"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
		},
	}, WithSecureBootPolicyProfile(), WithBootManagerCodeProfile(), WithKernelConfigProfile())
	c.Check(err, IsNil)
}

func (s *pcrProfileSuite) TestAddPCRProfileUC20SbatPolicyLatest(c *C) {
	// Test with a standard UC20 profile with an option to generate a profile for
	// SbatPolicy=latest.
	shim := newMockUbuntuShimImage15_7(c)
	grub := newMockUbuntuGrubImage3(c)
	recoverKernel := newMockUbuntuKernelImage2(c)
	runKernel := newMockUbuntuKernelImage3(c)

	err := s.testAddPCRProfile(c, &testAddPCRProfileData{
		vars: makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2022052400\ngrub,2\n"))),
		log: efitest.NewLog(c, &efitest.LogOptions{
			Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		}),
		alg: tpm2.HashAlgorithmSHA256,
		loadSequences: NewImageLoadSequences(
			SnapModelParams(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")),
		).Append(
			NewImageLoadActivity(shim).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(runKernel),
					),
					NewImageLoadActivity(recoverKernel),
				),
			),
		),
		expected: []tpm2.PCRValues{
			// Branches with current SbatLevel
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "bec6121586508581e08a41244944292ef452879f8e19c7f93d166e912c6aac5e"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "c731a39b7fc6475c7d8a9264e704902157c7cee40c22f59fa1690ea99ff70c67"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
			// Branches with updated SbatLevel
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "bec6121586508581e08a41244944292ef452879f8e19c7f93d166e912c6aac5e"),
					7:  testutil.DecodeHexString(c, "ecb8e9facbb7f23594b887e3df384cf998d800400bae4acb1efe5b7e7e2a0029"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "c731a39b7fc6475c7d8a9264e704902157c7cee40c22f59fa1690ea99ff70c67"),
					7:  testutil.DecodeHexString(c, "ecb8e9facbb7f23594b887e3df384cf998d800400bae4acb1efe5b7e7e2a0029"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
		},
	}, WithSecureBootPolicyProfile(), WithBootManagerCodeProfile(), WithKernelConfigProfile(), WithShimSbatPolicyLatest())
	c.Check(err, IsNil)
}

func (s *pcrProfileSuite) TestAddPCRProfileUC20PreSbat(c *C) {
	// Test with a standard UC20 profile pre-SBAT
	shim := newMockUbuntuShimImage15b(c)
	grub := newMockUbuntuGrubImage1(c)
	kernel := newMockUbuntuKernelImage1(c)

	err := s.testAddPCRProfile(c, &testAddPCRProfileData{
		vars: makeMockVars(c, withMsSecureBootConfig()),
		log: efitest.NewLog(c, &efitest.LogOptions{
			Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		}),
		alg: tpm2.HashAlgorithmSHA256,
		loadSequences: NewImageLoadSequences(
			SnapModelParams(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")),
		).Append(
			NewImageLoadActivity(shim).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(kernel),
					),
					NewImageLoadActivity(kernel),
				),
			),
		),
		expected: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "39edc30b02bd577c7b36fe3d52953894ad3781611428082df5af0a9c04421398"),
					7:  testutil.DecodeHexString(c, "65df349cba09824e925f4563877f2e0b145ce929db0cc1d8a665014857e9e7e9"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "c9daf36f478b0636bee66330ccb5c5878db5f41fa3a94df796b88e3c2744bac9"),
					7:  testutil.DecodeHexString(c, "65df349cba09824e925f4563877f2e0b145ce929db0cc1d8a665014857e9e7e9"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
		},
	}, WithSecureBootPolicyProfile(), WithBootManagerCodeProfile(), WithKernelConfigProfile())
	c.Check(err, IsNil)
}

func (s *pcrProfileSuite) TestAddPCRProfileUC20WithDbxUpdate(c *C) {
	// Test with a standard UC20 profile
	shim := newMockUbuntuShimImage15_7(c)
	grub := newMockUbuntuGrubImage3(c)
	recoverKernel := newMockUbuntuKernelImage2(c)
	runKernel := newMockUbuntuKernelImage3(c)

	err := s.testAddPCRProfile(c, &testAddPCRProfileData{
		vars: makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2022052400\ngrub,2\n"))),
		log: efitest.NewLog(c, &efitest.LogOptions{
			Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		}),
		alg: tpm2.HashAlgorithmSHA256,
		loadSequences: NewImageLoadSequences(
			SnapModelParams(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")),
		).Append(
			NewImageLoadActivity(shim).Loads(
				NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover")).Loads(
					NewImageLoadActivity(grub, KernelCommandlineParams("console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run")).Loads(
						NewImageLoadActivity(runKernel),
					),
					NewImageLoadActivity(recoverKernel),
				),
			),
		),
		expected: []tpm2.PCRValues{
			// Pre-dbx update branches:
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "bec6121586508581e08a41244944292ef452879f8e19c7f93d166e912c6aac5e"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "c731a39b7fc6475c7d8a9264e704902157c7cee40c22f59fa1690ea99ff70c67"),
					7:  testutil.DecodeHexString(c, "3d65dbe406e9427d402488ea4f87e07e8b584c79c578a735d48d21a6405fc8bb"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
			// Post-dbx update branches:
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "bec6121586508581e08a41244944292ef452879f8e19c7f93d166e912c6aac5e"),
					7:  testutil.DecodeHexString(c, "51d90abb35648752a0b4866f8b4eb0e5b53113abea015b7576f8b5d373c62dae"),
					12: testutil.DecodeHexString(c, "fd1000c6f691c3054e2ff5cfacb39305820c9f3534ba67d7894cb753aa85074b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  testutil.DecodeHexString(c, "c731a39b7fc6475c7d8a9264e704902157c7cee40c22f59fa1690ea99ff70c67"),
					7:  testutil.DecodeHexString(c, "51d90abb35648752a0b4866f8b4eb0e5b53113abea015b7576f8b5d373c62dae"),
					12: testutil.DecodeHexString(c, "5b354c57a61bb9f71fcf596d7e9ef9e2e0d6f4ad8151c9f358e6f0aaa7823756"),
				},
			},
		},
	}, WithSecureBootPolicyProfile(), WithBootManagerCodeProfile(), WithKernelConfigProfile(), WithSignatureDBUpdates(&SignatureDBUpdate{Name: Dbx, Data: msDbxUpdate2}))
	c.Check(err, IsNil)
}

func (s *pcrProfileSuite) TestAddPCRProfileLoadFailsFromLeafImage(c *C) {
	shim := newMockUbuntuShimImage15_7(c)
	grub := newMockUbuntuGrubImage3(c)
	kernel := newMockUbuntuKernelImage3(c)

	err := s.testAddPCRProfile(c, &testAddPCRProfileData{
		vars: makeMockVars(c, withMsSecureBootConfig(), withSbatLevel([]byte("sbat,1,2022052400\ngrub,2\n"))),
		log: efitest.NewLog(c, &efitest.LogOptions{
			Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		}),
		alg: tpm2.HashAlgorithmSHA256,
		loadSequences: NewImageLoadSequences(
			SnapModelParams(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")),
		).Append(
			NewImageLoadActivity(shim).Loads(
				NewImageLoadActivity(grub).Loads(
					NewImageLoadActivity(grub).Loads(
						NewImageLoadActivity(kernel).Loads(
							NewImageLoadActivity(kernel),
						),
					),
				),
			),
		),
	}, WithSecureBootPolicyProfile(), WithBootManagerCodeProfile(), WithKernelConfigProfile())
	c.Check(err, ErrorMatches, `cannot measure image 0x[[:xdigit:]]{10}: cannot measure image load: kernel is a leaf image`)
}
