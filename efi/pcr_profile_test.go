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
	"fmt"
	"io"
	"strconv"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
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
	c.Check(gen.Flags(), Equals, SecureBootPolicyProfile)
}

func (s *pcrProfileMockedSuite) TestWithBootManagerCodeProfile(c *C) {
	gen := NewPcrProfileGenerator(tpm2.HashAlgorithmSHA256, NewImageLoadSequences(), WithBootManagerCodeProfile())
	c.Check(gen.Flags(), Equals, BootManagerCodeProfile)
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
		WithHostEnvironment(newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{}, expectedLog)),
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

	images := []Image{new(mockImage), new(mockImage), new(mockImage)}
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
		WithHostEnvironment(newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
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

	images := []Image{new(mockImage), new(mockImage), new(mockImage), new(mockImage)}
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
		WithHostEnvironment(newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
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

	images := []Image{new(mockImage), new(mockImage), new(mockImage), new(mockImage)}
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
		WithHostEnvironment(newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
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

	images := []Image{new(mockImage), new(mockImage), new(mockImage)}
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
		WithHostEnvironment(newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
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

	images := []Image{new(mockImage), new(mockImage), new(mockImage)}
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
		WithHostEnvironment(newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
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

	images := []Image{new(mockImage), new(mockImage), new(mockImage)}
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
		WithHostEnvironment(newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
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

	images := []Image{new(mockImage), new(mockImage), new(mockImage)}
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
		WithHostEnvironment(newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
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
