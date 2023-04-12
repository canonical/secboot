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
	_ "crypto/sha1"
	_ "crypto/sha256"
	"io"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

var (
	testGuid1 = efi.MakeGUID(0x48864a44, 0x0314, 0x4a25, 0x8f3e, [6]byte{0x21, 0xf0, 0x8e, 0x13, 0x4b, 0xad})
	testGuid2 = efi.MakeGUID(0x959fcc90, 0x420b, 0x4cf0, 0xa6b4, [6]byte{0xb3, 0xd3, 0xcb, 0xee, 0xe5, 0x94})
)

type pcrBranchContextSuite struct{}

var _ = Suite(&pcrBranchContextSuite{})

func (s *pcrBranchContextSuite) TestPcrBranchContextImplProfileContext(c *C) {
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, nil, new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	c.Check(bc.PCRAlg(), Equals, tpm2.HashAlgorithmSHA256)
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplParams(c *C) {
	params := &LoadParams{KernelCommandline: "foo"}
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, nil, params, new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	c.Check(bc.Params(), Not(Equals), params)
	c.Check(bc.Params(), DeepEquals, params)
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplVars(c *C) {
	vars := NewRootVarsCollector(newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)).Next()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, nil, new(LoadParams), vars, new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	c.Assert(bc.Vars(), NotNil)
	c.Check(bc.Vars().WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)

	data, _, err := bc.Vars().ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{2})

	data, _, err = vars.ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{1})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplFwContext(c *C) {
	fc := new(FwContext)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	fc.AppendVerificationEvent(h.Sum(nil))

	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, nil, new(LoadParams), new(VarBranch), fc, new(ShimContext))
	c.Assert(bc, NotNil)

	c.Check(bc.FwContext(), Not(Equals), fc)
	c.Check(bc.FwContext(), DeepEquals, fc)
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplShimContext(c *C) {
	sc := new(ShimContext)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	sc.AppendVerificationEvent(h.Sum(nil))

	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, nil, new(LoadParams), new(VarBranch), new(FwContext), sc)
	c.Assert(bc, NotNil)

	c.Check(bc.ShimContext(), Not(Equals), sc)
	c.Check(bc.ShimContext(), DeepEquals, sc)
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplResetPCR(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	bc.ResetPCR(0)

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplResetPCRSHA1(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA1}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	bc.ResetPCR(0)

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplExtendPCR(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	bc.ExtendPCR(0, h.Sum(nil))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "84f372030a8bcfeee7138224f74187f3e5e1ede554cd18133b65deafa65af648")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplExtendPCRDifferentDigest(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	bc.ExtendPCR(0, h.Sum(nil))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "44fc701f6e0fd4a746406306870ac08987e4b064df14f38c09881f5274b090e1")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplExtendPCRDifferentPCR(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	bc.ExtendPCR(1, h.Sum(nil))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{1}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "84f372030a8bcfeee7138224f74187f3e5e1ede554cd18133b65deafa65af648")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplExtendPCRSHA1(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA1}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	h := crypto.SHA1.New()
	io.WriteString(h, "foo")
	bc.ExtendPCR(0, h.Sum(nil))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "bee9da853047671ca8c21839cf18533461aac5e0cfad217dc644790ac3fe4541")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplMeasureVariable(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(0, testGuid1, "foo", []byte{0})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "ff9fb2ff447a2d010ec88975ef3ff6afd264b396e47b1e55fd4169ab6b83fa40")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplMeasureVariableDifferentGUID(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(0, testGuid2, "foo", []byte{0})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "353f4ac30571d87c68ad0ddc735ed49f39e01e3f9305f8eab14ee3b026e4282d")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplMeasureVariableDifferentName(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(0, testGuid1, "bar", []byte{0})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "b43859ac69bdede3ada42eb3da0faad92c7e7440df2b10b780ca7fdcced8e337")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplMeasureVariableDifferentData(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(0, testGuid1, "foo", []byte{1})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "31dbaed8f91224061ff1014ca6d398e946d4382ae15152a8913cf5d06eea76df")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplMeasureVariableDifferentPCR(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(1, testGuid1, "foo", []byte{0})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{1}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "ff9fb2ff447a2d010ec88975ef3ff6afd264b396e47b1e55fd4169ab6b83fa40")})
}

func (s *pcrBranchContextSuite) TestPcrBranchContextImplMeasureVariableSHA1(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewPcrBranchContextImpl(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA1}, profile.RootBranch(), new(LoadParams), new(VarBranch), new(FwContext), new(ShimContext))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(0, testGuid1, "foo", []byte{0})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "0129426f46863a6ca457fff32460c333fe3437830c88f50a786c5c4fc9f838a9")})
}
