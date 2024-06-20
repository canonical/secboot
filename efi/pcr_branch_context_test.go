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
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

var (
	testGuid1 = efi.MakeGUID(0x48864a44, 0x0314, 0x4a25, 0x8f3e, [6]byte{0x21, 0xf0, 0x8e, 0x13, 0x4b, 0xad})
	testGuid2 = efi.MakeGUID(0x959fcc90, 0x420b, 0x4cf0, 0xa6b4, [6]byte{0xb3, 0xd3, 0xcb, 0xee, 0xe5, 0x94})
)

type pcrBranchContextSuite struct{}

var _ = Suite(&pcrBranchContextSuite{})

func (s *pcrBranchContextSuite) TestPcrBranchCtxProfileContext(c *C) {
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, nil, new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	c.Check(bc.PCRAlg(), Equals, tpm2.HashAlgorithmSHA256)
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxParams(c *C) {
	params := &LoadParams{KernelCommandline: "foo"}
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, nil, params, new(VarBranch))
	c.Assert(bc, NotNil)

	c.Assert(bc.Params(), NotNil)
	c.Check(bc.Params(), DeepEquals, params)
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxParamsSubBranch(c *C) {
	params1 := &LoadParams{KernelCommandline: "foo"}
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, secboot_tpm2.NewPCRProtectionProfile().RootBranch(), params1, new(VarBranch))
	c.Assert(bc, NotNil)

	params2 := &LoadParams{KernelCommandline: "bar"}
	subBc := bc.AddBranchPoint().AddBranch(params2)
	c.Assert(subBc, NotNil)

	c.Check(bc.Params(), DeepEquals, params1)
	c.Assert(subBc.Params(), NotNil)
	c.Check(subBc.Params(), DeepEquals, params2)
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxVars(c *C) {
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{
		{Name: "foo", GUID: efi.GlobalVariable}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)).Next()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, nil, new(LoadParams), vars)
	c.Assert(bc, NotNil)

	c.Assert(bc.Vars(), NotNil)

	data, _, err := bc.Vars().ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{1})

	c.Check(bc.Vars().WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)

	data, _, err = bc.Vars().ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{2})
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxVarsSubBranch(c *C) {
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{
		{Name: "foo", GUID: efi.GlobalVariable}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)).Next()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, secboot_tpm2.NewPCRProtectionProfile().RootBranch(), new(LoadParams), vars)
	c.Assert(bc, NotNil)

	subBc := bc.AddBranchPoint().AddBranch(new(LoadParams))
	c.Assert(subBc, NotNil)

	c.Assert(subBc.Vars(), NotNil)
	c.Check(subBc.Vars(), Not(Equals), bc.Vars())
	c.Check(subBc.Vars().WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)

	data, _, err := subBc.Vars().ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{2})

	data, _, err = bc.Vars().ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{1})
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxFwContext(c *C) {
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, secboot_tpm2.NewPCRProtectionProfile().RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	c.Assert(bc.FwContext(), NotNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	bc.FwContext().AppendVerificationEvent(h.Sum(nil))

	subBc := bc.AddBranchPoint().AddBranch(new(LoadParams))
	c.Assert(subBc, NotNil)

	c.Assert(subBc.FwContext(), NotNil)
	c.Check(subBc.FwContext(), Not(Equals), bc.FwContext())
	c.Check(bc.FwContext().HasVerificationEvent(h.Sum(nil)), testutil.IsTrue)
	c.Check(subBc.FwContext().HasVerificationEvent(h.Sum(nil)), testutil.IsTrue)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	subBc.FwContext().AppendVerificationEvent(h.Sum(nil))

	c.Check(bc.FwContext().HasVerificationEvent(h.Sum(nil)), testutil.IsFalse)
	c.Check(subBc.FwContext().HasVerificationEvent(h.Sum(nil)), testutil.IsTrue)
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxShimContext(c *C) {
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, secboot_tpm2.NewPCRProtectionProfile().RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	c.Assert(bc.ShimContext(), NotNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	bc.ShimContext().AppendVerificationEvent(h.Sum(nil))

	subBc := bc.AddBranchPoint().AddBranch(new(LoadParams))
	c.Assert(subBc, NotNil)

	c.Assert(subBc.ShimContext(), NotNil)
	c.Check(subBc.ShimContext(), Not(Equals), bc.ShimContext())
	c.Check(bc.ShimContext().HasVerificationEvent(h.Sum(nil)), testutil.IsTrue)
	c.Check(subBc.ShimContext().HasVerificationEvent(h.Sum(nil)), testutil.IsTrue)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	subBc.ShimContext().AppendVerificationEvent(h.Sum(nil))

	c.Check(bc.ShimContext().HasVerificationEvent(h.Sum(nil)), testutil.IsFalse)
	c.Check(subBc.ShimContext().HasVerificationEvent(h.Sum(nil)), testutil.IsTrue)
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxResetPCR(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	bc.ResetPCR(0)

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")})
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxResetPCRSHA1(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA1}, profile.RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	bc.ResetPCR(0)

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90")})
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxExtendPCR(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch))
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

func (s *pcrBranchContextSuite) TestPcrBranchCtxExtendPCRDifferentDigest(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch))
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

func (s *pcrBranchContextSuite) TestPcrBranchCtxExtendPCRDifferentPCR(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch))
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

func (s *pcrBranchContextSuite) TestPcrBranchCtxExtendPCRSHA1(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA1}, profile.RootBranch(), new(LoadParams), new(VarBranch))
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

func (s *pcrBranchContextSuite) TestPcrBranchCtxMeasureVariable(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(0, testGuid1, "foo", []byte{0})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "ff9fb2ff447a2d010ec88975ef3ff6afd264b396e47b1e55fd4169ab6b83fa40")})
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxMeasureVariableDifferentGUID(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(0, testGuid2, "foo", []byte{0})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "353f4ac30571d87c68ad0ddc735ed49f39e01e3f9305f8eab14ee3b026e4282d")})
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxMeasureVariableDifferentName(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(0, testGuid1, "bar", []byte{0})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "b43859ac69bdede3ada42eb3da0faad92c7e7440df2b10b780ca7fdcced8e337")})
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxMeasureVariableDifferentData(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(0, testGuid1, "foo", []byte{1})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "31dbaed8f91224061ff1014ca6d398e946d4382ae15152a8913cf5d06eea76df")})
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxMeasureVariableDifferentPCR(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(1, testGuid1, "foo", []byte{0})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{1}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "ff9fb2ff447a2d010ec88975ef3ff6afd264b396e47b1e55fd4169ab6b83fa40")})
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxMeasureVariableSHA1(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA1}, profile.RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	bc.MeasureVariable(0, testGuid1, "foo", []byte{0})

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 1)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{testutil.DecodeHexString(c, "0129426f46863a6ca457fff32460c333fe3437830c88f50a786c5c4fc9f838a9")})
}

func (s *pcrBranchContextSuite) TestPcrBranchCtxExtendPCRSubBranches(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	bc := NewRootPcrBranchCtx(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256}, profile.RootBranch(), new(LoadParams), new(VarBranch))
	c.Assert(bc, NotNil)

	bp := bc.AddBranchPoint()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	bp.AddBranch(new(LoadParams)).ExtendPCR(0, h.Sum(nil))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bp.AddBranch(new(LoadParams)).ExtendPCR(0, h.Sum(nil))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(pcrDigests, HasLen, 2)
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "84f372030a8bcfeee7138224f74187f3e5e1ede554cd18133b65deafa65af648"),
		testutil.DecodeHexString(c, "44fc701f6e0fd4a746406306870ac08987e4b064df14f38c09881f5274b090e1"),
	})
}
