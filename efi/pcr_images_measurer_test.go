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

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

type pcrImagesMeasurerSuite struct {
	mockImageHandleMixin
}

var _ = Suite(&pcrImagesMeasurerSuite{})

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerMeasureOneLeaf(c *C) {
	// Simple case of measuring a single leaf application
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1),
		images[1]: newMockLoadHandler().withExtendPCROnImageStart(1, digest2),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1]))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
    ExtendPCR(TPM_ALG_SHA256, 1, %x)
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "f5eb5992a5a8500fb11ef01f1ecbaf2b90530dfbba57f4428f3f34f745f6aa44"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerTwoLeaf(c *C) {
	// Simple case of measuring 2 leaf applications to ensure that they end
	// up in separate branches.
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1, digest2),
		images[1]: newMockLoadHandler(),
		images[2]: newMockLoadHandler(),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1]), NewImageLoadActivity(images[2]))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "84f372030a8bcfeee7138224f74187f3e5e1ede554cd18133b65deafa65af648"),
		testutil.DecodeHexString(c, "44fc701f6e0fd4a746406306870ac08987e4b064df14f38c09881f5274b090e1"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerNonLeaf(c *C) {
	// Ensure that measuring a non-leaf application returns a new measurer instance
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage(), newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1),
		images[1]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest2),
		images[2]: newMockLoadHandler(),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1]).Loads(NewImageLoadActivity(images[2])))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 1)

	next, err = next[0].Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
    BranchPoint(
      Branch 0 {
       ExtendPCR(TPM_ALG_SHA256, 0, %x)
      }
    )
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "e841c580d064eba4269aae5f846c341a1f027bf8ef6ec897bfb1e78e40a0f829"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerTwoNonLeaf(c *C) {
	// Ensure that measuring a 2 non-leaf application returns 2 new measurer instances
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo1")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "foo2")
	digest2 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest3 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage(), newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1, digest2),
		images[1]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest3),
		images[2]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest3),
		images[3]: newMockLoadHandler(),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]],
		NewImageLoadActivity(images[1]).Loads(NewImageLoadActivity(images[3])),
		NewImageLoadActivity(images[2]).Loads(NewImageLoadActivity(images[3])),
	)
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 2)

	for _, m := range next {
		next, err = m.Measure()
		c.Check(err, IsNil)
		c.Check(next, HasLen, 0)
	}

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    BranchPoint(
      Branch 0 {
       ExtendPCR(TPM_ALG_SHA256, 0, %[3]x)
      }
    )
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[2]x)
    BranchPoint(
      Branch 0 {
       ExtendPCR(TPM_ALG_SHA256, 0, %[3]x)
      }
    )
   }
 )
`, digest1, digest2, digest3))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "6156b5898bc52750f98fa224658afa733d57bb795b1e882484d061d03273d395"),
		testutil.DecodeHexString(c, "f2461eb04ded480d849e244535804f6a39176c82c6b75c58e799333dea1cb4f1"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerMeasureWithParams(c *C) {
	// Ensure that measrung an application creates a branch for each parameter set
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1, digest2),
		images[1]: newMockLoadHandler().withCheckParamsOnImageStartMulti(c,
			LoadParams{KernelCommandlineParamKey: "foo"},
			LoadParams{KernelCommandlineParamKey: "bar"},
		),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1], KernelCommandlineParams("foo", "bar")))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "84f372030a8bcfeee7138224f74187f3e5e1ede554cd18133b65deafa65af648"),
		testutil.DecodeHexString(c, "44fc701f6e0fd4a746406306870ac08987e4b064df14f38c09881f5274b090e1"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerMeasureWithInheritedParams(c *C) {
	// Ensure that parameters are inherited.
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{"foo": "bar"}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1, digest2),
		images[1]: newMockLoadHandler().withCheckParamsOnImageStartMulti(c,
			LoadParams{KernelCommandlineParamKey: "foo", "foo": "bar"},
			LoadParams{KernelCommandlineParamKey: "bar", "foo": "bar"},
		),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1], KernelCommandlineParams("foo", "bar")))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "84f372030a8bcfeee7138224f74187f3e5e1ede554cd18133b65deafa65af648"),
		testutil.DecodeHexString(c, "44fc701f6e0fd4a746406306870ac08987e4b064df14f38c09881f5274b090e1"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerMeasureWithVars(c *C) {
	// Ensure that variables are inherited correctly
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{
		{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1),
		images[1]: newMockLoadHandler().
			withExtendPCROnImageStart(1, digest2).
			withCheckVarOnImageStartMulti(c, "foo", testGuid1, []byte{1}),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1]))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
    ExtendPCR(TPM_ALG_SHA256, 1, %x)
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "f5eb5992a5a8500fb11ef01f1ecbaf2b90530dfbba57f4428f3f34f745f6aa44"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerMeasureEnsureVarsAreCopied(c *C) {
	// Ensure that variables associated with sibling nodes are copied
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{
		{Name: "foo", GUID: testGuid1}: {Payload: []byte{1}, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1, digest1),
		images[1]: newMockLoadHandler().
			withExtendPCROnImageStart(1, digest2).
			withCheckVarOnImageStartMulti(c, "foo", testGuid1, []byte{1}, []byte{1}).
			withSetVarOnImageStart("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{0}),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1]), NewImageLoadActivity(images[1]))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 1, %[2]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 1, %[2]x)
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "f5eb5992a5a8500fb11ef01f1ecbaf2b90530dfbba57f4428f3f34f745f6aa44"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerMeasureWithFwContext(c *C) {
	// Ensure that fwContext is inherited correctly
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1),
		images[1]: newMockLoadHandler().
			withExtendPCROnImageStart(1, digest2).
			withCheckFwHasVerificationEventOnImageStart(c, digest1, true),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)
	bc.FwContext().AppendVerificationEvent(digest1)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1]))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
    ExtendPCR(TPM_ALG_SHA256, 1, %x)
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "f5eb5992a5a8500fb11ef01f1ecbaf2b90530dfbba57f4428f3f34f745f6aa44"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerMeasureEnsureFwContextIsCopied(c *C) {
	// Ensure that fwContexts associated with sibling nodes are copied
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1, digest1),
		images[1]: newMockLoadHandler().
			withExtendPCROnImageStart(1, digest2).
			withCheckFwHasVerificationEventOnImageStart(c, digest1, true).
			withCheckFwHasVerificationEventOnImageStart(c, digest2, false).
			withAppendFwVerificationEventOnImageStart(c, digest2),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)
	bc.FwContext().AppendVerificationEvent(digest1)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1]), NewImageLoadActivity(images[1]))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 1, %[2]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 1, %[2]x)
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "f5eb5992a5a8500fb11ef01f1ecbaf2b90530dfbba57f4428f3f34f745f6aa44"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerMeasureWithShimContext(c *C) {
	// Ensure that shimContext is inherited correctly
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1),
		images[1]: newMockLoadHandler().
			withExtendPCROnImageStart(1, digest2).
			withCheckShimHasVerificationEventOnImageStart(c, digest1, true),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)
	bc.ShimContext().AppendVerificationEvent(digest1)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1]))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %x)
    ExtendPCR(TPM_ALG_SHA256, 1, %x)
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "f5eb5992a5a8500fb11ef01f1ecbaf2b90530dfbba57f4428f3f34f745f6aa44"),
	})
}

func (s *pcrImagesMeasurerSuite) TestPcrImagesMeasurerMeasureEnsureShimContextIsCopied(c *C) {
	// Ensure that shimContexts associated with sibling nodes are copied
	profile := secboot_tpm2.NewPCRProtectionProfile()

	params := LoadParams{}
	vars := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)).Next()

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	images := []*mockImage{newMockImage(), newMockImage()}
	handlers := mockImageLoadHandlerMap{
		images[0]: newMockLoadHandler().withExtendPCROnImageLoadMulti(0, digest1, digest1),
		images[1]: newMockLoadHandler().
			withExtendPCROnImageStart(1, digest2).
			withCheckShimHasVerificationEventOnImageStart(c, digest1, true).
			withCheckShimHasVerificationEventOnImageStart(c, digest2, false).
			withAppendShimVerificationEventOnImageStart(c, digest2),
	}
	pc := &mockPcrProfileContext{
		alg:      tpm2.HashAlgorithmSHA256,
		handlers: handlers,
	}
	bc := NewRootPcrBranchCtx(pc, profile.RootBranch(), params, vars)
	bc.ShimContext().AppendVerificationEvent(digest1)

	m := NewPcrImagesMeasurer(bc, handlers[images[0]], NewImageLoadActivity(images[1]), NewImageLoadActivity(images[1]))
	next, err := m.Measure()
	c.Check(err, IsNil)
	c.Check(next, HasLen, 0)

	c.Check(profile.String(), Equals, fmt.Sprintf(`
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 1, %[2]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 0, %[1]x)
    ExtendPCR(TPM_ALG_SHA256, 1, %[2]x)
   }
 )
`, digest1, digest2))

	pcrs, pcrDigests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1}}})
	c.Check(pcrDigests, DeepEquals, tpm2.DigestList{
		testutil.DecodeHexString(c, "f5eb5992a5a8500fb11ef01f1ecbaf2b90530dfbba57f4428f3f34f745f6aa44"),
	})
}
