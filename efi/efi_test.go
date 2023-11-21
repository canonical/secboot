// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"testing"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

func Test(t *testing.T) { TestingT(t) }

type mockPcrProfileContext struct {
	alg      tpm2.HashAlgorithmId
	flags    PcrProfileFlags
	handlers ImageLoadHandlerMap
}

func (c *mockPcrProfileContext) PCRAlg() tpm2.HashAlgorithmId {
	return c.alg
}

func (c *mockPcrProfileContext) Flags() PcrProfileFlags {
	return c.flags
}

func (c *mockPcrProfileContext) ImageLoadHandlerMap() ImageLoadHandlerMap {
	return c.handlers
}

type mockPcrBranchEventType int

const (
	mockPcrBranchResetEvent mockPcrBranchEventType = iota
	mockPcrBranchExtendEvent
	mockPcrBranchMeasureVariableEvent
)

type mockPcrBranchEvent struct {
	pcr       int
	eventType mockPcrBranchEventType

	digest tpm2.Digest

	varName efi.VariableDescriptor
	varData []byte
}

type mockPcrBranchContext struct {
	PcrProfileContext
	vars   VarReadWriter
	fc     *FwContext
	sc     *ShimContext
	events []*mockPcrBranchEvent
}

func newMockPcrBranchContext(pc PcrProfileContext, vars VarReadWriter) *mockPcrBranchContext {
	return &mockPcrBranchContext{
		PcrProfileContext: pc,
		vars:              vars,
		fc:                new(FwContext),
		sc:                new(ShimContext),
	}
}

func (*mockPcrBranchContext) Params() *LoadParams { return nil }

func (c *mockPcrBranchContext) Vars() VarReadWriter {
	return c.vars
}

func (c *mockPcrBranchContext) FwContext() *FwContext {
	return c.fc
}

func (c *mockPcrBranchContext) ShimContext() *ShimContext {
	return c.sc
}

func (c *mockPcrBranchContext) ResetPCR(pcr int) {
	c.events = append(c.events, &mockPcrBranchEvent{
		pcr:       pcr,
		eventType: mockPcrBranchResetEvent,
	})
}

func (c *mockPcrBranchContext) ExtendPCR(pcr int, digest tpm2.Digest) {
	c.events = append(c.events, &mockPcrBranchEvent{
		pcr:       pcr,
		eventType: mockPcrBranchExtendEvent,
		digest:    digest,
	})
}

func (c *mockPcrBranchContext) MeasureVariable(pcr int, guid efi.GUID, name string, data []byte) {
	c.events = append(c.events, &mockPcrBranchEvent{
		pcr:       pcr,
		eventType: mockPcrBranchMeasureVariableEvent,
		varName:   efi.VariableDescriptor{Name: name, GUID: guid},
		varData:   data,
	})
}

type mockPeImageHandle struct {
	*mockImage
}

func (*mockPeImageHandle) Close() error    { return nil }
func (h *mockPeImageHandle) Source() Image { return h.mockImage }

func (h *mockPeImageHandle) OpenSection(name string) *io.SectionReader {
	data, exists := h.sections[name]
	if !exists {
		return nil
	}
	return io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data)))
}

func (h *mockPeImageHandle) HasSection(name string) bool {
	_, exists := h.sections[name]
	return exists
}

func (h *mockPeImageHandle) HasSbatSection() bool {
	return len(h.sbat) > 0
}

func (h *mockPeImageHandle) SbatComponents() ([]SbatComponent, error) {
	if len(h.sbat) == 0 {
		return nil, errors.New("no sbat")
	}
	return h.sbat, nil
}

func (h *mockPeImageHandle) ImageDigest(alg crypto.Hash) ([]byte, error) {
	if alg != h.digestAlg {
		return nil, errors.New("invalid alg")
	}
	return h.digest, nil
}

func (h *mockPeImageHandle) SecureBootSignatures() ([]*efi.WinCertificateAuthenticode, error) {
	return h.sigs, nil
}

func (h *mockPeImageHandle) newShimImageHandle() *mockShimImageHandle {
	return &mockShimImageHandle{mockPeImageHandle: h}
}

type mockShimImageHandle struct {
	*mockPeImageHandle
}

func (h *mockShimImageHandle) Version() (ShimVersion, error) {
	if h.shimVersion == nil {
		return ShimVersion{}, errors.New("no version")
	}
	return *h.shimVersion, nil
}

func (h *mockShimImageHandle) ReadVendorDB() (efi.SignatureDatabase, ShimVendorCertFormat, error) {
	if h.shimVendorDbFormat == 0 {
		return nil, 0, errors.New("no vendor db")
	}
	return h.shimVendorDb, h.shimVendorDbFormat, nil
}

func (h *mockShimImageHandle) HasSbatLevelSection() bool {
	return h.shimSbatLevel != nil
}

func (h *mockShimImageHandle) ReadSbatLevel() (ShimSbatLevel, error) {
	if h.shimSbatLevel == nil {
		return ShimSbatLevel{}, errors.New("no sbatlevel")
	}
	return *h.shimSbatLevel, nil
}

type mockImage struct {
	sections  map[string][]byte
	sbat      []SbatComponent
	digestAlg crypto.Hash
	digest    []byte
	sigs      []*efi.WinCertificateAuthenticode

	shimVersion        *ShimVersion
	shimVendorDb       efi.SignatureDatabase
	shimVendorDbFormat ShimVendorCertFormat
	shimSbatLevel      *ShimSbatLevel
}

func newMockImage() *mockImage {
	return &mockImage{
		sections: make(map[string][]byte),
	}
}

func (i *mockImage) withDigest(alg crypto.Hash, digest []byte) *mockImage {
	i.digestAlg = alg
	i.digest = digest
	return i
}

func (i *mockImage) appendSignatures(sigs ...*efi.WinCertificateAuthenticode) *mockImage {
	if len(sigs) > 0 && i.digestAlg == crypto.Hash(0) {
		i.digestAlg = sigs[0].DigestAlgorithm()
		i.digest = sigs[0].Digest()
	}
	i.sigs = append(i.sigs, sigs...)
	return i
}

func (i *mockImage) sign(c *C, key crypto.Signer, signer *x509.Certificate, certs ...*x509.Certificate) *mockImage {
	i.sigs = append(i.sigs, efitest.ReadWinCertificateAuthenticodeDetached(c, efitest.GenerateWinCertificateAuthenticodeDetached(c, key, signer, i.digest, i.digestAlg, certs...)))
	return i
}

func (i *mockImage) unsign() *mockImage {
	i.sigs = nil
	return i
}

func (i *mockImage) addSection(name string, data []byte) *mockImage {
	i.sections[name] = data
	return i
}

func (i *mockImage) withSbat(sbat []SbatComponent) *mockImage {
	i.sbat = sbat
	i.sections[".sbat"] = nil
	return i
}

func (i *mockImage) withShimVersion(version ShimVersion) *mockImage {
	i.shimVersion = &version
	return i
}

func (i *mockImage) withShimVendorDb(db efi.SignatureDatabase, format ShimVendorCertFormat) *mockImage {
	i.shimVendorDb = db
	i.shimVendorDbFormat = format
	i.sections[".vendor_cert"] = nil
	return i
}

func (i *mockImage) withShimSbatLevel(sbatLevel ShimSbatLevel) *mockImage {
	i.shimSbatLevel = &sbatLevel
	i.sections[".sbatlevel"] = nil
	return i
}

func newMockUbuntuShimImage15a(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig1)).
		withShimVersion(MustParseShimVersion("15")).
		withShimVendorDb(efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})}, ShimVendorCertIsX509)
}

func newMockUbuntuShimImage15b(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig2)).
		withShimVersion(MustParseShimVersion("15")).
		withShimVendorDb(efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})}, ShimVendorCertIsX509)
}

func newMockUbuntuShimImage15_4(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)).
		withSbat([]SbatComponent{
			{Name: "shim"},
			{Name: "shim.ubuntu"},
		}).
		withShimVersion(MustParseShimVersion("15.4")).
		withShimVendorDb(efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})}, ShimVendorCertIsX509)
}

func newMockUbuntuShimImage15_7(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)).
		withSbat([]SbatComponent{
			{Name: "shim"},
			{Name: "shim.ubuntu"},
		}).
		withShimVersion(MustParseShimVersion("15.7")).
		withShimVendorDb(efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})}, ShimVendorCertIsX509).
		withShimSbatLevel(ShimSbatLevel{[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"), []byte("sbat,1,2022052400\ngrub,2\n")})
}

func newMockUbuntuGrubImage1(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig1)).
		addSection("mods", nil)
}

func newMockUbuntuGrubImage2(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig2)).
		addSection("mods", nil).
		withSbat([]SbatComponent{
			{Name: "grub"},
			{Name: "grub.ubuntu"},
		})
}

func newMockUbuntuGrubImage3(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)).
		addSection("mods", nil).
		withSbat([]SbatComponent{
			{Name: "grub"},
			{Name: "grub.ubuntu"},
		})
}

func newMockUbuntuKernelImage1(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, kernelUbuntuSig1)).
		addSection(".linux", nil).
		addSection(".initrd", nil)
}

func newMockUbuntuKernelImage2(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, kernelUbuntuSig2)).
		addSection(".linux", nil).
		addSection(".initrd", nil).
		addSection(".sdmagic", nil).
		withSbat([]SbatComponent{
			{Name: "systemd"},
			{Name: "systemd.ubuntu"},
		})
}

func newMockUbuntuKernelImage3(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, kernelUbuntuSig3)).
		addSection(".linux", nil).
		addSection(".initrd", nil).
		addSection(".sdmagic", nil).
		withSbat([]SbatComponent{
			{Name: "systemd"},
			{Name: "systemd.ubuntu"},
		})
}

func newMockUbuntuKernelImage4(c *C) *mockImage {
	return newMockImage().
		appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, kernelUbuntuSig4)).
		addSection(".linux", nil).
		addSection(".initrd", nil).
		addSection(".sdmagic", nil).
		withSbat([]SbatComponent{
			{Name: "systemd"},
			{Name: "systemd.ubuntu"},
		})
}

func (i *mockImage) String() string           { return fmt.Sprintf("%p", i) }
func (*mockImage) Open() (ImageReader, error) { return nil, errors.New("not implemented") }

func (i *mockImage) newPeImageHandle() *mockPeImageHandle {
	return &mockPeImageHandle{mockImage: i}
}

type mockImageHandleMixin struct {
	restore func()
}

func (m *mockImageHandleMixin) SetUpTest(c *C) {
	orig := OpenPeImage
	m.restore = MockOpenPeImage(func(image Image) (PeImageHandle, error) {
		i, ok := image.(*mockImage)
		if !ok {
			return orig(image)
		}
		return i.newPeImageHandle(), nil
	})
}

func (m *mockImageHandleMixin) TearDownTest(c *C) {
	if m.restore != nil {
		m.restore()
	}
}

type mockShimImageHandleMixin struct {
	restore func()
}

func (m *mockShimImageHandleMixin) SetUpTest(c *C) {
	orig := NewShimImageHandle
	m.restore = MockNewShimImageHandle(func(image PeImageHandle) ShimImageHandle {
		h, ok := image.(*mockPeImageHandle)
		if !ok {
			return orig(image)
		}
		return h.newShimImageHandle()
	})
}

func (m *mockShimImageHandleMixin) TearDownTest(c *C) {
	if m.restore != nil {
		m.restore()
	}
}

type mockImageLoadHandlerMap map[Image]ImageLoadHandler

func (h mockImageLoadHandlerMap) LookupHandler(image PeImageHandle) (ImageLoadHandler, error) {
	handler, exists := h[image.Source()]
	if !exists {
		return nil, errors.New("no handler")
	}
	return handler, nil
}

type mockLoadHandler struct {
	startActions []func(PcrBranchContext) error
	loadActions  []func(PcrBranchContext) error
}

type mockLoadHandlerAction func(*mockLoadHandler)

func newMockLoadHandler(actions ...mockLoadHandlerAction) *mockLoadHandler {
	out := new(mockLoadHandler)
	for _, action := range actions {
		action(out)
	}
	return out
}

func (h *mockLoadHandler) withExtendPCROnImageStart(pcr int, digest tpm2.Digest) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		ctx.ExtendPCR(pcr, digest)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withMeasureVariableOnImageStart(pcr int, guid efi.GUID, name string) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		data, _, err := ctx.Vars().ReadVar(name, guid)
		switch {
		case err == efi.ErrVarNotExist:
		case err != nil:
			return err
		}
		ctx.MeasureVariable(pcr, guid, name, data)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withCheckParamsOnImageStarts(c *C, params ...*LoadParams) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		c.Assert(params, Not(HasLen), 0)
		c.Check(ctx.Params(), DeepEquals, params[0])
		params = params[1:]
		return nil
	})
	return h
}

func (h *mockLoadHandler) withCheckVarOnImageStarts(c *C, name string, guid efi.GUID, data ...[]byte) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		c.Assert(data, Not(HasLen), 0)
		d, _, err := ctx.Vars().ReadVar(name, guid)
		c.Check(err, IsNil)
		c.Check(d, DeepEquals, data[0])
		data = data[1:]
		return nil
	})
	return h
}

func (h *mockLoadHandler) withSetVarOnImageStart(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		return ctx.Vars().WriteVar(name, guid, attrs, data)
	})
	return h
}

func (h *mockLoadHandler) withCheckFwHasVerificationEventOnImageStart(c *C, digest tpm2.Digest, exists bool) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		var checker Checker
		if exists {
			checker = testutil.IsTrue
		} else {
			checker = testutil.IsFalse
		}
		c.Check(ctx.FwContext().HasVerificationEvent(digest), checker)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withAppendFwVerificationEventOnImageStart(c *C, digest tpm2.Digest) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		ctx.FwContext().AppendVerificationEvent(digest)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withCheckShimHasVerificationEventOnImageStart(c *C, digest tpm2.Digest, exists bool) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		var checker Checker
		if exists {
			checker = testutil.IsTrue
		} else {
			checker = testutil.IsFalse
		}
		c.Check(ctx.ShimContext().HasVerificationEvent(digest), checker)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withAppendShimVerificationEventOnImageStart(c *C, digest tpm2.Digest) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		ctx.ShimContext().AppendVerificationEvent(digest)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withExtendPCROnImageLoads(pcr int, digests ...tpm2.Digest) *mockLoadHandler {
	h.loadActions = append(h.loadActions, func(ctx PcrBranchContext) error {
		if len(digests) == 0 {
			return errors.New("no digests")
		}
		digest := digests[0]
		digests = digests[1:]
		ctx.ExtendPCR(pcr, digest)
		return nil
	})
	return h
}

func (h *mockLoadHandler) MeasureImageStart(ctx PcrBranchContext) error {
	for _, action := range h.startActions {
		if err := action(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (h *mockLoadHandler) MeasureImageLoad(ctx PcrBranchContext, image PeImageHandle) (ImageLoadHandler, error) {
	for _, action := range h.loadActions {
		if err := action(ctx); err != nil {
			return nil, err
		}
	}
	return LookupImageLoadHandler(ctx, image)
}

type mockSecureBootNamespaceRules []*x509.Certificate

func (mockSecureBootNamespaceRules) String() string {
	return "mock secure boot namespace image rules"
}

func (s *mockSecureBootNamespaceRules) AddAuthorities(certs ...*x509.Certificate) {
	*s = append(*s, certs...)
}

func (mockSecureBootNamespaceRules) NewImageLoadHandler(image PeImageHandle) (ImageLoadHandler, error) {
	return nil, errors.New("not implemented")
}
