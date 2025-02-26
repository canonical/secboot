// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package preinstall_test

import (
	"context"
	"crypto"
	"io"

	"github.com/canonical/cpuid"
	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	secboot_efi "github.com/snapcore/secboot/efi"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	pe "github.com/snapcore/secboot/internal/pe1.14"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type runChecksContextSuite struct {
	tpm2_testutil.TPMSimulatorTest
	tpmPropertyModifierMixin
	tcglogReplayMixin
}

func (s *runChecksContextSuite) SetUpTest(c *C) {
	s.TPMSimulatorTest.SetUpTest(c)
	s.tpmPropertyModifierMixin.transport = s.Transport
	s.tcglogReplayMixin.impl = s
}

func (s *runChecksContextSuite) Tpm() *tpm2.TPMContext {
	return s.TPM
}

var _ = Suite(&runChecksContextSuite{})

type testRunChecksContextRunParams struct {
	env                  internal_efi.HostEnvironment
	tpmPropertyModifiers map[tpm2.Property]uint32
	enabledBanks         []tpm2.HashAlgorithmId
	prepare              func()

	initialFlags CheckFlags
	loadedImages []secboot_efi.Image
	profileOpts  PCRProfileOptionsFlags

	action     Action
	actionArgs []any

	expectedPcrAlg                   tpm2.HashAlgorithmId
	expectedUsedSecureBootCAs        []*X509CertificateID
	expectedFlags                    CheckResultFlags
	expectedWarningsMatch            string
	expectedIntermediateErrorMatches []string
}

func (s *runChecksContextSuite) testRun(c *C, params *testRunChecksContextRunParams) []*ErrorKindAndActions {
	_, err := params.env.TPMDevice()
	if err == nil {
		s.allocatePCRBanks(c, params.enabledBanks...)
		s.addTPMPropertyModifiers(c, params.tpmPropertyModifiers)

		log, err := params.env.ReadEventLog()
		if err == nil {
			s.resetTPMAndReplayLog(c, log, log.Algorithms...)
		}
	}

	restore := MockEfiComputePeImageDigest(func(alg crypto.Hash, r io.ReaderAt, sz int64) ([]byte, error) {
		c.Check(alg, Equals, params.expectedPcrAlg.GetHash())
		c.Assert(r, testutil.ConvertibleTo, &mockImageReader{})
		imageReader := r.(*mockImageReader)
		c.Check(sz, Equals, int64(len(imageReader.contents)))
		return imageReader.digest, nil
	})

	restore = MockRunChecksEnv(params.env)
	defer restore()

	restore = MockInternalEfiSecureBootSignaturesFromPEFile(func(pefile *pe.File, r io.ReaderAt) ([]*efi.WinCertificateAuthenticode, error) {
		c.Assert(r, testutil.ConvertibleTo, &mockImageReader{})
		imageReader := r.(*mockImageReader)
		return imageReader.signatures, nil
	})
	defer restore()

	restore = MockPeNewFile(func(r io.ReaderAt) (*pe.File, error) {
		return new(pe.File), nil
	})
	defer restore()

	if params.prepare != nil {
		params.prepare()
	}

	ctx := NewRunChecksContext(params.initialFlags, params.loadedImages, params.profileOpts)
	c.Assert(ctx, NotNil)

	result, errs := ctx.Run(context.Background(), params.action, params.actionArgs...)

	// Check errors that were captured from intermediate execution of the Run() loop.
	expectedErrsLen := len(params.expectedIntermediateErrorMatches)
	if len(errs) > 0 {
		// The final loop failed, so we're expecting an extra error.
		expectedErrsLen += 1
	}
	c.Assert(ctx.Errors(), HasLen, expectedErrsLen)

	// Test each imtermediate error.
	intermediateErrs := ctx.Errors()[:len(params.expectedIntermediateErrorMatches)]
	for i, err := range intermediateErrs {
		c.Check(err, ErrorMatches, params.expectedIntermediateErrorMatches[i])
	}

	// Make sure that LastError() is the same as the last value returned from Errors()
	if len(ctx.Errors()) > 0 {
		c.Check(ctx.LastError(), Equals, ctx.Errors()[len(ctx.Errors())-1])
	}

	if len(errs) > 0 {
		// Bail early on errors and have the caller test these.
		for i, err := range errs {
			c.Logf("errno %d: %v", i, err.Error)
		}
		return errs
	}

	// We passed without any errors, so test the result.
	c.Check(result.PCRAlg, Equals, params.expectedPcrAlg)
	c.Assert(result.UsedSecureBootCAs, HasLen, len(params.expectedUsedSecureBootCAs))
	for i, ca := range result.UsedSecureBootCAs {
		c.Check(ca, DeepEquals, params.expectedUsedSecureBootCAs[i])
	}
	c.Check(result.Flags, Equals, params.expectedFlags)
	c.Check(result.Warnings, ErrorMatches, params.expectedWarningsMatch)

	c.Check(ctx.Result(), DeepEquals, result)

	dev, err := params.env.TPMDevice()
	c.Assert(err, IsNil)
	c.Assert(dev, testutil.ConvertibleTo, &tpm2_testutil.TransportBackedDevice{})
	c.Check(dev.(*tpm2_testutil.TransportBackedDevice).NumberOpen(), Equals, 0)

	return nil
}

func (s *runChecksContextSuite) TestRunGood(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodSHA384(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)

	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "030ac3c913dab858f1d69239115545035cff671d6229f95577bb0ffbd827b35abaf6af6bfd223e04ecc9b60a9803642d"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "6c2df9007211786438be210b6908f2935d0b25ebdcd2c65621826fd2ec55fb9fbacbfe080d48db98f0ef970273b8254a")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "42f61b3089f5ce0646b422a59c9632065db2630f3e5b01690e63c41420ed31f10ff2a191f3440f9501109fc85f7fb00f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA384,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodSHA1FromInitialFlags(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1},
		initialFlags: PermitWeakPCRBanks,
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25b4e4624ea1f2144a90d7de7aff87b23de0457d"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "1dc8bcbdb8b5ee60e87281e36161ec1f923f53b7")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "fc7840d38322a595e50a6b477685fdd2244f9292")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA1,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test a good case that selects SHA1 without supplying the initial flag when we have an action to enable PermitWeakPCRBanks.

func (s *runChecksContextSuite) TestRunGoodEmptySHA384FromInitialFlags(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)

	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		initialFlags: PermitEmptyPCRBanks,
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test a good case with an empty SHA-384 bank when we have an action to turn on the PermitEmptyPCRBanks flag

func (s *runChecksContextSuite) TestRunGoodPostInstall(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     6,
			tpm2.PropertyNVCounters:        5,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		initialFlags: PostInstallChecks,
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test a good case with a VM setup when we have an action to turn on the PermitVirtualMachine flag.
//
// TODO: Test a good case with a discrete TPM where the startup locality is 0, when we have an action to turn on the PermitNoDiscreteTPMResetMitigation flag.

func (s *runChecksContextSuite) TestRunGoodDiscreteTPMDetectedSL3(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 3,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test a good case with a discrete TPM where the startup locality is 3, but not protected, when we have an action to turn on the PermitNoDiscreteTPMResetMitigation flag.

func (s *runChecksContextSuite) TestRunGoodDiscreteTPMDetectedHCRTM(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 4,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test a good case with a discrete TPM where there is a HCRTM event but startup locality is 4 is not protected, when we have an action to turn on the PermitNoDiscreteTPMResetMitigation flag.

func (s *runChecksContextSuite) TestRunGoodInvalidPCR0Value(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(0), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformFirmwareProfileSupport | NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform firmware \(PCR0\) measurements: PCR value mismatch \(actual from TPM 0xe9995745ca25279ec699688b70488116fe4d9f053cb0991dd71e82e7edfa66b5, reconstructed from log 0xa6602a7a403068b5556e78cc3f5b00c9c76d33d514093ca9b584dce7590e6c69\)
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Good test case for invalid PCR1 when we support it.

func (s *runChecksContextSuite) TestRunGoodInvalidPCR2ValueWhenOmittedFromPCRProfileOpts(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(2), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionTrustCAsForVARSuppliedDrivers,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with drivers and apps \(PCR2\) measurements: PCR value mismatch \(actual from TPM 0xfa734a6a4d262d7405d47d48c0a1b127229ca808032555ad919ed5dd7c1f6519, reconstructed from log 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969\)
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Good test case for invalid PCR3 when we support it.

func (s *runChecksContextSuite) TestRunGoodInvalidPCR4ValueWhenOmittedFromPCRProfileOpts(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(4), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionTrustCAsForBootCode,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerCodeProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with boot manager code \(PCR4\) measurements: PCR value mismatch \(actual from TPM 0x1c93930d6b26232e061eaa33ecf6341fae63ce598a0c6a26ee96a0828639c044, reconstructed from log 0x4bc74f3ffe49b4dd275c9f475887b68193e2db8348d72e1c3c9099c2dcfa85b0\)
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Good test case for invalid PCR5 when we support it.
// TODO: Good test case for invalid PCR7 when PCRProfileOptionPermitNoSecureBootPolicyProfile is supported.

func (s *runChecksContextSuite) TestRunGoodVARDriversPresentFromInitialFlags(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		initialFlags: PermitVARSuppliedDrivers,
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | VARDriversPresent,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test the above case without the initial flag when we have an action to set PermitVARSuppliedDrivers.

func (s *runChecksContextSuite) TestRunGoodSysPrepAppsPresentFromInitialFlags(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		initialFlags: PermitSysPrepApplications,
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | SysPrepApplicationsPresent,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test the above case without the initial flag when we have an action to set PermitSysPrepApplications.

func (s *runChecksContextSuite) TestRunGoodAbsoluteActiveFromInitialFlags(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		action:       ActionNone,
		initialFlags: PermitAbsoluteComputrace,
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | AbsoluteComputraceActive,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test the above case without the initial flag when we have an action to set PermitAbsoluteComputrace.

func (s *runChecksContextSuite) TestRunGoodNoBootManagerCodeProfileSupportWhenOmittedFromPCRProfileOpts(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			// We have to cheat a bit here because the digest is hardcoded in the test log. We set an invalid Authenticode digest for the mock image so the intial test
			// fails and then have the following code digest the same string that produces the log digest ("mock grub executable"), to get a digest that matches what's in
			// the log so the test thinks that the log contains the flat file digest.
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "80fd5a9364df79953369758a419f7cb167201cf580160b91f837aad455c55bcd")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "c49a23d0315fa446781686de3ee5c04288078911c89c39618c6a54d5fedddf44")},
		},
		profileOpts:               PCRProfileOptionTrustCAsForBootCode,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerCodeProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager code \(PCR4\) measurements: log contains unexpected EV_EFI_BOOT_SERVICES_APPLICATION digest for OS-present application mock image: log digest matches flat file digest \(0xd5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0\) which suggests an image loaded outside of the LoadImage API and firmware lacking support for the EFI_TCG2_PROTOCOL and/or the PE_COFF_IMAGE flag
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodPreOSVerificationUsingDigestsFromInitialFlags(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA256,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		initialFlags: PermitVARSuppliedDrivers | PermitPreOSVerificationUsingDigests,
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | VARDriversPresent | PreOSVerificationUsingDigestsDetected,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test the above case without the initial flag when we have an action to set PermitPreOSVerificationUsingDigests.

func (s *runChecksContextSuite) TestRunGoodWeakSecureBootAlgsFromInitialFlags(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA1,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		initialFlags: PermitVARSuppliedDrivers | PermitWeakSecureBootAlgorithms | PermitPreOSVerificationUsingDigests,
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | VARDriversPresent | PreOSVerificationUsingDigestsDetected | WeakSecureBootAlgorithmsDetected,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test the above case without the initial flag when we have an action to set PermitWeakSecureBootAlgorithms.
// TODO: Good test case for invalid secure boot config (eg, no DeployedMode) when PCRProfileOptionPermitNoSecureBootPolicyProfile is supported.

// **End of good cases ** //

func (s *runChecksContextSuite) TestRunBadVirtualMachine(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode("qemu", internal_efi.DetectVirtModeVM),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		action:       ActionNone,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindRunningInVM,
		ErrorArgs: []byte("[]"),
		Error:     ErrVirtualMachineDetected,
	})
}

func (s *runChecksContextSuite) TestRunBadNoTPM2Device(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		action:       ActionNone,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindNoSuitableTPM2Device,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: no TPM2 device is available`)
}

func (s *runChecksContextSuite) TestRunBadNoPCClientTPMDevice(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyPSFamilyIndicator: 2,
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		action:       ActionNone,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindNoSuitableTPM2Device,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: TPM2 device is present but it is not a PC-Client TPM`)
}

func (s *runChecksContextSuite) TestRunBadTPMDeviceFailure(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		prepare: func() {
			// The next command following this is inside openAndCheckTPM2Device
			// which runs TPM2_SelfTest(false) and will trigger the device's
			// failure mode.
			s.Mssim(c).TestFailureMode()
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		action:       ActionNone,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindTPMDeviceFailure,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionReboot, ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: TPM2 device is in failure mode`)
}

func (s *runChecksContextSuite) TestRunBadTPM2DeviceDisabled(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			// Disable owner and endorsement hierarchies
			c.Assert(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
			c.Assert(s.TPM.HierarchyControl(s.TPM.EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)

		},
		profileOpts: PCRProfileOptionsDefault,
		action:      ActionNone,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindTPMDeviceDisabled,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error, // Test the error string separately
		Actions:   []Action{ActionRebootToFWSettings},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: TPM2 device is present but is currently disabled by the platform firmware`)
}

func (s *runChecksContextSuite) TestRunBadTPMHierarchiesOwned(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
			c.Check(s.TPM.SetPrimaryPolicy(s.TPM.OwnerHandleContext(), make([]byte, 32), tpm2.HashAlgorithmSHA256, nil), IsNil)
		},
		profileOpts: PCRProfileOptionsDefault,
		action:      ActionNone,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindTPMHierarchiesOwned,
		ErrorArgs: []byte(`[{"hierarchy":1073741834,"type":"auth-value"},{"hierarchy":1073741825,"type":"auth-policy"}]`),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: one or more of the TPM hierarchies is already owned:
- TPM_RH_LOCKOUT has an authorization value
- TPM_RH_OWNER has an authorization policy
`)
}

func (s *runChecksContextSuite) TestRunBadTPMDeviceLockedOut(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 32, 7200, 86400, nil), IsNil)
			// Authorize the lockout hierarchy enough times with a bogus value to trip it
			object, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), &tpm2.SensitiveCreate{UserAuth: []byte("foo")}, objectutil.NewECCKeyTemplate(objectutil.UsageSign), nil, nil, nil)
			c.Assert(err, IsNil)

			object.SetAuthValue(nil)
			digest := testutil.DecodeHexString(c, "fbde6a7fe0a4a95d2656f206437a3db64322a74822e581cf63b69f205c63ab6f")
			scheme := &tpm2.SigScheme{
				Scheme: tpm2.SigSchemeAlgECDSA,
				Details: &tpm2.SigSchemeU{
					ECDSA: &tpm2.SigSchemeECDSA{
						HashAlg: tpm2.HashAlgorithmSHA256,
					},
				},
			}

			for i := 0; i < 32; i++ {
				_, err := s.TPM.Sign(object, digest, scheme, nil, nil)
				if tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandSign, 1) {
					continue
				}
				if tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandSign) {
					break
				}
				c.Errorf("unexpected error: %v", err)
			}
		},
		profileOpts: PCRProfileOptionsDefault,
		action:      ActionNone,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindTPMDeviceLockout,
		ErrorArgs: []byte(`["7200000000000", "230400000000000"]`),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: TPM is in DA lockout mode`)
}

func (s *runChecksContextSuite) TestRunBadTPMInsufficientCounters(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     6,
			tpm2.PropertyNVCounters:        5,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		action:       ActionNone,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindInsufficientTPMCounters,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: insufficient NV counters available`)
}

func (s *runChecksContextSuite) TestRunBadTCGLog(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		action:       ActionNone,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindTCGLog,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TCG log: nil log`)
}
func (s *runChecksContextSuite) TestRunBadInvalidPCR0Value(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 3,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(0), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindNoSuitablePCRBank,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings, ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TCG log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256\(PCR0\): PCR value mismatch \(actual from TPM 0x420bd3899738e6b41dccd18253a556e152e2b107559b89cbf0cbf1661ff6ee55, reconstructed from log 0xb0d6d5f50852be1524306ad88b928605c14338e56a1b8c0dc211a144524df2ef\).
`)
}

func (s *runChecksContextSuite) TestRunBadInvalidPCR2Value(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(2), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindNoSuitablePCRBank,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings, ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TCG log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256\(PCR2\): PCR value mismatch \(actual from TPM 0xfa734a6a4d262d7405d47d48c0a1b127229ca808032555ad919ed5dd7c1f6519, reconstructed from log 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969\).
`)
}

func (s *runChecksContextSuite) TestRunBadInvalidPCR4Value(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(4), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindNoSuitablePCRBank,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings, ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TCG log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256\(PCR4\): PCR value mismatch \(actual from TPM 0x1c93930d6b26232e061eaa33ecf6341fae63ce598a0c6a26ee96a0828639c044, reconstructed from log 0x4bc74f3ffe49b4dd275c9f475887b68193e2db8348d72e1c3c9099c2dcfa85b0\).
`)
}

func (s *runChecksContextSuite) TestRunBadInvalidPCR7Value(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindNoSuitablePCRBank,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings, ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TCG log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256\(PCR7\): PCR value mismatch \(actual from TPM 0xdf7b5d709755f1bd7142dd2f8c2d1195fc6b4dab5c78d41daf5c795da55db5f2, reconstructed from log 0xafc99bd8b298ea9b70d2796cb0ca22fe2b70d784691a1cae2aa3ba55edc365dc\).
`)
}

func (s *runChecksContextSuite) TestRunBadFirmwareProtectionError(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000255
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPlatformFirmwareInsufficientProtection,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with platform firmware protection configuration: encountered an error when determining platform firmware protections using Intel MEI: no hardware root-of-trust properly configured: ME is in manufacturing mode: no firmware protections are enabled`)
}

func (s *runChecksContextSuite) TestRunBadSHA1(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25b4e4624ea1f2144a90d7de7aff87b23de0457d"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "1dc8bcbdb8b5ee60e87281e36161ec1f923f53b7")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "fc7840d38322a595e50a6b477685fdd2244f9292")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA1,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindNoSuitablePCRBank,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings, ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TCG log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256: the PCR bank is missing from the TCG log.
`)
}

func (s *runChecksContextSuite) TestRunBadPCRProfileMostSecure(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionMostSecure,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 3)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[1,\"https://github.com/canonical/secboot/issues/322\"]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionContactOSVendor},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet`)

	c.Check(errs[1], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[3,\"https://github.com/canonical/secboot/issues/341\"]"),
		Error:     errs[1].Error,
		Actions:   []Action{ActionContactOSVendor},
	})
	c.Check(errs[1].Error, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet`)

	c.Check(errs[2], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[5,\"https://github.com/canonical/secboot/issues/323\"]"),
		Error:     errs[2].Error,
		Actions:   []Action{ActionContactOSVendor},
	})
	c.Check(errs[2].Error, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet`)
}

func (s *runChecksContextSuite) TestRunBadInvalidPCR7ValuePCRProfilePermitNoSecureBoot(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionPermitNoSecureBootPolicyProfile,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 3)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[1,\"https://github.com/canonical/secboot/issues/322\"]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionContactOSVendor},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet`)

	c.Check(errs[1], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[3,\"https://github.com/canonical/secboot/issues/341\"]"),
		Error:     errs[1].Error,
		Actions:   []Action{ActionContactOSVendor},
	})
	c.Check(errs[1].Error, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet`)

	c.Check(errs[2], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[5,\"https://github.com/canonical/secboot/issues/323\"]"),
		Error:     errs[2].Error,
		Actions:   []Action{ActionContactOSVendor},
	})
	c.Check(errs[2].Error, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet`)
}

func (s *runChecksContextSuite) TestRunBadEmptySHA384(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)

	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindEmptyPCRBanks,
		ErrorArgs: []byte("[[12]]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings, ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `the PCR bank for TPM_ALG_SHA384 is missing from the TCG log but active and with one or more empty PCRs on the TPM`)
}

func (s *runChecksContextSuite) TestRunBadVARDriversPresent(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindVARSuppliedDriversPresent,
		ErrorArgs: []byte("[]"),
		Error:     ErrVARSuppliedDriversPresent,
	})
}

func (s *runChecksContextSuite) TestRunBadSysPrepAppsPresent(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindSysPrepApplicationsPresent,
		ErrorArgs: []byte("[]"),
		Error:     ErrSysPrepApplicationsPresent,
	})
}

func (s *runChecksContextSuite) TestRunBadAbsoluteActive(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindAbsolutePresent,
		ErrorArgs: []byte("[]"),
		Error:     ErrAbsoluteComputraceActive,
		Actions:   []Action{ActionContactOEM, ActionRebootToFWSettings},
	})
}

func (s *runChecksContextSuite) TestRunBadNotAllBootManagerCodeDigestsVerified(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
		},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindInternal,
		ErrorArgs: []byte("[]"),
		Error:     ErrNotAllBootManagerCodeDigestsVerified,
	})
}

func (s *runChecksContextSuite) TestRunBadInvalidSecureBootMode(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindInvalidSecureBootMode,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with secure boot policy \(PCR7\) measurements: deployed mode should be enabled in order to generate secure boot profiles`)
}

func (s *runChecksContextSuite) TestRunBadWeakSecureBootAlgs(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA1,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:    PCRProfileOptionsDefault,
		action:         ActionNone,
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(errs, HasLen, 3)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindVARSuppliedDriversPresent,
		ErrorArgs: []byte("[]"),
		Error:     ErrVARSuppliedDriversPresent,
	})
	c.Check(errs[1], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindWeakSecureBootAlgorithmsDetected,
		ErrorArgs: []byte("[]"),
		Error:     ErrWeakSecureBootAlgorithmDetected,
	})
	c.Check(errs[2], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPreOSDigestVerificationDetected,
		ErrorArgs: []byte("[]"),
		Error:     ErrPreOSVerificationUsingDigests,
	})
}
