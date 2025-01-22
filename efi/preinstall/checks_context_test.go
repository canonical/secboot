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

type actionAndArgs struct {
	action Action
	args   []any
}

type testRunChecksContextRunParams struct {
	env                  internal_efi.HostEnvironment
	tpmPropertyModifiers map[tpm2.Property]uint32
	enabledBanks         []tpm2.HashAlgorithmId

	initialFlags CheckFlags
	loadedImages []secboot_efi.Image
	profileOpts  PCRProfileOptionsFlags

	iterations int
	prepare    func(int)
	actions    []actionAndArgs

	expectedPcrAlg                   tpm2.HashAlgorithmId
	expectedUsedSecureBootCAs        []*X509CertificateID
	expectedFlags                    CheckResultFlags
	expectedWarningsMatch            string
	expectedIntermediateErrorMatches []string
}

func (s *runChecksContextSuite) testRun(c *C, params *testRunChecksContextRunParams) (errs []*ErrorKindAndActions) {
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
	defer restore()

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

	ctx := NewRunChecksContext(params.initialFlags, params.loadedImages, params.profileOpts)
	c.Assert(ctx, NotNil)

	iterations := params.iterations
	if iterations == 0 {
		iterations = 1
	}
	c.Assert(params.actions, HasLen, iterations)

	var result *CheckResult
	for i := 0; i < iterations; i++ {
		if params.prepare != nil {
			params.prepare(i)
		}
		result, errs = ctx.Run(context.Background(), params.actions[i].action, params.actions[i].args...)
	}

	// Make sure we don't leave any open TPM connections
	dev, err := params.env.TPMDevice()
	if err == nil {
		c.Assert(dev, testutil.ConvertibleTo, &tpm2_testutil.TransportBackedDevice{})
		c.Check(dev.(*tpm2_testutil.TransportBackedDevice).NumberOpen(), Equals, 0)
	}

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

	return nil
}

func (s *runChecksContextSuite) TestRunGood(c *C) {
	// Good test on a fTPM with a single run
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Good test on a fTPM with a single run and SHA384 selected as the PCR bank
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Good test on a fTPM with a single run and SHA1 as the selected algorithm,
	// permitted by passing the PermitWeakPCRBanks flag as an initial flag.
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Good test case on a fTPM despite an empty PCR bank, permitted by using
	// PermitEmptyPCRBanks as an initial flag.
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test good post-install scenario on a fTPM, which skips some tests related to
	// TPM ownership, lockout status and checking the number of available
	// NV counters.
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test a good case on a dTPM where the startup locality is 3 and
	// access to locality 3 is restricted to ring 0 code.
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test a good case on a dTPM where there is a H-CRTM event and
	// access to locality 4 is restricted to ring 0 code.
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test a good case where the value of PCR0 is inconsistenw with the log,
	// but in a configuration where PCR0 isn't required because the system is
	// configured with verified boot and there is a fTPM.
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
		profileOpts: PCRProfileOptionsDefault,
		prepare: func(_ int) {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(0), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test a good case on a fTPM where the value of PCR2 is inconsistent
	// with the log, but PCR2 isn't required for the specified profile options.
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
		profileOpts: PCRProfileOptionTrustCAsForVARSuppliedDrivers,
		prepare: func(_ int) {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(2), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test a good case on a fTPM where the value of PCR4 is inconsistent
	// with the log, but PCR4 isn't required for the specified profile options.
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
		profileOpts: PCRProfileOptionTrustCAsForBootCode,
		prepare: func(_ int) {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(4), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test good case on a fTPM where there are value-added-retailer drivers
	// detected, and these are permitted with the PermitVARSuppliedDrivers
	// initial flag.
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test good case on a fTPM where there are system preparation applications
	// detected, and these are permitted with the PermitSysPrepApplications
	// initial flag.
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test good case on a fTPM where Absolute is detected, and this is
	// permitted with the PermitAbsoluteComputrace initial flag.
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
		actions:      []actionAndArgs{{action: ActionNone}},
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
	// Test a good case on a fTPM where the launch digests in the log for OS components
	// are invalid, but the profile options permits the omission of PCR4.
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test a good case where there are value-added-retailer drivers being loaded,
	// authenticated by way of a digest in db, permitted by supplying PermitPreOSVerificationUsingDigests
	// as one of the initial flags.
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test a good case on a fTPM where there are weak secure boot algorithms
	// detected, but this is permitted because PermitWeakSecureBootAlgorithms
	// was supplied as an initial flag.
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
		actions:                   []actionAndArgs{{action: ActionNone}},
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
	// Test the error case where a virtualized environment
	// is detected.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode("qemu", internal_efi.DetectVirtModeVM),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindRunningInVM,
		ErrorArgs: []byte("[]"),
		Error:     ErrVirtualMachineDetected,
	})
	c.Check(errs[0].String(), Equals, `{"kind":"running-in-vm","args":[],"actions":null} (original error: "virtual machine environment detected")`)
}

func (s *runChecksContextSuite) TestRunBadNoTPM2Device(c *C) {
	// Test the error case where no valid TPM2 device is detected.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindNoSuitableTPM2Device,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: no TPM2 device is available`)
	c.Check(errs[0].String(), Equals, `{"kind":"no-suitable-tpm2-device","args":[],"actions":null} (original error: "error with TPM2 device: no TPM2 device is available")`)
}

func (s *runChecksContextSuite) TestRunBadTPMDeviceFailure(c *C) {
	// Test the error case where the TPM device is in failure mode.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		prepare: func(_ int) {
			// The next command following this is inside openAndCheckTPM2Device
			// which runs TPM2_SelfTest(false) and will trigger the device's
			// failure mode.
			s.Mssim(c).TestFailureMode()
		},
		actions: []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindTPMDeviceFailure,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionReboot, ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: TPM2 device is in failure mode`)
	c.Check(errs[0].String(), Equals, `{"kind":"tpm-device-failure","args":[],"actions":["reboot","contact-oem"]} (original error: "error with TPM2 device: TPM2 device is in failure mode")`)
}

func (s *runChecksContextSuite) TestRunBadNoPCClientTPMDevice(c *C) {
	// Test the error case where there is a TPM2 device, but it isn't
	// a PC Client device.
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
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindNoSuitableTPM2Device,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: TPM2 device is present but it is not a PC-Client TPM`)
	c.Check(errs[0].String(), Equals, `{"kind":"no-suitable-tpm2-device","args":[],"actions":null} (original error: "error with TPM2 device: TPM2 device is present but it is not a PC-Client TPM")`)
}

func (s *runChecksContextSuite) TestRunBadTPM2DeviceDisabled(c *C) {
	// Test the error case where the TPM has been disabled by firmware.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		prepare: func(_ int) {
			// Disable owner and endorsement hierarchies
			c.Assert(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
			c.Assert(s.TPM.HierarchyControl(s.TPM.EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)

		},
		actions: []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindTPMDeviceDisabled,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error, // Test the error string separately
		Actions:   []Action{ActionRebootToFWSettings},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: TPM2 device is present but is currently disabled by the platform firmware`)
	c.Check(errs[0].String(), Equals, `{"kind":"tpm-device-disabled","args":[],"actions":["reboot-to-fw-settings"]} (original error: "error with TPM2 device: TPM2 device is present but is currently disabled by the platform firmware")`)
}

func (s *runChecksContextSuite) TestRunBadTPMHierarchiesOwned(c *C) {
	// Test the error case where one or more hierarchies of the TPM are already owned.
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
		prepare: func(_ int) {
			s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
			c.Check(s.TPM.SetPrimaryPolicy(s.TPM.OwnerHandleContext(), make([]byte, 32), tpm2.HashAlgorithmSHA256, nil), IsNil)
		},
		actions: []actionAndArgs{{action: ActionNone}},
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
	c.Check(errs[0].String(), Equals, `{"kind":"tpm-hierarchies-owned","args":[{"hierarchy":1073741834,"type":"auth-value"},{"hierarchy":1073741825,"type":"auth-policy"}],"actions":["reboot-to-fw-settings"]} (original error: "error with TPM2 device: one or more of the TPM hierarchies is already owned:\n- TPM_RH_LOCKOUT has an authorization value\n- TPM_RH_OWNER has an authorization policy\n")`)
}

func (s *runChecksContextSuite) TestRunBadTPMDeviceLockedOut(c *C) {
	// Test the error case where the TPM's DA protection has been tripped.
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
		prepare: func(_ int) {
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
		actions: []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindTPMDeviceLockout,
		ErrorArgs: []byte(`[7200000000000,230400000000000]`),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: TPM is in DA lockout mode`)
	c.Check(errs[0].String(), Equals, `{"kind":"tpm-device-lockout","args":[7200000000000,230400000000000],"actions":["reboot-to-fw-settings"]} (original error: "error with TPM2 device: TPM is in DA lockout mode")`)
}

func (s *runChecksContextSuite) TestRunBadTPMInsufficientCounters(c *C) {
	// Test the error case where there appears to be too few NV counters.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     6,
			tpm2.PropertyNVCounters:        5,
			tpm2.PropertyPSFamilyIndicator: 1,
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindInsufficientTPMCounters,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionRebootToFWSettings},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TPM2 device: insufficient NV counters available`)
	c.Check(errs[0].String(), Equals, `{"kind":"insufficient-tpm-counters","args":[],"actions":["reboot-to-fw-settings"]} (original error: "error with TPM2 device: insufficient NV counters available")`)
}

func (s *runChecksContextSuite) TestRunBadTCGLog(c *C) {
	// Test the error case where the TCG log cannot be decoded.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindTCGLog,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with TCG log: nil log`)
	c.Check(errs[0].String(), Equals, `{"kind":"tcg-log","args":[],"actions":["contact-oem"]} (original error: "error with TCG log: nil log")`)
}

func (s *runChecksContextSuite) TestRunBadInvalidPCR0Value(c *C) {
	// Test the error case where PCR0 is inconsistent for the log, but it
	// gets marked as mandatory because we have a dTPM.
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
		profileOpts: PCRProfileOptionsDefault,
		prepare: func(_ int) {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(0), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		actions:        []actionAndArgs{{action: ActionNone}},
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
	c.Check(errs[0].String(), Equals, `{"kind":"no-suitable-pcr-bank","args":[],"actions":["reboot-to-fw-settings","contact-oem"]} (original error: "error with TCG log: no suitable PCR algorithm available:\n- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.\n- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.\n- TPM_ALG_SHA256(PCR0): PCR value mismatch (actual from TPM 0x420bd3899738e6b41dccd18253a556e152e2b107559b89cbf0cbf1661ff6ee55, reconstructed from log 0xb0d6d5f50852be1524306ad88b928605c14338e56a1b8c0dc211a144524df2ef).\n")`)
}

func (s *runChecksContextSuite) TestRunBadInvalidPCR2Value(c *C) {
	// Test the error case where PCR2 is inconsistent with the log, but it
	// has been marked as mandatory due to the usage of the Microsoft UEFI CA.
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
		profileOpts: PCRProfileOptionsDefault,
		prepare: func(_ int) {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(2), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		actions:        []actionAndArgs{{action: ActionNone}},
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
	c.Check(errs[0].String(), Equals, `{"kind":"no-suitable-pcr-bank","args":[],"actions":["reboot-to-fw-settings","contact-oem"]} (original error: "error with TCG log: no suitable PCR algorithm available:\n- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.\n- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.\n- TPM_ALG_SHA256(PCR2): PCR value mismatch (actual from TPM 0xfa734a6a4d262d7405d47d48c0a1b127229ca808032555ad919ed5dd7c1f6519, reconstructed from log 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969).\n")`)
}

func (s *runChecksContextSuite) TestRunBadInvalidPCR4Value(c *C) {
	// Test the error case where PCR4 is inconsistent with the log, but it
	// has been marked as mandatory due to the usage of the Microsoft UEFI CA.
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
		profileOpts: PCRProfileOptionsDefault,
		prepare: func(_ int) {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(4), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		actions:        []actionAndArgs{{action: ActionNone}},
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
	c.Check(errs[0].String(), Equals, `{"kind":"no-suitable-pcr-bank","args":[],"actions":["reboot-to-fw-settings","contact-oem"]} (original error: "error with TCG log: no suitable PCR algorithm available:\n- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.\n- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.\n- TPM_ALG_SHA256(PCR4): PCR value mismatch (actual from TPM 0x1c93930d6b26232e061eaa33ecf6341fae63ce598a0c6a26ee96a0828639c044, reconstructed from log 0x4bc74f3ffe49b4dd275c9f475887b68193e2db8348d72e1c3c9099c2dcfa85b0).\n")`)
}

func (s *runChecksContextSuite) TestRunBadInvalidPCR7Value(c *C) {
	// Test the error case where PCR7 is inconsistent with the log, but it
	// has been marked as mandatory because the default profile options
	// require it.
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
		profileOpts: PCRProfileOptionsDefault,
		prepare: func(_ int) {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		actions:        []actionAndArgs{{action: ActionNone}},
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
	c.Check(errs[0].String(), Equals, `{"kind":"no-suitable-pcr-bank","args":[],"actions":["reboot-to-fw-settings","contact-oem"]} (original error: "error with TCG log: no suitable PCR algorithm available:\n- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.\n- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.\n- TPM_ALG_SHA256(PCR7): PCR value mismatch (actual from TPM 0xdf7b5d709755f1bd7142dd2f8c2d1195fc6b4dab5c78d41daf5c795da55db5f2, reconstructed from log 0xafc99bd8b298ea9b70d2796cb0ca22fe2b70d784691a1cae2aa3ba55edc365dc).\n")`)
}

func (s *runChecksContextSuite) TestRunBadFirmwareProtectionError(c *C) {
	// Test the error case where we're running on an Intel based device
	// and BootGuard is mis-configured.
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
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPlatformFirmwareInsufficientProtection,
		ErrorArgs: []byte("[]"),
		Error:     errs[0].Error,
		Actions:   []Action{ActionContactOEM},
	})
	c.Check(errs[0].Error, ErrorMatches, `error with platform firmware protection configuration: encountered an error when determining platform firmware protections using Intel MEI: no hardware root-of-trust properly configured: ME is in manufacturing mode: no firmware protections are enabled`)
	c.Check(errs[0].String(), Equals, `{"kind":"platform-firmware-insufficient-protection","args":[],"actions":["contact-oem"]} (original error: "error with platform firmware protection configuration: encountered an error when determining platform firmware protections using Intel MEI: no hardware root-of-trust properly configured: ME is in manufacturing mode: no firmware protections are enabled")`)
}

func (s *runChecksContextSuite) TestRunBadSHA1(c *C) {
	// Test the error case where there is no suitable PCR bank other
	// than SHA1, but SHA1 is disallowed by default.
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
		actions:        []actionAndArgs{{action: ActionNone}},
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
	c.Check(errs[0].String(), Equals, `{"kind":"no-suitable-pcr-bank","args":[],"actions":["reboot-to-fw-settings","contact-oem"]} (original error: "error with TCG log: no suitable PCR algorithm available:\n- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.\n- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.\n- TPM_ALG_SHA256: the PCR bank is missing from the TCG log.\n")`)
}

func (s *runChecksContextSuite) TestRunBadPCRProfileMostSecure(c *C) {
	// Test the error case where the profile options are set to "most secure".
	// This is currently unsupported because of a lack of source for some
	// PCRs - it is intended that this will work eventually.
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
		actions:        []actionAndArgs{{action: ActionNone}},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 3)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[1,\"https://github.com/canonical/secboot/issues/322\"]"),
		Error:     errs[0].Error,
	})
	c.Check(errs[0].Error, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet`)
	c.Check(errs[0].String(), Equals, `{"kind":"tpm-pcr-unsupported","args":[1,"https://github.com/canonical/secboot/issues/322"],"actions":null} (original error: "error with platform config (PCR1) measurements: generating profiles for PCR 1 is not supported yet")`)

	c.Check(errs[1], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[3,\"https://github.com/canonical/secboot/issues/341\"]"),
		Error:     errs[1].Error,
	})
	c.Check(errs[1].Error, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet`)
	c.Check(errs[1].String(), Equals, `{"kind":"tpm-pcr-unsupported","args":[3,"https://github.com/canonical/secboot/issues/341"],"actions":null} (original error: "error with drivers and apps config (PCR3) measurements: generating profiles for PCR 3 is not supported yet")`)

	c.Check(errs[2], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[5,\"https://github.com/canonical/secboot/issues/323\"]"),
		Error:     errs[2].Error,
	})
	c.Check(errs[2].Error, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet`)
	c.Check(errs[2].String(), Equals, `{"kind":"tpm-pcr-unsupported","args":[5,"https://github.com/canonical/secboot/issues/323"],"actions":null} (original error: "error with boot manager config (PCR5) measurements: generating profiles for PCR 5 is not supported yet")`)
}

func (s *runChecksContextSuite) TestRunBadInvalidPCR7ValuePCRProfilePermitNoSecureBoot(c *C) {
	// Test the error case where PCR7 is unusable and the profile options are set
	// to permit policies without PCR7, but this fails due to a lack of support
	// for some mandatory alternative PCRs - it is intended that this case will
	// work in the future.
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
		profileOpts: PCRProfileOptionPermitNoSecureBootPolicyProfile,
		prepare: func(_ int) {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		actions:        []actionAndArgs{{action: ActionNone}},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 3)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[1,\"https://github.com/canonical/secboot/issues/322\"]"),
		Error:     errs[0].Error,
	})
	c.Check(errs[0].Error, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet`)
	c.Check(errs[0].String(), Equals, `{"kind":"tpm-pcr-unsupported","args":[1,"https://github.com/canonical/secboot/issues/322"],"actions":null} (original error: "error with platform config (PCR1) measurements: generating profiles for PCR 1 is not supported yet")`)

	c.Check(errs[1], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[3,\"https://github.com/canonical/secboot/issues/341\"]"),
		Error:     errs[1].Error,
	})
	c.Check(errs[1].Error, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet`)
	c.Check(errs[1].String(), Equals, `{"kind":"tpm-pcr-unsupported","args":[3,"https://github.com/canonical/secboot/issues/341"],"actions":null} (original error: "error with drivers and apps config (PCR3) measurements: generating profiles for PCR 3 is not supported yet")`)

	c.Check(errs[2], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPCRUnsupported,
		ErrorArgs: []byte("[5,\"https://github.com/canonical/secboot/issues/323\"]"),
		Error:     errs[2].Error,
	})
	c.Check(errs[2].Error, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet`)
	c.Check(errs[2].String(), Equals, `{"kind":"tpm-pcr-unsupported","args":[5,"https://github.com/canonical/secboot/issues/323"],"actions":null} (original error: "error with boot manager config (PCR5) measurements: generating profiles for PCR 5 is not supported yet")`)
}

func (s *runChecksContextSuite) TestRunBadEmptySHA384(c *C) {
	// Test the error case where the TPM has a SHA384 bank enabled but
	// unused by the firmware.
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
		actions:        []actionAndArgs{{action: ActionNone}},
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
	c.Check(errs[0].String(), Equals, `{"kind":"empty-pcr-banks","args":[[12]],"actions":["reboot-to-fw-settings","contact-oem"]} (original error: "the PCR bank for TPM_ALG_SHA384 is missing from the TCG log but active and with one or more empty PCRs on the TPM")`)
}

func (s *runChecksContextSuite) TestRunBadVARDriversPresent(c *C) {
	// Test the error case where value-added-retailer drivers have been detected
	// but the initial flags do not permit these.
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
		actions:        []actionAndArgs{{action: ActionNone}},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindVARSuppliedDriversPresent,
		ErrorArgs: []byte("[]"),
		Error:     ErrVARSuppliedDriversPresent,
	})
	c.Check(errs[0].String(), Equals, `{"kind":"var-supplied-drivers-present","args":[],"actions":null} (original error: "value added retailer supplied drivers were detected to be running")`)
}

func (s *runChecksContextSuite) TestRunBadSysPrepAppsPresent(c *C) {
	// Test the error case where system preparations have been detected
	// but the initial flags do not permit these.
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
		actions:        []actionAndArgs{{action: ActionNone}},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindSysPrepApplicationsPresent,
		ErrorArgs: []byte("[]"),
		Error:     ErrSysPrepApplicationsPresent,
	})
	c.Check(errs[0].String(), Equals, `{"kind":"sys-prep-applications-present","args":[],"actions":null} (original error: "system preparation applications were detected to be running")`)
}

func (s *runChecksContextSuite) TestRunBadAbsoluteActive(c *C) {
	// Test the error case where Absolute has been detected but the initial
	// flags do not permit this.
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
		actions:        []actionAndArgs{{action: ActionNone}},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindAbsolutePresent,
		ErrorArgs: []byte("[]"),
		Error:     ErrAbsoluteComputraceActive,
		Actions:   []Action{ActionContactOEM, ActionRebootToFWSettings},
	})
	c.Check(errs[0].String(), Equals, `{"kind":"absolute-present","args":[],"actions":["contact-oem","reboot-to-fw-settings"]} (original error: "Absolute was detected to be active and it is advised that this is disabled")`)
}

func (s *runChecksContextSuite) TestRunBadNotAllBootManagerCodeDigestsVerified(c *C) {
	// Test the error case where PCR4 is mandatory because some of the components
	// that were booted are signed under the Microsoft UEFI CA and the default
	// profile options were supplied, but where PCR4 is marked unusable because
	// not all of the EFI applications that were part of the current boot were
	// supplied when creating the RunChecksContext.
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
		profileOpts:    PCRProfileOptionsDefault,
		actions:        []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindInternal, // This is "internal" because the error is caused by the user of this API
		ErrorArgs: []byte("[]"),
		Error:     ErrNotAllBootManagerCodeDigestsVerified,
	})
	c.Check(errs[0].String(), Equals, `{"kind":"internal-error","args":[],"actions":null} (original error: "not all EV_EFI_BOOT_SERVICES_APPLICATION boot manager launch digests could be verified")`)
}

func (s *runChecksContextSuite) TestRunBadInvalidSecureBootMode(c *C) {
	// Test the error case where PCR7 is mandatory with the supplied profile options,
	// but is marked invalid because the system is not in deployed. Note that is is
	// my intention to support user mode in the future.
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
		actions:        []actionAndArgs{{action: ActionNone}},
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
	c.Check(errs[0].String(), Equals, `{"kind":"invalid-secure-boot-mode","args":[],"actions":["reboot-to-fw-settings"]} (original error: "error with secure boot policy (PCR7) measurements: deployed mode should be enabled in order to generate secure boot profiles")`)
}

func (s *runChecksContextSuite) TestRunBadWeakSecureBootAlgs(c *C) {
	// Test the error case where PCR7 is mandatory with the supplied profile options,
	// but is marked invalid because the use of weak algorithms were detected during
	// the current boot.
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
		actions:        []actionAndArgs{{action: ActionNone}},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(errs, HasLen, 3)
	c.Check(errs[0], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindVARSuppliedDriversPresent,
		ErrorArgs: []byte("[]"),
		Error:     ErrVARSuppliedDriversPresent,
	})
	c.Check(errs[0].String(), Equals, `{"kind":"var-supplied-drivers-present","args":[],"actions":null} (original error: "value added retailer supplied drivers were detected to be running")`)

	c.Check(errs[1], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindWeakSecureBootAlgorithmsDetected,
		ErrorArgs: []byte("[]"),
		Error:     ErrWeakSecureBootAlgorithmDetected,
	})
	c.Check(errs[1].String(), Equals, `{"kind":"weak-secure-boot-algorithms-detected","args":[],"actions":null} (original error: "a weak cryptographic algorithm was detected during secure boot verification")`)

	c.Check(errs[2], DeepEquals, &ErrorKindAndActions{
		ErrorKind: ErrorKindPreOSDigestVerificationDetected,
		ErrorArgs: []byte("[]"),
		Error:     ErrPreOSVerificationUsingDigests,
	})
	c.Check(errs[2].String(), Equals, `{"kind":"pre-os-digest-verification-detected","args":[],"actions":null} (original error: "some pre-OS components were authenticated from the authorized signature database using an Authenticode digest")`)
}
