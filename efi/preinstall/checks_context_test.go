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
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/canonical/cpuid"
	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/ppi"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/tcglog-parser"
	secboot_efi "github.com/snapcore/secboot/efi"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	pe "github.com/snapcore/secboot/internal/pe1.14"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2_device"
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
	args   any
}

type testRunChecksContextRunParams struct {
	env                  internal_efi.HostEnvironment
	tpmPropertyModifiers map[tpm2.Property]uint32
	enabledBanks         []tpm2.HashAlgorithmId

	initialFlags CheckFlags
	loadedImages []secboot_efi.Image
	profileOpts  PCRProfileOptionsFlags

	iterations            int
	prepare               func(int)
	actions               []actionAndArgs
	checkIntermediateErrs func(int, []*WithKindAndActionsError)

	expectedPcrAlg            tpm2.HashAlgorithmId
	expectedUsedSecureBootCAs []*X509CertificateID
	expectedFlags             CheckResultFlags
	expectedWarningsMatch     string
}

func (s *runChecksContextSuite) testRun(c *C, params *testRunChecksContextRunParams) (errs []*WithKindAndActionsError) {
	dev, err := params.env.TPMDevice()
	if err == nil {
		s.allocatePCRBanks(c, params.enabledBanks...)
		s.addTPMPropertyModifiers(c, params.tpmPropertyModifiers)

		s.ForgetCommands()

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

		errs = nil

		var args map[string]json.RawMessage
		if params.actions[i].args != nil {
			jsonArgs, err := json.Marshal(params.actions[i].args)
			c.Assert(err, IsNil)
			c.Assert(json.Unmarshal(jsonArgs, &args), IsNil)
		}

		var err error
		result, err = ctx.Run(context.Background(), params.actions[i].action, args)
		if err == nil {
			c.Check(i, Equals, iterations-1)
			break
		}

		for _, e := range UnwrapCompoundError(err) {
			c.Assert(e, testutil.ConvertibleTo, &WithKindAndActionsError{})
			errs = append(errs, e.(*WithKindAndActionsError))
		}

		if i < (iterations-1) && params.checkIntermediateErrs != nil {
			params.checkIntermediateErrs(i, errs)
		}
	}

	// Make sure we don't leave any open TPM connections
	dev, err = params.env.TPMDevice()
	if err == nil {
		c.Assert(dev, testutil.ConvertibleTo, &tpmDevice{})
		c.Assert(dev.(*tpmDevice).TPMDevice, testutil.ConvertibleTo, &tpm2_testutil.TransportBackedDevice{})
		c.Check(dev.(*tpmDevice).TPMDevice.(*tpm2_testutil.TransportBackedDevice).NumberOpen(), Equals, 0)
	}

	// Check errors that were captured from intermediate execution of the Run() loop.
	expectedErrsLen := iterations - 1
	if len(errs) > 0 {
		// The final loop failed, so we're expecting an extra error.
		expectedErrsLen += 1
	}
	c.Assert(ctx.Errors(), HasLen, expectedErrsLen)

	// Make sure that LastError() is the same as the last value returned from Errors(),
	// only if the last execution of the Run() loop failed else LastError() will
	// return nil
	if len(errs) > 0 && len(ctx.Errors()) > 0 {
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
	c.Check(ctx.ProfileOpts(), DeepEquals, params.profileOpts)

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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedWarningsMatch: `3 errors detected:
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedWarningsMatch: `3 errors detected:
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedWarningsMatch: `3 errors detected:
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodActionProceedPermitEmptyPCRBanks(c *C) {
	// Test that ActionProceed turns on PermitEmptyPCRBanks.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsErrorForTest(
					ErrorKindEmptyPCRBanks,
					map[string]json.RawMessage{"algs": []byte("[12]")},
					[]Action{ActionProceed, ActionContactOEM},
					&EmptyPCRBanksError{Algs: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA384}},
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodPermitInsufficientDMAProtectionFromInitialFlags(c *C) {
	// Test case where there is an empty PCR bank, but it is permitted by
	// supplying PermitInsufficientDMAProtection as an initial flag.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				DMAProtection: efitest.DMAProtectionDisabled,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		initialFlags: PermitInsufficientDMAProtection,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | InsufficientDMAProtectionDetected,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodActionProceedPermitInsufficientDMAProtection(c *C) {
	// Test that ActionProceed enables PermitInsufficientDMAProtection.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				DMAProtection: efitest.DMAProtectionDisabled,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindInsufficientDMAProtection,
					nil,
					[]Action{ActionRebootToFWSettings, ActionProceed, ActionContactOEM},
					errs[0].Unwrap(),
				))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed},
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | InsufficientDMAProtectionDetected,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 0)
}

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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodPreAndPostInstall(c *C) {
	// Test good pre-install and post-install scenario on a fTPM.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
			tpm2.PropertyNVCounters:        4,
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
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)

	errs = s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
			tpm2.PropertyPermanent:         uint32(tpm2.AttrLockoutAuthSet),
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
		expectedWarningsMatch: `4 errors detected:
- availability of TPM's lockout hierarchy was not checked because the lockout hierarchy has an authorization value set
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodPermitVirtualMachineFromInitialFlags(c *C) {
	// Test on a virtual machine, wehere PermitVirtualMachine is supplied via
	// the initial flags to permit it.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode("qemu", internal_efi.DetectVirtModeVM),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{}),
			efitest.WithSysfsDevices(devices...),
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
		initialFlags: PermitVirtualMachine,
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
		expectedWarningsMatch: `4 errors detected:
- virtual machine environment detected
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodActionProceedPermitVirtualMachine(c *C) {
	// Test that ActionProceed turns on PermitVirtualMachine.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode("qemu", internal_efi.DetectVirtModeVM),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindRunningInVM,
					nil,
					[]Action{ActionProceed},
					ErrVirtualMachineDetected,
				))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed},
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `4 errors detected:
- virtual machine environment detected
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 3,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | RequestPartialDiscreteTPMResetAttackMitigation,
		expectedWarningsMatch: `3 errors detected:
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 4,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | RequestPartialDiscreteTPMResetAttackMitigation,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test a good case with a discrete TPM where there is a HCRTM event but startup locality is 4 is not protected, when we have an action to turn on the PermitNoDiscreteTPMResetMitigation flag.

func (s *runChecksContextSuite) TestRunGoodInvalidPCR0Value(c *C) {
	// Test a good case where the value of PCR0 is inconsistent with the log,
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedWarningsMatch: `4 errors detected:
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		profileOpts: PCRProfileOptionTrustCAsForAddonDrivers,
		prepare: func(_ int) {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(2), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		actions:                   []actionAndArgs{{action: ActionNone}},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `4 errors detected:
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedWarningsMatch: `4 errors detected:
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

func (s *runChecksContextSuite) TestRunGoodAddonDriversPresentFromInitialFlags(c *C) {
	// Test good case on a fTPM where there are value-added-retailer drivers
	// detected, and these are permitted with the PermitAddonDrivers
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		initialFlags: PermitAddonDrivers,
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
		expectedWarningsMatch: `4 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- addon drivers were detected:
  - \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test the above case without the initial flag when we have an action to set PermitAddonDrivers.

func (s *runChecksContextSuite) TestRunGoodActionProceedPermitAddonDrivers(c *C) {
	// Test that ActionProceed turns on PermitAddonDrivers.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				imageInfo := []*LoadedImageInfo{
					{
						Format: LoadedImageFormatPE,
						DevicePath: efi.DevicePath{
							&efi.ACPIDevicePathNode{
								HID: 0x0a0341d0,
								UID: 0x0,
							},
							&efi.PCIDevicePathNode{
								Function: 0x1c,
								Device:   0x2,
							},
							&efi.PCIDevicePathNode{
								Function: 0x0,
								Device:   0x0,
							},
							&efi.MediaRelOffsetRangeDevicePathNode{
								StartingOffset: 0x38,
								EndingOffset:   0x11dff,
							},
						},
						DigestAlg: tpm2.HashAlgorithmSHA256,
						Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
					},
				}

				c.Check(errs[0], ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindAddonDriversPresent,
					LoadedImagesInfoArg(imageInfo),
					[]Action{ActionProceed},
					&AddonDriversPresentError{
						Drivers: imageInfo,
					},
				))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed},
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `4 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- addon drivers were detected:
  - \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				{Name: "SysPrepOrder", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1, 0x0}},
				{Name: "SysPrep0001", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: efitest.MakeVarPayload(c, &efi.LoadOption{
					Attributes:  efi.LoadOptionActive | efi.LoadOptionCategoryApp,
					Description: "Mock sysprep app",
					FilePath: efi.DevicePath{
						&efi.HardDriveDevicePathNode{
							PartitionNumber: 1,
							PartitionStart:  0x800,
							PartitionSize:   0x100000,
							Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
							MBRType:         efi.GPT},
						efi.FilePathDevicePathNode("\\EFI\\Dell\\sysprep.efi"),
					},
				})},
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `4 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- system preparation applications were detected:
  - Mock sysprep app path=\\PciRoot\(0x0\)\\Pci\(0x1d,0x0\)\\Pci\(0x0,0x0\)\\NVMe\(0x1,00-00-00-00-00-00-00-00\)\\HD\(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960\)\\\\EFI\\Dell\\sysprep.efi authenticode-digest=TPM_ALG_SHA256:11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4 load-option=SysPrep0001
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodActionProceedPermitSysPrepApplications(c *C) {
	// Test that ActionProceed enables PermitSysPrepApplications.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				{Name: "SysPrepOrder", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1, 0x0}},
				{Name: "SysPrep0001", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: efitest.MakeVarPayload(c, &efi.LoadOption{
					Attributes:  efi.LoadOptionActive | efi.LoadOptionCategoryApp,
					Description: "Mock sysprep app",
					FilePath: efi.DevicePath{
						&efi.HardDriveDevicePathNode{
							PartitionNumber: 1,
							PartitionStart:  0x800,
							PartitionSize:   0x100000,
							Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
							MBRType:         efi.GPT},
						efi.FilePathDevicePathNode("\\EFI\\Dell\\sysprep.efi"),
					},
				})},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		iterations:   2,
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
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)

				c.Check(errs[0], ErrorMatches, `system preparation applications were detected:
- Mock sysprep app path=\\PciRoot\(0x0\)\\Pci\(0x1d,0x0\)\\Pci\(0x0,0x0\)\\NVMe\(0x1,00-00-00-00-00-00-00-00\)\\HD\(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960\)\\\\EFI\\Dell\\sysprep.efi authenticode-digest=TPM_ALG_SHA256:11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4 load-option=SysPrep0001
`)
				imageInfo := []*LoadedImageInfo{
					{
						Format:         LoadedImageFormatPE,
						Description:    "Mock sysprep app",
						LoadOptionName: "SysPrep0001",
						DevicePath: efi.DevicePath{
							&efi.ACPIDevicePathNode{
								HID: 0x0a0341d0,
								UID: 0x0},
							&efi.PCIDevicePathNode{
								Function: 0x0,
								Device:   0x1d},
							&efi.PCIDevicePathNode{
								Function: 0x0,
								Device:   0x0},
							&efi.NVMENamespaceDevicePathNode{
								NamespaceID:   0x1,
								NamespaceUUID: efi.EUI64{}},
							&efi.HardDriveDevicePathNode{
								PartitionNumber: 1,
								PartitionStart:  0x800,
								PartitionSize:   0x100000,
								Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
								MBRType:         efi.GPT},
							efi.FilePathDevicePathNode("\\EFI\\Dell\\sysprep.efi"),
						},
						DigestAlg: tpm2.HashAlgorithmSHA256,
						Digest:    testutil.DecodeHexString(c, "11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4"),
					},
				}

				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindSysPrepApplicationsPresent,
					LoadedImagesInfoArg(imageInfo),
					[]Action{ActionProceed},
					&SysPrepApplicationsPresentError{
						Apps: imageInfo,
					},
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `4 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- system preparation applications were detected:
  - Mock sysprep app path=\\PciRoot\(0x0\)\\Pci\(0x1d,0x0\)\\Pci\(0x0,0x0\)\\NVMe\(0x1,00-00-00-00-00-00-00-00\)\\HD\(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960\)\\\\EFI\\Dell\\sysprep.efi authenticode-digest=TPM_ALG_SHA256:11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4 load-option=SysPrep0001
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 0)
}

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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `4 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- Absolute was detected to be active and it is advised that this is disabled
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodActionProceedPermitAbsolute(c *C) {
	// Test that ActionProceed enables PermitAbsoluteComputrace.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
		profileOpts:  PCRProfileOptionsDefault,
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Check(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindAbsolutePresent,
					nil,
					[]Action{ActionRebootToFWSettings, ActionProceed, ActionContactOEM},
					ErrAbsoluteComputraceActive,
				))
			}
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
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `4 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- Absolute was detected to be active and it is advised that this is disabled
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedWarningsMatch: `4 errors detected:
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA256,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		initialFlags: PermitAddonDrivers | PermitPreOSVerificationUsingDigests,
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
		expectedWarningsMatch: `5 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- addon drivers were detected:
  - \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
- some pre-OS components were authenticated from the authorized signature database using an Authenticode digest
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodActionProceedPermitPreOSVerificationUsingDigests(c *C) {
	// Test that ActionProceed enables the PermitPreOSVerificationUsingDigests flag. As
	// this test generates 2 errors, it also tests the case where ActionProceed can
	// be used to ignore multiple errors.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA256,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Check(errs, HasLen, 2)

				imageInfo := []*LoadedImageInfo{
					{
						Format: LoadedImageFormatPE,
						DevicePath: efi.DevicePath{
							&efi.ACPIDevicePathNode{
								HID: 0x0a0341d0,
								UID: 0x0,
							},
							&efi.PCIDevicePathNode{
								Function: 0x1c,
								Device:   0x2,
							},
							&efi.PCIDevicePathNode{
								Function: 0x0,
								Device:   0x0,
							},
							&efi.MediaRelOffsetRangeDevicePathNode{
								StartingOffset: 0x38,
								EndingOffset:   0x11dff,
							},
						},
						DigestAlg: tpm2.HashAlgorithmSHA256,
						Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
					},
				}

				c.Check(errs[0], ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindAddonDriversPresent,
					LoadedImagesInfoArg(imageInfo),
					[]Action{ActionProceed},
					&AddonDriversPresentError{
						Drivers: imageInfo,
					},
				))

				c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(
					ErrorKindPreOSDigestVerificationDetected,
					nil,
					[]Action{ActionProceed},
					ErrPreOSVerificationUsingDigests,
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `5 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- addon drivers were detected:
  - \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
- some pre-OS components were authenticated from the authorized signature database using an Authenticode digest
`,
	})
	c.Check(errs, HasLen, 0)
}

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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA1,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		initialFlags: PermitAddonDrivers | PermitWeakSecureBootAlgorithms | PermitPreOSVerificationUsingDigests,
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
		expectedWarningsMatch: `6 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- addon drivers were detected:
  - \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
- a weak cryptographic algorithm was detected during secure boot verification
- some pre-OS components were authenticated from the authorized signature database using an Authenticode digest
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodActionProceedPermitWeakSecureBootAlgs(c *C) {
	// Test that ActionProceed enables PermitWeakSecureBootAlgorithms. As
	// this test generates 3 errors, it also tests the case where ActionProceed
	// can be used to ignore multiple errors.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA1,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Check(errs, HasLen, 3)

				imageInfo := []*LoadedImageInfo{
					{
						Format: LoadedImageFormatPE,
						DevicePath: efi.DevicePath{
							&efi.ACPIDevicePathNode{
								HID: 0x0a0341d0,
								UID: 0x0,
							},
							&efi.PCIDevicePathNode{
								Function: 0x1c,
								Device:   0x2,
							},
							&efi.PCIDevicePathNode{
								Function: 0x0,
								Device:   0x0,
							},
							&efi.MediaRelOffsetRangeDevicePathNode{
								StartingOffset: 0x38,
								EndingOffset:   0x11dff,
							},
						},
						DigestAlg: tpm2.HashAlgorithmSHA256,
						Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
					},
				}

				c.Check(errs[0], ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindAddonDriversPresent,
					LoadedImagesInfoArg(imageInfo),
					[]Action{ActionProceed},
					&AddonDriversPresentError{
						Drivers: imageInfo,
					},
				))

				c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(
					ErrorKindWeakSecureBootAlgorithmsDetected,
					nil,
					[]Action{ActionProceed},
					ErrWeakSecureBootAlgorithmDetected,
				))

				c.Check(errs[2], DeepEquals, NewWithKindAndActionsError(
					ErrorKindPreOSDigestVerificationDetected,
					nil,
					[]Action{ActionProceed},
					ErrPreOSVerificationUsingDigests,
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `6 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- addon drivers were detected:
  - \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
- a weak cryptographic algorithm was detected during secure boot verification
- some pre-OS components were authenticated from the authorized signature database using an Authenticode digest
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Good test case for invalid secure boot config (eg, no DeployedMode) when PCRProfileOptionPermitNoSecureBootPolicyProfile is supported.

func (s *runChecksContextSuite) TestRunGoodActionProceedIndividualWithMultipleErrors(c *C) {
	// Test that ActionProceed can be used to ignore individual errors when
	// multiple errors are reported.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA1,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   4,
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
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed, args: ActionProceedArgs{ErrorKindAddonDriversPresent}},
			{action: ActionProceed, args: ActionProceedArgs{ErrorKindWeakSecureBootAlgorithmsDetected}},
			{action: ActionProceed, args: ActionProceedArgs{ErrorKindPreOSDigestVerificationDetected}},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Check(errs, HasLen, 3)

				imageInfo := []*LoadedImageInfo{
					{
						Format: LoadedImageFormatPE,
						DevicePath: efi.DevicePath{
							&efi.ACPIDevicePathNode{
								HID: 0x0a0341d0,
								UID: 0x0,
							},
							&efi.PCIDevicePathNode{
								Function: 0x1c,
								Device:   0x2,
							},
							&efi.PCIDevicePathNode{
								Function: 0x0,
								Device:   0x0,
							},
							&efi.MediaRelOffsetRangeDevicePathNode{
								StartingOffset: 0x38,
								EndingOffset:   0x11dff,
							},
						},
						DigestAlg: tpm2.HashAlgorithmSHA256,
						Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
					},
				}

				c.Check(errs[0], ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindAddonDriversPresent,
					LoadedImagesInfoArg(imageInfo),
					[]Action{ActionProceed},
					&AddonDriversPresentError{
						Drivers: imageInfo,
					},
				))

				c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(
					ErrorKindWeakSecureBootAlgorithmsDetected,
					nil,
					[]Action{ActionProceed},
					ErrWeakSecureBootAlgorithmDetected,
				))

				c.Check(errs[2], DeepEquals, NewWithKindAndActionsError(
					ErrorKindPreOSDigestVerificationDetected,
					nil,
					[]Action{ActionProceed},
					ErrPreOSVerificationUsingDigests,
				))
			case 1:
				c.Check(errs, HasLen, 2)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindWeakSecureBootAlgorithmsDetected,
					nil,
					[]Action{ActionProceed},
					ErrWeakSecureBootAlgorithmDetected,
				))

				c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(
					ErrorKindPreOSDigestVerificationDetected,
					nil,
					[]Action{ActionProceed},
					ErrPreOSVerificationUsingDigests,
				))
			case 2:
				c.Check(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindPreOSDigestVerificationDetected,
					nil,
					[]Action{ActionProceed},
					ErrPreOSVerificationUsingDigests,
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `6 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- addon drivers were detected:
  - \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
- a weak cryptographic algorithm was detected during secure boot verification
- some pre-OS components were authenticated from the authorized signature database using an Authenticode digest
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodPostInstallTPMDeviceLockedOut(c *C) {
	// Test the good case where the TPM is locked out during post-install
	// where the lockout availability test doesn't run because the lockout
	// hierarchy has an authorization value. The TPM lockout is returned as
	// a warning because it's normally cleared during a successful boot and
	// it will be cleared during a reprovision as well.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		initialFlags: PostInstallChecks,
		profileOpts:  PCRProfileOptionsDefault,
		prepare: func(_ int) {
			// Trip the DA logic by triggering an auth failure with a DA protected
			// resource.
			c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 1, 10000, 10000, nil), IsNil)
			pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, []byte("foo"), []byte("5678"))
			c.Assert(err, IsNil)
			key, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
			c.Assert(err, IsNil)
			key.SetAuthValue(nil)
			_, err = s.TPM.Unseal(key, nil)
			c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandUnseal, 1), testutil.IsTrue)

			// Take ownership of the lockout hierarchy
			s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
		},
		actions:                   []actionAndArgs{{action: ActionNone}},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `5 errors detected:
- availability of TPM's lockout hierarchy was not checked because the lockout hierarchy has an authorization value set
- error with TPM2 device: TPM is in DA lockout mode
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodActionClearTPMSimple(c *C) {
	// Test that ActionClearTPMSimple works.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the storage hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPMSimple},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleOwner}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)

	val, err := s.TPM.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Assert(err, IsNil)
	c.Check(tpm2.PermanentAttributes(val)&(tpm2.AttrOwnerAuthSet|tpm2.AttrEndorsementAuthSet|tpm2.AttrLockoutAuthSet), Equals, tpm2.PermanentAttributes(0))
}

func (s *runChecksContextSuite) TestRunGoodActionClearTPM(c *C) {
	// Test that ActionClearTPM works.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the lockout hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPM, args: TPMAuthValueArg("1234")},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleLockout}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)

	val, err := s.TPM.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Assert(err, IsNil)
	c.Check(tpm2.PermanentAttributes(val)&(tpm2.AttrOwnerAuthSet|tpm2.AttrEndorsementAuthSet|tpm2.AttrLockoutAuthSet), Equals, tpm2.PermanentAttributes(0))
}

func (s *runChecksContextSuite) TestRunGoodActionClearTPMMissingAuthValueArg(c *C) {
	// Test that ActionClearTPM works if the lockout hierarchy has no authorization
	// value and no arguments are suppled.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the storage hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPM},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleOwner}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)

	val, err := s.TPM.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Assert(err, IsNil)
	c.Check(tpm2.PermanentAttributes(val)&(tpm2.AttrOwnerAuthSet|tpm2.AttrEndorsementAuthSet|tpm2.AttrLockoutAuthSet), Equals, tpm2.PermanentAttributes(0))
}

func (s *runChecksContextSuite) TestRunGoodStartupLocalityNotProtected(c *C) {
	// Test the case where there is a dTPM and the startup locality
	// is not protected from ring 0 access.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		expectedWarningsMatch: `4 errors detected:
- error with system security: cannot enable partial mitigation against discrete TPM reset attacks
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodInvalidPCR0ValueDiscreteTPM(c *C) {
	// Test the case where there is a dTPM and PCR0 is inconsistent with
	// the log.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 3,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		actions:                   []actionAndArgs{{action: ActionNone}},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformFirmwareProfileSupport | NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `5 errors detected:
- error with platform firmware \(PCR0\) measurements: PCR value mismatch \(actual from TPM 0x420bd3899738e6b41dccd18253a556e152e2b107559b89cbf0cbf1661ff6ee55, reconstructed from log 0xb0d6d5f50852be1524306ad88b928605c14338e56a1b8c0dc211a144524df2ef\)
- error with system security: cannot enable partial mitigation against discrete TPM reset attacks
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 0)
}

// **End of good cases ** //

func (s *runChecksContextSuite) TestRunBadUnexpectedAction(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env:         efitest.NewMockHostEnvironmentWithOpts(),
		profileOpts: PCRProfileOptionsDefault,
		actions:     []actionAndArgs{{action: ActionClearTPMViaFirmware}},
	})
	c.Assert(errs, HasLen, 1)
	c.Assert(errs[0], ErrorMatches, `specified action is not expected`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindUnexpectedAction, nil, nil, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadExternalAction(c *C) {
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		iterations:   2,
		prepare: func(i int) {
			switch i {
			case 0:
				// Disable owner and endorsement hierarchies
				c.Assert(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
				c.Assert(s.TPM.HierarchyControl(s.TPM.EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionRebootToFWSettings},
		},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `specified action is not implemented directly by this package`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindUnexpectedAction, nil, nil, errs[0].Unwrap()))
}

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
	c.Assert(errs[0], ErrorMatches, `virtual machine environment detected`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindRunningInVM,
		nil,
		[]Action{ActionProceed},
		ErrVirtualMachineDetected,
	))
}

func (s *runChecksContextSuite) TestRunBadNotEFI(c *C) {
	// Test the error case where the host system is not EFI
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Assert(errs[0], ErrorMatches, `host system is not an EFI system`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindSystemNotEFI, nil, nil, ErrSystemNotEFI))
}

func (s *runChecksContextSuite) TestRunBadEFIVariableAccessError(c *C) {
	// Test the error case where an EFI variable access fails
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Err: efi.ErrVarDeviceError},
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
	c.Assert(errs[0], ErrorMatches, `cannot access EFI variable: cannot obtain boot option support: variable access failed because of a hardware error`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindEFIVariableAccess, EFIVarDeviceError, []Action{ActionContactOEM}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadNoTPM2Device(c *C) {
	// Test the error case where no valid TPM2 device is detected.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: cannot open TPM device: cannot obtain TPM device: no TPM2 device is available`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindNoSuitableTPM2Device, nil, nil, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadTPMDeviceFailure(c *C) {
	// Test the error case where the TPM device is in failure mode.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: TPM2 device is in failure mode`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindTPMDeviceFailure, nil, []Action{ActionReboot, ActionContactOEM}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadNoPCClientTPMDevice(c *C) {
	// Test the error case where there is a TPM2 device, but it isn't
	// a PC Client device.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyPSFamilyIndicator: 2,
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: TPM2 device is present but it is not a PC-Client TPM`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindNoSuitableTPM2Device, nil, nil, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadTPM2DeviceDisabled(c *C) {
	// Test the error case where the TPM has been disabled by firmware.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: TPM2 device is present but is currently disabled by the platform firmware`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindTPMDeviceDisabled, nil, []Action{ActionEnableTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionRebootToFWSettings}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadTPM2DeviceDisabledRunEnableTPMViaFirmwareAction(c *C) {
	// Test the error case where the TPM has been disabled by firmware, and
	// we run the ActionEnableTPMViaFirmware action.

	p := &mockPPI{
		sta: ppi.StateTransitionRebootRequired,
		ops: map[ppi.OperationId]ppi.OperationStatus{
			ppi.OperationEnableTPM:         ppi.OperationPPRequired,
			ppi.OperationClearTPM:          ppi.OperationPPRequired,
			ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), p, nil)),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		prepare: func(i int) {
			switch i {
			case 0:
				// Disable owner and endorsement hierarchies on the first iteration
				c.Assert(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
				c.Assert(s.TPM.HierarchyControl(s.TPM.EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)
			}
		},
		iterations: 2,
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionEnableTPMViaFirmware},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindTPMDeviceDisabled, nil, []Action{ActionEnableTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionRebootToFWSettings}, errs[0].Unwrap()))
			}
		},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `a reboot is required to complete the action`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindRebootRequired, nil, []Action{ActionReboot}, errs[0].Unwrap()))

	c.Check(p.called, DeepEquals, []string{"EnableTPM()"})
}

func (s *runChecksContextSuite) TestRunBadTPM2DeviceDisabledRunEnableAndClearTPMViaFirmwareAction(c *C) {
	// Test the error case where the TPM has been disabled by firmware, and
	// we run the ActionEnableAndClearTPMViaFirmware action.

	p := &mockPPI{
		sta: ppi.StateTransitionRebootRequired,
		ops: map[ppi.OperationId]ppi.OperationStatus{
			ppi.OperationEnableTPM:         ppi.OperationPPRequired,
			ppi.OperationClearTPM:          ppi.OperationPPRequired,
			ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), p, nil)),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		prepare: func(i int) {
			switch i {
			case 0:
				// Disable owner and endorsement hierarchies on the first iteration
				c.Assert(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
				c.Assert(s.TPM.HierarchyControl(s.TPM.EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)
			}
		},
		iterations: 2,
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionEnableAndClearTPMViaFirmware},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindTPMDeviceDisabled, nil, []Action{ActionEnableTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionRebootToFWSettings}, errs[0].Unwrap()))
			}
		},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `a reboot is required to complete the action`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindRebootRequired, nil, []Action{ActionReboot}, errs[0].Unwrap()))

	c.Check(p.called, DeepEquals, []string{"EnableAndClearTPM()"})
}

func (s *runChecksContextSuite) TestRunBadTPMHierarchiesOwned(c *C) {
	// Test the error case where one or more hierarchies of the TPM are already owned.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		prepare: func(_ int) {
			// Set an authorization value for the endorsement hierarchy and
			// an authorization policy for the storage hierarchy.
			s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, []byte("1234"))
			c.Check(s.TPM.SetPrimaryPolicy(s.TPM.OwnerHandleContext(), make([]byte, 32), tpm2.HashAlgorithmSHA256, nil), IsNil)
		},
		actions: []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: one or more of the TPM hierarchies is already owned:
- TPM_RH_ENDORSEMENT has an authorization value
- TPM_RH_OWNER has an authorization policy
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindTPMHierarchiesOwned,
		&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleEndorsement}, WithAuthPolicy: tpm2.HandleList{tpm2.HandleOwner}},
		[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadTPMHierarchiesOwnedRunActionClearTPMViaFirmware(c *C) {
	// Test the error case where one or more hierarchies of the TPM are already owned, and
	// we run the ActionClearTPMViaFirmware action.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	p := &mockPPI{
		sta: ppi.StateTransitionRebootRequired,
		ops: map[ppi.OperationId]ppi.OperationStatus{
			ppi.OperationEnableTPM:         ppi.OperationPPRequired,
			ppi.OperationClearTPM:          ppi.OperationPPRequired,
			ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), p, nil)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the endorsement hierarchy and
				// an authorization policy for the storage hierarchy on the
				// first iteration.
				s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, []byte("1234"))
				c.Check(s.TPM.SetPrimaryPolicy(s.TPM.OwnerHandleContext(), make([]byte, 32), tpm2.HashAlgorithmSHA256, nil), IsNil)
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPMViaFirmware},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleEndorsement}, WithAuthPolicy: tpm2.HandleList{tpm2.HandleOwner}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			}
		},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `a reboot is required to complete the action`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindRebootRequired, nil, []Action{ActionReboot}, errs[0].Unwrap()))

	c.Check(p.called, DeepEquals, []string{"ClearTPM()"})
}

func (s *runChecksContextSuite) TestRunBadTPMHierarchiesOwnedRunActionEnableAndClearTPMViaFirmware(c *C) {
	// Test the error case where one or more hierarchies of the TPM are already owned, and
	// we run the ActionEnableAndClearTPMViaFirmware action.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	p := &mockPPI{
		sta: ppi.StateTransitionRebootRequired,
		ops: map[ppi.OperationId]ppi.OperationStatus{
			ppi.OperationEnableTPM:         ppi.OperationPPRequired,
			ppi.OperationClearTPM:          ppi.OperationPPRequired,
			ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), p, nil)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the endorsement hierarchy and
				// an authorization policy for the storage hierarchy on the
				// first iteration.
				s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, []byte("1234"))
				c.Check(s.TPM.SetPrimaryPolicy(s.TPM.OwnerHandleContext(), make([]byte, 32), tpm2.HashAlgorithmSHA256, nil), IsNil)
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionEnableAndClearTPMViaFirmware},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleEndorsement}, WithAuthPolicy: tpm2.HandleList{tpm2.HandleOwner}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			}
		},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `a reboot is required to complete the action`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindRebootRequired, nil, []Action{ActionReboot}, errs[0].Unwrap()))

	c.Check(p.called, DeepEquals, []string{"EnableAndClearTPM()"})
}

func (s *runChecksContextSuite) TestRunBadTPMDeviceLockoutLockedOut(c *C) {
	// Test the error case where the TPM's lockout hierarchy is locked out.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
			c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 32, 7200, 86400, nil), IsNil)

			// Disable the lockout hierarchy by authorizing it incorrectly
			s.TPM.LockoutHandleContext().SetAuthValue([]byte("1234"))
			err := s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil)
			c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandDictionaryAttackLockReset, 1), testutil.IsTrue)
		},
		actions:        []actionAndArgs{{action: ActionNone}},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: TPM's lockout hierarchy is unavailable because it is locked out`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindTPMDeviceLockoutLockedOut,
		TPMDeviceLockoutRecoveryArg(24*time.Hour),
		[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionRebootToFWSettings},
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadTPMDeviceLockoutLockedOutRunActionClearTPMViaFirmware(c *C) {
	// Test the error case where the TPM's lockout hierarchy is locked out, and
	// we run the ActionClearTPMViaFirmware action.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	p := &mockPPI{
		sta: ppi.StateTransitionRebootRequired,
		ops: map[ppi.OperationId]ppi.OperationStatus{
			ppi.OperationEnableTPM:         ppi.OperationPPRequired,
			ppi.OperationClearTPM:          ppi.OperationPPRequired,
			ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), p, nil)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:  2,
		prepare: func(i int) {
			switch i {
			case 0:
				// Disable the lockout hierarchy on the first iteration.
				c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 32, 7200, 86400, nil), IsNil)

				// Disable the lockout hierarchy by authorizing it incorrectly
				s.TPM.LockoutHandleContext().SetAuthValue([]byte("1234"))
				err := s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil)
				c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandDictionaryAttackLockReset, 1), testutil.IsTrue)
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPMViaFirmware},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMDeviceLockoutLockedOut,
					TPMDeviceLockoutRecoveryArg(24*time.Hour),
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))

			}
		},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `a reboot is required to complete the action`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindRebootRequired, nil, []Action{ActionReboot}, errs[0].Unwrap()))

	c.Check(p.called, DeepEquals, []string{"ClearTPM()"})
}

func (s *runChecksContextSuite) TestRunBadTPMDeviceLockoutLockedOutRunActionEnableAndClearTPMViaFirmware(c *C) {
	// Test the error case where the TPM's lockout hierarchy is locked out, and
	// we run the ActionEnableAndClearTPMViaFirmware action.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	p := &mockPPI{
		sta: ppi.StateTransitionRebootRequired,
		ops: map[ppi.OperationId]ppi.OperationStatus{
			ppi.OperationEnableTPM:         ppi.OperationPPRequired,
			ppi.OperationClearTPM:          ppi.OperationPPRequired,
			ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), p, nil)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:  2,
		prepare: func(i int) {
			switch i {
			case 0:
				// Disable the lockout hierarchy on the first iteration.
				c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 32, 7200, 86400, nil), IsNil)

				// Disable the lockout hierarchy by authorizing it incorrectly
				s.TPM.LockoutHandleContext().SetAuthValue([]byte("1234"))
				err := s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil)
				c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandDictionaryAttackLockReset, 1), testutil.IsTrue)
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionEnableAndClearTPMViaFirmware},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMDeviceLockoutLockedOut,
					TPMDeviceLockoutRecoveryArg(24*time.Hour),
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))

			}
		},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `a reboot is required to complete the action`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindRebootRequired, nil, []Action{ActionReboot}, errs[0].Unwrap()))

	c.Check(p.called, DeepEquals, []string{"EnableAndClearTPM()"})
}

func (s *runChecksContextSuite) TestRunBadTPMInsufficientCounters(c *C) {
	// Test the error case where there appears to be too few NV counters.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: insufficient NV counters available`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindInsufficientTPMStorage,
		nil,
		[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadTPMInsufficientCountersRunActionClearTPMViaFirmware(c *C) {
	// Test the error case where there appears to be too few NV counters, and
	// we run the ActionClearTPMViaFirmware action.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	p := &mockPPI{
		sta: ppi.StateTransitionRebootRequired,
		ops: map[ppi.OperationId]ppi.OperationStatus{
			ppi.OperationEnableTPM:         ppi.OperationPPRequired,
			ppi.OperationClearTPM:          ppi.OperationPPRequired,
			ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), p, nil)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		iterations:   2,
		profileOpts:  PCRProfileOptionsDefault,
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPMViaFirmware},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			c.Assert(errs, HasLen, 1)
			c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
				ErrorKindInsufficientTPMStorage,
				nil,
				[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
				errs[0].Unwrap(),
			))
		},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `a reboot is required to complete the action`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindRebootRequired, nil, []Action{ActionReboot}, errs[0].Unwrap()))

	c.Check(p.called, DeepEquals, []string{"ClearTPM()"})
}

func (s *runChecksContextSuite) TestRunBadTPMInsufficientCountersRunActionEnableAndClearTPMViaFirmware(c *C) {
	// Test the error case where there appears to be too few NV counters, and
	// we run the ActionEnableAndClearTPMViaFirmware action.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	p := &mockPPI{
		sta: ppi.StateTransitionRebootRequired,
		ops: map[ppi.OperationId]ppi.OperationStatus{
			ppi.OperationEnableTPM:         ppi.OperationPPRequired,
			ppi.OperationClearTPM:          ppi.OperationPPRequired,
			ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), p, nil)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		iterations:   2,
		profileOpts:  PCRProfileOptionsDefault,
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionEnableAndClearTPMViaFirmware},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			c.Assert(errs, HasLen, 1)
			c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
				ErrorKindInsufficientTPMStorage,
				nil,
				[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
				errs[0].Unwrap(),
			))
		},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `a reboot is required to complete the action`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindRebootRequired, nil, []Action{ActionReboot}, errs[0].Unwrap()))

	c.Check(p.called, DeepEquals, []string{"EnableAndClearTPM()"})
}

func (s *runChecksContextSuite) TestRunBadTPMHierarchiesOwnedAndLockedOut(c *C) {
	// Test case with more than one TPM error - in this case, one of the errors
	// is ErrTPMLockout which is converted to a warning and suppressed unless
	// RunChecks completes with success.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		prepare: func(_ int) {
			// Trip the DA logic by triggering an auth failure with a DA protected
			// resource.
			c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 1, 10000, 10000, nil), IsNil)
			pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, []byte("foo"), []byte("5678"))
			c.Assert(err, IsNil)
			key, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
			c.Assert(err, IsNil)
			key.SetAuthValue(nil)
			_, err = s.TPM.Unseal(key, nil)
			c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandUnseal, 1), testutil.IsTrue)

			// Take ownership of the lockout hierarchy
			s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
		},
		actions: []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)

	c.Check(errs[0], ErrorMatches, `error with TPM2 device: one or more of the TPM hierarchies is already owned:
- TPM_RH_LOCKOUT has an authorization value
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindTPMHierarchiesOwned,
		&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleLockout}},
		[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPM, ActionRebootToFWSettings},
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadTCGLog(c *C) {
	// Test the error case where the TCG log cannot be decoded.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
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
	c.Check(errs[0], ErrorMatches, `error with or detected from measurement log: nil log`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindMeasuredBoot, nil, nil, errs[0].Unwrap()))
}

// TODO: Test another bad case where PCR0 is mandatory but unusable, but is mandatory
// because the firmware is only protected with measured boot (this isn't supported yet,
// but it would result in the "no-suitable-pcr-bank" error kind).

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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `error with or detected from measurement log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256: error with drivers and apps \(PCR2\) measurements: PCR value mismatch \(actual from TPM 0xfa734a6a4d262d7405d47d48c0a1b127229ca808032555ad919ed5dd7c1f6519, reconstructed from log 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969\).
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindNoSuitablePCRBank, nil, []Action{ActionRebootToFWSettings, ActionContactOEM}, errs[0].Unwrap()))
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `error with or detected from measurement log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256: error with boot manager code \(PCR4\) measurements: PCR value mismatch \(actual from TPM 0x1c93930d6b26232e061eaa33ecf6341fae63ce598a0c6a26ee96a0828639c044, reconstructed from log 0x4bc74f3ffe49b4dd275c9f475887b68193e2db8348d72e1c3c9099c2dcfa85b0\).
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindNoSuitablePCRBank, nil, []Action{ActionRebootToFWSettings, ActionContactOEM}, errs[0].Unwrap()))
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `error with or detected from measurement log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256: error with secure boot policy \(PCR7\) measurements: PCR value mismatch \(actual from TPM 0xdf7b5d709755f1bd7142dd2f8c2d1195fc6b4dab5c78d41daf5c795da55db5f2, reconstructed from log 0xafc99bd8b298ea9b70d2796cb0ca22fe2b70d784691a1cae2aa3ba55edc365dc\).
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindNoSuitablePCRBank, nil, []Action{ActionRebootToFWSettings, ActionContactOEM}, errs[0].Unwrap()))
}

// TODO: Add a test for ErrorKindUnsupportedPlatform

func (s *runChecksContextSuite) TestRunBadUEFIDebuggingEnabled(c *C) {
	// Test the error case where a UEFI debugger is enabled.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:       []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				FirmwareDebugger: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
	c.Check(errs[0], ErrorMatches, `error with system security: the platform firmware contains a debugging endpoint enabled`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindUEFIDebuggingEnabled, nil, []Action{ActionContactOEM}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadInsufficientDMAProtection(c *C) {
	// Test the error case where DMA protection is disabled.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				DMAProtection: efitest.DMAProtectionDisabled,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
	c.Check(errs[0], ErrorMatches, `error with system security: the platform firmware indicates that DMA protections are insufficient`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindInsufficientDMAProtection,
		nil,
		[]Action{ActionRebootToFWSettings, ActionProceed, ActionContactOEM},
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadNoKernelIOMMU(c *C) {
	// Test the error case where the kernel doesn't enable a IOMMU
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
	c.Check(errs[0], ErrorMatches, `error with system security: no kernel IOMMU support was detected`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindNoKernelIOMMU,
		nil,
		[]Action{ActionRebootToFWSettings, ActionProceed, ActionContactOSVendor},
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunChecksBadUEFIDebuggingEnabledAndNoKernelIOMMU(c *C) {
	// Test case with more than one host security error. This also tests the case
	// where ActionProceed is suppressed because one of the returned errors
	// doesn't permit it.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:       []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality:  3,
				FirmwareDebugger: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		actions:      []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 2)
	c.Check(errs[0], ErrorMatches, `error with system security: the platform firmware contains a debugging endpoint enabled`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindUEFIDebuggingEnabled, nil, []Action{ActionContactOEM}, errs[0].Unwrap()))

	c.Check(errs[1], ErrorMatches, `error with system security: no kernel IOMMU support was detected`)
	c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(
		ErrorKindNoKernelIOMMU,
		nil,
		[]Action{ActionRebootToFWSettings, ActionContactOSVendor},
		errs[1].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadHostSecurityErrorMissingIntelMEModule(c *C) {
	// Test case where host security checks fail because the intel ME kernel module is missing.
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00:16:0", map[string]string{"PCI_CLASS": "78000", "PCI_ID": "8086:7E70"}, "pci", nil, nil),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
	c.Check(errs[0], ErrorMatches, `error with system security: encountered an error when checking Intel BootGuard configuration: the kernel module "mei_me" must be loaded`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindInternal, nil, nil, errs[0].Unwrap()))
	c.Check(errors.Is(errs[0], MissingKernelModuleError("mei_me")), testutil.IsTrue)
}

func (s *runChecksContextSuite) TestRunBadHostSecurityErrorMissingMSR(c *C) {
	// Test case where host security checks fail because the MSR kernel module is missing.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 0, nil),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
	c.Check(errs[0], ErrorMatches, `error with system security: encountered an error when checking Intel CPU debugging configuration: the kernel module "msr" must be loaded`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindInternal, nil, nil, errs[0].Unwrap()))
	c.Check(errors.Is(errs[0], MissingKernelModuleError("msr")), testutil.IsTrue)
}

func (s *runChecksContextSuite) TestRunBadHostSecurityError(c *C) {
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
	c.Check(errs[0], ErrorMatches, `error with system security: encountered an error when checking Intel BootGuard configuration: no hardware root-of-trust properly configured: ME is in manufacturing mode`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindHostSecurity, nil, []Action{ActionContactOEM}, errs[0].Unwrap()))
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `error with or detected from measurement log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256: the PCR bank is missing from the TCG log.
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindNoSuitablePCRBank, nil, []Action{ActionRebootToFWSettings, ActionContactOEM}, errs[0].Unwrap()))
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindPCRUnsupported, &PCRUnsupportedArgs{PCR: 1, URL: "https://github.com/canonical/secboot/issues/322"}, nil, errs[0].Unwrap()))

	c.Check(errs[1], ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet`)
	c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(ErrorKindPCRUnsupported, &PCRUnsupportedArgs{PCR: 3, URL: "https://github.com/canonical/secboot/issues/341"}, nil, errs[1].Unwrap()))

	c.Check(errs[2], ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet`)
	c.Check(errs[2], DeepEquals, NewWithKindAndActionsError(ErrorKindPCRUnsupported, &PCRUnsupportedArgs{PCR: 5, URL: "https://github.com/canonical/secboot/issues/323"}, nil, errs[2].Unwrap()))
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindPCRUnsupported, &PCRUnsupportedArgs{PCR: 1, URL: "https://github.com/canonical/secboot/issues/322"}, nil, errs[0].Unwrap()))

	c.Check(errs[1], ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet`)
	c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(ErrorKindPCRUnsupported, &PCRUnsupportedArgs{PCR: 3, URL: "https://github.com/canonical/secboot/issues/341"}, nil, errs[1].Unwrap()))

	c.Check(errs[2], ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet`)
	c.Check(errs[2], DeepEquals, NewWithKindAndActionsError(ErrorKindPCRUnsupported, &PCRUnsupportedArgs{PCR: 5, URL: "https://github.com/canonical/secboot/issues/323"}, nil, errs[2].Unwrap()))
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `the PCR bank for TPM_ALG_SHA384 is missing from the TCG log but active and with one or more empty PCRs on the TPM`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsErrorForTest(
		ErrorKindEmptyPCRBanks,
		map[string]json.RawMessage{"algs": []byte("[12]")},
		[]Action{ActionProceed, ActionContactOEM},
		&EmptyPCRBanksError{Algs: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA384}},
	))
}

func (s *runChecksContextSuite) TestRunBadAddonDriversPresent(c *C) {
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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

	imageInfo := []*LoadedImageInfo{
		{
			Format: LoadedImageFormatPE,
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0,
				},
				&efi.PCIDevicePathNode{
					Function: 0x1c,
					Device:   0x2,
				},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x0,
				},
				&efi.MediaRelOffsetRangeDevicePathNode{
					StartingOffset: 0x38,
					EndingOffset:   0x11dff,
				},
			},
			DigestAlg: tpm2.HashAlgorithmSHA256,
			Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
		},
	}

	c.Check(errs[0], ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindAddonDriversPresent,
		LoadedImagesInfoArg(imageInfo),
		[]Action{ActionProceed},
		&AddonDriversPresentError{
			Drivers: imageInfo,
		},
	))
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				{Name: "SysPrepOrder", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1, 0x0}},
				{Name: "SysPrep0001", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: efitest.MakeVarPayload(c, &efi.LoadOption{
					Attributes:  efi.LoadOptionActive | efi.LoadOptionCategoryApp,
					Description: "Mock sysprep app",
					FilePath: efi.DevicePath{
						&efi.HardDriveDevicePathNode{
							PartitionNumber: 1,
							PartitionStart:  0x800,
							PartitionSize:   0x100000,
							Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
							MBRType:         efi.GPT},
						efi.FilePathDevicePathNode("\\EFI\\Dell\\sysprep.efi"),
					},
				})},
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

	c.Check(errs[0], ErrorMatches, `system preparation applications were detected:
- Mock sysprep app path=\\PciRoot\(0x0\)\\Pci\(0x1d,0x0\)\\Pci\(0x0,0x0\)\\NVMe\(0x1,00-00-00-00-00-00-00-00\)\\HD\(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960\)\\\\EFI\\Dell\\sysprep.efi authenticode-digest=TPM_ALG_SHA256:11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4 load-option=SysPrep0001
`)
	imageInfo := []*LoadedImageInfo{
		{
			Format:         LoadedImageFormatPE,
			Description:    "Mock sysprep app",
			LoadOptionName: "SysPrep0001",
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x1d},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x0},
				&efi.NVMENamespaceDevicePathNode{
					NamespaceID:   0x1,
					NamespaceUUID: efi.EUI64{}},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\Dell\\sysprep.efi"),
			},
			DigestAlg: tpm2.HashAlgorithmSHA256,
			Digest:    testutil.DecodeHexString(c, "11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4"),
		},
	}

	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindSysPrepApplicationsPresent,
		LoadedImagesInfoArg(imageInfo),
		[]Action{ActionProceed},
		&SysPrepApplicationsPresentError{
			Apps: imageInfo,
		},
	))
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `Absolute was detected to be active and it is advised that this is disabled`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindAbsolutePresent,
		nil,
		[]Action{ActionRebootToFWSettings, ActionProceed, ActionContactOEM},
		ErrAbsoluteComputraceActive,
	))
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `error with boot manager code \(PCR4\) measurements: cannot verify correctness of EV_EFI_BOOT_SERVICES_APPLICATION event digest: not enough images supplied`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindPCRUnusable, PCRUnusableArg(4), []Action{ActionContactOEM}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadInvalidSecureBootMode(c *C) {
	// Test the error case where PCR7 is mandatory with the supplied profile options,
	// but is marked invalid because the system is not in deployed mode. Note that it is
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `error with secure boot policy \(PCR7\) measurements: deployed mode should be enabled in order to generate secure boot profiles`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindInvalidSecureBootMode, nil, []Action{ActionRebootToFWSettings}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadInvalidSecureBootModeSecureBootDisabled(c *C) {
	// Test the error case where PCR7 is mandatory with the supplied profile options,
	// but is marked invalid because secure boot is disabled.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				SecureBootDisabled: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(false).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
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
	c.Check(errs[0], ErrorMatches, `error with secure boot policy \(PCR7\) measurements: secure boot should be enabled in order to generate secure boot profiles`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindInvalidSecureBootMode, nil, []Action{ActionRebootToFWSettings}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadInvalidSecureBootModeSecureBootDisabledAndNoSBATLevel(c *C) {
	// Simulate running on a machine with secure boot disabled and running
	// shim on a system with an empty SbatLevel variable. In this case,
	// there are no EV_EFI_VARIABLE_AUTHORITY events which caused
	// https://launchpad.net/bugs/2125439
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				SecureBootDisabled: true,
				NoSBAT:             true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(false).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
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
	c.Check(errs[0], ErrorMatches, `error with secure boot policy \(PCR7\) measurements: secure boot should be enabled in order to generate secure boot profiles`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindInvalidSecureBootMode, nil, []Action{ActionRebootToFWSettings}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunBadNoSecureBootPolicySupport(c *C) {
	// Test the error case where PCR7 is mandatory but the secure boot checks fail
	// because dbx is measured twice.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	for _, ev := range log.Events {
		eventsCopy = append(eventsCopy, ev)

		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableDriverConfig {
			continue
		}
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		c.Assert(ok, testutil.IsTrue)
		if data.UnicodeName == "dbx" {
			// Measure dbx twice
			eventsCopy = append(eventsCopy, ev)
		}
	}
	log.Events = eventsCopy

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(log),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Check(errs[0], ErrorMatches, `error with secure boot policy \(PCR7\) measurements: unexpected EV_EFI_VARIABLE_DRIVER_CONFIG event: all expected secure boot variable have been measured`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindPCRUnusable, PCRUnusableArg(7), []Action{ActionContactOEM}, errs[0].Unwrap()))
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA1,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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

	imageInfo := []*LoadedImageInfo{
		{
			Format: LoadedImageFormatPE,
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0,
				},
				&efi.PCIDevicePathNode{
					Function: 0x1c,
					Device:   0x2,
				},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x0,
				},
				&efi.MediaRelOffsetRangeDevicePathNode{
					StartingOffset: 0x38,
					EndingOffset:   0x11dff,
				},
			},
			DigestAlg: tpm2.HashAlgorithmSHA256,
			Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
		},
	}

	c.Check(errs[0], ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindAddonDriversPresent,
		LoadedImagesInfoArg(imageInfo),
		[]Action{ActionProceed},
		&AddonDriversPresentError{
			Drivers: imageInfo,
		},
	))

	c.Check(errs[1], ErrorMatches, `a weak cryptographic algorithm was detected during secure boot verification`)
	c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(
		ErrorKindWeakSecureBootAlgorithmsDetected,
		nil,
		[]Action{ActionProceed},
		ErrWeakSecureBootAlgorithmDetected,
	))

	c.Check(errs[2], ErrorMatches, `some pre-OS components were authenticated from the authorized signature database using an Authenticode digest`)
	c.Check(errs[2], DeepEquals, NewWithKindAndActionsError(
		ErrorKindPreOSDigestVerificationDetected,
		nil,
		[]Action{ActionProceed},
		ErrPreOSVerificationUsingDigests,
	))
}

// TODO: This is disabled temporarily until a follow-up PR which adds warnings to the returned errors
// if RunChecks is going to return one or more errors anyway.
//func (s *runChecksContextSuite) TestRunChecksBadTPMHierarchiesOwnedAndNoSecureBootPolicySupport(c *C) {
//	// Test case with more than one error.
//	meiAttrs := map[string][]byte{
//		"fw_ver": []byte(`0:16.1.27.2176
//0:16.1.27.2176
//0:16.0.15.1624
//`),
//		"fw_status": []byte(`94000245
//09F10506
//00000020
//00004000
//00041F03
//C7E003CB
//`),
//	}
//	devices := []internal_efi.SysfsDevice{
//		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
//		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
//		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
//			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
//		)),
//	}
//
//	errs := s.testRun(c, &testRunChecksContextRunParams{
//		env: efitest.NewMockHostEnvironmentWithOpts(
//			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
//			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
//			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
//				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
//			})),
//			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
//			efitest.WithSysfsDevices(devices...),
//			efitest.WithMockVars(efitest.MockVars{
//				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
//				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
//				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
//				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
//				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
//				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
//			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
//		),
//		tpmPropertyModifiers: map[tpm2.Property]uint32{
//			tpm2.PropertyNVCountersMax:     0,
//			tpm2.PropertyPSFamilyIndicator: 1,
//			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
//		},
//		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
//		prepare: func(_ int) {
//			c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.LockoutHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)
//		},
//		loadedImages: []secboot_efi.Image{
//			&mockImage{
//				contents: []byte("mock shim executable"),
//				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
//				signatures: []*efi.WinCertificateAuthenticode{
//					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
//				},
//			},
//			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
//			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
//		},
//		profileOpts:    PCRProfileOptionsDefault,
//		actions:        []actionAndArgs{{action: ActionNone}},
//		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
//	})
//	c.Assert(errs, HasLen, 2)
//
//	c.Check(errs[0], ErrorMatches, `error with TPM2 device: one or more of the TPM hierarchies is already owned:
//- TPM_RH_LOCKOUT has an authorization value
//`)
//	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindTPMHierarchiesOwned, &TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleLockout}}, []Action{ActionRebootToFWSettings}, errs[0].Unwrap()))
//
//	c.Check(errs[1], ErrorMatches, `error with secure boot policy \(PCR7\) measurements: deployed mode should be enabled in order to generate secure boot profiles`)
//	c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(ErrorKindInvalidSecureBootMode, nil, []Action{ActionRebootToFWSettings}, errs[1].Unwrap()))
//}

// TODO: This is disabled temporarily until a follow-up PR which adds warnings to the returned errors
// if RunChecks is going to return one or more errors anyway.
//func (s *runChecksContextSuite) TestRunChecksBadEmptyPCRBankAndNoBootManagerCodeProfileSupport(c *C) {
//	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)
//
//	meiAttrs := map[string][]byte{
//		"fw_ver": []byte(`0:16.1.27.2176
//0:16.1.27.2176
//0:16.0.15.1624
//`),
//		"fw_status": []byte(`94000245
//09F10506
//00000020
//00004000
//00041F03
//C7E003CB
//`),
//	}
//	devices := []internal_efi.SysfsDevice{
//		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
//		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
//		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
//			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
//		)),
//	}
//
//	errs := s.testRun(c, &testRunChecksContextRunParams{
//		env: efitest.NewMockHostEnvironmentWithOpts(
//			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
//			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
//			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
//				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
//			})),
//			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
//			efitest.WithSysfsDevices(devices...),
//			efitest.WithMockVars(efitest.MockVars{
//				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
//				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
//				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
//				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
//				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
//				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
//			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
//		),
//		tpmPropertyModifiers: map[tpm2.Property]uint32{
//			tpm2.PropertyNVCountersMax:     0,
//			tpm2.PropertyPSFamilyIndicator: 1,
//			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
//		},
//		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
//		loadedImages: []secboot_efi.Image{
//			&mockImage{
//				contents: []byte("mock shim executable"),
//				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
//				signatures: []*efi.WinCertificateAuthenticode{
//					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
//				},
//			},
//			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
//		},
//		profileOpts:    PCRProfileOptionsDefault,
//		actions:        []actionAndArgs{{action: ActionNone}},
//		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
//	})
//	c.Assert(errs, HasLen, 2)
//
//	c.Check(errs[0], ErrorMatches, `the PCR bank for TPM_ALG_SHA384 is missing from the TCG log but active and with one or more empty PCRs on the TPM`)
//	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
//		ErrorKindEmptyPCRBanks,
//		&EmptyPCRBanksError{Algs: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA384}},
//		[]Action{ActionRebootToFWSettings, ActionContactOEM},
//		errs[0].Unwrap(),
//	))
//
//	c.Check(errs[1], ErrorMatches, `error with boot manager code \(PCR4\) measurements: not all EV_EFI_BOOT_SERVICES_APPLICATION boot manager launch digests could be verified`)
//	c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(ErrorKindPCRUnusable, PCRUnusableArg(4), []Action{ActionContactOEM}, errs[1].Unwrap()))
//}

func (s *runChecksContextSuite) TestRunChecksBadEmptyPCRBankAndNoKernelIOMMU(c *C) {
	// Test with a system that has an empty PCR bank and no kernel IOMMU.
	// As both errors support ActionProceed, it is a valid action for
	// both of the returned errors.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
	c.Assert(errs, HasLen, 2)

	c.Check(errs[0], ErrorMatches, `the PCR bank for TPM_ALG_SHA384 is missing from the TCG log but active and with one or more empty PCRs on the TPM`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindEmptyPCRBanks,
		&EmptyPCRBanksError{Algs: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA384}},
		[]Action{ActionProceed, ActionContactOEM},
		errs[0].Unwrap(),
	))

	c.Check(errs[1], ErrorMatches, `error with system security: no kernel IOMMU support was detected`)
	c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(
		ErrorKindNoKernelIOMMU,
		nil,
		[]Action{ActionRebootToFWSettings, ActionProceed, ActionContactOSVendor},
		errs[1].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunChecksActionEnableTPMViaFirmwareNotAvailable(c *C) {
	// Generate an error that could be fixed by ActionEnableTPMViaFirmware when
	// this action is not available.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: TPM2 device is present but is currently disabled by the platform firmware`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindTPMDeviceDisabled, nil, []Action{ActionEnableAndClearTPMViaFirmware, ActionRebootToFWSettings}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunChecksActionEnableAndClearTPMViaFirmwareNotAvailable(c *C) {
	// Generate an error that could be fixed by ActionEnableAndClearTPMViaFirmware when
	// this action is not available.
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionShutdownRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM: ppi.OperationPPRequired,
						ppi.OperationClearTPM:  ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: TPM2 device is present but is currently disabled by the platform firmware`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindTPMDeviceDisabled, nil, []Action{ActionEnableTPMViaFirmware, ActionRebootToFWSettings}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunChecksActionClearTPMViaFirmwareNotAvailable(c *C) {
	// Generate an error that could be fixed by ActionClearTPMViaFirmware when this action
	// is not available.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		prepare: func(_ int) {
			// Set an authorization value for the endorsement hierarchy and
			// an authorization policy for the storage hierarchy.
			s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, []byte("1234"))
			c.Check(s.TPM.SetPrimaryPolicy(s.TPM.OwnerHandleContext(), make([]byte, 32), tpm2.HashAlgorithmSHA256, nil), IsNil)
		},
		actions: []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: one or more of the TPM hierarchies is already owned:
- TPM_RH_ENDORSEMENT has an authorization value
- TPM_RH_OWNER has an authorization policy
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindTPMHierarchiesOwned,
		&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleEndorsement}, WithAuthPolicy: tpm2.HandleList{tpm2.HandleOwner}},
		[]Action{ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunChecksPPIActionWithShutdownTransition(c *C) {
	// Generate an error that can be resolve using a PPI action, with the
	// state transition action being "shutdown" rather than the more common
	// "reboot".
	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionShutdownRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		profileOpts:  PCRProfileOptionsDefault,
		iterations:   2,
		prepare: func(i int) {
			switch i {
			case 0:
				// Disable owner and endorsement hierarchies on the first iteration
				c.Assert(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
				c.Assert(s.TPM.HierarchyControl(s.TPM.EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionEnableTPMViaFirmware},
		},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `a shutdown is required to complete the action`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindShutdownRequired, nil, []Action{ActionShutdown}, errs[0].Unwrap()))
}

func (s *runChecksContextSuite) TestRunChecksActionProceedUnavailable(c *C) {
	// Return 2 errors where only 1 supports ActionProceed. It should
	// be suppressed in this case.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				DMAProtection: efitest.DMAProtectionDisabled,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		prepare: func(_ int) {
			// Set an authorization value for the endorsement hierarchy.
			s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, []byte("1234"))
		},
		actions: []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 2)
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: one or more of the TPM hierarchies is already owned:
- TPM_RH_ENDORSEMENT has an authorization value
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindTPMHierarchiesOwned,
		&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleEndorsement}},
		[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
		errs[0].Unwrap(),
	))

	c.Check(errs[1], ErrorMatches, `error with system security: the platform firmware indicates that DMA protections are insufficient`)
	c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(
		ErrorKindInsufficientDMAProtection,
		nil,
		[]Action{ActionRebootToFWSettings, ActionContactOEM},
		errs[1].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunChecksActionProceedErrorsOrderedAfterOtherErrors(c *C) {
	// Ensure that errors which support ActionProceed get reordered to be
	// returned after other errors.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:       []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				FirmwareDebugger: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks:   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
		actions:        []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 2)

	c.Check(errs[0], ErrorMatches, `error with system security: the platform firmware contains a debugging endpoint enabled`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(ErrorKindUEFIDebuggingEnabled, nil, []Action{ActionContactOEM}, errs[0].Unwrap()))

	c.Check(errs[1], ErrorMatches, `the PCR bank for TPM_ALG_SHA384 is missing from the TCG log but active and with one or more empty PCRs on the TPM`)
	c.Check(errs[1], DeepEquals, NewWithKindAndActionsErrorForTest(
		ErrorKindEmptyPCRBanks,
		map[string]json.RawMessage{"algs": []byte("[12]")},
		[]Action{ActionContactOEM},
		&EmptyPCRBanksError{Algs: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA384}},
	))
}

func (s *runChecksContextSuite) TestRunChecksActionProceedUnsupportedArgumentType(c *C) {
	// Test that passing an unsupported type as an argument to ActionProceed
	// generates an error.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed, args: map[string]any{"error-kinds": 1}},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Check(errs, HasLen, 1)
				imageInfo := []*LoadedImageInfo{
					{
						Format: LoadedImageFormatPE,
						DevicePath: efi.DevicePath{
							&efi.ACPIDevicePathNode{
								HID: 0x0a0341d0,
								UID: 0x0,
							},
							&efi.PCIDevicePathNode{
								Function: 0x1c,
								Device:   0x2,
							},
							&efi.PCIDevicePathNode{
								Function: 0x0,
								Device:   0x0,
							},
							&efi.MediaRelOffsetRangeDevicePathNode{
								StartingOffset: 0x38,
								EndingOffset:   0x11dff,
							},
						},
						DigestAlg: tpm2.HashAlgorithmSHA256,
						Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
					},
				}

				c.Check(errs[0], ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindAddonDriversPresent,
					LoadedImagesInfoArg(imageInfo),
					[]Action{ActionProceed},
					&AddonDriversPresentError{
						Drivers: imageInfo,
					},
				))
			}
		},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `cannot deserialize argument map from JSON to type preinstall.ActionProceedArgs: json: cannot unmarshal number into Go value of type \[\]preinstall.ErrorKind`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindInvalidArgument,
		InvalidActionArgumentDetails{
			Field:  "error-kinds",
			Reason: InvalidActionArgumentReasonType,
		},
		nil,
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunChecksActionProceedUnsupportedErrorKind(c *C) {
	// Test that passing an unsupported ErrorKind as an argument to ActionProceed
	// generates an error.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed, args: ActionProceedArgs{ErrorKindInvalidSecureBootMode}},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Check(errs, HasLen, 1)
				imageInfo := []*LoadedImageInfo{
					{
						Format: LoadedImageFormatPE,
						DevicePath: efi.DevicePath{
							&efi.ACPIDevicePathNode{
								HID: 0x0a0341d0,
								UID: 0x0,
							},
							&efi.PCIDevicePathNode{
								Function: 0x1c,
								Device:   0x2,
							},
							&efi.PCIDevicePathNode{
								Function: 0x0,
								Device:   0x0,
							},
							&efi.MediaRelOffsetRangeDevicePathNode{
								StartingOffset: 0x38,
								EndingOffset:   0x11dff,
							},
						},
						DigestAlg: tpm2.HashAlgorithmSHA256,
						Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
					},
				}

				c.Check(errs[0], ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindAddonDriversPresent,
					LoadedImagesInfoArg(imageInfo),
					[]Action{ActionProceed},
					&AddonDriversPresentError{
						Drivers: imageInfo,
					},
				))
			}
		},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `invalid value for argument "error-kinds" at index 0: "invalid-secure-boot-mode" does not support the "proceed" action`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindInvalidArgument,
		InvalidActionArgumentDetails{
			Field:  "error-kinds",
			Reason: InvalidActionArgumentReasonValue,
		},
		nil,
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunChecksActionProceedUnexpectedErrorKind1(c *C) {
	// Test that passing an unexpected ErrorKind as an argument to ActionProceed
	// generates an error.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed, args: ActionProceedArgs{ErrorKindPreOSDigestVerificationDetected}},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Check(errs, HasLen, 1)
				imageInfo := []*LoadedImageInfo{
					{
						Format: LoadedImageFormatPE,
						DevicePath: efi.DevicePath{
							&efi.ACPIDevicePathNode{
								HID: 0x0a0341d0,
								UID: 0x0,
							},
							&efi.PCIDevicePathNode{
								Function: 0x1c,
								Device:   0x2,
							},
							&efi.PCIDevicePathNode{
								Function: 0x0,
								Device:   0x0,
							},
							&efi.MediaRelOffsetRangeDevicePathNode{
								StartingOffset: 0x38,
								EndingOffset:   0x11dff,
							},
						},
						DigestAlg: tpm2.HashAlgorithmSHA256,
						Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
					},
				}

				c.Check(errs[0], ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindAddonDriversPresent,
					LoadedImagesInfoArg(imageInfo),
					[]Action{ActionProceed},
					&AddonDriversPresentError{
						Drivers: imageInfo,
					},
				))
			}
		},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `invalid value for argument "error-kinds" at index 0: "pre-os-digest-verification-detected" is not expected`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindInvalidArgument,
		InvalidActionArgumentDetails{
			Field:  "error-kinds",
			Reason: InvalidActionArgumentReasonValue,
		},
		nil,
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunChecksActionProceedUnexpectedErrorKind2(c *C) {
	// Test that passing the same ErrorKind as an argument to ActionProceed
	// more than once generates an error.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA256,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   3,
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
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionProceed, args: ActionProceedArgs{ErrorKindAddonDriversPresent}},
			{action: ActionProceed, args: ActionProceedArgs{ErrorKindAddonDriversPresent}},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Check(errs, HasLen, 2)

				imageInfo := []*LoadedImageInfo{
					{
						Format: LoadedImageFormatPE,
						DevicePath: efi.DevicePath{
							&efi.ACPIDevicePathNode{
								HID: 0x0a0341d0,
								UID: 0x0,
							},
							&efi.PCIDevicePathNode{
								Function: 0x1c,
								Device:   0x2,
							},
							&efi.PCIDevicePathNode{
								Function: 0x0,
								Device:   0x0,
							},
							&efi.MediaRelOffsetRangeDevicePathNode{
								StartingOffset: 0x38,
								EndingOffset:   0x11dff,
							},
						},
						DigestAlg: tpm2.HashAlgorithmSHA256,
						Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
					},
				}

				c.Check(errs[0], ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindAddonDriversPresent,
					LoadedImagesInfoArg(imageInfo),
					[]Action{ActionProceed},
					&AddonDriversPresentError{
						Drivers: imageInfo,
					},
				))

				c.Check(errs[1], DeepEquals, NewWithKindAndActionsError(
					ErrorKindPreOSDigestVerificationDetected,
					nil,
					[]Action{ActionProceed},
					ErrPreOSVerificationUsingDigests,
				))
			case 1:
				c.Check(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindPreOSDigestVerificationDetected,
					nil,
					[]Action{ActionProceed},
					ErrPreOSVerificationUsingDigests,
				))
			}
		},
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `invalid value for argument "error-kinds" at index 0: "addon-drivers-present" is not expected`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindInvalidArgument,
		InvalidActionArgumentDetails{
			Field:  "error-kinds",
			Reason: InvalidActionArgumentReasonValue,
		},
		nil,
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunChecksClearTPMNotAvailable(c *C) {
	// Test the case where neither ActionClearTPMSimple and ActionClearTPM are
	// not available because owner clear is disabled.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		prepare: func(_ int) {
			// Set an authorization value for the storage hierarchy.
			s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))

			// Disable owner clear.
			c.Assert(s.TPM.ClearControl(s.TPM.LockoutHandleContext(), true, nil), IsNil)
		},
		actions: []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: one or more of the TPM hierarchies is already owned:
- TPM_RH_OWNER has an authorization value
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindTPMHierarchiesOwned,
		&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleOwner}},
		[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionRebootToFWSettings},
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunChecksClearTPMSimpleNotAvailable(c *C) {
	// Test the case where ActionClearTPMSimple is not available because the
	// lockout hierarchy has a non-empty authorization value.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		prepare: func(_ int) {
			// Set an authorization value for the lockout hierarchy.
			s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
		},
		actions: []actionAndArgs{{action: ActionNone}},
	})
	c.Assert(errs, HasLen, 1)
	c.Check(errs[0], ErrorMatches, `error with TPM2 device: one or more of the TPM hierarchies is already owned:
- TPM_RH_LOCKOUT has an authorization value
`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindTPMHierarchiesOwned,
		&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleLockout}},
		[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPM, ActionRebootToFWSettings},
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadActionClearTPMSimpleFailsInvalidAuthValue(c *C) {
	// Test that ActionClearTPMSimple returns an error if something sets
	// the authorization value for the lockout hierarchy in between
	// receiving the first error and submitting the action.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the storage hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
			case 1:
				// Set an authorization value for the lockout hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPMSimple},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleOwner}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 1)

	c.Check(errs[0], ErrorMatches, `specified action is no longer available because the TPM's lockout hierarchy now has a non-empty auth value: use "clear-tpm" action instead`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindUnexpectedAction,
		nil, nil, // args, actions
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadActionClearTPMSimpleFailsWithError(c *C) {
	// Test that ActionClearTPMSimple returns an error if clearing the
	// TPM fails for some reason.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the storage hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
			case 1:
				// Disable owner clear
				c.Check(s.TPM.ClearControl(s.TPM.LockoutHandleContext(), true, nil), IsNil)
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPMSimple},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleOwner}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 1)

	c.Check(errs[0], ErrorMatches, `cannot clear TPM: TPM returned an error whilst executing command TPM_CC_Clear: TPM_RC_DISABLED \(the command is disabled\)`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindActionFailed,
		nil, nil, // args, actions
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadActionClearTPMSimpleBecomesUnavailableAfterLockoutAuthFailure(c *C) {
	// Test that ActionClearTPMSimple becomes unavailable if the lockout
	// hierarchy is used with an invalid auth value.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   3,
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
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the storage hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
			case 1:
				// Set an authorization value for the lockout hierarchy,
				// so that we can run ActionClearTPM with the wrong value.
				s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPM, args: TPMAuthValueArg("5678")},
			{action: ActionClearTPMSimple},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleOwner}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			case 1:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindInvalidArgument,
					InvalidActionArgumentDetails{
						Field:  "auth-value",
						Reason: InvalidActionArgumentReasonValue,
					},
					nil, // actions,
					errs[0].Unwrap(),
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 1)

	c.Check(errs[0], ErrorMatches, `specified action is no longer available`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindUnexpectedAction,
		nil, nil, // args, actions
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadActionClearTPMInvalidAuthValueArgumentType(c *C) {
	// Test that ActionClearTPM returns an error if the supplied lockout
	// hierarchy authorization value argument is the wrong type.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the storage hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPM, args: map[string]any{"auth-value": 1}},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleOwner}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 1)

	c.Check(errs[0], ErrorMatches, `cannot deserialize argument map from JSON to type preinstall.TPMAuthValueArg: json: cannot unmarshal number into Go value of type \[\]uint8`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindInvalidArgument,
		InvalidActionArgumentDetails{
			Field:  "auth-value",
			Reason: InvalidActionArgumentReasonType,
		},
		nil, // actions
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadActionClearTPMInvalidAuthValue(c *C) {
	// Test that ActionClearTPM returns an error if the supplied lockout
	// hierarchy authorization value is inconsistent with the value of
	// the lockoutAuthSet attribute.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the storage hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPM, args: TPMAuthValueArg("1234")},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleOwner}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 1)

	c.Check(errs[0], ErrorMatches, `supplied TPM lockout hierarchy authorization value is inconsistent with the value of the TPM_PT_PERMANENT lockoutAuthSet attribute`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindInvalidArgument,
		InvalidActionArgumentDetails{
			Field:  "auth-value",
			Reason: InvalidActionArgumentReasonValue,
		},
		nil, // actions
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadActionClearTPMFailsWithError(c *C) {
	// Test that ActionClearTPM returns an error if clearing the
	// TPM fails for some reason.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   2,
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
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the storage hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
			case 1:
				// Disable owner clear
				c.Check(s.TPM.ClearControl(s.TPM.LockoutHandleContext(), true, nil), IsNil)
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPM, args: TPMAuthValueArg(nil)},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleOwner}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMSimple, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 1)

	c.Check(errs[0], ErrorMatches, `cannot clear TPM: TPM returned an error whilst executing command TPM_CC_Clear: TPM_RC_DISABLED \(the command is disabled\)`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindActionFailed,
		nil, nil, // args, actions
		errs[0].Unwrap(),
	))
}

func (s *runChecksContextSuite) TestRunBadActionClearTPMBecomesUnavailableAfterLockoutAuthFailure(c *C) {
	// Test that ActionClearTPM becomes unavailable if the lockout
	// hierarchy is used with an invalid auth value.
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(
				tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1),
				&mockPPI{
					sta: ppi.StateTransitionRebootRequired,
					ops: map[ppi.OperationId]ppi.OperationStatus{
						ppi.OperationEnableTPM:         ppi.OperationPPRequired,
						ppi.OperationClearTPM:          ppi.OperationPPRequired,
						ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
					},
				},
				nil,
			)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1), 0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices...),
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
		iterations:   3,
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
		prepare: func(i int) {
			switch i {
			case 0:
				// Set an authorization value for the lockout hierarchy.
				s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
			}
		},
		actions: []actionAndArgs{
			{action: ActionNone},
			{action: ActionClearTPM, args: TPMAuthValueArg("5678")},
			{action: ActionClearTPM},
		},
		checkIntermediateErrs: func(i int, errs []*WithKindAndActionsError) {
			switch i {
			case 0:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindTPMHierarchiesOwned,
					&TPM2OwnedHierarchiesError{WithAuthValue: tpm2.HandleList{tpm2.HandleLockout}},
					[]Action{ActionClearTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPM, ActionRebootToFWSettings},
					errs[0].Unwrap(),
				))
			case 1:
				c.Assert(errs, HasLen, 1)
				c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
					ErrorKindInvalidArgument,
					InvalidActionArgumentDetails{
						Field:  "auth-value",
						Reason: InvalidActionArgumentReasonValue,
					},
					nil, // actions,
					errs[0].Unwrap(),
				))
			}
		},
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `3 errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Assert(errs, HasLen, 1)

	c.Check(errs[0], ErrorMatches, `specified action is no longer available`)
	c.Check(errs[0], DeepEquals, NewWithKindAndActionsError(
		ErrorKindUnexpectedAction,
		nil, nil, // args, actions
		errs[0].Unwrap(),
	))
}

type insertActionProceedTestSuite struct{}

var _ = Suite(&insertActionProceedTestSuite{})

func (s *insertActionProceedTestSuite) TestInsertActionProceed(c *C) {
	for _, tc := range []struct {
		desc     string
		actions  []Action
		expected []Action
	}{
		{
			desc: "insert before ActionContactOEM",
			actions: []Action{
				ActionClearTPMViaFirmware,
				ActionRebootToFWSettings,
				ActionContactOEM,
			},
			expected: []Action{
				ActionClearTPMViaFirmware,
				ActionRebootToFWSettings,
				ActionProceed,
				ActionContactOEM,
			},
		},
		{
			desc: "insert before ActionContactOSVendor",
			actions: []Action{
				ActionRebootToFWSettings,
				ActionContactOSVendor,
			},
			expected: []Action{
				ActionRebootToFWSettings,
				ActionProceed,
				ActionContactOSVendor,
			},
		},
		{
			desc: "insert before first contact action",
			actions: []Action{
				ActionClearTPMViaFirmware,
				ActionContactOEM,
				ActionContactOSVendor,
			},
			expected: []Action{
				ActionClearTPMViaFirmware,
				ActionProceed,
				ActionContactOEM,
				ActionContactOSVendor,
			},
		},
		{
			desc: "append when no contact actions",
			actions: []Action{
				ActionClearTPMViaFirmware,
				ActionRebootToFWSettings,
			},
			expected: []Action{
				ActionClearTPMViaFirmware,
				ActionRebootToFWSettings,
				ActionProceed,
			},
		},
		{
			desc:     "empty slice",
			actions:  []Action{},
			expected: []Action{ActionProceed},
		},
		{
			desc:    "only ActionContactOEM",
			actions: []Action{ActionContactOEM},
			expected: []Action{
				ActionProceed,
				ActionContactOEM,
			},
		},
		{
			desc:    "only ActionContactOSVendor",
			actions: []Action{ActionContactOSVendor},
			expected: []Action{
				ActionProceed,
				ActionContactOSVendor,
			},
		},
	} {
		result := InsertActionProceed(tc.actions)
		c.Check(result, DeepEquals, tc.expected, Commentf(tc.desc))
	}
}
