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
	"errors"
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
	"github.com/snapcore/secboot/internal/tpm2_device"
	. "gopkg.in/check.v1"
)

type runChecksSuite struct {
	tpm2_testutil.TPMSimulatorTest
	tpmPropertyModifierMixin
	tcglogReplayMixin
}

func (s *runChecksSuite) SetUpTest(c *C) {
	s.TPMSimulatorTest.SetUpTest(c)
	s.tpmPropertyModifierMixin.transport = s.Transport
	s.tcglogReplayMixin.impl = s
}

func (s *runChecksSuite) Tpm() *tpm2.TPMContext {
	return s.TPM
}

var _ = Suite(&runChecksSuite{})

type testRunChecksParams struct {
	env                  internal_efi.HostEnvironment
	tpmPropertyModifiers map[tpm2.Property]uint32
	enabledBanks         []tpm2.HashAlgorithmId
	prepare              func()
	flags                CheckFlags
	loadedImages         []secboot_efi.Image

	expectedPcrAlg            tpm2.HashAlgorithmId
	expectedUsedSecureBootCAs []*X509CertificateID
	expectedFlags             CheckResultFlags
}

func (s *runChecksSuite) testRunChecks(c *C, params *testRunChecksParams) (warnings []error, err error) {
	s.allocatePCRBanks(c, params.enabledBanks...)
	log, err := params.env.ReadEventLog()
	c.Assert(err, IsNil)
	s.resetTPMAndReplayLog(c, log, log.Algorithms...)
	s.addTPMPropertyModifiers(c, params.tpmPropertyModifiers)

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

	result, err := RunChecks(context.Background(), params.flags, params.loadedImages)
	if err != nil {
		return nil, err
	}

	c.Check(result.PCRAlg, Equals, params.expectedPcrAlg)
	c.Assert(result.UsedSecureBootCAs, HasLen, len(params.expectedUsedSecureBootCAs))
	for i, ca := range result.UsedSecureBootCAs {
		c.Check(ca, DeepEquals, params.expectedUsedSecureBootCAs[i])
	}
	c.Check(result.Flags, Equals, params.expectedFlags)

	dev, err := params.env.TPMDevice()
	c.Assert(err, IsNil)
	c.Assert(dev, testutil.ConvertibleTo, &tpmDevice{})
	c.Assert(dev.(*tpmDevice).TPMDevice, testutil.ConvertibleTo, &tpm2_testutil.TransportBackedDevice{})
	c.Check(dev.(*tpmDevice).TPMDevice.(*tpm2_testutil.TransportBackedDevice).NumberOpen(), Equals, 0)

	return result.Warnings.Unwrap(), nil
}

func (s *runChecksSuite) TestRunChecksGood(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 3)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodSHA384(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg:            tpm2.HashAlgorithmSHA384,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 3)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodSHA1(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitWeakPCRBanks,
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
		expectedPcrAlg:            tpm2.HashAlgorithmSHA1,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 3)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodEmptySHA384(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `the PCR bank for TPM_ALG_SHA384 is missing from the TCG log but active and with one or more empty PCRs on the TPM`)
	var epbe *EmptyPCRBanksError
	c.Check(errors.As(warning, &epbe), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodPostInstall(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PostInstallChecks,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 3)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodVirtualMachine(c *C) {
	family, err := s.TPM.GetCapabilityTPMProperty(tpm2.PropertyFamilyIndicator)
	c.Assert(err, IsNil)

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode("qemu", internal_efi.DetectVirtModeVM),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
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
			tpm2.PropertyPSFamilyIndicator: family,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerMSFT),
			tpm2.PropertyHRPersistentMin:   7, // The simulator seems to set this to 2
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitVirtualMachine,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, Equals, ErrVirtualMachineDetected)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodDiscreteTPMDetected(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (2 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with system security: cannot enable partial mitigation against discrete TPM reset attacks`)
	var hse *HostSecurityError
	c.Assert(errors.As(warning, &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, ErrNoPartialDiscreteTPMResetAttackMitigation), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodDiscreteTPMDetectedSL3(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 3,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (2 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | RequestPartialDiscreteTPMResetAttackMitigation,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 3)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodDiscreteTPMDetectedSL3NotProtected(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 3,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (2 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with system security: cannot enable partial mitigation against discrete TPM reset attacks`)
	var hse *HostSecurityError
	c.Assert(errors.As(warning, &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, ErrNoPartialDiscreteTPMResetAttackMitigation), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodDiscreteTPMDetectedHCRTM(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 4,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (2 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | RequestPartialDiscreteTPMResetAttackMitigation,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 3)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodDiscreteTPMDetectedHCRTMLocality4NotProtected(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 4,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (2 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with system security: cannot enable partial mitigation against discrete TPM reset attacks`)
	var hse *HostSecurityError
	c.Assert(errors.As(warning, &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, ErrNoPartialDiscreteTPMResetAttackMitigation), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodInvalidPCR0Value(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(0), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		flags: PermitNoPlatformFirmwareProfileSupport | PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedFlags:             NoPlatformFirmwareProfileSupport | NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform firmware \(PCR0\) measurements: PCR value mismatch \(actual from TPM 0xe9995745ca25279ec699688b70488116fe4d9f053cb0991dd71e82e7edfa66b5, reconstructed from log 0xa6602a7a403068b5556e78cc3f5b00c9c76d33d514093ca9b584dce7590e6c69\)`)
	var pfe *PlatformFirmwarePCRError
	c.Check(errors.As(warning, &pfe), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodInvalidPCR0ValueWithDiscreteTPM(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (2 << 1)}),
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
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(0), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		flags: PermitNoPlatformFirmwareProfileSupport | PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedFlags:             NoPlatformFirmwareProfileSupport | NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 5)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform firmware \(PCR0\) measurements: PCR value mismatch \(actual from TPM 0xe9995745ca25279ec699688b70488116fe4d9f053cb0991dd71e82e7edfa66b5, reconstructed from log 0xa6602a7a403068b5556e78cc3f5b00c9c76d33d514093ca9b584dce7590e6c69\)`)
	var pfe *PlatformFirmwarePCRError
	c.Check(errors.As(warning, &pfe), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with system security: cannot enable partial mitigation against discrete TPM reset attacks`)
	var hse *HostSecurityError
	c.Assert(errors.As(warning, &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, ErrNoPartialDiscreteTPMResetAttackMitigation), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[4]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

// TODO: Good test case for invalid PCR1 when we support it.

func (s *runChecksSuite) TestRunChecksGoodInvalidPCR2Value(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(2), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with drivers and apps \(PCR2\) measurements: PCR value mismatch \(actual from TPM 0xfa734a6a4d262d7405d47d48c0a1b127229ca808032555ad919ed5dd7c1f6519, reconstructed from log 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969\)`)
	var de *DriversAndAppsPCRError
	c.Check(errors.As(warning, &de), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

// TODO: Good test case for invalid PCR3 when we support it.

func (s *runChecksSuite) TestRunChecksGoodInvalidPCR4Value(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(4), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerCodeProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerCodeProfileSupport | NoBootManagerConfigProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with boot manager code \(PCR4\) measurements: PCR value mismatch \(actual from TPM 0x1c93930d6b26232e061eaa33ecf6341fae63ce598a0c6a26ee96a0828639c044, reconstructed from log 0x4bc74f3ffe49b4dd275c9f475887b68193e2db8348d72e1c3c9099c2dcfa85b0\)`)
	var bme *BootManagerCodePCRError
	c.Check(errors.As(warning, &bme), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

// TODO: Good test case for invalid PCR5 when we support it.

func (s *runChecksSuite) TestRunChecksGoodInvalidPCR7Value(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitNoSecureBootPolicyProfileSupport,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with secure boot policy \(PCR7\) measurements: PCR value mismatch \(actual from TPM 0xdf7b5d709755f1bd7142dd2f8c2d1195fc6b4dab5c78d41daf5c795da55db5f2, reconstructed from log 0xafc99bd8b298ea9b70d2796cb0ca22fe2b70d784691a1cae2aa3ba55edc365dc\)`)
	var sbe *SecureBootPolicyPCRError
	c.Check(errors.As(warning, &sbe), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodAddonDriversPresent(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitAddonDrivers,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	var adpe *AddonDriversPresentError
	c.Check(warning, ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
	c.Check(errors.As(warning, &adpe), testutil.IsTrue)
	c.Check(adpe.Drivers, DeepEquals, []*LoadedImageInfo{
		{
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
	})

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodVARDriversPresentWithInvalidPCR2Value(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(2), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitAddonDrivers,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 5)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with drivers and apps \(PCR2\) measurements: PCR value mismatch \(actual from TPM 0x33da7dc7c748c1767c14a1328487ad2f1a058cda30956405bc9ccf02a75bcfb9, reconstructed from log 0x6a16b79136a20b5fa1d3d3812165fddf6e2a4d9c5a682e15f26c6e4fbc8f4d04\)`)
	var de *DriversAndAppsPCRError
	c.Check(errors.As(warning, &de), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	var adpe *AddonDriversPresentError
	c.Check(warning, ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
	c.Check(errors.As(warning, &adpe), testutil.IsTrue)
	c.Check(adpe.Drivers, DeepEquals, []*LoadedImageInfo{
		{
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
	})

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[4]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodSysPrepAppsPresent(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				{Name: "SysPrepOrder", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1, 0x0}},
				{Name: "SysPrep0001", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: efitest.MakeVarPayload(c, &efi.LoadOption{
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitSysPrepApplications,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `system preparation applications were detected:
- Mock sysprep app path=\\PciRoot\(0x0\)\\Pci\(0x1d,0x0\)\\Pci\(0x0,0x0\)\\NVMe\(0x1,00-00-00-00-00-00-00-00\)\\HD\(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960\)\\\\EFI\\Dell\\sysprep.efi authenticode-digest=TPM_ALG_SHA256:11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4 load-option=SysPrep0001
`)
	var spape *SysPrepApplicationsPresentError
	c.Check(errors.As(warning, &spape), testutil.IsTrue)
	c.Check(spape.Apps, DeepEquals, []*LoadedImageInfo{
		{
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
	})

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodSysPrepAppsPresentWithInvalidPCR4Value(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				{Name: "SysPrepOrder", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1, 0x0}},
				{Name: "SysPrep0001", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: efitest.MakeVarPayload(c, &efi.LoadOption{
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
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(4), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerCodeProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitSysPrepApplications,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoBootManagerCodeProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 5)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with boot manager code \(PCR4\) measurements: PCR value mismatch \(actual from TPM 0xe17df8a36f5af4ae49c1ca567f6194bb06269c81339d87be07a3b3993edc6773, reconstructed from log 0x37704821d1e3005e2b31a7011ae80beec847c639699ed234bcaf9e0dd2fe47fe\)`)
	var bme *BootManagerCodePCRError
	c.Check(errors.As(warning, &bme), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `system preparation applications were detected:
- Mock sysprep app path=\\PciRoot\(0x0\)\\Pci\(0x1d,0x0\)\\Pci\(0x0,0x0\)\\NVMe\(0x1,00-00-00-00-00-00-00-00\)\\HD\(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960\)\\\\EFI\\Dell\\sysprep.efi authenticode-digest=TPM_ALG_SHA256:11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4 load-option=SysPrep0001
`)
	var spape *SysPrepApplicationsPresentError
	c.Check(errors.As(warning, &spape), testutil.IsTrue)
	c.Check(spape.Apps, DeepEquals, []*LoadedImageInfo{
		{
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
	})

	warning = warnings[4]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodAbsoluteActive(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitAbsoluteComputrace,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, Equals, ErrAbsoluteComputraceActive)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodAbsoluteActiveWithInvalidPCR4Value(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(4), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerCodeProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitAbsoluteComputrace,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerCodeProfileSupport | NoBootManagerConfigProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 5)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with boot manager code \(PCR4\) measurements: PCR value mismatch \(actual from TPM 0x7b023f4133ed7e29f9445fa186592378dbaac21c2a9737f37e170b3062e174cb, reconstructed from log 0xf9464e8dcd68eddcaa704e885ba08a129bc4d0178f7f88593c68be8a27bc5f01\)`)
	var bme *BootManagerCodePCRError
	c.Check(errors.As(warning, &bme), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, Equals, ErrAbsoluteComputraceActive)

	warning = warnings[4]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodNoBootManagerCodeProfileSupport(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerCodeProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerCodeProfileSupport | NoBootManagerConfigProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with boot manager code \(PCR4\) measurements: log contains unexpected EV_EFI_BOOT_SERVICES_APPLICATION digest for OS-present application mock image: log digest matches flat file digest \(0xd5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0\) which suggests an image loaded outside of the LoadImage API and firmware lacking support for the EFI_TCG2_PROTOCOL and\/or the PE_COFF_IMAGE flag`)
	var bme *BootManagerCodePCRError
	c.Check(errors.As(warning, &bme), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodPreOSSecureBootAuthByEnrolledDigests(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA256,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitAddonDrivers | PermitPreOSSecureBootAuthByEnrolledDigests,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 5)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	var adpe *AddonDriversPresentError
	c.Check(warning, ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
	c.Check(errors.As(warning, &adpe), testutil.IsTrue)
	c.Check(adpe.Drivers, DeepEquals, []*LoadedImageInfo{
		{
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
	})

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)

	warning = warnings[4]
	c.Check(warning, Equals, ErrPreOSSecureBootAuthByEnrolledDigests)
}

func (s *runChecksSuite) TestRunChecksGoodPreOSSecureBootAuthByEnrolledDigestsWithInvalidPCR7Value(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA256,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitNoSecureBootPolicyProfileSupport | PermitAddonDrivers | PermitPreOSSecureBootAuthByEnrolledDigests,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 6)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with secure boot policy \(PCR7\) measurements: PCR value mismatch \(actual from TPM 0x41cc3a26db1bf43609d3fb0b15b1e87a3f68822a6770ab1b912e1b07e6e49952, reconstructed from log 0x3cb6f84240068b76a933839a170565fdf5de48ff7d6ef361b6474a41e2cd60af\)`)
	var sbe *SecureBootPolicyPCRError
	c.Check(errors.As(warning, &sbe), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	var adpe *AddonDriversPresentError
	c.Check(warning, ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
	c.Check(errors.As(warning, &adpe), testutil.IsTrue)
	c.Check(adpe.Drivers, DeepEquals, []*LoadedImageInfo{
		{
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
	})

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[4]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)

	warning = warnings[5]
	c.Check(warning, Equals, ErrPreOSSecureBootAuthByEnrolledDigests)
}

func (s *runChecksSuite) TestRunChecksGoodWeakSecureBootAlgs(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA1,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitAddonDrivers | PermitWeakSecureBootAlgorithms | PermitPreOSSecureBootAuthByEnrolledDigests,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 6)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	var adpe *AddonDriversPresentError
	c.Check(warning, ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
	c.Check(errors.As(warning, &adpe), testutil.IsTrue)
	c.Check(adpe.Drivers, DeepEquals, []*LoadedImageInfo{
		{
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
	})

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)

	warning = warnings[4]
	c.Check(warning, Equals, ErrWeakSecureBootAlgorithmDetected)

	warning = warnings[5]
	c.Check(warning, Equals, ErrPreOSSecureBootAuthByEnrolledDigests)
}

func (s *runChecksSuite) TestRunChecksGoodWeakSecureBootAlgsWithInvalidPCR7Value(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA1,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitNoSecureBootPolicyProfileSupport | PermitAddonDrivers | PermitWeakSecureBootAlgorithms | PermitPreOSSecureBootAuthByEnrolledDigests,
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
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 7)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with secure boot policy \(PCR7\) measurements: PCR value mismatch \(actual from TPM 0x97fe6e8a33309869583ba98ecc25b5c528270db96e41dfdd75ebf20eb7562441, reconstructed from log 0x5e99922ef40f9e7e64ca71f1128423e8400c9e5fe60cfbad3d905bb91b9e8949\)`)
	var sbe *SecureBootPolicyPCRError
	c.Check(errors.As(warning, &sbe), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	var adpe *AddonDriversPresentError
	c.Check(warning, ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)
	c.Check(errors.As(warning, &adpe), testutil.IsTrue)
	c.Check(adpe.Drivers, DeepEquals, []*LoadedImageInfo{
		{
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
	})

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[4]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)

	warning = warnings[5]
	c.Check(warning, Equals, ErrWeakSecureBootAlgorithmDetected)

	warning = warnings[6]
	c.Check(warning, Equals, ErrPreOSSecureBootAuthByEnrolledDigests)
}

func (s *runChecksSuite) TestRunChecksGoodNoSecureBootPolicyProfileSupport(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitNoSecureBootPolicyProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
		expectedFlags:  NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with secure boot policy \(PCR7\) measurements: deployed mode should be enabled in order to generate secure boot profiles`)
	c.Check(errors.Is(warning, ErrNoDeployedMode), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodTPMLockout(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			// Trip the DA logic by setting newMaxTries to 0. This also prevents
			// the lockout hierarchy availability test from clearing the lockout,
			// although that test does still run.
			c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 10000, 10000, nil), IsNil)
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `error with TPM2 device: TPM is in DA lockout mode`)
	var tde *TPM2DeviceError
	c.Assert(errors.As(warning, &tde), testutil.IsTrue)
	c.Check(errors.Is(tde, ErrTPMLockout), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksGoodPostInstallLockoutAvailabilityCheckSkipped(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			// Take ownership of the lockout hierarchy
			s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PostInstallChecks,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 4)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `availability of TPM's lockout hierarchy was not checked because the lockout hierarchy has an authorization value set`)
	c.Check(errors.Is(warning, ErrTPMLockoutAvailabilityNotChecked), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadVirtualMachine(c *C) {
	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode("qemu", internal_efi.DetectVirtModeVM),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})
	c.Check(err, Equals, ErrVirtualMachineDetected)
}

func (s *runChecksSuite) TestRunChecksBadNotEFI(c *C) {
	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
	})
	c.Check(err, Equals, ErrSystemNotEFI)
}

func (s *runChecksSuite) TestRunChecksBadTPM2DeviceDisabled(c *C) {
	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
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
			// Disable owner and endorsement hierarchies
			c.Assert(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
			c.Assert(s.TPM.HierarchyControl(s.TPM.EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)
		},
	})
	c.Check(err, ErrorMatches, `error with TPM2 device: TPM2 device is present but is currently disabled by the platform firmware`)
	c.Check(errors.Is(err, ErrTPMDisabled), testutil.IsTrue)
	var te *TPM2DeviceError
	c.Check(errors.As(err, &te), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadTPMOwnedHierarchiesAndLockedOut(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
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
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerCodeProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitNoSecureBootPolicyProfileSupport,
	})
	c.Check(err, ErrorMatches, `error with TPM2 device: one or more of the TPM hierarchies is already owned:
- TPM_RH_LOCKOUT has an authorization value
`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	var te *TPM2DeviceError
	c.Assert(errors.As(errs[0], &te), testutil.IsTrue)
	var ohe *TPM2OwnedHierarchiesError
	c.Check(errors.As(te, &ohe), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadInvalidPCR0Value(c *C) {
	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{}, 1, map[uint32]uint64{0x13a: (3 << 1)}),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
	})
	c.Check(err, ErrorMatches, `error with or detected from measurement log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256: error with platform firmware \(PCR0\) measurements: PCR value mismatch \(actual from TPM 0xe9995745ca25279ec699688b70488116fe4d9f053cb0991dd71e82e7edfa66b5, reconstructed from log 0xa6602a7a403068b5556e78cc3f5b00c9c76d33d514093ca9b584dce7590e6c69\).
`)
	var te *MeasuredBootError
	c.Assert(errors.As(err, &te), testutil.IsTrue)
	var pe *NoSuitablePCRAlgorithmError
	c.Check(errors.As(te, &pe), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadInvalidPCR2Value(c *C) {
	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{}, 1, map[uint32]uint64{0x13a: (3 << 1)}),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
	})
	c.Check(err, ErrorMatches, `error with or detected from measurement log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256: error with drivers and apps \(PCR2\) measurements: PCR value mismatch \(actual from TPM 0xfa734a6a4d262d7405d47d48c0a1b127229ca808032555ad919ed5dd7c1f6519, reconstructed from log 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969\).
`)
	var te *MeasuredBootError
	c.Assert(errors.As(err, &te), testutil.IsTrue)
	var pe *NoSuitablePCRAlgorithmError
	c.Check(errors.As(te, &pe), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadInvalidPCR4Value(c *C) {
	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{}, 1, map[uint32]uint64{0x13a: (3 << 1)}),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
	})
	c.Check(err, ErrorMatches, `error with or detected from measurement log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256: error with boot manager code \(PCR4\) measurements: PCR value mismatch \(actual from TPM 0x1c93930d6b26232e061eaa33ecf6341fae63ce598a0c6a26ee96a0828639c044, reconstructed from log 0x4bc74f3ffe49b4dd275c9f475887b68193e2db8348d72e1c3c9099c2dcfa85b0\).
`)
	var te *MeasuredBootError
	c.Assert(errors.As(err, &te), testutil.IsTrue)
	var pe *NoSuitablePCRAlgorithmError
	c.Check(errors.As(te, &pe), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadInvalidPCR7Value(c *C) {
	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{}, 1, map[uint32]uint64{0x13a: (3 << 1)}),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
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
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
	})
	c.Check(err, ErrorMatches, `error with or detected from measurement log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256: error with secure boot policy \(PCR7\) measurements: PCR value mismatch \(actual from TPM 0xdf7b5d709755f1bd7142dd2f8c2d1195fc6b4dab5c78d41daf5c795da55db5f2, reconstructed from log 0xafc99bd8b298ea9b70d2796cb0ca22fe2b70d784691a1cae2aa3ba55edc365dc\).
`)
	var te *MeasuredBootError
	c.Assert(errors.As(err, &te), testutil.IsTrue)
	var pe *NoSuitablePCRAlgorithmError
	c.Check(errors.As(te, &pe), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadNoHardwareRootOfTrustError(c *C) {
	// Test case with no hardware root-of-trust configured.
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
	})
	c.Check(err, ErrorMatches, `error with system security: encountered an error when checking Intel BootGuard configuration: no hardware root-of-trust properly configured: ME is in manufacturing mode`)

	var hse *HostSecurityError
	c.Assert(errors.As(err, &hse), testutil.IsTrue)
	var rote *NoHardwareRootOfTrustError
	c.Check(errors.As(hse, &rote), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadHostSecurityMissingIntelMEModule(c *C) {
	// Test case where host security checks fail because the intel ME kernel module is missing.
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0", map[string]string{"PCI_CLASS": "78000", "PCI_ID": "8086:7E70"}, "pci", nil, nil),
	}

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
	})
	c.Check(err, ErrorMatches, `error with system security: encountered an error when checking Intel BootGuard configuration: the kernel module "mei_me" must be loaded`)
	var hse *HostSecurityError
	c.Assert(errors.As(err, &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, MissingKernelModuleError("mei_me")), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadHostSecurityMissingMSR(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
	})
	c.Check(err, ErrorMatches, `error with system security: encountered an error when checking Intel CPU debugging configuration: the kernel module "msr" must be loaded`)
	var hse *HostSecurityError
	c.Assert(errors.As(err, &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, MissingKernelModuleError("msr")), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadUEFIDebuggingEnabledAndNoKernelIOMMU(c *C) {
	// Test case with more than one host security error.
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:       []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				FirmwareDebugger: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(false)),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerCodeProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitNoSecureBootPolicyProfileSupport,
	})
	c.Check(err, ErrorMatches, `2 errors detected:
- error with system security: the platform firmware contains a debugging endpoint enabled
- error with system security: no kernel IOMMU support was detected
`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 2)

	var hse *HostSecurityError
	c.Assert(errors.As(errs[0], &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, ErrUEFIDebuggingEnabled), testutil.IsTrue)

	c.Assert(errors.As(errs[1], &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, ErrNoKernelIOMMU), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadSHA1(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
	})
	c.Check(err, ErrorMatches, `error with or detected from measurement log: no suitable PCR algorithm available:
- TPM_ALG_SHA512: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA384: the PCR bank is missing from the TCG log.
- TPM_ALG_SHA256: the PCR bank is missing from the TCG log.
`)

	var e *NoSuitablePCRAlgorithmError
	c.Assert(errors.As(err, &e), testutil.IsTrue)

	// Test that we can access individual errors.
	c.Check(e.Errs[tpm2.HashAlgorithmSHA512], DeepEquals, []error{ErrPCRBankMissingFromLog})
	c.Check(e.Errs[tpm2.HashAlgorithmSHA384], DeepEquals, []error{ErrPCRBankMissingFromLog})
	c.Check(e.Errs[tpm2.HashAlgorithmSHA256], DeepEquals, []error{ErrPCRBankMissingFromLog})
}

func (s *runChecksSuite) TestRunChecksBadMandatoryPCR1(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	var pce *PlatformConfigPCRError
	c.Check(errors.As(errs[0], &pce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadMandatoryPCR3(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(errs[0], &dce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadMandatoryPCR5(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(errs[0], &bmce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadAddonDriversPresent(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `addon drivers were detected:
- \[no description\] path=\\PciRoot\(0x0\)\\Pci\(0x2,0x1c\)\\Pci\(0x0,0x0\)\\Offset\(0x38,0x11dff\) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6
`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	var adpe *AddonDriversPresentError
	c.Check(errors.As(errs[0], &adpe), testutil.IsTrue)
	c.Check(adpe.Drivers, DeepEquals, []*LoadedImageInfo{
		{
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
	})
}

func (s *runChecksSuite) TestRunChecksBadSysPrepAppsPresent(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				{Name: "SysPrepOrder", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1, 0x0}},
				{Name: "SysPrep0001", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: efitest.MakeVarPayload(c, &efi.LoadOption{
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `system preparation applications were detected:
- Mock sysprep app path=\\PciRoot\(0x0\)\\Pci\(0x1d,0x0\)\\Pci\(0x0,0x0\)\\NVMe\(0x1,00-00-00-00-00-00-00-00\)\\HD\(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960\)\\\\EFI\\Dell\\sysprep.efi authenticode-digest=TPM_ALG_SHA256:11b68a5ce0facfa4233cb71140e3d59c686bc7a176a49a520947c57247fe86f4 load-option=SysPrep0001
`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	var spape *SysPrepApplicationsPresentError
	c.Check(errors.As(errs[0], &spape), testutil.IsTrue)
	c.Check(spape.Apps, DeepEquals, []*LoadedImageInfo{
		{
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
	})
}

func (s *runChecksSuite) TestRunChecksBadAbsoluteActive(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `Absolute was detected to be active and it is advised that this is disabled`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	c.Check(errors.Is(errs[0], ErrAbsoluteComputraceActive), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadWeakSecureBootAlgs(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA1,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitAddonDrivers,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `2 errors detected:
- a weak cryptographic algorithm was detected during secure boot verification
- some pre-OS components were authenticated from the authorized signature database using an enrolled Authenticode digest
`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 2)

	c.Check(errors.Is(errs[0], ErrWeakSecureBootAlgorithmDetected), testutil.IsTrue)
	c.Check(errors.Is(errs[1], ErrPreOSSecureBootAuthByEnrolledDigests), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadPreOSSecureBootAuthByEnrolledDigests(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA256,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitAddonDrivers,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `some pre-OS components were authenticated from the authorized signature database using an enrolled Authenticode digest`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	c.Check(errors.Is(errs[0], ErrPreOSSecureBootAuthByEnrolledDigests), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadEFIVariableAccessErrorBootOptionSupport(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `cannot access EFI variable: cannot obtain boot option support: variable access failed because of a hardware error`)

	var e *EFIVariableAccessError
	c.Assert(errors.As(err, &e), testutil.IsTrue)
	c.Check(errors.Is(e, efi.ErrVarDeviceError), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadNoBootManagerCodeProfileSupport(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `error with boot manager code \(PCR4\) measurements: log contains unexpected EV_EFI_BOOT_SERVICES_APPLICATION digest for OS-present application mock image: log digest matches flat file digest \(0xd5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0\) which suggests an image loaded outside of the LoadImage API and firmware lacking support for the EFI_TCG2_PROTOCOL and\/or the PE_COFF_IMAGE flag`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	var bce *BootManagerCodePCRError
	c.Check(errors.As(errs[0], &bce), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadEFIVariableAccessErrorSetupMode(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			efitest.WithSysfsDevices(devices...),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `cannot access EFI variable: cannot compute secure boot mode: cannot read SetupMode variable: variable does not exist`)

	var e *EFIVariableAccessError
	c.Assert(errors.As(err, &e), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadNoSecureBootPolicyProfileSupport(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `error with secure boot policy \(PCR7\) measurements: deployed mode should be enabled in order to generate secure boot profiles`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	var sbe *SecureBootPolicyPCRError
	c.Assert(errors.As(errs[0], &sbe), testutil.IsTrue)
	c.Check(errors.Is(sbe, ErrNoDeployedMode), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadNoSecureBootPolicyProfileSupportSecureBootDisabled(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				SecureBootDisabled: true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `error with secure boot policy \(PCR7\) measurements: secure boot should be enabled in order to generate secure boot profiles`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	var sbe *SecureBootPolicyPCRError
	c.Assert(errors.As(errs[0], &sbe), testutil.IsTrue)
	c.Check(errors.Is(sbe, ErrNoSecureBoot), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadNoSecureBootPolicyProfileSupportSecureBootDisabledAndNoSBATLevel(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				SecureBootDisabled: true,
				NoSBAT:             true,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `error with secure boot policy \(PCR7\) measurements: secure boot should be enabled in order to generate secure boot profiles`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 1)

	var sbe *SecureBootPolicyPCRError
	c.Assert(errors.As(errs[0], &sbe), testutil.IsTrue)
	c.Check(errors.Is(sbe, ErrNoSecureBoot), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadTPMHierarchiesOwnedAndNoSecureBootPolicySupport(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		prepare: func() {
			c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.LockoutHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)
		},
		flags: PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
	})
	c.Assert(err, ErrorMatches, `2 errors detected:
- error with TPM2 device: one or more of the TPM hierarchies is already owned:
  - TPM_RH_LOCKOUT has an authorization value
- error with secure boot policy \(PCR7\) measurements: deployed mode should be enabled in order to generate secure boot profiles
`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 2)

	var te *TPM2DeviceError
	c.Assert(errors.As(errs[0], &te), testutil.IsTrue)
	var ohe *TPM2OwnedHierarchiesError
	c.Check(errors.As(te, &ohe), testutil.IsTrue)

	var sbpe *SecureBootPolicyPCRError
	c.Check(errors.As(errs[1], &sbpe), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadInsufficientDMAProtectionAndNoBootManagerCodeProfileSupport(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				DMAProtection: efitest.DMAProtectionDisabled,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
	c.Assert(err, ErrorMatches, `3 errors detected:
- error with system security: the platform firmware indicates that DMA protections are insufficient
- error with boot manager code \(PCR4\) measurements: cannot verify correctness of EV_EFI_BOOT_SERVICES_APPLICATION event digest: not enough images supplied
- error with secure boot policy \(PCR7\) measurements: unexpected EV_EFI_ACTION event "DMA Protection Disabled" whilst measuring config
`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 3)

	var hse *HostSecurityError
	c.Assert(errors.As(errs[0], &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, ErrInsufficientDMAProtection), testutil.IsTrue)

	var bme *BootManagerCodePCRError
	c.Check(errors.As(errs[1], &bme), testutil.IsTrue)

	var sbpe *SecureBootPolicyPCRError
	c.Check(errors.As(errs[2], &sbpe), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksBadInsufficientDMAProtectionAndNoKernelIOMMU(c *C) {
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

	_, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				DMAProtection: efitest.DMAProtectionDisabled,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport,
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
	})
	c.Assert(err, ErrorMatches, `3 errors detected:
- error with system security: the platform firmware indicates that DMA protections are insufficient
- error with system security: no kernel IOMMU support was detected
- error with secure boot policy \(PCR7\) measurements: unexpected EV_EFI_ACTION event "DMA Protection Disabled" whilst measuring config
`)

	var ce CompoundError
	c.Assert(err, Implements, &ce)
	ce = err.(CompoundError)
	errs := ce.Unwrap()
	c.Assert(errs, HasLen, 3)

	var hse *HostSecurityError
	c.Assert(errors.As(errs[0], &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, ErrInsufficientDMAProtection), testutil.IsTrue)

	c.Assert(errors.As(errs[1], &hse), testutil.IsTrue)
	c.Check(errors.Is(hse, ErrNoKernelIOMMU), testutil.IsTrue)

	var sbpe *SecureBootPolicyPCRError
	c.Check(errors.As(errs[2], &sbpe), testutil.IsTrue)
}

func (s *runChecksSuite) TestRunChecksAllowInsufficientDMAProtection(c *C) {
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

	warnings, err := s.testRunChecks(c, &testRunChecksParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(newTpmDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1), nil, tpm2_device.ErrNoPPI)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				DMAProtection: efitest.DMAProtectionDisabled,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
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
		flags:        PermitNoPlatformConfigProfileSupport | PermitNoDriversAndAppsConfigProfileSupport | PermitNoBootManagerConfigProfileSupport | PermitInsufficientDMAProtection,
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
	})
	c.Assert(err, IsNil)
	c.Assert(warnings, HasLen, 5)

	warning := warnings[0]
	c.Check(warning, ErrorMatches, `the platform firmware indicates that DMA protections are insufficient`)
	c.Check(errors.Is(warning, ErrInsufficientDMAProtection), testutil.IsTrue)

	warning = warnings[1]
	c.Check(warning, ErrorMatches, `no kernel IOMMU support was detected`)
	c.Check(errors.Is(warning, ErrNoKernelIOMMU), testutil.IsTrue)

	warning = warnings[2]
	c.Check(warning, ErrorMatches, `error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet, see https://github.com/canonical/secboot/issues/322`)
	var pce *PlatformConfigPCRError
	c.Check(errors.As(warning, &pce), testutil.IsTrue)

	warning = warnings[3]
	c.Check(warning, ErrorMatches, `error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet, see https://github.com/canonical/secboot/issues/341`)
	var dce *DriversAndAppsConfigPCRError
	c.Check(errors.As(warning, &dce), testutil.IsTrue)

	warning = warnings[4]
	c.Check(warning, ErrorMatches, `error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet, see https://github.com/canonical/secboot/issues/323`)
	var bmce *BootManagerConfigPCRError
	c.Check(errors.As(warning, &bmce), testutil.IsTrue)
}
