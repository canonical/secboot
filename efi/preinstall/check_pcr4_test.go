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
	"errors"
	"io"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	secboot_efi "github.com/snapcore/secboot/efi"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type pcr4Suite struct{}

var _ = Suite(&pcr4Suite{})

func (s *pcr4Suite) TestReadLoadOptionFromLog(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	opt, err := ReadLoadOptionFromLog(log, 3)
	c.Assert(err, IsNil)
	c.Check(opt, DeepEquals, &efi.LoadOption{
		Attributes:  1,
		Description: "ubuntu",
		FilePath: efi.DevicePath{
			&efi.HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         efi.GPT},
			efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"),
		},
		OptionalData: []byte{},
	})
}

func (s *pcr4Suite) TestReadLoadOptionFromLogNotExist(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	_, err := ReadLoadOptionFromLog(log, 10)
	c.Check(err, ErrorMatches, `cannot find specified boot option`)
}

func (s *pcr4Suite) TestReadLoadOptionFromLogInvalidData(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.PlatformConfigPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableBoot {
			continue
		}
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		c.Assert(ok, testutil.IsTrue)
		if data.UnicodeName != "Boot0003" {
			continue
		}
		ev.Data = &invalidEventData{errors.New("some error")}
	}
	_, err := ReadLoadOptionFromLog(log, 3)
	c.Check(err, ErrorMatches, `boot variable measurement has wrong data format: some error`)
}

func (s *pcr4Suite) TestReadLoadOptionFromLogInvalidVariableName(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.PlatformConfigPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableBoot {
			continue
		}
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		c.Assert(ok, testutil.IsTrue)
		data.VariableName = efi.MakeGUID(0x6be4d043, 0x2ded, 0x4669, 0xa43b, [...]byte{0x91, 0x37, 0xb8, 0xa9, 0xd1, 0xa4})
	}
	_, err := ReadLoadOptionFromLog(log, 3)
	c.Check(err, ErrorMatches, `cannot find specified boot option`)
}

func (s *pcr4Suite) TestIsLaunchedFromLoadOptionGood(c *C) {
	opt := &efi.LoadOption{
		Attributes:  1,
		Description: "ubuntu",
		FilePath: efi.DevicePath{
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
				NamespaceUUID: 0x0},
			&efi.HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         efi.GPT},
			efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"),
		},
	}
	ev := &tcglog.Event{
		PCRIndex:  internal_efi.BootManagerCodePCR,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x6556c018,
			LengthInMemory:   955072,
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
					NamespaceUUID: 0x0},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"),
			},
		},
	}

	yes, err := IsLaunchedFromLoadOption(ev, opt)
	c.Check(err, IsNil)
	c.Check(yes, testutil.IsTrue)
}

func (s *pcr4Suite) TestIsLaunchedFromLoadOptionGoodShortFormOpt(c *C) {
	opt := &efi.LoadOption{
		Attributes:  1,
		Description: "ubuntu",
		FilePath: efi.DevicePath{
			&efi.HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         efi.GPT},
			efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"),
		},
	}
	ev := &tcglog.Event{
		PCRIndex:  internal_efi.BootManagerCodePCR,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x6556c018,
			LengthInMemory:   955072,
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
					NamespaceUUID: 0x0},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"),
			},
		},
	}

	yes, err := IsLaunchedFromLoadOption(ev, opt)
	c.Check(err, IsNil)
	c.Check(yes, testutil.IsTrue)
}

func (s *pcr4Suite) TestIsLaunchedFromLoadOptionGoodRemovableCDROM(c *C) {
	opt := &efi.LoadOption{
		Attributes:  1,
		Description: "ubuntu",
		FilePath: efi.DevicePath{
			&efi.ACPIDevicePathNode{
				HID: 0x0a0341d0,
				UID: 0x0},
			&efi.PCIDevicePathNode{
				Function: 0x0,
				Device:   0x1d},
			&efi.PCIDevicePathNode{
				Function: 0x0,
				Device:   0x1},
		},
	}
	ev := &tcglog.Event{
		PCRIndex:  internal_efi.BootManagerCodePCR,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x6556c018,
			LengthInMemory:   955072,
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x1d},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x1},
				&efi.CDROMDevicePathNode{
					BootEntry:      0,
					PartitionStart: 0x800,
					PartitionSize:  0x100000},
				efi.FilePathDevicePathNode("\\EFI\\BOOT\\BOOTX64.EFI"),
			},
		},
	}

	yes, err := IsLaunchedFromLoadOption(ev, opt)
	c.Check(err, IsNil)
	c.Check(yes, testutil.IsTrue)
}

func (s *pcr4Suite) TestIsLaunchedFromLoadOptionGoodRemovableUSB(c *C) {
	opt := &efi.LoadOption{
		Attributes:  1,
		Description: "ubuntu",
		FilePath: efi.DevicePath{
			&efi.ACPIDevicePathNode{
				HID: 0x0a0341d0,
				UID: 0x0},
			&efi.PCIDevicePathNode{
				Function: 0x0,
				Device:   0x8},
			&efi.USBDevicePathNode{
				ParentPortNumber: 2,
				InterfaceNumber:  0},
		},
	}
	ev := &tcglog.Event{
		PCRIndex:  internal_efi.BootManagerCodePCR,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x6556c018,
			LengthInMemory:   955072,
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x8},
				&efi.USBDevicePathNode{
					ParentPortNumber: 2,
					InterfaceNumber:  0},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\BOOT\\BOOTX64.EFI"),
			},
		},
	}

	yes, err := IsLaunchedFromLoadOption(ev, opt)
	c.Check(err, IsNil)
	c.Check(yes, testutil.IsTrue)
}

func (s *pcr4Suite) TestIsLaunchedFromLoadOptionNoMatch(c *C) {
	opt := &efi.LoadOption{
		Attributes:  1,
		Description: "ubuntu",
		FilePath: efi.DevicePath{
			&efi.HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x1e482b5b, 0x6600, 0x427f, 0xb394, [...]uint8{0x9a, 0x68, 0x82, 0x3e, 0x55, 0x04})),
				MBRType:         efi.GPT},
			efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"),
		},
	}
	ev := &tcglog.Event{
		PCRIndex:  internal_efi.BootManagerCodePCR,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x6556c018,
			LengthInMemory:   955072,
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x1d},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x1},
				&efi.CDROMDevicePathNode{
					BootEntry:      0,
					PartitionStart: 0x800,
					PartitionSize:  0x100000},
				efi.FilePathDevicePathNode("\\EFI\\BOOT\\BOOTX64.EFI"),
			},
		},
	}

	yes, err := IsLaunchedFromLoadOption(ev, opt)
	c.Check(err, IsNil)
	c.Check(yes, testutil.IsFalse)
}

func (s *pcr4Suite) TestIsLaunchedFromLoadOptionNoMatchRemovable(c *C) {
	opt := &efi.LoadOption{
		Attributes:  1,
		Description: "ubuntu",
		FilePath: efi.DevicePath{
			&efi.ACPIDevicePathNode{
				HID: 0x0a0341d0,
				UID: 0x0},
			&efi.PCIDevicePathNode{
				Function: 0x0,
				Device:   0x8},
			&efi.USBDevicePathNode{
				ParentPortNumber: 2,
				InterfaceNumber:  0},
		},
	}
	ev := &tcglog.Event{
		PCRIndex:  internal_efi.BootManagerCodePCR,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x6556c018,
			LengthInMemory:   955072,
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
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\BOOT\\BOOTX64.EFI"),
			},
		},
	}

	yes, err := IsLaunchedFromLoadOption(ev, opt)
	c.Check(err, IsNil)
	c.Check(yes, testutil.IsFalse)
}

func (s *pcr4Suite) TestIsLaunchedFromLoadOptionEmptyDevicePath(c *C) {
	opt := &efi.LoadOption{
		Attributes:  1,
		Description: "ubuntu",
		FilePath: efi.DevicePath{
			&efi.HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         efi.GPT},
			efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"),
		},
	}
	ev := &tcglog.Event{
		PCRIndex:  internal_efi.BootManagerCodePCR,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x6556c018,
			LengthInMemory:   955072,
			DevicePath:       efi.DevicePath{},
		},
	}

	_, err := IsLaunchedFromLoadOption(ev, opt)
	c.Check(err, ErrorMatches, `EV_EFI_BOOT_SERVICES_APPLICATION event has empty device path`)
}

func (s *pcr4Suite) TestIsLaunchedFromLoadOptionNotActive(c *C) {
	opt := &efi.LoadOption{
		Attributes:  0,
		Description: "ubuntu",
		FilePath: efi.DevicePath{
			&efi.HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         efi.GPT},
			efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"),
		},
	}
	ev := &tcglog.Event{
		PCRIndex:  internal_efi.BootManagerCodePCR,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x6556c018,
			LengthInMemory:   955072,
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
					NamespaceUUID: 0x0},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi"),
			},
		},
	}

	_, err := IsLaunchedFromLoadOption(ev, opt)
	c.Check(err, ErrorMatches, `boot option is not active`)
}

type testCheckBootManagerCodeMeasurementsParams struct {
	env            internal_efi.HostEnvironment
	pcrAlg         tpm2.HashAlgorithmId
	images         []secboot_efi.Image
	expectedResult BootManagerCodeResultFlags
}

func (s *pcr4Suite) testCheckBootManagerCodeMeasurements(c *C, params *testCheckBootManagerCodeMeasurementsParams) error {
	log, err := params.env.ReadEventLog()
	c.Assert(err, IsNil)

	restore := MockEfiComputePeImageDigest(func(alg crypto.Hash, r io.ReaderAt, sz int64) ([]byte, error) {
		c.Check(alg, Equals, params.pcrAlg.GetHash())
		c.Assert(r, testutil.ConvertibleTo, &mockImageReader{})
		imageReader := r.(*mockImageReader)
		c.Check(sz, Equals, int64(len(imageReader.contents)))
		return imageReader.digest, nil
	})
	defer restore()

	result, err := CheckBootManagerCodeMeasurements(context.Background(), params.env, log, params.pcrAlg, params.images)
	if err != nil {
		return err
	}
	c.Check(result, Equals, params.expectedResult)
	return nil
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsGoodSHA256(c *C) {
	// Test good result with SHA-256
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		expectedResult: 0,
	})
	c.Check(err, IsNil)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsGoodSHA384(c *C) {
	// Test good result with SHA-384, when log also contains SHA-256
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA384,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "030ac3c913dab858f1d69239115545035cff671d6229f95577bb0ffbd827b35abaf6af6bfd223e04ecc9b60a9803642d")},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "6c2df9007211786438be210b6908f2935d0b25ebdcd2c65621826fd2ec55fb9fbacbfe080d48db98f0ef970273b8254a")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "42f61b3089f5ce0646b422a59c9632065db2630f3e5b01690e63c41420ed31f10ff2a191f3440f9501109fc85f7fb00f")},
		},
		expectedResult: 0,
	})
	c.Check(err, IsNil)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsGoodWithSysprepApp(c *C) {
	// Test good result with sysprep application in log before OS-present
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		expectedResult: BootManagerCodeSysprepAppsPresent,
	})
	c.Check(err, IsNil)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsGoodWithAbsolute(c *C) {
	// Test good result with Absolute running as part of OS-present before shim
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		expectedResult: BootManagerCodeAbsoluteComputraceRunning,
	})
	c.Check(err, IsNil)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsGoodWithMissingImages(c *C) {
	// Test good result with missing boot images - the function needs at least the IBL (in our case, shim) and SBL (in our case, grub)
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
		},
		expectedResult: BootManagerCodeNotAllLaunchDigestsVerified,
	})
	c.Check(err, IsNil)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsGoodWithoutCallingEFIApplicationEvent(c *C) {
	// Test good result with log without EV_EFI_ACTION "Calling EFI Application from Boot Option" event
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				NoCallingEFIApplicationEvent: true,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		expectedResult: 0,
	})
	c.Check(err, IsNil)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsGoodSkipOtherEventTypesInOSPresent(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	var addedEvent bool
	for _, ev := range log.Events {
		eventsCopy = append(eventsCopy, ev)
		if ev.PCRIndex == internal_efi.BootManagerCodePCR && ev.EventType == tcglog.EventTypeEFIBootServicesApplication && !addedEvent {
			addedEvent = true
			eventsCopy = append(eventsCopy, &tcglog.Event{
				PCRIndex:  internal_efi.BootManagerCodePCR,
				EventType: tcglog.EventTypeIPL,
				Data:      tcglog.StringEventData("some data"),
				Digests: map[tpm2.HashAlgorithmId]tpm2.Digest{
					tpm2.HashAlgorithmSHA256: tcglog.ComputeStringEventDigest(crypto.SHA256, "some data"),
				},
			})
		}
	}
	log.Events = eventsCopy

	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		expectedResult: 0,
	})
	c.Check(err, IsNil)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadNoImages(c *C) {
	// Test error result because no load images were supplied
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `at least the initial EFI application loaded during this boot must be supplied`)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadBootOptionSupport(c *C) {
	// Test error result because of invalid BootOptionSupport
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
		},
	})
	c.Check(err, ErrorMatches, `cannot obtain boot option support: variable contents has an unexpected size \(5 bytes\)`)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadBootCurrent(c *C) {
	// Test error result because of bad BootCurrent
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
		},
	})
	c.Check(err, ErrorMatches, `cannot read BootCurrent variable: BootCurrent variable contents has the wrong size \(1 bytes\)`)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadLoadOption(c *C) {
	// Test error result because BootCurrent value doesn't match entry in log
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x5, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
		},
	})
	c.Check(err, ErrorMatches, `cannot read current Boot0005 load option from log: cannot find specified boot option`)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadMissingInitialLaunch(c *C) {
	// Test error result because IBL launch can't be identified - it doesn't match boot entry in log that BootCurrent points to
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
		},
	})
	c.Check(err, ErrorMatches, `OS-present EV_EFI_BOOT_SERVICES_APPLICATION event for \\PciRoot\(0x0\)\\Pci\(0x1d,0x0\)\\Pci\(0x0,0x0\)\\NVMe\(0x1,00-00-00-00-00-00-00-00\)\\HD\(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960\)\\\\EFI\\ubuntu\\shimx64\.efi is not associated with the current boot load option and is not Absolute`)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadMissingSBL(c *C) {
	// Test error result because it wasn't possible to verify Authenticode digest for SBL launch (in our case, grub), as it wasn't supplied
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
		},
	})
	c.Check(err, ErrorMatches, `cannot verify digest for EV_EFI_BOOT_SERVICES_APPLICATION event associated with the secondary boot loader`)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadSBLMeasuredFlatFileDigest_NoEFITCG2Protocol(c *C) {
	// Test error result because digest associated with SBL launch matches the file digest rather than the Authenticode digest, which in the
	// case of shim -> grub, might mean that EFI_TCG2_PROTOCOL is missing from the firmware.
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
			// We have to cheat a bit here because the digest is hardcoded in the test log. We set an invalid Authenticode digest for the mock image so the intial test
			// fails and then have the following code digest the same string that produces the log digest ("mock grub executable"), to get a digest that matches what's in
			// the log so the test thinks that the log contains the flat file digest.
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "80fd5a9364df79953369758a419f7cb167201cf580160b91f837aad455c55bcd")},
		},
	})
	c.Check(err, ErrorMatches, `log contains unexpected EV_EFI_BOOT_SERVICES_APPLICATION digest for OS-present application mock image: log digest matches flat file digest \(0xd5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0\) which suggests an image loaded outside of the LoadImage API and firmware lacking support for the EFI_TCG2_PROTOCOL and/or the PE_COFF_IMAGE flag`)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadProvidedBootImages(c *C) {
	// Test error result because the SBL image (in our case grub) has a digest that doesn't match what's in the log
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
			// In this case, we provide an invalid Authenticode digest, and a payload that also subsequently produces the wrong file digest.
			&mockImage{contents: []byte("foo"), digest: testutil.DecodeHexString(c, "80fd5a9364df79953369758a419f7cb167201cf580160b91f837aad455c55bcd")},
		},
	})
	c.Check(err, ErrorMatches, `log contains unexpected EV_EFI_BOOT_SERVICES_APPLICATION digest for OS-present application mock image \(calculated PE digest: 0x80fd5a9364df79953369758a419f7cb167201cf580160b91f837aad455c55bcd, log value: 0xd5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0\) - were the correct boot images supplied\?`)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadWithUnsupportedSysprepApp(c *C) {
	// Test error result because a sysprep app was detected when BootOptionSupport indicates they aren't supported
	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x03, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
		},
	})
	c.Check(err, ErrorMatches, `encountered pre-OS EV_EFI_BOOT_SERVICES_APPLICATION event for \\PciRoot\(0x0\)\\Pci\(0x1d,0x0\)\\Pci\(0x0,0x0\)\\NVMe\(0x1,00-00-00-00-00-00-00-00\)\\HD\(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960\)\\\\EFI\\Dell\\sysprep.efi when SysPrep applications are not supported`)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadUnexpectedTransitionToOSPresentEvent(c *C) {
	// Test error result because of an unexpected event after the EV_EFI_ACTION "Calling EFI
	// Application from Boot Option" event
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	for _, ev := range log.Events {
		eventsCopy = append(eventsCopy, ev)
		if ev.PCRIndex == internal_efi.BootManagerCodePCR && ev.EventType == tcglog.EventTypeEFIAction {
			// Just duplicate the EV_EFI_ACTION "Calling EFI Application from Boot Option" event
			eventsCopy = append(eventsCopy, ev)
		}
	}
	log.Events = eventsCopy

	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
		},
	})
	c.Check(err, ErrorMatches, `unexpected event type EV_EFI_ACTION: expecting transition from pre-OS to OS-present event`)
}

func (s *pcr4Suite) TestCheckBootManagerCodeMeasurementsBadUnexpectedFirstOSPresentEvent(c *C) {
	// Test error result because the first OS-present event is not EV_EFI_BOOT_SERVICES_APPLICATION
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	for _, ev := range log.Events {
		eventsCopy = append(eventsCopy, ev)
		if ev.PCRIndex == internal_efi.PlatformManufacturerPCR && ev.EventType == tcglog.EventTypeSeparator {
			eventsCopy = append(eventsCopy, &tcglog.Event{
				PCRIndex:  internal_efi.BootManagerCodePCR,
				EventType: tcglog.EventTypeIPL,
				Data:      tcglog.StringEventData("some data"),
				Digests: map[tpm2.HashAlgorithmId]tpm2.Digest{
					tpm2.HashAlgorithmSHA256: tcglog.ComputeStringEventDigest(crypto.SHA256, "some data"),
				},
			})
		}
	}
	log.Events = eventsCopy

	err := s.testCheckBootManagerCodeMeasurements(c, &testCheckBootManagerCodeMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
			}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		images: []secboot_efi.Image{
			&mockImage{contents: []byte("mock shim executable"), digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7")},
		},
	})
	c.Check(err, ErrorMatches, `unexpected OS-present log event type EV_IPL \(expected EV_EFI_BOOT_SERVICES_APPLICATION\)`)
}

// TODO (other error cases - some harder, some may require more customizable log generator in internal/efitest/log.go):
// - Event data decode errors in pre-OS environment.
// - Unexpected event types in log in pre-OS environment.
// - Logs with EV_OMIT_BOOT_DEVICE_EVENTS.
// - More than one EV_OMIT_BOOT_DEVICE_EVENTS event in log.
// - EV_EFI_ACTION "Calling EFI Application from Boot Option" measured before secure boot config.
// - EV_EFI_ACTION "Calling EFI Application from Boot Option" along with EV_OMIT_BOOT_DEVICE_EVENTS event.
// - Driver / sysprep launches before secure boot config is measured.
// - Event data decode error for initial EV_EFI_BOOT_SERVICES_APPLICATION event in OS-present environment.
// - EV_EFI_BOOT_SERVICES_APPLICATION event after detecting Absolute, and which is not associated with the IBL launch (doesn't match boot option)
// - Image open errors.
// - efi.ComputePeImageDigest errors.
// - internal_efi.IsAbsoluteAgentLaunch error.
