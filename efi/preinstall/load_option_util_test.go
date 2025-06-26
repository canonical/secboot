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
	"errors"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type loadOptionUtilSuite struct{}

var _ = Suite(&loadOptionUtilSuite{})

func (s *loadOptionUtilSuite) TestReadLoadOptionFromLog(c *C) {
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

func (s *loadOptionUtilSuite) TestReadLoadOptionFromLogNotExist(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	_, err := ReadLoadOptionFromLog(log, 10)
	c.Check(err, ErrorMatches, `cannot find specified boot option`)
}

func (s *loadOptionUtilSuite) TestReadLoadOptionFromLogInvalidData(c *C) {
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

func (s *loadOptionUtilSuite) TestReadLoadOptionFromLogInvalidVariableName(c *C) {
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

func (s *loadOptionUtilSuite) TestReadCurrentBootLoadOptionFromLog(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{})),
		efitest.WithMockVars(efitest.MockVars{
			{Name: "BootCurrent", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
		}),
	)

	log, err := env.ReadEventLog()
	c.Assert(err, IsNil)

	opt, err := ReadCurrentBootLoadOptionFromLog(env.VarContext(context.Background()), log)
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

func (s *loadOptionUtilSuite) TestReadCurrentBootLoadOptionFromLogMissingBootCurrent(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{})),
		efitest.WithMockVars(efitest.MockVars{}),
	)

	log, err := env.ReadEventLog()
	c.Assert(err, IsNil)

	_, err = ReadCurrentBootLoadOptionFromLog(env.VarContext(context.Background()), log)
	c.Check(err, ErrorMatches, `cannot read BootCurrent variable: variable does not exist`)
}

func (s *loadOptionUtilSuite) TestReadCurrentBootLoadOptionFromLogInvalidBootCurrent(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{})),
		efitest.WithMockVars(efitest.MockVars{
			{Name: "BootCurrent", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0xA, 0x0}},
		}),
	)

	log, err := env.ReadEventLog()
	c.Assert(err, IsNil)

	_, err = ReadCurrentBootLoadOptionFromLog(env.VarContext(context.Background()), log)
	c.Check(err, ErrorMatches, `cannot read current Boot000A load option from log: cannot find specified boot option`)
}

func (s *loadOptionUtilSuite) TestIsLaunchedFromLoadOptionGood(c *C) {
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
				NamespaceUUID: efi.EUI64{}},
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
					NamespaceUUID: efi.EUI64{}},
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

func (s *loadOptionUtilSuite) TestIsLaunchedFromLoadOptionGoodShortFormOpt(c *C) {
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
					NamespaceUUID: efi.EUI64{}},
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

func (s *loadOptionUtilSuite) TestIsLaunchedFromLoadOptionGoodRemovableCDROM(c *C) {
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

func (s *loadOptionUtilSuite) TestIsLaunchedFromLoadOptionGoodRemovableUSB(c *C) {
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

func (s *loadOptionUtilSuite) TestIsLaunchedFromLoadOptionNoMatch(c *C) {
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

func (s *loadOptionUtilSuite) TestIsLaunchedFromLoadOptionNoMatchRemovable(c *C) {
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

func (s *loadOptionUtilSuite) TestIsLaunchedFromLoadOptionInvalidEventData(c *C) {
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
		Data:      &invalidEventData{errors.New("some error")},
	}
	_, err := IsLaunchedFromLoadOption(ev, opt)
	c.Check(err, ErrorMatches, `event has invalid event data: some error`)
}

func (s *loadOptionUtilSuite) TestIsLaunchedFromLoadOptionEmptyDevicePath(c *C) {
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
	c.Check(err, ErrorMatches, `event has empty device path`)
}

func (s *loadOptionUtilSuite) TestIsLaunchedFromLoadOptionNotActive(c *C) {
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
					NamespaceUUID: efi.EUI64{}},
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
