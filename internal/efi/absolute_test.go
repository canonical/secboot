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

package efi_test

import (
	"fmt"
	"io"

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-efilib/guids"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/testutil"
)

type absoluteSuite struct{}

var _ = Suite(&absoluteSuite{})

func (s *absoluteSuite) TestIsAbsoluteAgentLaunchTrueAbsoluteAbtInstaller(c *C) {
	ev := &tcglog.Event{
		PCRIndex:  4,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			DevicePath: efi.DevicePath{
				efi.MediaFvDevicePathNode(efi.MakeGUID(0x9375b02b, 0x4c60, 0x5d56, 0x4c1c, [...]byte{0x55, 0xa6, 0x99, 0x71, 0x77, 0x37})),
				efi.MediaFvFileDevicePathNode(efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d})),
			},
		},
	}
	isAbsolute, err := IsAbsoluteAgentLaunch(ev)
	c.Check(err, IsNil)
	c.Check(isAbsolute, testutil.IsTrue)
}

func (s *absoluteSuite) TestIsAbsoluteAgentLaunchTrueAbsoluteComputraceInstaller(c *C) {
	ev := &tcglog.Event{
		PCRIndex:  4,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			DevicePath: efi.DevicePath{
				efi.MediaFvDevicePathNode(efi.MakeGUID(0x9375b02b, 0x4c60, 0x5d56, 0x4c1c, [...]byte{0x55, 0xa6, 0x99, 0x71, 0x77, 0x37})),
				efi.MediaFvFileDevicePathNode(efi.MakeGUID(0x8feeecf1, 0xbcfd, 0x4a78, 0x9231, [...]byte{0x48, 0x01, 0x56, 0x6b, 0x35, 0x67})),
			},
		},
	}
	isAbsolute, err := IsAbsoluteAgentLaunch(ev)
	c.Check(err, IsNil)
	c.Check(isAbsolute, testutil.IsTrue)
}

func (s *absoluteSuite) TestIsAbsoluteAgentLaunchFalseWrongEventType(c *C) {
	ev := &tcglog.Event{
		PCRIndex:  4,
		EventType: tcglog.EventTypeSeparator,
		Data:      &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventNormalValue},
	}
	isAbsolute, err := IsAbsoluteAgentLaunch(ev)
	c.Check(err, IsNil)
	c.Check(isAbsolute, testutil.IsFalse)
}

func (s *absoluteSuite) TestIsAbsoluteAgentLaunchFalseNotFirmwareVolume(c *C) {
	hid, err := efi.NewEISAID("PNP", 0x0a03)
	c.Assert(err, IsNil)

	ev := &tcglog.Event{
		PCRIndex:  4,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{HID: hid, UID: 0},
				&efi.PCIDevicePathNode{Function: 0, Device: 6},
				&efi.PCIDevicePathNode{Function: 0, Device: 0},
				&efi.NVMENamespaceDevicePathNode{NamespaceID: 1, NamespaceUUID: 0},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x1000000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x3b5c4f7d, 0x3934, 0x4b3f, 0xbebf, [...]byte{0x09, 0xe3, 0x53, 0xa1, 0xf7, 0x68})),
					MBRType:         efi.GPT,
				},
				efi.NewFilePathDevicePathNode("EFI/ubuntu/shimx64.efi"),
			},
		},
	}
	isAbsolute, err := IsAbsoluteAgentLaunch(ev)
	c.Check(err, IsNil)
	c.Check(isAbsolute, testutil.IsFalse)
}

func (s *absoluteSuite) TestIsAbsoluteAgentLaunchFalseNotWellKnownFirmwareFilename(c *C) {
	// Make sure this is not a well known GUID so we know we're testing the correct thing
	filename := efi.MakeGUID(0x66719632, 0xe1b3, 0x4fd8, 0x8a79, [...]byte{0x14, 0x60, 0x00, 0xf7, 0x62, 0xfc})
	_, known := guids.FileOrVolumeNameString(filename)
	c.Assert(known, testutil.IsFalse)

	ev := &tcglog.Event{
		PCRIndex:  4,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			DevicePath: efi.DevicePath{
				efi.MediaFvDevicePathNode(efi.MakeGUID(0x9375b02b, 0x4c60, 0x5d56, 0x4c1c, [...]byte{0x55, 0xa6, 0x99, 0x71, 0x77, 0x37})),
				efi.MediaFvFileDevicePathNode(filename),
			},
		},
	}
	isAbsolute, err := IsAbsoluteAgentLaunch(ev)
	c.Check(err, IsNil)
	c.Check(isAbsolute, testutil.IsFalse)
}

func (s *absoluteSuite) TestIsAbsoluteAgentLaunchFalseWrongFilename(c *C) {
	ev := &tcglog.Event{
		PCRIndex:  4,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			DevicePath: efi.DevicePath{
				efi.MediaFvDevicePathNode(efi.MakeGUID(0x9375b02b, 0x4c60, 0x5d56, 0x4c1c, [...]byte{0x55, 0xa6, 0x99, 0x71, 0x77, 0x37})),
				efi.MediaFvFileDevicePathNode(efi.MakeGUID(0xee993080, 0x5197, 0x4d4e, 0xb63c, [...]byte{0xf1, 0xf7, 0x41, 0x3e, 0x33, 0xce})),
			},
		},
	}
	isAbsolute, err := IsAbsoluteAgentLaunch(ev)
	c.Check(err, IsNil)
	c.Check(isAbsolute, testutil.IsFalse)
}

type mockErrLogData struct {
	err error
}

func (d *mockErrLogData) String() string {
	return fmt.Sprintf("Invalid event data: %v", d.err)
}

func (d *mockErrLogData) Bytes() []byte {
	panic("not implemented")
}

func (d *mockErrLogData) Write(w io.Writer) error {
	panic("not implemented")
}

func (d *mockErrLogData) Error() string {
	return d.err.Error()
}

func (d *mockErrLogData) Unwrap() error {
	return d.err
}

func (s *absoluteSuite) TestIsAbsoluteAgentLaunchErrInvalidEventData(c *C) {
	ev := &tcglog.Event{
		PCRIndex:  4,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data:      &mockErrLogData{io.ErrUnexpectedEOF},
	}
	_, err := IsAbsoluteAgentLaunch(ev)
	c.Check(err, ErrorMatches, `EV_EFI_BOOT_SERVICES_APPLICATION event has wrong data format: unexpected EOF`)
}

func (s *absoluteSuite) TestIsAbsoluteAgentLaunchErrEmptyDevicePath(c *C) {
	ev := &tcglog.Event{
		PCRIndex:  4,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			DevicePath: efi.DevicePath{},
		},
	}
	_, err := IsAbsoluteAgentLaunch(ev)
	c.Check(err, ErrorMatches, `EV_EFI_BOOT_SERVICES_APPLICATION event has empty device path`)
}

func (s *absoluteSuite) TestIsAbsoluteAgentLaunchErrWrongFvDevicePathLength(c *C) {
	ev := &tcglog.Event{
		PCRIndex:  4,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			DevicePath: efi.DevicePath{
				efi.MediaFvDevicePathNode(efi.MakeGUID(0x9375b02b, 0x4c60, 0x5d56, 0x4c1c, [...]byte{0x55, 0xa6, 0x99, 0x71, 0x77, 0x37})),
			},
		},
	}
	_, err := IsAbsoluteAgentLaunch(ev)
	c.Check(err, ErrorMatches, `invalid firmware volume device path \(\\Fv\(9375b02b-4c60-5d56-4c1c-55a699717737\)\): invalid length \(expected 2 components\)`)
}

func (s *absoluteSuite) TestIsAbsoluteAgentLaunchErrWrongFvDevicePathTerminator(c *C) {
	ev := &tcglog.Event{
		PCRIndex:  4,
		EventType: tcglog.EventTypeEFIBootServicesApplication,
		Data: &tcglog.EFIImageLoadEvent{
			DevicePath: efi.DevicePath{
				efi.MediaFvDevicePathNode(efi.MakeGUID(0x9375b02b, 0x4c60, 0x5d56, 0x4c1c, [...]byte{0x55, 0xa6, 0x99, 0x71, 0x77, 0x37})),
				efi.NewFilePathDevicePathNode("EFI/ubuntu/shimx64.efi"),
			},
		},
	}
	_, err := IsAbsoluteAgentLaunch(ev)
	c.Check(err, ErrorMatches, `invalid firmware volume device path \(\\Fv\(9375b02b-4c60-5d56-4c1c-55a699717737\)\\\\EFI\\ubuntu\\shimx64.efi\): doesn't terminate with FvFile`)
}
