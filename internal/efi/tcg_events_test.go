// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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
	"errors"
	"io"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type tcgEventsSuite struct{}

var _ = Suite(&tcgEventsSuite{})

func (*tcgEventsSuite) TestIsVendorEventType(c *C) {
	for _, params := range []struct {
		t        tcglog.EventType
		expected bool
	}{
		{t: tcglog.EventTypeSCRTMContents, expected: false},
		{t: tcglog.EventTypeEFIVariableDriverConfig, expected: false},
		{t: 0x00007011, expected: false},
		{t: 0x80008412, expected: false},
		{t: 0x00008401, expected: true},
		{t: 0x80010000, expected: true},
	} {
		c.Check(IsVendorEventType(params.t), Equals, params.expected, Commentf("%x", params.t))
	}
}

type invalidEventData struct {
	err error
}

func (e *invalidEventData) String() string        { return "invalid event data: " + e.err.Error() }
func (*invalidEventData) Bytes() []byte           { return nil }
func (*invalidEventData) Write(w io.Writer) error { return errors.New("not supported") }
func (e *invalidEventData) Error() string         { return e.err.Error() }

func (s *tcgEventsSuite) TestIsLaunchedFromFirmwareVolumeYes(c *C) {
	yes, err := IsLaunchedFromFirmwareVolume(&tcglog.Event{
		EventType: tcglog.EventTypeEFIBootServicesDriver,
		Data: &tcglog.EFIImageLoadEvent{
			DevicePath: efi.DevicePath{
				efi.FWVolDevicePathNode(efi.MakeGUID(0xf0d99c58, 0x3e06, 0x430c, 0x8d02, [...]uint8{0x9a, 0xb8, 0x8b, 0xa1, 0x61, 0x20})),
				efi.FWFileDevicePathNode(efi.MakeGUID(0x0c2c4003, 0x6551, 0x4eea, 0xb006, [...]uint8{0x0f, 0xec, 0xb4, 0xbb, 0x30, 0x0b})),
			},
		},
	})
	c.Check(err, IsNil)
	c.Check(yes, testutil.IsTrue)
}

func (s *tcgEventsSuite) TestIsLaunchedFromFirmwareVolumeNo(c *C) {
	yes, err := IsLaunchedFromFirmwareVolume(&tcglog.Event{
		EventType: tcglog.EventTypeEFIBootServicesDriver,
		Data: &tcglog.EFIImageLoadEvent{
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
		},
	})
	c.Check(err, IsNil)
	c.Check(yes, testutil.IsFalse)
}

func (s *tcgEventsSuite) TestIsLaunchedFromFirmwareVolumeYesRuntimeDriver(c *C) {
	yes, err := IsLaunchedFromFirmwareVolume(&tcglog.Event{
		EventType: tcglog.EventTypeEFIRuntimeServicesDriver,
		Data: &tcglog.EFIImageLoadEvent{
			DevicePath: efi.DevicePath{
				efi.FWVolDevicePathNode(efi.MakeGUID(0xf0d99c58, 0x3e06, 0x430c, 0x8d02, [...]uint8{0x9a, 0xb8, 0x8b, 0xa1, 0x61, 0x20})),
				efi.FWFileDevicePathNode(efi.MakeGUID(0x0c2c4003, 0x6551, 0x4eea, 0xb006, [...]uint8{0x0f, 0xec, 0xb4, 0xbb, 0x30, 0x0b})),
			},
		},
	})
	c.Check(err, IsNil)
	c.Check(yes, testutil.IsTrue)
}

func (s *tcgEventsSuite) TestIsLaunchedFromFirmwareVolumeErrInvalidEventType(c *C) {
	_, err := IsLaunchedFromFirmwareVolume(&tcglog.Event{EventType: tcglog.EventTypeSeparator})
	c.Check(err, ErrorMatches, `unexpected event type EV_SEPARATOR`)
}

func (s *tcgEventsSuite) TestIsLaunchedFromFirmwareVolumeErrInvalidEventData(c *C) {
	_, err := IsLaunchedFromFirmwareVolume(&tcglog.Event{
		EventType: tcglog.EventTypeEFIBootServicesDriver,
		Data:      &invalidEventData{errors.New("some error")},
	})
	c.Check(err, ErrorMatches, `event has invalid event data: some error`)
}

func (s *tcgEventsSuite) TestIsLaunchedFromFirmwareVolumeErrEmptyPath(c *C) {
	_, err := IsLaunchedFromFirmwareVolume(&tcglog.Event{
		EventType: tcglog.EventTypeEFIBootServicesDriver,
		Data:      &tcglog.EFIImageLoadEvent{},
	})
	c.Check(err, ErrorMatches, `empty device path`)
}
