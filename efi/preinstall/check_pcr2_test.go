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
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type pcr2Suite struct{}

var _ = Suite(&pcr2Suite{})

func (s *pcr2Suite) TestIsLaunchedFromFirmwareVolumeYes(c *C) {
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

func (s *pcr2Suite) TestIsLaunchedFromFirmwareVolumeNo(c *C) {
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

func (s *pcr2Suite) TestIsLaunchedFromFirmwareVolumeYesRuntimeDriver(c *C) {
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

func (s *pcr2Suite) TestIsLaunchedFromFirmwareVolumeErrInvalidEventType(c *C) {
	_, err := IsLaunchedFromFirmwareVolume(&tcglog.Event{EventType: tcglog.EventTypeSeparator})
	c.Check(err, ErrorMatches, `unexpected event type EV_SEPARATOR`)
}

func (s *pcr2Suite) TestIsLaunchedFromFirmwareVolumeErrInvalidEventData(c *C) {
	_, err := IsLaunchedFromFirmwareVolume(&tcglog.Event{
		EventType: tcglog.EventTypeEFIBootServicesDriver,
		Data:      &invalidEventData{errors.New("some error")},
	})
	c.Check(err, ErrorMatches, `event has invalid event data: some error`)
}

func (s *pcr2Suite) TestIsLaunchedFromFirmwareVolumeErrEmptyPath(c *C) {
	_, err := IsLaunchedFromFirmwareVolume(&tcglog.Event{
		EventType: tcglog.EventTypeEFIBootServicesDriver,
		Data:      &tcglog.EFIImageLoadEvent{},
	})
	c.Check(err, ErrorMatches, `empty device path`)
}

type testCheckDriversAndAppsMeasurementsParams struct {
	env            internal_efi.HostEnvironment
	pcrAlg         tpm2.HashAlgorithmId
	expectedResult []*LoadedImageInfo
}

func (s *pcr2Suite) testCheckDriversAndAppsMeasurements(c *C, params *testCheckDriversAndAppsMeasurementsParams) error {
	log, err := params.env.ReadEventLog()
	c.Assert(err, IsNil)

	result, err := CheckDriversAndAppsMeasurements(context.Background(), params.env, log, params.pcrAlg)
	if err != nil {
		return err
	}
	c.Check(result, DeepEquals, params.expectedResult)
	return nil
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsGoodNoDriversPresent(c *C) {
	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, IsNil)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsGoodOptionROMPresent(c *C) {
	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		expectedResult: []*LoadedImageInfo{
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
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsGoodDriverPresent(c *C) {
	path := efi.DevicePath{
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
	}

	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "DriverOrder", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0, 0x0}},
				{Name: "Driver0000", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: efitest.MakeVarPayload(c, &efi.LoadOption{
					Attributes:  efi.LoadOptionActive | efi.LoadOptionCategoryApp,
					Description: "Mock EFI driver",
					FilePath:    path,
				})},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		expectedResult: []*LoadedImageInfo{
			{
				Description:    "Mock EFI driver",
				LoadOptionName: "Driver0000",
				DevicePath:     path,
				DigestAlg:      tpm2.HashAlgorithmSHA256,
				Digest:         testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
			},
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsGoodOptionROMPresentSHA384(c *C) {
	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
				IncludeDriverLaunch: true,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA384,
		expectedResult: []*LoadedImageInfo{
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
				DigestAlg: tpm2.HashAlgorithmSHA384,
				Digest:    testutil.DecodeHexString(c, "b40a4d33b23ba18664e56b0e3d578e84bd5286af942a9ab18ae705961a465b354f59f25b11976425717826be2559a62f"),
			},
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsGoodDriverFromFwVolPresent(c *C) {
	// TODO: Add this functionality to efitest later on.
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var events []*tcglog.Event
	for _, ev := range log.Events {
		events = append(events, ev)
		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR || ev.EventType != tcglog.EventTypeSeparator {
			continue
		}

		events = append(events, &tcglog.Event{
			PCRIndex:  internal_efi.DriversAndAppsPCR,
			EventType: tcglog.EventTypeEFIBootServicesDriver,
			Digests: map[tpm2.HashAlgorithmId]tpm2.Digest{
				tpm2.HashAlgorithmSHA256: testutil.DecodeHexString(c, "382805bd31232813ae8779cc933b0e8b4dcab68e0a819dc13c3f6dc2c3417206"),
			},
			Data: &tcglog.EFIImageLoadEvent{
				DevicePath: efi.DevicePath{
					efi.FWVolDevicePathNode(efi.MakeGUID(0xf0d99c58, 0x3e06, 0x430c, 0x8d02, [...]uint8{0x9a, 0xb8, 0x8b, 0xa1, 0x61, 0x20})),
					efi.FWFileDevicePathNode(efi.MakeGUID(0x0c2c4003, 0x6551, 0x4eea, 0xb006, [...]uint8{0x0f, 0xec, 0xb4, 0xbb, 0x30, 0x0b})),
				},
			},
		})
	}
	log.Events = events

	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, IsNil)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsLogError(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.EventType != tcglog.EventTypeSeparator {
			continue
		}

		ev.Data = &invalidEventData{errors.New("some error")}
		break
	}

	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `invalid event data for EV_SEPARATOR event in PCR 7: some error`)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsLogNoTransitionToOSPresent(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		if (ev.PCRIndex >= 0 && ev.PCRIndex < 7) && ev.EventType == tcglog.EventTypeSeparator {
			break
		}
		events = events[1:]
	}
	// Truncate the log
	log.Events = log.Events[:len(log.Events)-len(events)]

	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{}),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `reached end of log before encountering transition to OS-present`)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsLogDriverVariableError(c *C) {
	err := s.testCheckDriversAndAppsMeasurements(c, &testCheckDriversAndAppsMeasurementsParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "DriverOrder", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
			}),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `cannot read driver load option variables: cannot read load order variable: DriverOrder variable contents has odd size \(1 bytes\)`)
}
