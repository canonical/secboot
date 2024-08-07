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
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	. "gopkg.in/check.v1"
)

type pcr0Suite struct{}

var _ = Suite(&pcr0Suite{})

func (s *pcr0Suite) TestCheckPlatformFirmwareMeasurementsGood(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	c.Check(CheckPlatformFirmwareMeasurements(log), IsNil)
}

func (s *pcr0Suite) TestCheckPlatformFirmwareMeasurementsGoodSL3(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{StartupLocality: 3})
	c.Check(CheckPlatformFirmwareMeasurements(log), IsNil)
}

func (s *pcr0Suite) TestCheckPlatformFirmwareMeasurementsGoodHCRTM(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{StartupLocality: 4})
	c.Check(CheckPlatformFirmwareMeasurements(log), IsNil)
}

func (s *pcr0Suite) TestCheckPlatformFirmwareMeasurementsUnexpectedEventType(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	for i, ev := range log.Events {
		if ev.PCRIndex == internal_efi.PlatformFirmwarePCR && ev.EventType == tcglog.EventTypeEFIPlatformFirmwareBlob {
			log.Events[i].EventType = tcglog.EventTypeNonhostConfig
		}
	}
	c.Check(CheckPlatformFirmwareMeasurements(log), ErrorMatches, `unexpected pre-OS log event type EV_NONHOST_CONFIG`)
}

func (s *pcr0Suite) TestCheckPlatformFirmwareMeasurementsUnexpectedOSPresentEvent(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	log.Events = append(log.Events, &tcglog.Event{
		PCRIndex:  internal_efi.PlatformFirmwarePCR,
		EventType: tcglog.EventTypeEFIAction,
		Data:      tcglog.StringEventData("foo"),
	})
	c.Check(CheckPlatformFirmwareMeasurements(log), ErrorMatches, `firmware measures events as part of the OS-present environment`)
}
