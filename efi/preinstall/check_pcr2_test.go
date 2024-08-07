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

type pcr2Suite struct{}

var _ = Suite(&pcr2Suite{})

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsGood(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	result, err := CheckDriversAndAppsMeasurements(log)
	c.Check(err, IsNil)
	c.Check(result, Equals, DriversAndAppsResultFlags(0))
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsWithDrivers(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{IncludeDriverLaunch: true})
	result, err := CheckDriversAndAppsMeasurements(log)
	c.Check(err, IsNil)
	c.Check(result, Equals, DriversAndAppsDriversPresent)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsUnexpectedEventType(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{IncludeDriverLaunch: true})
	for i, ev := range log.Events {
		if ev.PCRIndex == internal_efi.DriversAndAppsPCR && ev.EventType == tcglog.EventTypeEFIBootServicesDriver {
			log.Events[i].EventType = tcglog.EventTypeNonhostConfig
		}
	}
	_, err := CheckDriversAndAppsMeasurements(log)
	c.Check(err, ErrorMatches, `unexpected pre-OS log event type EV_NONHOST_CONFIG`)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsUnexpectedOSPresentEvent(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	log.Events = append(log.Events, &tcglog.Event{
		PCRIndex:  internal_efi.DriversAndAppsPCR,
		EventType: tcglog.EventTypeEFIAction,
		Data:      tcglog.StringEventData("foo"),
	})
	_, err := CheckDriversAndAppsMeasurements(log)
	c.Check(err, ErrorMatches, `firmware measures events as part of the OS-present environment`)
}
