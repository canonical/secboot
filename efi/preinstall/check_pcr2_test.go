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
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/efitest"
	. "gopkg.in/check.v1"
)

type pcr2Suite struct{}

var _ = Suite(&pcr2Suite{})

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsGoodNonePresent(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	result := CheckDriversAndAppsMeasurements(log)
	c.Check(result, Equals, NoDriversAndAppsPresent)
}

func (s *pcr2Suite) TestCheckDriversAndAppsMeasurementsGoodDriversPresent(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		IncludeDriverLaunch: true,
	})
	result := CheckDriversAndAppsMeasurements(log)
	c.Check(result, Equals, DriversAndAppsPresent)
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

	c.Check(func() { CheckDriversAndAppsMeasurements(log) }, PanicMatches, `invalid event data for EV_SEPARATOR event in PCR 7: some error`)
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

	c.Check(func() { CheckDriversAndAppsMeasurements(log) }, PanicMatches, `reached end of log before encountering transition to OS-present`)
}
