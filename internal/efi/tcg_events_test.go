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
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/internal/efi"

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
