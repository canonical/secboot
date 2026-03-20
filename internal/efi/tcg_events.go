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

package efi

import (
	"github.com/canonical/tcglog-parser"
)

// IsVendorEventType indicates whether the supplied event type is vendor
// defined. Officially, this applies to any event type that is not within the
// range of TCG reserved types (0x00000000-0x0000ffff and 0x80000000-0x8000ffff),
// however, this also considers event types between 0x00008000-0x0000ffff to be
// vendor defined because AMD firmware is using these and it's unlikely that
// these types are going to be used by the TCG.
func IsVendorEventType(t tcglog.EventType) bool {
	switch {
	case t&0x80000000 > 0:
		return t > 0x8000ffff
	default:
		return t > 0x7fff
	}
}
