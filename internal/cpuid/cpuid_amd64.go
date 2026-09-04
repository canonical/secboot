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

// Package cpuid is a deliberately thin, architecture-gated wrapper around
// github.com/canonical/cpuid, which does not compile on non-x86 architectures.
// Confining that dependency here keeps every consumer architecture-neutral, so
// that consumers are compiled and unit tested on every architecture rather than
// being gated by build constraints.
//
// On amd64 the functions delegate to the upstream package. On every other
// architecture they return zero values, because CPUID is x86-only.
package cpuid

import (
	upstream_cpuid "github.com/canonical/cpuid"
)

// VendorIdentificator returns the CPU vendor identificator string, e.g. "GenuineIntel".
func VendorIdentificator() string {
	return upstream_cpuid.VendorIdentificatorString
}

// Family returns the CPU display family ID.
func Family() uint32 {
	return upstream_cpuid.DisplayFamily
}

// HasFeature returns whether the supplied CPUID feature bit is set.
func HasFeature(feature uint64) bool {
	return upstream_cpuid.HasFeature(feature)
}
