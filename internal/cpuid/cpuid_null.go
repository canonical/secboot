//go:build !amd64

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

package cpuid

// VendorIdentificator returns the CPU vendor identificator string.
// CPUID is x86-only; this stub always returns "" on this architecture.
func VendorIdentificator() string {
	return ""
}

// Family returns the CPU display family ID.
// CPUID is x86-only; this stub always returns 0 on this architecture.
func Family() uint32 {
	return 0
}

// HasFeature returns whether the supplied CPUID feature bit is set.
// CPUID is x86-only; this stub always returns false on this architecture.
func HasFeature(feature uint64) bool {
	return false
}
