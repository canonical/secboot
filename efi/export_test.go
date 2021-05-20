// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

// Export constants for testing
const (
	SigDbUpdateQuirkModeNone              = sigDbUpdateQuirkModeNone
	SigDbUpdateQuirkModeDedupIgnoresOwner = sigDbUpdateQuirkModeDedupIgnoresOwner
)

// Export variables and unexported functions for testing
var (
	ComputeDbUpdate    = computeDbUpdate
	ReadShimVendorCert = readShimVendorCert
)

// Alias some unexported types for testing. These are required in order to pass these between functions in tests, or to access
// unexported members of some unexported types.
type SigDbUpdateQuirkMode = sigDbUpdateQuirkMode
