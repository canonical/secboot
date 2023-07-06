// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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
	"bytes"

	"github.com/canonical/go-tpm2"
)

type shimFlags int

const (
	// shimHasSbatVerification indicates that the shim
	// binary performs SBAT verification of subsequent loaders,
	// and performs an additional measurement of the SBAT
	// variable.
	shimHasSbatVerification shimFlags = 1 << iota

	// shimFixVariableAuthorityEventsMatchSpec indicates that shim
	// performs EV_EFI_VARIABLE_AUTHORITY events according to the
	// TCG specification when an image is authenticated with a
	// EFI_SIGNATURE_DATA structure, ie, it has this commit:
	// https://github.com/rhboot/shim/commit/e3325f8100f5a14e0684ff80290e53975de1a5d9
	shimFixVariableAuthorityEventsMatchSpec

	// shimVendorCertContainsDb indicates that shim's .vendor_cert
	// section contains a signature database rather than a single
	// X.509 certificate. This affects how some measurements are
	// performed.
	shimVendorCertContainsDb

	// shimBugVendorCertAuthenticatesFromMokListRT indicates that
	// shim performs EV_EFI_VARIABLE_AUTHORITY events that incorrectly
	// identify the source as MokListRT when authenticating with
	// the built in vendor cert, and the .vendor_cert section contains
	// a single X.509 certificate, ie, it has this commit:
	// https://github.com/rhboot/shim/commit/092c2b2bbed950727e41cf450b61c794881c33e7
	shimBugVendorCertAuthenticatesFromMokListRT
)

// shimContext maintains context associated with shim for a branch.
type shimContext struct {
	flags              shimFlags
	vendorDb           *secureBootDB
	verificationEvents tpm2.DigestList
}

func (c *shimContext) AppendVerificationEvent(digest tpm2.Digest) {
	c.verificationEvents = append(c.verificationEvents, digest)
}

func (c *shimContext) HasVerificationEvent(digest tpm2.Digest) bool {
	for _, e := range c.verificationEvents {
		if bytes.Equal(e, digest) {
			return true
		}
	}
	return false
}
