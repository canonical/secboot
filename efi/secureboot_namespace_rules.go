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

import "crypto/x509"

// secureBootAuthoritySet provides a way to customize authorities associated with
// a set of rules that are scoped to a secure boot namespace.
type secureBootAuthoritySet interface {
	// AddAuthorities adds additional authorities to a secure boot namespace
	// which isused when one authority delegates image signing to another authority
	// (eg, via shim's vendor cert) in order to identify images signed by the
	// delegated authority as part of the same namespace.
	AddAuthorities(certs ...*x509.Certificate)
}
