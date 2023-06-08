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

package testutil

import (
	"crypto/rsa"
	"crypto/x509"

	. "gopkg.in/check.v1"
)

// ParseCertificate parses a certificate from the supplied DER encoded data.
func ParseCertificate(c *C, data []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(data)
	c.Assert(err, IsNil)
	return cert
}

// ParsePKCS1PrivateKey parses a RSA private key from the supplied DER encoded data.
func ParsePKCS1PrivateKey(c *C, data []byte) *rsa.PrivateKey {
	key, err := x509.ParsePKCS1PrivateKey(data)
	c.Assert(err, IsNil)
	return key
}
