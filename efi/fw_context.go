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

// fwContext maintains context associated with the platform firmware for a branch
type fwContext struct {
	db                 *secureBootDB
	verificationEvents tpm2.DigestList
}

func (c *fwContext) AppendVerificationEvent(digest tpm2.Digest) {
	c.verificationEvents = append(c.verificationEvents, digest)
}

func (c *fwContext) HasVerificationEvent(digest tpm2.Digest) bool {
	for _, e := range c.verificationEvents {
		if bytes.Equal(e, digest) {
			return true
		}
	}
	return false
}
