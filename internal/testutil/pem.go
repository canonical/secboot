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
	"encoding/pem"
)

// MustDecodePEMType decodes a PEM block with the specified type from
// the supplied data.
func MustDecodePEMType(expectType string, data []byte) []byte {
	block, rest := pem.Decode(data)
	if len(rest) > 0 {
		panic("trailing bytes")
	}
	if block.Type != expectType {
		panic("unexpected type")
	}
	return block.Bytes
}
