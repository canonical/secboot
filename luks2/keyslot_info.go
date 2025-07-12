// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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

package luks2

import "github.com/snapcore/secboot"

type keyslotInfoImpl struct {
	keyslotType     secboot.KeyslotType
	keyslotName     string
	keyslotId       int
	keyslotPriority int
	keyslotData     secboot.KeyDataReader // This will eventually just be a io.Reader
}

func (i *keyslotInfoImpl) Type() secboot.KeyslotType {
	return i.keyslotType
}

func (i *keyslotInfoImpl) Name() string {
	return i.keyslotName
}

func (i *keyslotInfoImpl) Priority() int {
	return i.keyslotPriority
}

func (i *keyslotInfoImpl) Data() secboot.KeyDataReader {
	return i.keyslotData
}

func (i *keyslotInfoImpl) KeyslotID() int {
	return i.keyslotId
}

// KeyslotInfo provides information about a LUKS2 keyslot.
type KeyslotInfo interface {
	secboot.KeyslotInfo

	// KeyslotID returns the LUKS2 keyslot ID associated
	// with this secboot keyslot.
	KeyslotID() int
}
