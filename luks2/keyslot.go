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

import (
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luks2"
)

type keyslotImpl struct {
	keyslotType     secboot.KeyslotType
	keyslotName     string
	keyslotIds      []int
	keyslotPriority int
	keyslotData     secboot.KeyDataReader // This will eventually just be a io.Reader
}

func (i *keyslotImpl) Type() secboot.KeyslotType {
	return i.keyslotType
}

func (i *keyslotImpl) Name() string {
	return i.keyslotName
}

func (i *keyslotImpl) Priority() int {
	return i.keyslotPriority
}

func (i *keyslotImpl) Data() secboot.KeyDataReader {
	return i.keyslotData
}

func (i *keyslotImpl) PreferredKeyslotId() int {
	if len(i.keyslotIds) == 1 {
		return i.keyslotIds[0]
	} else {
		return luks2.AnySlot
	}
}

// Keyslot provides information about a LUKS2 keyslot.
type Keyslot interface {
	secboot.Keyslot

	// As LUKS2 tokens can be associated to multiple keyslots (eg: during reencryption)
	// PreferredKeyslotId returns either the only LUKS2 keyslot identifier of the token
	// or AnySlot if there isn't only one.
	PreferredKeyslotId() int
}
