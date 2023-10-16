// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package secboot

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func unmarshalV1KeyPayload(data []byte) (unlockKey DiskUnlockKey, primaryKey PrimaryKey, err error) {
	r := bytes.NewReader(data)

	var sz uint16
	if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
		return nil, nil, err
	}

	if sz > 0 {
		unlockKey = make(DiskUnlockKey, sz)
		if _, err := r.Read(unlockKey); err != nil {
			return nil, nil, err
		}
	}

	if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
		return nil, nil, err
	}

	if sz > 0 {
		primaryKey = make(PrimaryKey, sz)
		if _, err := r.Read(primaryKey); err != nil {
			return nil, nil, err
		}
	}

	if r.Len() > 0 {
		return nil, nil, fmt.Errorf("%v excess byte(s)", r.Len())
	}

	return unlockKey, primaryKey, nil
}
