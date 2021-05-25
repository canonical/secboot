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

package testutil

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/canonical/go-efilib"
)

func EFIReadVar(dir, name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
	path := filepath.Join(dir, fmt.Sprintf("%s-%s", name, guid))
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, efi.ErrVariableNotFound
		}
		return nil, 0, err
	}
	defer f.Close()

	var attrs efi.VariableAttributes
	if err := binary.Read(f, binary.LittleEndian, &attrs); err != nil {
		return nil, 0, err
	}

	val, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}

	return val, attrs, nil
}
