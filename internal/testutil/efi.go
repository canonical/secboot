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
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

func MockEFIVarsPath(path string) (restore func()) {
	origPath := internal_efi.EFIVarsPath
	internal_efi.EFIVarsPath = path
	return func() {
		internal_efi.EFIVarsPath = origPath
	}
}

func MockEventLogPath(path string) (restore func()) {
	origPath := internal_efi.EventLogPath
	internal_efi.EventLogPath = path
	return func() {
		internal_efi.EventLogPath = origPath
	}
}

func MockEFIReadVar(dir string) (restore func()) {
	origReadVar := internal_efi.ReadVar

	internal_efi.ReadVar = func(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
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

	return func() {
		internal_efi.ReadVar = origReadVar
	}
}
