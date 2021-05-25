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

package efi_test

import (
	"os"
	"testing"

	"github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type mockEFIEnvironment struct {
	efivars string
	log     string
}

func (e *mockEFIEnvironment) ReadVar(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
	return testutil.EFIReadVar(e.efivars, name, guid)
}

func (e *mockEFIEnvironment) ReadEventLog() (*tcglog.Log, error) {
	f, err := os.Open(e.log)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return tcglog.ParseLog(f, &tcglog.LogOptions{})
}
