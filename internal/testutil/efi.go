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
	"github.com/snapcore/secboot/internal/efi"
)

func MockEFIVarsPath(path string) (restore func()) {
	origPath := efi.EFIVarsPath
	efi.EFIVarsPath = path
	return func() {
		efi.EFIVarsPath = origPath
	}
}

func MockEventLogPath(path string) (restore func()) {
	origPath := efi.EventLogPath
	efi.EventLogPath = path
	return func() {
		efi.EventLogPath = origPath
	}
}
