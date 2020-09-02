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

package luks2

import (
	"os"

	"golang.org/x/sys/unix"
)

func MockDataDeviceFstatResult(stMock *unix.Stat_t) (restore func()) {
	origFn := dataDeviceFstat
	dataDeviceFstat = func(fd int, st *unix.Stat_t) error {
		*st = *stMock
		return nil
	}
	return func() {
		dataDeviceFstat = origFn
	}
}

func MockIsBlockDeviceArgs(mode os.FileMode) (restore func()) {
	origFn := isBlockDevice
	isBlockDevice = func(os.FileMode) bool {
		return origFn(mode)
	}
	return func() {
		isBlockDevice = origFn
	}
}
