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
	"github.com/snapcore/secboot/internal/luks2"
)

func MockRunDir(path string) (restore func()) {
	origRunDir := luks2.RunDir
	luks2.RunDir = path
	return func() {
		luks2.RunDir = origRunDir
	}
}

func MockSystemdCryptsetupPath(path string) (restore func()) {
	origSystemdCryptsetupPath := luks2.SystemdCryptsetupPath
	luks2.SystemdCryptsetupPath = path
	return func() {
		luks2.SystemdCryptsetupPath = origSystemdCryptsetupPath
	}
}
