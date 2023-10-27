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

package bootenv

import "github.com/snapcore/secboot"

var (
	ComputeSnapModelHash = computeSnapModelHash
)

func MockSetModel(f func(secboot.SnapModel) bool) (restore func()) {
	origSetModel := SetModel
	SetModel = f
	return func() {
		SetModel = origSetModel
	}
}

func MockSetBootMode(f func(string) bool) (restore func()) {
	origSetBootMode := SetBootMode
	SetBootMode = f
	return func() {
		SetBootMode = origSetBootMode
	}
}

func MockLoadCurrentModel(f func() (secboot.SnapModel, error)) (restore func()) {
	origLoadCurrentModel := loadCurrentModel
	loadCurrentModel = f
	return func() {
		loadCurrentModel = origLoadCurrentModel
	}
}

func MockLoadCurrenBootMode(f func() (string, error)) (restore func()) {
	origLoadCurrentBootMode := loadCurrentBootMode
	loadCurrentBootMode = f
	return func() {
		loadCurrentBootMode = origLoadCurrentBootMode
	}
}
