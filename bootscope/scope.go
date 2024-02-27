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

// Package bootscope implements key scoping support for platforms that
// don't support measured boot.
//
// It is used to track the currently used boot mode and model, provides
// the KeyDataScope object which encapsulates boot environment information
// and helper functions used to authenticate and associate a scope with a key.
package bootscope

import (
	"sync/atomic"

	"github.com/snapcore/secboot"
)

var (
	currentModel    atomic.Value
	currentBootMode atomic.Value
)

func SetModel(model secboot.SnapModel) {
	currentModel.Store(model)
}

func SetBootMode(mode string) {
	currentBootMode.Store(mode)
}
