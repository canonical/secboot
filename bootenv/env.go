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

import (
	"errors"
	"sync/atomic"

	"github.com/snapcore/secboot"
)

var (
	currentModel    atomic.Value
	currentBootMode atomic.Value
)

var SetModel = func(model secboot.SnapModel) bool {
	return currentModel.CompareAndSwap(nil, model)
}

var SetBootMode = func(mode string) bool {
	return currentBootMode.CompareAndSwap(nil, mode)
}

var loadCurrentModel = func() (secboot.SnapModel, error) {
	model, ok := currentModel.Load().(secboot.SnapModel)
	if !ok {
		return nil, errors.New("SetModel hasn't been called yet")
	}
	return model, nil
}

var loadCurrentBootMode = func() (string, error) {
	mode, ok := currentBootMode.Load().(string)
	if !ok {
		return "", errors.New("SetBootMode hasn't been called yet")
	}
	return mode, nil
}
