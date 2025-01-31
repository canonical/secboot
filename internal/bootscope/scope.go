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

package bootscope

import (
	"sync/atomic"

	"github.com/snapcore/secboot/internal/testenv"
	"github.com/snapcore/snapd/asserts"
)

var (
	currentModel atomic.Value
)

// SnapModel exists to avoid a circular dependency on the core secboot package.
// It must be kept in sync with the interface in snap.go.
type SnapModel interface {
	Series() string
	BrandID() string
	Model() string
	Classic() bool
	Grade() asserts.ModelGrade
	SignKeyID() string
}

func GetModel() SnapModel {
	model, ok := currentModel.Load().(SnapModel)
	if !ok {
		return nil
	}
	return model
}

func SetModel(model SnapModel) {
	currentModel.Store(model)
}

func UnsafeClearModelForTesting() {
	testenv.MustBeTestBinary()
	currentModel = atomic.Value{}
}
