// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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

package luks2_test

import (
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	. "github.com/snapcore/secboot/luks2"
	. "gopkg.in/check.v1"
)

type mockActivateConfig map[any]any

func makeMockActivateConfigGetter(opts ...secboot.ActivateOption) secboot.ActivateConfigGetter {
	cfg := make(mockActivateConfig)
	for _, opt := range opts {
		opt.ApplyOptionToConfig(cfg)
	}
	return cfg
}

func (c mockActivateConfig) Get(key any) (val any, exists bool) {
	val, exists = c[key]
	return val, exists
}

func (c mockActivateConfig) Set(key, val any) {
	c[key] = val
}

type optionsSuite struct{}

var _ = Suite(&optionsSuite{})

func (*optionsSuite) TestWithVolumeName1(c *C) {
	cfg := makeMockActivateConfigGetter(WithVolumeName("data"))

	val, exists := secboot.ActivateConfigGet[string](cfg, VolumeNameKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(val, Equals, "data")
}

func (*optionsSuite) TestWithVolumeName2(c *C) {
	cfg := makeMockActivateConfigGetter(WithVolumeName("save"))

	val, exists := secboot.ActivateConfigGet[string](cfg, VolumeNameKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(val, Equals, "save")
}
