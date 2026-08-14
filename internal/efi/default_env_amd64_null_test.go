//go:build !amd64

// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2024 Canonical Ltd
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
	. "github.com/snapcore/secboot/internal/efi"
	. "gopkg.in/check.v1"
)

type defaultEnvAMD64Suite struct{}

var _ = Suite(&defaultEnvAMD64Suite{})

func (s *defaultEnvAMD64Suite) TestNotAMD64Host(c *C) {
	_, err := DefaultEnv.AMD64()
	c.Check(err, Equals, ErrNotAMD64Host)
}
