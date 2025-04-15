// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package preinstall_test

import (
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/efitest"
	. "gopkg.in/check.v1"
)

type utilAmd64Suite struct{}

var _ = Suite(&utilAmd64Suite{})

func (s *utilAmd64Suite) TestDetermineCPUVendorIntel(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", nil, 0, nil))

	vendor, err := DetermineCPUVendor(env)
	c.Check(err, IsNil)
	c.Check(vendor, Equals, CpuVendorIntel)
}

func (s *utilAmd64Suite) TestDetermineCPUVendorAMD(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("AuthenticAMD", nil, 0, nil))

	vendor, err := DetermineCPUVendor(env)
	c.Check(err, IsNil)
	c.Check(vendor, Equals, CpuVendorAMD)
}

func (s *utilAmd64Suite) TestDetermineCPUVendorUnknown(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineInte", nil, 0, nil))

	_, err := DetermineCPUVendor(env)
	c.Check(err, ErrorMatches, `unknown CPU vendor: GenuineInte`)
}
