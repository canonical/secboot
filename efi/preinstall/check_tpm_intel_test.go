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
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type tpmIntelSuite struct{}

var _ = Suite(&tpmIntelSuite{})

func (s *tpmIntelSuite) TestIsTPMDiscreteFromIntelBootguardTPM2(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (2 << 1)}),
	)
	amd64, err := env.AMD64()
	c.Assert(err, IsNil)
	discrete, err := IsTPMDiscreteFromIntelBootGuard(amd64)
	c.Check(err, IsNil)
	c.Check(discrete, testutil.IsTrue)
}

func (s *tpmIntelSuite) TestIsTPMDiscreteFromIntelBootguardPTT(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}),
	)
	amd64, err := env.AMD64()
	c.Assert(err, IsNil)
	discrete, err := IsTPMDiscreteFromIntelBootGuard(amd64)
	c.Check(err, IsNil)
	c.Check(discrete, testutil.IsFalse)
}

func (s *tpmIntelSuite) TestIsTPMDiscreteFromIntelBootguardTPM12(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (1 << 1)}),
	)
	amd64, err := env.AMD64()
	c.Assert(err, IsNil)
	_, err = IsTPMDiscreteFromIntelBootGuard(amd64)
	c.Check(err, Equals, ErrNoTPM2Device)
}

func (s *tpmIntelSuite) TestIsTPMDiscreteFromIntelBootguardNoTPM(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (0 << 1)}),
	)
	amd64, err := env.AMD64()
	c.Assert(err, IsNil)
	_, err = IsTPMDiscreteFromIntelBootGuard(amd64)
	c.Check(err, Equals, ErrNoTPM2Device)
}
