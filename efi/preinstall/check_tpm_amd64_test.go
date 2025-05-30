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
	"errors"

	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type tpmAmd64Suite struct{}

var _ = Suite(&tpmAmd64Suite{})

func (s *tpmIntelSuite) TestIsTPMDiscreteIntelYes(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (2 << 1)}),
	)
	discrete, err := IsTPMDiscrete(env)
	c.Check(err, IsNil)
	c.Check(discrete, testutil.IsTrue)
}

func (s *tpmIntelSuite) TestIsTPMDiscreteIntelNo(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}),
	)
	discrete, err := IsTPMDiscrete(env)
	c.Check(err, IsNil)
	c.Check(discrete, testutil.IsFalse)
}

func (s *tpmIntelSuite) TestIsTPMDiscreteIntelNoTPM2(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (0 << 1)}),
	)
	_, err := IsTPMDiscrete(env)
	c.Check(err, ErrorMatches, `cannot check TPM discreteness using Intel BootGuard status: no TPM2 device is available`)
	c.Check(errors.Is(err, ErrNoTPM2Device), testutil.IsTrue)
}

func (s *tpmIntelSuite) TestIsTPMDiscreteAMDNotSupported(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("AuthenticAMD", nil, 1, nil))
	_, err := IsTPMDiscrete(env)
	c.Check(err, ErrorMatches, `unsupported platform: cannot check TPM discreteness on AMD systems`)

	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}

func (s *tpmIntelSuite) TestIsTPMDiscreteUnrecognizedCPUVendor(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineInte", nil, 1, nil))
	_, err := IsTPMDiscrete(env)
	c.Check(err, ErrorMatches, `unsupported platform: cannot determine CPU vendor: unknown CPU vendor: GenuineInte`)

	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}
