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
	"context"
	"errors"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type checkEfiSuite struct{}

var _ = Suite(&checkEfiSuite{})

func (*checkEfiSuite) TestCheckSystemIsEFIGood(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithMockVars(efitest.MockVars{}.SetSecureBoot(true)),
	)
	c.Check(CheckSystemIsEFI(context.Background(), env), IsNil)
}

func (*checkEfiSuite) TestCheckSystemIsEFIBad1(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()
	c.Check(CheckSystemIsEFI(context.Background(), env), Equals, ErrSystemNotEFI)
}

func (*checkEfiSuite) TestCheckSystemIsEFIBad2(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithMockVars(efitest.MockVars{}),
	)
	err := CheckSystemIsEFI(context.Background(), env)
	c.Check(err, ErrorMatches, `cannot access EFI variable: variable does not exist`)
	var e *EFIVariableAccessError
	c.Check(errors.As(err, &e), testutil.IsTrue)
}
