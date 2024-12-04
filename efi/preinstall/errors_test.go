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
	. "gopkg.in/check.v1"
)

type errorsSuite struct{}

var _ = Suite(&errorsSuite{})

func (s *errorsSuite) TestRunChecksErrorsError(c *C) {
	err := &RunChecksErrors{
		Errs: []error{
			errors.New("some error 1"),
			errors.New(`some error 2
across more than one line`),
			errors.New("some error 3"),
			errors.New(`some error 4
which also spans across
multiple lines
`),
		},
	}

	c.Check(err.Error(), Equals, `one or more errors detected:
- some error 1
- some error 2
  across more than one line
- some error 3
- some error 4
  which also spans across
  multiple lines
`)
}
