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

package secboot_test

import (
	"io"

	. "github.com/snapcore/secboot"
	. "gopkg.in/check.v1"
)

type activateExternalKeysSuite struct{}

var _ = Suite(&activateExternalKeysSuite{})

func (*activateExternalKeysSuite) TestNewExternalKeyData(c *C) {
	r := newMockKeyDataReader("", []byte("foo mock key data"))
	data := NewExternalKeyData("foo", r)
	c.Assert(data, NotNil)
	c.Check(data.Name(), Equals, "foo")
	c.Check(data.ReadableName(), Equals, "foo")

	b, err := io.ReadAll(r)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, []byte("foo mock key data"))
}

func (*activateExternalKeysSuite) TestNewExternalKeyDataDifferentName(c *C) {
	r := newMockKeyDataReader("", []byte("bar mock key data"))
	data := NewExternalKeyData("bar", r)
	c.Assert(data, NotNil)
	c.Check(data.Name(), Equals, "bar")
	c.Check(data.ReadableName(), Equals, "bar")

	b, err := io.ReadAll(r)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, []byte("bar mock key data"))
}
