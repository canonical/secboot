// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2022 Canonical Ltd
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
	. "github.com/snapcore/secboot"

	. "gopkg.in/check.v1"
)

type platformSuite struct{}

var _ = Suite(&platformSuite{})

func (s *platformSuite) TestPlatformKeyDataHandlerFlagsAddPlatformFlagsGood1(c *C) {
	flags := PlatformKeyDataHandlerFlags(0x080000000000)
	flags = flags.AddPlatformFlags(50)
	c.Check(flags, Equals, PlatformKeyDataHandlerFlags(0x080000000032))
}

func (s *platformSuite) TestPlatformKeyDataHandlerFlagsAddPlatformFlagsGood2(c *C) {
	flags := PlatformKeyDataHandlerFlags(0x480000000000)
	flags = flags.AddPlatformFlags(0xffffffffff)
	c.Check(flags, Equals, PlatformKeyDataHandlerFlags(0x48ffffffffff))
}

func (s *platformSuite) TestPlatformKeyDataHandlerFlagsAddPlatformFlagsBad(c *C) {
	flags := PlatformKeyDataHandlerFlags(0x080000000000)
	c.Check(func() { flags.AddPlatformFlags(0x090000000000) }, PanicMatches, `platform is using flag bits reserved for common flags: 0x90000000000`)
}

func (s *platformSuite) TestRegisterPlatformKeyDataHandler(c *C) {
	handler := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock", handler, 50)
	handler2, flags, err := RegisteredPlatformKeyDataHandler("mock")
	c.Assert(err, IsNil)
	c.Check(handler2, Equals, handler)
	c.Check(flags, Equals, PlatformKeyDataHandlerFlags(50))
}

func (s *platformSuite) TestRegisterPlatformKeyDataHandlerDifferentName(c *C) {
	handler := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("foo", handler, 50)
	handler2, flags, err := RegisteredPlatformKeyDataHandler("foo")
	c.Assert(err, IsNil)
	c.Check(handler2, Equals, handler)
	c.Check(flags, Equals, PlatformKeyDataHandlerFlags(50))
}

func (s *platformSuite) TestRegisterPlatformKeyDataHandlerDifferentFlags(c *C) {
	handler := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock", handler, 0xffffffffff)
	handler2, flags, err := RegisteredPlatformKeyDataHandler("mock")
	c.Assert(err, IsNil)
	c.Check(handler2, Equals, handler)
	c.Check(flags, Equals, PlatformKeyDataHandlerFlags(0xffffffffff))
}

func (s *platformSuite) TestUnregisterPlatformKeyDataHandler(c *C) {
	RegisterPlatformKeyDataHandler("mock", new(mockPlatformKeyDataHandler), 50)
	RegisterPlatformKeyDataHandler("mock", nil, 0)
	_, _, err := RegisteredPlatformKeyDataHandler("mock")
	c.Check(err, Equals, ErrNoPlatformHandlerRegistered)
}

func (s *platformSuite) TestReRegisterPlatformKeyDataHandler(c *C) {
	handler1 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock", handler1, 50)
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock", handler2, 0xffffffffff)
	handler3, flags, err := RegisteredPlatformKeyDataHandler("mock")
	c.Assert(err, IsNil)
	c.Check(handler3, Equals, handler2)
	c.Check(flags, Equals, PlatformKeyDataHandlerFlags(0xffffffffff))
}

func (s *platformSuite) TestRegisterMultiplePlatformKeyDataHandler(c *C) {
	handler1 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock", handler1, 50)
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("foo", handler2, 0xffffffffff)

	handler3, flags, err := RegisteredPlatformKeyDataHandler("mock")
	c.Assert(err, IsNil)
	c.Check(handler3, Equals, handler1)
	c.Check(flags, Equals, PlatformKeyDataHandlerFlags(50))

	handler3, flags, err = RegisteredPlatformKeyDataHandler("foo")
	c.Assert(err, IsNil)
	c.Check(handler3, Equals, handler2)
	c.Check(flags, Equals, PlatformKeyDataHandlerFlags(0xffffffffff))
}

func (s *platformSuite) TestListRegisteredKeyDataPlatforms(c *C) {
	handler1 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock", handler1, 50)
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("foo", handler2, 0xffffffffff)

	c.Check(ListRegisteredKeyDataPlatforms(), DeepEquals, []string{"foo", "mock"})
}
