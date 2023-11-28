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

package efi_test

import (
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
)

type grubSuite struct{}

var _ = Suite(&grubSuite{})

func (s *grubSuite) TestGrubImageHandlePrefix1(c *C) {
	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockgrub.efi"))
	c.Assert(err, IsNil)
	defer image.Close()

	grubImage := NewGrubImageHandle(image)

	prefix, err := grubImage.Prefix()
	c.Check(err, IsNil)
	c.Check(prefix, Equals, "/EFI/ubuntu")
}

func (s *grubSuite) TestGrubImageHandlePrefix2(c *C) {
	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockgrub_debian.efi"))
	c.Assert(err, IsNil)
	defer image.Close()

	grubImage := NewGrubImageHandle(image)

	prefix, err := grubImage.Prefix()
	c.Check(err, IsNil)
	c.Check(prefix, Equals, "/EFI/debian")
}

func (s *grubSuite) TestGrubImageHandlePrefixNone(c *C) {
	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockgrub_no_prefix.efi"))
	c.Assert(err, IsNil)
	defer image.Close()

	grubImage := NewGrubImageHandle(image)

	prefix, err := grubImage.Prefix()
	c.Check(err, IsNil)
	c.Check(prefix, Equals, "")
}
