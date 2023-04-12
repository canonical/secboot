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
	"crypto"
	_ "crypto/sha256"
	"io"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
)

type shimContextSuite struct{}

var _ = Suite(&shimContextSuite{})

func (s *shimContextSuite) TestHasVerificationEvent(c *C) {
	ctx := new(ShimContext)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	c.Check(ctx.HasVerificationEvent(digest1), testutil.IsFalse)
	c.Check(ctx.HasVerificationEvent(digest2), testutil.IsFalse)

	ctx.AppendVerificationEvent(digest1)

	c.Check(ctx.HasVerificationEvent(digest1), testutil.IsTrue)
	c.Check(ctx.HasVerificationEvent(digest2), testutil.IsFalse)

	ctx.AppendVerificationEvent(digest2)

	c.Check(ctx.HasVerificationEvent(digest1), testutil.IsTrue)
	c.Check(ctx.HasVerificationEvent(digest2), testutil.IsTrue)
}
