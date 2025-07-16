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

package fido2_test

import (
	"os"
	"testing"

	"github.com/snapcore/secboot/fido2"
	testutil "github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

type fidoTestSuite struct{}

var _ = Suite(&fidoTestSuite{})

func (s *fidoTestSuite) TestConnect(c *C) {
	authRequestor := &testutil.MockFidoAuthRequestor{Pin: ""}
	_, err := fido2.ConnectToFIDO2Authenticator(authRequestor)
	c.Check(err, IsNil)
}
