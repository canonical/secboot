// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
)

type authRequestorSuite struct{}

var _ = Suite(&authRequestorSuite{})

func (*authRequestorSuite) TestFormatUserAuthTypeStringNone(c *C) {
	c.Check(FormatUserAuthTypeString(0), Equals, "")
}

func (*authRequestorSuite) TestFormatUserAuthTypeStringPassphrase(c *C) {
	c.Check(FormatUserAuthTypeString(UserAuthTypePassphrase), Equals, "passphrase")
}

func (*authRequestorSuite) TestFormatUserAuthTypeStringPIN(c *C) {
	c.Check(FormatUserAuthTypeString(UserAuthTypePIN), Equals, "PIN")
}

func (*authRequestorSuite) TestFormatUserAuthTypeStringRecoveryKey(c *C) {
	c.Check(FormatUserAuthTypeString(UserAuthTypeRecoveryKey), Equals, "recovery key")
}

func (*authRequestorSuite) TestFormatUserAuthTypeStringPassphraseOrPIN(c *C) {
	c.Check(FormatUserAuthTypeString(UserAuthTypePassphrase|UserAuthTypePIN), Equals, "passphrase or PIN")
}

func (*authRequestorSuite) TestFormatUserAuthTypeStringPassphraseOrRecoveryKey(c *C) {
	c.Check(FormatUserAuthTypeString(UserAuthTypePassphrase|UserAuthTypeRecoveryKey), Equals, "passphrase or recovery key")
}

func (*authRequestorSuite) TestFormatUserAuthTypeStringPINOrRecoveryKey(c *C) {
	c.Check(FormatUserAuthTypeString(UserAuthTypePIN|UserAuthTypeRecoveryKey), Equals, "PIN or recovery key")
}

func (*authRequestorSuite) TestFormatUserAuthTypeStringPassphraseOrPINOrRecoveryKey(c *C) {
	c.Check(FormatUserAuthTypeString(UserAuthTypePassphrase|UserAuthTypePIN|UserAuthTypeRecoveryKey), Equals, "passphrase, PIN or recovery key")
}
