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
	"errors"
	"fmt"

	. "github.com/snapcore/secboot"
	. "gopkg.in/check.v1"
)

type activateStateSuite struct{}

var _ = Suite(&activateStateSuite{})

func (*activateStateSuite) TestErrorToKeyslotErrorNil(c *C) {
	c.Check(ErrorToKeyslotError(nil), Equals, KeyslotErrorNone)
}

func (*activateStateSuite) TestErrorToKeyslotErrorInvalidPrimaryKey(c *C) {
	c.Check(ErrorToKeyslotError(fmt.Errorf("%w", ErrInvalidPrimaryKey)), Equals, KeyslotErrorInvalidPrimaryKey)
}

func (*activateStateSuite) TestErrorToKeyslotErrorInvalidKeyData(c *C) {
	c.Check(ErrorToKeyslotError(fmt.Errorf("%w", NewInvalidKeyDataError(errors.New("some error")))), Equals, KeyslotErrorInvalidKeyData)
}

func (*activateStateSuite) TestErrorToKeyslotErrorIncompatibleKeyDataRoleParams(c *C) {
	c.Check(ErrorToKeyslotError(fmt.Errorf("%w", NewIncompatibleKeyDataRoleParamsError(errors.New("some error")))), Equals, KeyslotErrorIncompatibleRoleParams)
}

func (*activateStateSuite) TestErrorToKeyslotErrorInvalidPassphrase(c *C) {
	c.Check(ErrorToKeyslotError(fmt.Errorf("%w", ErrInvalidPassphrase)), Equals, KeyslotErrorIncorrectUserAuth)
}

func (*activateStateSuite) TestErrorToKeyslotErrorInvalidRecoveryKey(c *C) {
	c.Check(ErrorToKeyslotError(fmt.Errorf("%w", ErrInvalidRecoveryKey)), Equals, KeyslotErrorIncorrectUserAuth)
}

func (*activateStateSuite) TestErrorToKeyslotErrorPlatformUninitialized(c *C) {
	c.Check(ErrorToKeyslotError(fmt.Errorf("%w", NewPlatformUninitializedError(errors.New("some error")))), Equals, KeyslotErrorPlatformFailure)
}

func (*activateStateSuite) TestErrorToKeyslotErrorPlatformDeviceUnavailable(c *C) {
	c.Check(ErrorToKeyslotError(fmt.Errorf("%w", NewPlatformDeviceUnavailableError(errors.New("some error")))), Equals, KeyslotErrorPlatformFailure)
}

func (*activateStateSuite) TestErrorToKeyslotErrorUnknown(c *C) {
	c.Check(ErrorToKeyslotError(errors.New("some error")), Equals, KeyslotErrorUnknown)
}
