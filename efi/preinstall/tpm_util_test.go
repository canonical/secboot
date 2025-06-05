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

package preinstall_test

import (
	"encoding/json"
	"time"

	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type tpmutilSuite struct{}

var _ = Suite(&tpmutilSuite{})

func (*tpmutilSuite) TestDeviceLockoutArgsIsValidTrue(c *C) {
	args := TPMDeviceLockoutArgs{
		IntervalDuration: 2 * time.Hour,
		TotalDuration:    64 * time.Hour,
	}
	c.Check(args.IsValid(), testutil.IsTrue)
}

func (*tpmutilSuite) TestDeviceLockoutArgsIsValidNotMod1False1(c *C) {
	args := TPMDeviceLockoutArgs{
		IntervalDuration: (2 * time.Hour) + (15625 * time.Millisecond),
		TotalDuration:    (64 * time.Hour) + time.Second,
	}
	c.Check(args.IsValid(), testutil.IsFalse)
}

func (*tpmutilSuite) TestDeviceLockoutArgsIsValidNotMod1False2(c *C) {
	args := TPMDeviceLockoutArgs{
		IntervalDuration: 2 * time.Hour,
		TotalDuration:    (64 * time.Hour) + (2 * time.Microsecond),
	}
	c.Check(args.IsValid(), testutil.IsFalse)
}

func (*tpmutilSuite) TestDeviceLockoutArgsIsValidNegativeFalse1(c *C) {
	args := TPMDeviceLockoutArgs{
		IntervalDuration: -2 * time.Hour,
		TotalDuration:    64 * time.Hour,
	}
	c.Check(args.IsValid(), testutil.IsFalse)
}

func (*tpmutilSuite) TestDeviceLockoutRecoveryArgJSON(c *C) {
	arg := TPMDeviceLockoutRecoveryArg(24 * time.Hour)
	data, err := json.Marshal(arg)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b226475726174696f6e223a38363430303030303030303030307d"))

	var arg2 TPMDeviceLockoutRecoveryArg
	c.Check(json.Unmarshal(data, &arg2), IsNil)
	c.Check(arg2, Equals, arg)
}

func (*tpmutilSuite) TestDeviceLockoutRecoveryArgDuration(c *C) {
	arg := TPMDeviceLockoutRecoveryArg(24 * time.Hour)
	c.Check(arg.Duration(), Equals, 24*time.Hour)
}

func (*tpmutilSuite) TestDeviceLockoutRecoveryArgLockoutClearsOnTPMStartupClearFalse(c *C) {
	arg := TPMDeviceLockoutRecoveryArg(24 * time.Hour)
	c.Check(arg.LockoutClearsOnTPMStartupClear(), testutil.IsFalse)
}

func (*tpmutilSuite) TestDeviceLockoutRecoveryArgLockoutClearsOnTPMStartupClearTrue(c *C) {
	var arg TPMDeviceLockoutRecoveryArg
	c.Check(arg.LockoutClearsOnTPMStartupClear(), testutil.IsTrue)
}

func (*tpmutilSuite) TestDeviceLockoutRecoveryArgIsValidTrue(c *C) {
	arg := TPMDeviceLockoutRecoveryArg(24 * time.Hour)
	c.Check(arg.IsValid(), testutil.IsTrue)
}

func (*tpmutilSuite) TestDeviceLockoutRecoveryArgIsValidFalse1(c *C) {
	arg := TPMDeviceLockoutRecoveryArg((24 * time.Hour) + (500 * time.Millisecond))
	c.Check(arg.IsValid(), testutil.IsFalse)
}

func (*tpmutilSuite) TestDeviceLockoutRecoveryArgIsValidFalse2(c *C) {
	arg := TPMDeviceLockoutRecoveryArg(-24 * time.Hour)
	c.Check(arg.IsValid(), testutil.IsFalse)
}
