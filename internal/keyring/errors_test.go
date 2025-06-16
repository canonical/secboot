// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2025 Canonical Ltd
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

package keyring_test

import (
	"fmt"
	"syscall"

	. "github.com/snapcore/secboot/internal/keyring"

	. "gopkg.in/check.v1"
)

type errorsSuite struct{}

var _ = Suite(&errorsSuite{})

func (*errorsSuite) TestProcessSyscallErrorENOTDIR(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.ENOTDIR)), Equals, ErrExpectedKeyring)
}

func (*errorsSuite) TestProcessSyscallErrorEINVAL(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.EINVAL)), Equals, ErrInvalidArgs)
}

func (*errorsSuite) TestProcessSyscallErrorEKEYEXPIRED(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.EKEYEXPIRED)), Equals, ErrKeyExpired)
}

func (*errorsSuite) TestProcessSyscallErrorENOKEY(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.ENOKEY)), Equals, ErrKeyNotExist)
}

func (*errorsSuite) TestProcessSyscallErrorENOENT(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.ENOENT)), Equals, ErrKeyNotExist)
}

func (*errorsSuite) TestProcessSyscallErrorEEXIST(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.EEXIST)), Equals, ErrKeyExists)
}

func (*errorsSuite) TestProcessSyscallErrorEKEYREVOKED(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.EKEYREVOKED)), Equals, ErrKeyRevoked)
}

func (*errorsSuite) TestProcessSyscallErrorEACCES(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.EACCES)), Equals, ErrPermission)
}

func (*errorsSuite) TestProcessSyscallErrorEPERM(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.EPERM)), Equals, ErrPermission)
}

func (*errorsSuite) TestProcessSyscallErrorEDQUOT(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.EDQUOT)), Equals, ErrQuota)
}

func (*errorsSuite) TestProcessSyscallErrorEOPNOTSUPP(c *C) {
	c.Check(ProcessSyscallError(fmt.Errorf("some error: %w", syscall.EOPNOTSUPP)), Equals, ErrUnsupported)
}
