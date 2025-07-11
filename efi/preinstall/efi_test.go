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
	"errors"
	"fmt"

	efi "github.com/canonical/go-efilib"
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type efiSuite struct{}

var _ = Suite(&efiSuite{})

func (*efiSuite) TestMakeEFIVariableAccessErrorArgVarsUnavailable(c *C) {
	arg := MakeEFIVariableAccessErrorArg(fmt.Errorf("some error: %w", efi.ErrVarsUnavailable))
	c.Check(arg, Equals, EFIVarsUnavailable)
}

func (*efiSuite) TestMakeEFIVariableAccessErrorArgVarNotExist(c *C) {
	arg := MakeEFIVariableAccessErrorArg(fmt.Errorf("some error: %w", efi.ErrVarNotExist))
	c.Check(arg, Equals, EFIVarNotExist)
}

func (*efiSuite) TestMakeEFIVariableAccessErrorArgInvalidParam(c *C) {
	arg := MakeEFIVariableAccessErrorArg(fmt.Errorf("some error: %w", efi.ErrVarInvalidParam))
	c.Check(arg, Equals, EFIVarInvalidParam)
}

func (*efiSuite) TestMakeEFIVariableAccessErrorArgVarDeviceError(c *C) {
	arg := MakeEFIVariableAccessErrorArg(fmt.Errorf("some error: %w", efi.ErrVarDeviceError))
	c.Check(arg, Equals, EFIVarDeviceError)
}

func (*efiSuite) TestMakeEFIVariableAccessErrorArgVarPermission(c *C) {
	arg := MakeEFIVariableAccessErrorArg(fmt.Errorf("some error: %w", efi.ErrVarPermission))
	c.Check(arg, Equals, EFIVarPermission)
}

func (*efiSuite) TestMakeEFIVariableAccessErrorArgVarInsufficientSpace(c *C) {
	arg := MakeEFIVariableAccessErrorArg(fmt.Errorf("some error: %w", efi.ErrVarInsufficientSpace))
	c.Check(arg, Equals, EFIVarInsufficientSpace)
}

func (*efiSuite) TestMakeEFIVariableAccessErrorArgVarWriteProtected(c *C) {
	arg := MakeEFIVariableAccessErrorArg(fmt.Errorf("some error: %w", efi.ErrVarWriteProtected))
	c.Check(arg, Equals, EFIVarWriteProtected)
}

func (*efiSuite) TestMakeEFIVariableAccessErrorArgUnrecognizedError(c *C) {
	arg := MakeEFIVariableAccessErrorArg(errors.New("some error"))
	c.Check(arg, Equals, EFIVarUnrecognizedError)
}

func (*efiSuite) TestEFIVariableAccessErrorArgMarshalVarsUnavailable(c *C) {
	arg1 := EFIVarsUnavailable
	data, err := json.Marshal(arg1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b22657272223a22766172732d756e617661696c61626c65227d"))

	var arg2 EFIVariableAccessErrorArg
	c.Check(json.Unmarshal(data, &arg2), IsNil)
	c.Check(arg1, Equals, arg2)
}

func (*efiSuite) TestEFIVariableAccessErrorArgMarshalVarNotExist(c *C) {
	arg1 := EFIVarNotExist
	data, err := json.Marshal(arg1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b22657272223a226e6f742d6578697374227d"))

	var arg2 EFIVariableAccessErrorArg
	c.Check(json.Unmarshal(data, &arg2), IsNil)
	c.Check(arg1, Equals, arg2)
}

func (*efiSuite) TestEFIVariableAccessErrorArgMarshalVarInvalidParam(c *C) {
	arg1 := EFIVarInvalidParam
	data, err := json.Marshal(arg1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b22657272223a22696e76616c69642d706172616d227d"))

	var arg2 EFIVariableAccessErrorArg
	c.Check(json.Unmarshal(data, &arg2), IsNil)
	c.Check(arg1, Equals, arg2)
}

func (*efiSuite) TestEFIVariableAccessErrorArgMarshalVarDeviceError(c *C) {
	arg1 := EFIVarDeviceError
	data, err := json.Marshal(arg1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b22657272223a226465766963652d6572726f72227d"))

	var arg2 EFIVariableAccessErrorArg
	c.Check(json.Unmarshal(data, &arg2), IsNil)
	c.Check(arg1, Equals, arg2)
}

func (*efiSuite) TestEFIVariableAccessErrorArgMarshalVarPermission(c *C) {
	arg1 := EFIVarPermission
	data, err := json.Marshal(arg1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b22657272223a227065726d697373696f6e227d"))

	var arg2 EFIVariableAccessErrorArg
	c.Check(json.Unmarshal(data, &arg2), IsNil)
	c.Check(arg1, Equals, arg2)
}

func (*efiSuite) TestEFIVariableAccessErrorArgMarshalVarInsufficientSpace(c *C) {
	arg1 := EFIVarInsufficientSpace
	data, err := json.Marshal(arg1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b22657272223a22696e73756666696369656e742d7370616365227d"))

	var arg2 EFIVariableAccessErrorArg
	c.Check(json.Unmarshal(data, &arg2), IsNil)
	c.Check(arg1, Equals, arg2)
}

func (*efiSuite) TestEFIVariableAccessErrorArgMarshalVarWriteProtected(c *C) {
	arg1 := EFIVarWriteProtected
	data, err := json.Marshal(arg1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b22657272223a2277726974652d70726f746563746564227d"))

	var arg2 EFIVariableAccessErrorArg
	c.Check(json.Unmarshal(data, &arg2), IsNil)
	c.Check(arg1, Equals, arg2)
}
