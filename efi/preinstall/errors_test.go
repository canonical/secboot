// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type errorsSuite struct{}

var _ = Suite(&errorsSuite{})

func (s *errorsSuite) TestJoinError(c *C) {
	err := JoinErrors(
		errors.New("some error 1"),
		errors.New(`some error 2
across more than one line`),
		errors.New("some error 3"),
		errors.New(`some error 4
which also spans across
multiple lines
`),
	)

	c.Check(err.Error(), Equals, `4 errors detected:
- some error 1
- some error 2
  across more than one line
- some error 3
- some error 4
  which also spans across
  multiple lines
`)
}

func (s *errorsSuite) TestJoinErrorOneError(c *C) {
	err := JoinErrors(errors.New("some error"))
	c.Check(err.Error(), Equals, `some error`)
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorNoArgsOrActions(c *C) {
	kind := ErrorKind("foo")
	rawErr := errors.New("some error")
	err := NewWithKindAndActionsError(kind, nil, nil, rawErr)
	c.Check(err, DeepEquals, NewWithKindAndActionsErrorForTest(kind, nil, nil, rawErr))
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorNoArgs(c *C) {
	kind := ErrorKind("bar")
	actions := []Action{"action1", "action2"}
	rawErr := errors.New("another error")
	err := NewWithKindAndActionsError(kind, nil, actions, rawErr)
	c.Check(err, DeepEquals, NewWithKindAndActionsErrorForTest(kind, nil, actions, rawErr))
}

func (s *errorsSuite) TestNewWithKindAndActionsError(c *C) {
	kind := ErrorKind("foo")
	args := map[string]any{
		"arg1": 1,
		"arg2": "bar",
	}
	argJson := make(map[string]json.RawMessage)
	for k, v := range args {
		j, err := json.Marshal(v)
		c.Assert(err, IsNil)
		argJson[k] = j
	}
	actions := []Action{"action2", "action1"}
	rawErr := errors.New("some error")
	err := NewWithKindAndActionsError(kind, args, actions, rawErr)
	c.Check(err, DeepEquals, NewWithKindAndActionsErrorForTest(kind, argJson, actions, rawErr))
}

type withKindAndActionsErrorArgs struct {
	Arg1 string `json:"arg1"`
	Arg2 int    `json:"arg2"`
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorArgStructure(c *C) {
	kind := ErrorKind("foo")
	args := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 35}
	argsJson := map[string]json.RawMessage{
		"arg1": []byte("\"bar\""),
		"arg2": []byte("35"),
	}
	rawErr := errors.New("some error")
	err := NewWithKindAndActionsError(kind, args, nil, rawErr)
	c.Check(err, DeepEquals, NewWithKindAndActionsErrorForTest(kind, argsJson, nil, rawErr))
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorMarshal(c *C) {
	kind := ErrorKind("bar")
	args := &withKindAndActionsErrorArgs{Arg1: "foo", Arg2: 35}
	argsJson := map[string]json.RawMessage{
		"arg1": []byte("\"foo\""),
		"arg2": []byte("35"),
	}
	actions := []Action{"action1", "action2"}
	rawErr := errors.New("some error")

	data, err := json.Marshal(NewWithKindAndActionsError(kind, args, actions, rawErr))
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b226b696e64223a22626172222c2261726773223a7b2261726731223a22666f6f222c2261726732223a33357d2c22616374696f6e73223a5b22616374696f6e31222c22616374696f6e32225d7d"))

	var decodedErr *WithKindAndActionsError
	c.Check(json.Unmarshal(data, &decodedErr), IsNil)
	c.Check(decodedErr, DeepEquals, NewWithKindAndActionsErrorForTest(kind, argsJson, actions, nil))
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorNoJsonArgsPanic(c *C) {
	c.Check(func() {
		NewWithKindAndActionsError("foo", []any{"bar1", json.RawMessage{0x22, 0x62, 0x61, 0x72}}, nil, errors.New("some error"))
	}, PanicMatches, `cannot serialize arguments to JSON: json: error calling MarshalJSON for type json.RawMessage: unexpected end of JSON input`)
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorNoMapArgsPanic(c *C) {
	c.Check(func() { NewWithKindAndActionsError("foo", []string{"bar1", "bar2"}, nil, errors.New("some error")) }, PanicMatches, `cannot deserialize arguments JSON to map: json: cannot unmarshal array into Go value of type map\[string\]json.RawMessage`)
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgByName1(c *C) {
	kind := ErrorKind("foo")
	args := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 20}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, args, nil, rawErr)

	val, err := testErr.GetArgByName("arg1")
	c.Check(err, IsNil)
	c.Check(val, Equals, any("bar"))
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgByName2(c *C) {
	kind := ErrorKind("foo")
	args := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 20}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, args, nil, rawErr)

	val, err := testErr.GetArgByName("arg2")
	c.Check(err, IsNil)
	c.Check(val, Equals, any(float64(20)))
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgByNameMissingName(c *C) {
	kind := ErrorKind("foo")
	args := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 20}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, args, nil, rawErr)

	_, err := testErr.GetArgByName("missing")
	c.Check(err, ErrorMatches, `argument "missing" does not exist`)
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgByNameInvalidJSON(c *C) {
	kind := ErrorKind("foo")
	args := map[string]json.RawMessage{
		"arg": []byte("\"bar"),
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsErrorForTest(kind, args, nil, rawErr)

	_, err := testErr.GetArgByName("arg")
	c.Check(err, ErrorMatches, `cannot deserialize argument "arg" from JSON: unexpected end of JSON input`)
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgMap(c *C) {
	kind := ErrorKind("foo")
	args := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 20}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, args, nil, rawErr)

	val, err := testErr.GetArgMap()
	c.Assert(err, IsNil)
	c.Check(val, DeepEquals, map[string]any{
		"arg1": any("bar"),
		"arg2": any(float64(20)),
	})
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgMapInvalidJSON(c *C) {
	kind := ErrorKind("foo")
	args := map[string]json.RawMessage{
		"arg1": []byte("\"bar"),
		"arg2": []byte("40"),
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsErrorForTest(kind, args, nil, rawErr)

	_, err := testErr.GetArgMap()
	c.Assert(err, ErrorMatches, `cannot deserialize argument "arg1" from JSON: unexpected end of JSON input`)
}

func (s *errorsSuite) TestGetWithKindAndActionsErrorArg1(c *C) {
	kind := ErrorKind("foo")
	expectedArgs := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 20}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, expectedArgs, nil, rawErr)

	args, err := GetWithKindAndActionsErrorArg[*withKindAndActionsErrorArgs](testErr)
	c.Assert(err, IsNil)
	c.Check(args, DeepEquals, expectedArgs)
}

func (s *errorsSuite) TestGetWithKindAndActionsErrorArg2(c *C) {
	kind := ErrorKind("foo")
	argsIn := map[string]any{
		"arg1": "bar",
		"arg2": 35,
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, argsIn, nil, rawErr)

	args, err := GetWithKindAndActionsErrorArg[withKindAndActionsErrorArgs](testErr)
	c.Assert(err, IsNil)
	c.Check(args, DeepEquals, withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 35})
}

func (s *errorsSuite) TestGetWithKindAndActionsErrorInvalidMap(c *C) {
	kind := ErrorKind("foo")
	argsJson := map[string]json.RawMessage{
		"arg1": []byte("\"bar"),
		"arg2": []byte("40"),
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsErrorForTest(kind, argsJson, nil, rawErr)

	_, err := GetWithKindAndActionsErrorArg[*withKindAndActionsErrorArgs](testErr)
	c.Assert(err, ErrorMatches, `cannot serialize argument map to JSON: json: error calling MarshalJSON for type json.RawMessage: unexpected end of JSON input`)
}

func (s *errorsSuite) TestGetWithKindAndActionsErrorInvalidType1(c *C) {
	kind := ErrorKind("foo")
	argsIn := map[string]any{
		"arg3": "bar",
		"arg4": 35,
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, argsIn, nil, rawErr)

	_, err := GetWithKindAndActionsErrorArg[*withKindAndActionsErrorArgs](testErr)
	c.Assert(err, ErrorMatches, `cannot deserialize argument map from JSON to type \*preinstall_test.withKindAndActionsErrorArgs: json: unknown field "arg3"`)
}

func (s *errorsSuite) TestGetWithKindAndActionsErrorInvalidType2(c *C) {
	kind := ErrorKind("foo")
	argsIn := map[string]any{
		"arg1": "bar",
		"arg2": true,
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, argsIn, nil, rawErr)

	_, err := GetWithKindAndActionsErrorArg[*withKindAndActionsErrorArgs](testErr)
	c.Assert(err, ErrorMatches, `cannot deserialize argument map from JSON to type \*preinstall_test.withKindAndActionsErrorArgs: json: cannot unmarshal bool into Go struct field withKindAndActionsErrorArgs.arg2 of type int`)
}

func (s *errorsSuite) TestMissingKernelModuleErrorModule(c *C) {
	c.Check(MissingKernelModuleError("msr").Module(), Equals, "msr")
	c.Check(MissingKernelModuleError("mei_me").Module(), Equals, "mei_me")
}
