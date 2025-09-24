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

	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type jsonutilSuite struct{}

var _ = Suite(&jsonutilSuite{})

type testJsonStruct struct {
	A int    `json:"a"`
	B string `json:"b"`
}

type testJsonCustom []int

func (c testJsonCustom) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string][]int{"test": []int(c)})
}

func (c *testJsonCustom) UnmarshalJSON(data []byte) error {
	var m map[string][]int
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	*c = testJsonCustom(m["test"])
	return nil
}

func (*jsonutilSuite) TestGetValueFromJSONMapStruct(c *C) {
	m := map[string]json.RawMessage{"a": json.RawMessage(`5`), "b": json.RawMessage(`"foo"`)}
	val, err := GetValueFromJSONMap[testJsonStruct](m)
	c.Check(err, IsNil)
	c.Check(val, Equals, testJsonStruct{A: 5, B: "foo"})
}

func (*jsonutilSuite) TestGetValueFromJSONMapStructWithZeroField(c *C) {
	m := map[string]json.RawMessage{"b": json.RawMessage(`"foo"`)}
	val, err := GetValueFromJSONMap[testJsonStruct](m)
	c.Check(err, IsNil)
	c.Check(val, Equals, testJsonStruct{B: "foo"})
}

func (*jsonutilSuite) TestGetValueFromJSONMapCustom(c *C) {
	m := map[string]json.RawMessage{"test": json.RawMessage(`[3, 1, 7]`)}
	val, err := GetValueFromJSONMap[testJsonCustom](m)
	c.Check(err, IsNil)
	c.Check(val, DeepEquals, testJsonCustom{3, 1, 7})
}

func (*jsonutilSuite) TestGetValueFromJSONMapNilMap(c *C) {
	val, err := GetValueFromJSONMap[testJsonStruct](nil)
	c.Check(err, IsNil)
	c.Check(val, Equals, testJsonStruct{})
}

func (*jsonutilSuite) TestGetValueFromJSONMapTypeError(c *C) {
	m := map[string]json.RawMessage{"a": json.RawMessage(`"foo"`)}
	_, err := GetValueFromJSONMap[testJsonStruct](m)
	c.Check(err, ErrorMatches, `cannot deserialize argument map from JSON to type preinstall_test.testJsonStruct: json: cannot unmarshal string into Go struct field testJsonStruct.a of type int`)

	var e *json.UnmarshalTypeError
	c.Assert(errors.As(err, &e), testutil.IsTrue)
	c.Check(e.Field, Equals, "a")
}

func (*jsonutilSuite) TestGetValueFromJSONMapUnknownField(c *C) {
	m := map[string]json.RawMessage{"foo": json.RawMessage(`2`)}
	_, err := GetValueFromJSONMap[testJsonStruct](m)
	c.Check(err, ErrorMatches, `cannot deserialize argument map from JSON to type preinstall_test.testJsonStruct: json: unknown field "foo"`)
}
