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

package testutil_test

import (
	"errors"
	"io"
	"os"
	"reflect"

	. "github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

func testInfo(c *C, checker Checker, name string, paramNames []string) {
	info := checker.Info()
	if info.Name != name {
		c.Fatalf("Got name %s, expected %s", info.Name, name)
	}
	if !reflect.DeepEqual(info.Params, paramNames) {
		c.Fatalf("Got param names %#v, expected %#v", info.Params, paramNames)
	}
}

func testCheck(c *C, checker Checker, result bool, error string, params ...interface{}) ([]interface{}, []string) {
	info := checker.Info()
	if len(params) != len(info.Params) {
		c.Fatalf("unexpected param count in test; expected %d got %d", len(info.Params), len(params))
	}
	names := append([]string{}, info.Params...)
	resultActual, errorActual := checker.Check(params, names)
	if resultActual != result || errorActual != error {
		c.Fatalf("%s.Check(%#v) returned (%#v, %#v) rather than (%#v, %#v)",
			info.Name, params, resultActual, errorActual, result, error)
	}
	return params, names
}

type checkersSuite struct{}

var _ = Suite(&checkersSuite{})

func (s *checkersSuite) TestHasKey(c *C) {
	testInfo(c, HasKey, "HasKey", []string{"map", "key"})
	testCheck(c, HasKey, true, "", map[string]int{"foo": 1, "bar": 2}, "foo")
	testCheck(c, HasKey, false, "", map[string]int{"foo": 1, "bar": 2}, "baz")
	testCheck(c, HasKey, true, "", map[int]int{5: 1, 8: 3}, 8)
	testCheck(c, HasKey, false, "", map[int]int{5: 1, 8: 3}, 3)
	testCheck(c, HasKey, false, "map is not a map", "foo", "foo")
	testCheck(c, HasKey, false, "key has an unexpected type", map[int]int{}, "foo")
}

func (s *checkersSuite) TestInSlice(c *C) {
	testInfo(c, InSlice(Equals), "InSlice(Equals)", []string{"obtained", "[]expected"})
	testCheck(c, InSlice(Equals), true, "", 1, []int{2, 1, 5})
	testCheck(c, InSlice(Equals), false, "", 10, []int{2, 1, 5})
	testCheck(c, InSlice(Equals), true, "", "foo", []string{"foo", "bar"})
	testCheck(c, InSlice(Equals), false, "", "baz", []string{"foo", "bar"})

	testCheck(c, InSlice(IsNil), false, "InSlice can only be used with checkers that require 2 parameters", nil, nil)
	testCheck(c, InSlice(Equals), false, "[]expected has the wrong kind", 1, 1)
}

func (s *checkersSuite) TestIsTrue(c *C) {
	testInfo(c, IsTrue, "IsTrue", []string{"value"})
	testCheck(c, IsTrue, true, "", true)
	testCheck(c, IsTrue, false, "", false)
	testCheck(c, IsTrue, false, "value is not a bool", 1)
}

func (s *checkersSuite) TestIsFalse(c *C) {
	testInfo(c, IsFalse, "IsFalse", []string{"value"})
	testCheck(c, IsFalse, true, "", false)
	testCheck(c, IsFalse, false, "", true)
	testCheck(c, IsFalse, false, "value is not a bool", 1)
}

type testError struct {
	err error
}

func (e testError) Error() string { return "error: " + e.err.Error() }
func (e testError) Unwrap() error { return e.err }

func (s *checkersSuite) TestConvertibleTo(c *C) {
	testInfo(c, ConvertibleTo, "ConvertibleTo", []string{"value", "sample"})
	testCheck(c, ConvertibleTo, true, "", testError{}, testError{})
	testCheck(c, ConvertibleTo, false, "", &testError{}, testError{})
	testCheck(c, ConvertibleTo, false, "", testError{}, &testError{})

	var e error = testError{}
	testCheck(c, ConvertibleTo, true, "", e, testError{})
	testCheck(c, ConvertibleTo, false, "", e, errors.New(""))

	e = new(os.PathError)
	testCheck(c, ConvertibleTo, true, "", e, &os.PathError{})
	testCheck(c, ConvertibleTo, false, "", e, testError{})
}

func (s *checkersSuite) TestErrorIs(c *C) {
	testInfo(c, ErrorIs, "ErrorIs", []string{"value", "expected"})
	testCheck(c, ErrorIs, true, "", os.ErrNotExist, os.ErrNotExist)
	testCheck(c, ErrorIs, false, "", os.ErrNotExist, io.EOF)
	testCheck(c, ErrorIs, false, "value is not an error", "foo", io.EOF)
	testCheck(c, ErrorIs, false, "expected is not an error", io.EOF, "foo")
}
