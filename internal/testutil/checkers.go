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

package testutil

import (
	"reflect"

	. "gopkg.in/check.v1"
)

type hasKeyChecker struct {
	*CheckerInfo
}

var HasKey = &hasKeyChecker{
	&CheckerInfo{Name: "HasKey", Params: []string{"map", "key"}}}

func (checker *hasKeyChecker) Check(params []interface{}, names []string) (result bool, error string) {
	m := reflect.ValueOf(params[0])
	if m.Kind() != reflect.Map {
		return false, names[0] + " is not a map"
	}

	k := reflect.ValueOf(params[1])
	if k.Type() != m.Type().Key() {
		return false, names[1] + " has an unexpected type"
	}

	keys := m.MapKeys()
	for _, key := range keys {
		if key.Interface() == k.Interface() {
			return true, ""
		}
	}

	return false, ""
}

type inSliceChecker struct {
	sub Checker
}

func (checker *inSliceChecker) Info() *CheckerInfo {
	info := *checker.sub.Info()
	info.Name = "InSlice(" + info.Name + ")"
	info.Params = append([]string{}, info.Params...)
	if len(info.Params) >= 2 {
		info.Params[1] = "[]" + info.Params[1]
	} else {
		info.Params = append(info.Params, "[]expected")
	}
	info.Params = info.Params[:2]
	return &info
}

func (checker *inSliceChecker) Check(params []interface{}, names []string) (result bool, error string) {
	if len(params) != len(checker.sub.Info().Params) {
		return false, "InSlice can only be used with checkers that require 2 parameters"
	}

	slice := reflect.ValueOf(params[1])
	if slice.Kind() != reflect.Slice {
		return false, names[1] + " has the wrong kind"
	}

	for i := 0; i < slice.Len(); i++ {
		if result, _ := checker.sub.Check([]interface{}{params[0], slice.Index(i).Interface()}, []string{names[0], checker.sub.Info().Params[1]}); result {
			return true, ""
		}
	}
	return false, ""
}

// InSlice determines whether a value is contained in the provided slice, using
// the specified checker.
//
// For example:
//
//	c.Check(value, InSlice(Equals), []int{1, 2, 3})
func InSlice(checker Checker) Checker {
	return &inSliceChecker{checker}
}

type isTrueChecker struct {
	*CheckerInfo
}

var IsTrue Checker = &isTrueChecker{
	&CheckerInfo{Name: "IsTrue", Params: []string{"value"}}}

func (checker *isTrueChecker) Check(params []interface{}, names []string) (result bool, error string) {
	value := reflect.ValueOf(params[0])
	if value.Kind() != reflect.Bool {
		return false, names[0] + " is not a bool"
	}
	return value.Bool(), ""
}
