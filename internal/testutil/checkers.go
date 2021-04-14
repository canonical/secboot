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
