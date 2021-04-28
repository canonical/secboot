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
	"time"

	"github.com/snapcore/snapd/asserts"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
)

func MakeMockCore20ModelAssertion(c *C, headers map[string]interface{}, signKeyHash string) secboot.SnapModel {
	template := map[string]interface{}{
		"type":              "model",
		"architecture":      "amd64",
		"base":              "core20",
		"timestamp":         time.Now().Format(time.RFC3339),
		"sign-key-sha3-384": signKeyHash,
		"snaps": []interface{}{
			map[string]interface{}{
				"name": "fake-linux",
				"id":   "fakelinuxidididididididididididi",
				"type": "kernel",
			},
			map[string]interface{}{
				"name": "fake-gadget",
				"id":   "fakegadgetididididididididididid",
				"type": "gadget",
			},
		},
	}
	for k, v := range headers {
		template[k] = v
	}

	assertion, err := asserts.Assemble(template, nil, nil, []byte("AXNpZw=="))
	c.Assert(err, IsNil)
	return assertion.(secboot.SnapModel)
}
