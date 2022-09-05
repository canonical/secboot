// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2021 Canonical Ltd
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

package tpm2_test

import (
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/tpm2"
)

type policyV2SuiteNoTPM struct{}

var _ = Suite(&policyV2SuiteNoTPM{})

func (s *policyV2SuiteNoTPM) TestV2IsTheSameAsV1(c *C) {
	c.Check(KeyDataPolicy_v2{}, FitsTypeOf, KeyDataPolicy_v1{})
}
