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

package bootenv_test

import (
	"crypto"
	"encoding/base64"

	"github.com/snapcore/secboot/bootenv"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type snapSuite struct {
}

var _ = Suite(&snapSuite{})

func (s *snapSuite) TestComputeSnapModelHash(c *C) {
	alg := crypto.SHA256
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	expected, err := base64.StdEncoding.DecodeString("OdtD1Oz+LVG4A77RTkE1JaKopD8p/AxcUQsa9M/PPrU=")
	c.Assert(err, IsNil)

	modelAsn, err := bootenv.ComputeSnapModelHash(alg, model)
	c.Assert(err, IsNil)
	c.Check(modelAsn, DeepEquals, expected)
}
