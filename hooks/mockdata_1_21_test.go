// -*- Mode: Go; indent-tabs-mode: t -*-

//go:build !go1.22

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

package hooks_test

import (
	"reflect"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
)

// bootscopeJsonSignature maps the supplied parameters to a hardcoded bootscope signature for
// signatures generated with go < 1.22.
func bootscopeJsonSignature(c *C, primaryKey, role string, bootModes []string, models []secboot.SnapModel) string {
	switch {
	case primaryKey == primaryKey1 && role == "foo" && reflect.DeepEqual(bootModes, []string{"run"}) && reflect.DeepEqual(models, []secboot.SnapModel{model1}):
		return "MEQCIA19SEUAhiGMpFpBzZYUfiC3iGC9W3n9G2DfztjNaORRAiBpX/6zHRUC6XFScX+0vajpMYdgrpckXmlO4imyYDrvCw=="
	case primaryKey == primaryKey1 && role == "bar" && reflect.DeepEqual(bootModes, []string{"run"}) && reflect.DeepEqual(models, []secboot.SnapModel{model1}):
		return "MEYCIQDbGuOz+1CJOPuzXFJtc87OjH5du7rPcPO66Y4N3ypyPQIhAMlMVMcyXLgAxGVrhMeMpNLuV+xBeUo+Pjq1ezt3m6i2"
	case primaryKey == primaryKey1 && role == "foo" && reflect.DeepEqual(bootModes, []string{"run", "recover"}) && reflect.DeepEqual(models, []secboot.SnapModel{model1, model2}):
		return "MEQCIGRKp3aXbNyn2vIbZC/cA65FcrhGGaOwgNs2SnrKYZJ6AiABNaEs1JDBCDitVG9Td68P/D8HsaSs8KlKLWIp8GNa/w=="
	case primaryKey == primaryKey1 && role == "foo" && len(bootModes) == 0 && len(models) == 0:
		return "MEUCIQDzPqopz+v505PetuBsnxvMF+FdxgwdQE1ZmoXW5Q6LZAIgEyMjnb9BndR6l6KUaLzgnMDoK986CxZ4/cfIOELmYSs="
	case primaryKey == primaryKey2 && role == "foo" && len(bootModes) == 0 && len(models) == 0:
		return "MEUCIQD2r1Th4xtwzjj8p9LQwLIf98QPOlMbmCDvK2DVAICqGwIgVKo6tNpjcfHiguLLAcPfTF2KEpgWozWhxSRpDn6IseM="
	case primaryKey == primaryKey3 && role == "foo" && len(bootModes) == 0 && len(models) == 0:
		return "MEQCIC7G/zO4BtP7PYQQKvf1jR4hm9vTbzca7k5h/ZuiGh7HAiAdfbplIZvWtU03BYQw4q1oOpRtN34mpRkFnOf1t3Y7YQ=="
	default:
		// TODO: should be fatal
		c.Error("no signature for parameter combination")
		return ""
	}
	panic("not reached")
}
