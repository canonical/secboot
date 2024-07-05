// -*- Mode: Go; indent-tabs-mode: t -*-

//go:build go1.22

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
// signatures generated with go >= 1.22.
func bootscopeJsonSignature(c *C, primaryKey, role string, bootModes []string, models []secboot.SnapModel) string {
	switch {
	case primaryKey == primaryKey1 && role == "foo" && reflect.DeepEqual(bootModes, []string{"run"}) && reflect.DeepEqual(models, []secboot.SnapModel{model1}):
		return "MEQCIC1TpdJB7WkibO5E0lM4wf/2pxUCqLSdglYZ2u0ODZPhAiADkQXehucH9jI7Ft/G8gvE4i6EY3leqN2dwM9fOuAXsQ=="
	case primaryKey == primaryKey1 && role == "bar" && reflect.DeepEqual(bootModes, []string{"run"}) && reflect.DeepEqual(models, []secboot.SnapModel{model1}):
		return "MEYCIQCAW1hsiPaHb+K5EEIdVVHK5nJ6d0MLiLXqgDgEZqjI0QIhAIrfaZ1QnatOrauFdTcbewJu2N0vzsl8nTyOz65KejEF"
	case primaryKey == primaryKey1 && role == "foo" && reflect.DeepEqual(bootModes, []string{"run", "recover"}) && reflect.DeepEqual(models, []secboot.SnapModel{model1, model2}):
		return "MEQCICTZ9puVJIC5Gp7hMSUMq48QpH6mJfR2U+dr8cmfVd17AiALiRvp/K4kCf90KJwZVfQM6zOIXi2b/Wf+PG7wW3uRZQ=="
	case primaryKey == primaryKey1 && role == "foo" && len(bootModes) == 0 && len(models) == 0:
		return "MEUCIQC7WkvJvAnhtXUwy17nTZjgJJPghkU0kcWgoWzfH/fppQIgSX9myUAecaMFVQW6qm23reb/hs5PbemkPRcZwLVlbPM="
	case primaryKey == primaryKey2 && role == "foo" && len(bootModes) == 0 && len(models) == 0:
		return "MEYCIQCTGRwz1dpF7MbsiYx/Bd4sqUcdD1vmSj1M9LjgolC1OAIhAPwQlMwK43HOA6qF2UCQX+mLboAi00rbNExYXduX5T4A"
	case primaryKey == primaryKey3 && role == "foo" && len(bootModes) == 0 && len(models) == 0:
		return "MEQCIF2xMnO/TOu6ceLaddrBvP8P2C5zm1kRcxCodK8WA1oaAiAbxMVXObPUZHyJ+OK9PR8gvNbqWYWNAXSny85R/wMYHQ=="
	default:
		// TODO: should be fatal
		c.Error("no signature for parameter combination")
		return ""
	}
	panic("not reached")
}
