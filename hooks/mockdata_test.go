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

package hooks_test

import (
	"reflect"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
)

// This contains some test parameters that affect bootscope signatures.
// The hardcoded signatures are only used for key recovery tests, where
// verification is done, rather than byte comparison.
var (
	model1 = testutil.MustMakeMockCore20ModelAssertion(map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")
	model2 = testutil.MustMakeMockCore20ModelAssertion(map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "other-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	primaryKey1 = "f51ad3cfef16e7076153d3a994f1fe09cc82c2ae4186d5322ffaae2f6e2b58fa"
	primaryKey2 = "a2c13845528f207216587b52f904fe8c322530d23f10ac47b04e1be6f06c3c04"
	primaryKey3 = "4ace63fad0a9adc77234322739d873c81da6e4e3d006214411d18ad81b2518b5"
)

// Returns a valid bootscope signature for the supplied parameters.
// It is used as an input for key recovery tests.
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
		c.Error("no signature for parameter combination")
		return ""
	}
}
