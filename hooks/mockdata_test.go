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
	"github.com/snapcore/secboot/internal/testutil"
)

// This contains some test parameters that affect bootscope signatures, in order to
// make it possible to have different sets of hardcoded signatures depending on the
// go version where go changes the mechanism it uses to perform nonce generation. We
// are fortunate so far that the changes between 1.21 and 1.22 result in mechanisms
// that still consume the same amount of entropy, so we don't have to customize our
// hardcoded entropy sources which would make things even more complicated.

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
