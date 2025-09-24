// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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

package preinstall

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func zero[T any]() T {
	var z T
	return z
}

// GetValueFromJSONMap returns the supplied map of JSON values as the specified
// type. If any values in the supplied map cannot be serialized or the serialized
// map cannot be unserialized to the specified type, an error will be returned.
func GetValueFromJSONMap[T any](m map[string]json.RawMessage) (T, error) {
	if m == nil {
		// Ensure that we always decode a JSON object rather than
		// null into the requested type.
		m = make(map[string]json.RawMessage)
	}

	// Serialize the argument map to JSON.
	jsonMap, err := json.Marshal(m)
	if err != nil {
		return zero[T](), fmt.Errorf("cannot serialize argument map to JSON: %w", err)
	}

	// Unserialize the serialized argument map to the desired type.
	var arg T
	dec := json.NewDecoder(bytes.NewReader(jsonMap))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&arg); err != nil {
		return zero[T](), fmt.Errorf("cannot deserialize argument map from JSON to type %T: %w", arg, err)
	}
	return arg, nil
}
