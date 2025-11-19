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

package secboot

type externalKeyslot struct {
	name string
	data KeyDataReader // This will eventually just be a io.Reader.
}

func newExternalKeyslot(name string, data KeyDataReader) *externalKeyslot {
	return &externalKeyslot{
		name: name,
		data: data,
	}
}

func (*externalKeyslot) Type() KeyslotType {
	return KeyslotTypePlatform
}

func (s *externalKeyslot) Name() string {
	return "external:" + s.name
}

func (*externalKeyslot) Priority() int {
	return 100
}

func (s *externalKeyslot) Data() KeyDataReader {
	return s.data
}

type externalKeyData struct {
	name string
	r    KeyDataReader // nil when WithExternalKeyData is used.
	data *KeyData      // nil when WithExternalKeyDataFromReader is used.
}
