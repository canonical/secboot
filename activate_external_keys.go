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
	*ExternalKeyData
}

func newExternalKeyslot(data *ExternalKeyData) *externalKeyslot {
	return &externalKeyslot{ExternalKeyData: data}
}

func (*externalKeyslot) Type() KeyslotType {
	return KeyslotTypePlatform
}

func (s *externalKeyslot) Name() string {
	return "external:" + s.ExternalKeyData.Name()
}

func (*externalKeyslot) Priority() int {
	return 100
}

// ExternalKeyData represents external key metadata that is not provided
// by a [StorageContainer].
type ExternalKeyData struct {
	name string
	data KeyDataReader
}

// NewExternalKeyData creates a new ExternalKeyData. External keys have
// a hardcoded priority of 100 so that these are tried before
// [StorageContainer] keyslots with the default priority (0). Note that
// the [KeyDataReader] argument will eventually be replaced by [io.Reader].
func NewExternalKeyData(name string, data KeyDataReader) *ExternalKeyData {
	return &ExternalKeyData{
		name: name,
		data: data,
	}
}

// Name returns the name associated with this external key metadata.
func (d *ExternalKeyData) Name() string {
	return d.name
}

// Data returns the external key metadata. Note that this will eventually
// return [io.Reader] rather than [KeyDataReader].
func (d *ExternalKeyData) Data() KeyDataReader {
	return d.data
}

// ReadableName implements [KeyDataReader.ReadableName].
//
// XXX: This only exists so that ExternalKeyData can be passed to
// [ReadKeyData] and will eventually be deleted along with [KeyDataReader]
// when the legacy activation API is deleted.
func (d *ExternalKeyData) ReadableName() string {
	return d.name
}

// Read implements [io.Reader].
func (d *ExternalKeyData) Read(data []byte) (int, error) {
	return d.data.Read(data)
}
