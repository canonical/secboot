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

import (
	"bytes"
	"fmt"
)

type externalKeyslotDataWriter struct {
	*bytes.Buffer
	r *bytes.Reader
}

func (w *externalKeyslotDataWriter) Commit() error {
	w.r = bytes.NewReader(w.Buffer.Bytes())
	return nil
}

type externalKeyslotDataReader struct {
	name string
	*bytes.Reader
}

func (d *externalKeyslotDataReader) ReadableName() string {
	return d.name
}

type externalKeyslotInfo struct {
	name string
	r    KeyDataReader
}

func (*externalKeyslotInfo) Type() KeyslotType {
	return KeyslotTypePlatform
}

func (i *externalKeyslotInfo) Name() string {
	return i.name
}

func (*externalKeyslotInfo) Priority() int {
	return 0
}

func (i *externalKeyslotInfo) Data() KeyDataReader {
	return i.r
}

func newExternalKeyslotInfo(d *ExternalKeyData) (*externalKeyslotInfo, error) {
	w := &externalKeyslotDataWriter{
		Buffer: new(bytes.Buffer),
	}

	// Serialize the supplied key so that it can be exposed via
	// KeyslotInfo.Data().
	if err := d.Key.WriteAtomic(w); err != nil {
		return nil, fmt.Errorf("cannot serialize key metadata: %w", err)
	}

	// Return a new keyslotInfo implementation. This has a hardcoded
	// type of KeyslotTypePlatform, a name that is passed from the
	// supplied ExternalKeyData, a hardcoded priority of 0 and a
	// KeyDataReader made from the supplied KeyData's ReadableName
	// method and a bytes.Reader containing the serialized form of
	// the supplied KeyData.
	return &externalKeyslotInfo{
		name: d.Name,
		r: &externalKeyslotDataReader{
			name:   d.Key.ReadableName(),
			Reader: bytes.NewReader(w.Buffer.Bytes()),
		},
	}, nil
}

// ExternalKeyData represents an external [KeyData] with a user supplied
// name. The name would ordinarily be determined by the backend from which
// the keydata is loaded, but this structure permits a way for the caller
// to specify an arbitrary name.
type ExternalKeyData struct {
	Name string
	Key  *KeyData
}
