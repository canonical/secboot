// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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
	"encoding/json"
	"os"

	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"
)

type fileKeyData struct {
	Name string          `json:"name"`
	Data json.RawMessage `json:"data"`
}

// FileKeyDataReader provides a mechanism to read a KeyData from a file.
type FileKeyDataReader struct {
	name string
	*bytes.Reader
}

// ID is the unique ID of the key data contained within this file.
func (r *FileKeyDataReader) ID() KeyID {
	return KeyID{Name: r.name}
}

// NewFileKeyDataReader is used to read a file containing key data at the specified path.
func NewFileKeyDataReader(path string) (*FileKeyDataReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	var d *fileKeyData
	dec := json.NewDecoder(f)
	if err := dec.Decode(&d); err != nil {
		return nil, xerrors.Errorf("cannot decode file key data: %w", err)
	}

	return &FileKeyDataReader{d.Name, bytes.NewReader(d.Data)}, nil
}

// FileKeyDataWriter provides a mechanism to write a KeyData to a file.
type FileKeyDataWriter struct {
	name string
	path string
	*bytes.Buffer
}

func (w *FileKeyDataWriter) Commit() error {
	f, err := osutil.NewAtomicFile(w.path, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return xerrors.Errorf("cannot create new atomic file: %w", err)
	}
	defer f.Cancel()

	d := &fileKeyData{Name: w.name, Data: w.Bytes()}
	enc := json.NewEncoder(f)
	if err := enc.Encode(d); err != nil {
		return xerrors.Errorf("cannot encode file key data: %w", err)
	}

	if err := f.Commit(); err != nil {
		return xerrors.Errorf("cannot commit update: %w", err)
	}

	return nil
}

// NewFileKeyDataWriter creates a new FileKeyDataWriter for atomically writing a
// KeyData to a file.
func NewFileKeyDataWriter(name, path string) *FileKeyDataWriter {
	return &FileKeyDataWriter{name, path, new(bytes.Buffer)}
}
