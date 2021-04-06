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
	"os"
	"path/filepath"

	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

// FileKeyDataReader corresponds to an open file from which key data can be read.
type FileKeyDataReader struct {
	*os.File

	dev  uint64
	name string
}

// ID is the unique ID of the key data contained within this file.
func (r *FileKeyDataReader) ID() *KeyID {
	return &KeyID{Loader: "file", Device: r.dev, Name: r.name}
}

// OpenKeyDataFile is used to open a file containing key data at the specified path.
// The file must be closed when it is no longer needed.
func OpenKeyDataFile(path string) (*FileKeyDataReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("cannot open file: %w", err)
	}

	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, xerrors.Errorf("cannot obtain file info: %w", err)
	}

	mountDir := filepath.Dir(path)
	for ; mountDir != "/"; mountDir = filepath.Dir(mountDir) {
		var dirSt unix.Stat_t
		if err := unix.Stat(mountDir, &dirSt); err != nil {
			return nil, xerrors.Errorf("cannot determine mount point: %w", err)
		}

		if dirSt.Dev != st.Dev {
			break
		}
	}

	name, err := filepath.Rel(mountDir, path)
	if err != nil {
		return nil, xerrors.Errorf("cannot determine name: %w", err)
	}

	return &FileKeyDataReader{f, st.Dev, name}, nil
}

// NewKeyDataFileWriter creates a new osutil.AtomicFile instance for atomically
// updating a key data file.
func NewKeyDataFileWriter(path string) (*osutil.AtomicFile, error) {
	f, err := osutil.NewAtomicFile(path, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return nil, xerrors.Errorf("cannot create new atomic file: %w", err)
	}

	return f, nil
}
