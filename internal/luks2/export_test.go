// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package luks2

import (
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	AcquireSharedLock = acquireSharedLock
)

func (o *FormatOptions) Validate() error {
	return o.validate()
}

func MockDataDeviceInfo(stMock *unix.Stat_t) (restore func()) {
	origFstatFn := dataDeviceFstat
	origIsBDFn := isBlockDevice

	dataDeviceFstat = func(fd int, st *unix.Stat_t) error {
		*st = *stMock
		return nil
	}

	isBlockDevice = func(os.FileMode) bool {
		mode := os.FileMode(stMock.Mode & 0777)
		switch stMock.Mode & unix.S_IFMT {
		case unix.S_IFBLK:
			mode |= os.ModeDevice
		case unix.S_IFCHR:
			mode |= os.ModeDevice | os.ModeCharDevice
		case unix.S_IFDIR:
			mode |= os.ModeDir
		case unix.S_IFIFO:
			mode |= os.ModeNamedPipe
		case unix.S_IFLNK:
			mode |= os.ModeSymlink
		case unix.S_IFREG:
		case unix.S_IFSOCK:
			mode |= os.ModeSocket
		}
		return origIsBDFn(mode)
	}

	return func() {
		isBlockDevice = origIsBDFn
		dataDeviceFstat = origFstatFn
	}
}

func MockSystemdCryptsetupPath(path string) (restore func()) {
	origSystemdCryptsetupPath := systemdCryptsetupPath
	systemdCryptsetupPath = path
	return func() {
		systemdCryptsetupPath = origSystemdCryptsetupPath
	}
}

func MockStderr(w io.Writer) (restore func()) {
	origStderr := stderr
	stderr = w
	return func() {
		stderr = origStderr
	}
}

func ResetCryptsetupFeatures() {
	featuresOnce = sync.Once{}
}
