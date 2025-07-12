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

package luks2

import (
	"context"
	"os"

	"golang.org/x/sys/unix"
)

var (
	DecodeKernelSysfsUeventAttr = decodeKernelSysfsUeventAttr
	ErrNotDMBlockDevice         = errNotDMBlockDevice
	ErrUnsupportedTargetType    = errUnsupportedTargetType
	NewStorageContainerBackend  = newStorageContainerBackend
	SourceDeviceFromDMDevice    = sourceDeviceFromDMDevice
)

type (
	Luks2Api                = luks2Api
	Luks2KeyDataReader      = luks2KeyDataReader
	LuksView                = luksView
	StorageContainerBackend = storageContainerBackend
	StorageContainerImpl    = storageContainerImpl
	StorageContainerReader  = storageContainerReader
)

func MockDevRoot(path string) (restore func()) {
	orig := devRoot
	devRoot = path
	return func() {
		devRoot = orig
	}
}

func MockFilepathEvalSymlinks(links map[string]string) (restore func()) {
	orig := filepathEvalSymlinks
	filepathEvalSymlinks = func(path string) (string, error) {
		target, exists := links[path]
		if !exists {
			return path, nil
		}
		return target, nil
	}
	return func() {
		filepathEvalSymlinks = orig
	}
}

func MockLUKS2Ops(ops *Luks2Api) (restore func()) {
	orig := luks2Ops
	luks2Ops = ops
	return func() {
		luks2Ops = orig
	}
}

func MockNewLuksView(fn func(context.Context, string) (LuksView, error)) (restore func()) {
	orig := newLuksView
	newLuksView = fn
	return func() {
		newLuksView = orig
	}
}

func MockOsStat(fn func(string) (os.FileInfo, error)) (restore func()) {
	orig := osStat
	osStat = fn
	return func() {
		osStat = orig
	}
}

func MockSourceDeviceFromDMDevice(fn func(context.Context, string) (string, error)) (restore func()) {
	orig := sourceDeviceFromDMDevice
	sourceDeviceFromDMDevice = fn
	return func() {
		sourceDeviceFromDMDevice = orig
	}
}

func MockSysfsRoot(path string) (restore func()) {
	orig := sysfsRoot
	sysfsRoot = path
	return func() {
		sysfsRoot = orig
	}
}

func MockUnixStat(fn func(string, *unix.Stat_t) error) (restore func()) {
	orig := unixStat
	unixStat = fn
	return func() {
		unixStat = orig
	}
}

func NewStorageContainer(path string, dev uint64) *StorageContainerImpl {
	return &storageContainerImpl{
		path: path,
		dev:  dev,
	}
}
