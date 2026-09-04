// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2026 Canonical Ltd
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

package efi

import (
	"os"

	"github.com/pilebones/go-udev/crawler"
	"github.com/pilebones/go-udev/netlink"
	"github.com/snapcore/secboot/internal/tpm2_device"
)

func MockEventLogPath(path string) (restore func()) {
	origPath := eventLogPath
	eventLogPath = path
	return func() {
		eventLogPath = origPath
	}
}

func MockDefaultTPM2Device(fn func(tpm2_device.DeviceMode) (tpm2_device.TPMDevice, error)) (restore func()) {
	orig := tpm2_deviceDefaultDevice
	tpm2_deviceDefaultDevice = fn
	return func() {
		tpm2_deviceDefaultDevice = orig
	}
}

func MockCrawlerExistingDevices(fn func(chan crawler.Device, chan error, netlink.Matcher) chan struct{}) (restore func()) {
	orig := crawlerExistingDevices
	crawlerExistingDevices = fn
	return func() {
		crawlerExistingDevices = orig
	}
}

func MockOsOpen(fn func(string) (*os.File, error)) (restore func()) {
	orig := osOpen
	osOpen = fn
	return func() {
		osOpen = orig
	}
}

func MockOsReadFile(fn func(string) ([]byte, error)) (restore func()) {
	orig := osReadFile
	osReadFile = fn
	return func() {
		osReadFile = orig
	}
}

func MockOsReadlink(fn func(string) (string, error)) (restore func()) {
	orig := osReadlink
	osReadlink = fn
	return func() {
		osReadlink = orig
	}
}

func MockCPUIDVendorIdentificator(fn func() string) (restore func()) {
	orig := cpuidVendorIdentificator
	cpuidVendorIdentificator = fn
	return func() {
		cpuidVendorIdentificator = orig
	}
}

func MockCPUIDFamily(fn func() uint32) (restore func()) {
	orig := cpuidFamily
	cpuidFamily = fn
	return func() {
		cpuidFamily = orig
	}
}

func MockCPUIDHasFeature(fn func(uint64) bool) (restore func()) {
	orig := cpuidHasFeature
	cpuidHasFeature = fn
	return func() {
		cpuidHasFeature = orig
	}
}

func MockDevcpuPath(path string) (restore func()) {
	orig := devcpuPath
	devcpuPath = path
	return func() {
		devcpuPath = orig
	}
}

func MockRuntimeGOARCH(arch string) (restore func()) {
	orig := runtimeGOARCH
	runtimeGOARCH = arch
	return func() {
		runtimeGOARCH = orig
	}
}
