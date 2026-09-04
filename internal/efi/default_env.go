// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2026 Canonical Ltd
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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	"github.com/pilebones/go-udev/crawler"
	"github.com/pilebones/go-udev/netlink"
	internal_cpuid "github.com/snapcore/secboot/internal/cpuid"
	"github.com/snapcore/secboot/internal/tpm2_device"
)

var (
	crawlerExistingDevices   = crawler.ExistingDevices
	cpuidFamily              = internal_cpuid.Family
	cpuidHasFeature          = internal_cpuid.HasFeature
	cpuidVendorIdentificator = internal_cpuid.VendorIdentificator
	devcpuPath               = "/dev/cpu"
	osOpen                   = os.Open
	osReadFile               = os.ReadFile
	osReadlink               = os.Readlink
	// runtimeGOARCH is the architecture that host security checks are performed
	// for. It is a variable so that tests can run the checks for architectures
	// other than the one the test binary was built for.
	runtimeGOARCH            = runtime.GOARCH
	tpm2_deviceDefaultDevice = tpm2_device.DefaultDevice

	eventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements" // Path of the TCG event log for the default TPM, in binary form

	dmiProcessorInfoPath = "/sys/firmware/dmi/entries/4-0/raw"
)

func SetEventLogPath(path string) {
	eventLogPath = path
}

func EventLogPath() string {
	return eventLogPath
}

// decodeKernelUeventParams decodes the uevent attribute for the device associated
// with the supplied sysfs path, and returns a map of variables.
//
// XXX: This is duplicated in luks2/dm_helper.go. A future PR may move device
// enumeration into a separate internal package.
func decodeKernelUeventParams(path string) (map[string]string, error) {
	data, err := osReadFile(filepath.Join(path, "uevent"))
	if err != nil {
		return nil, err
	}

	entries := bytes.Split(data, []byte("\n"))

	env := make(map[string]string)
	for i, entry := range entries[:len(entries)-1] {
		v := bytes.Split(entry, []byte("="))
		if len(v) != 2 {
			return nil, fmt.Errorf("invalid entry %d: %q", i, entry)
		}
		env[string(v[0])] = string(v[1])
	}

	return env, nil
}

type defaultEnvImpl struct{}

// VarContext implements [HostEnvironmentEFI.VarContext].
func (defaultEnvImpl) VarContext(parent context.Context) context.Context {
	return efi.WithDefaultVarsBackend(parent)
}

// ReadEventLog implements [HostEnvironmentEFI.ReadEventLog].
func (defaultEnvImpl) ReadEventLog() (*tcglog.Log, error) {
	f, err := os.Open(eventLogPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return tcglog.ReadLog(f, &tcglog.LogOptions{})
}

// TPMDevice implements [HostEnvironment.TPMDevice].
func (defaultEnvImpl) TPMDevice() (tpm2_device.TPMDevice, error) {
	return tpm2_deviceDefaultDevice(tpm2_device.DeviceModeTryResourceManaged)
}

// DetectVirtMode implements [HostEnvironment.DetectVirtMode].
func (defaultEnvImpl) DetectVirtMode(mode DetectVirtMode) (string, error) {
	var extraArgs []string
	switch mode {
	case DetectVirtModeAll:
		// no extra args
	case DetectVirtModeContainer:
		extraArgs = []string{"--container"}
	case DetectVirtModeVM:
		extraArgs = []string{"--vm"}
	default:
		panic("not reached")
	}

	output, err := exec.Command("systemd-detect-virt", extraArgs...).Output()
	virt := string(bytes.TrimSpace(output)) // The stdout is newline terminated
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok && virt == VirtModeNone {
			// systemd-detect-virt returns non zero exit code if no virtualization is detected
			return virt, nil
		}
		return "", err
	}
	return virt, nil
}

type defaultEnvSysfsDevice struct {
	path      string
	props     map[string]string
	subsystem string
}

// Path implements [SysfsDevice.Path].
func (d *defaultEnvSysfsDevice) Path() string {
	return d.path
}

// Properties implements [SysfsDevice.Properties].
func (d *defaultEnvSysfsDevice) Properties() map[string]string {
	return d.props
}

// Subsystem implements [SysfsDevice.Subsystem].
func (d *defaultEnvSysfsDevice) Subsystem() string {
	return d.subsystem
}

func (d *defaultEnvSysfsDevice) Parent() (SysfsDevice, error) {
	path := d.path
	for {
		path = filepath.Dir(path)
		if path == crawler.BASE_DEVPATH {
			return nil, nil
		}
		props, err := decodeKernelUeventParams(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("cannot decode kernel uevent properties for %s: %w", path, err)
		}

		subsystem, err := osReadlink(filepath.Join(path, "subsystem"))
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("cannot resolve subsystem for %s: %w", path, err)
		}

		return &defaultEnvSysfsDevice{
			path:      path,
			props:     props,
			subsystem: filepath.Base(subsystem),
		}, nil
	}
}

// AttributeReader implements [SysfsDevice.AttributeReader].
func (d *defaultEnvSysfsDevice) AttributeReader(attr string) (rc io.ReadCloser, err error) {
	if attr == "uevent" {
		return nil, ErrNoDeviceAttribute
	}

	f, err := osOpen(filepath.Join(d.path, attr))
	switch {
	case os.IsNotExist(err):
		return nil, ErrNoDeviceAttribute
	case err != nil:
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		f.Close()
	}()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, ErrNoDeviceAttribute
	}

	return f, nil
}

// EnumerateDevices implements [HostEnvironment.EnumerateDevices].
func (defaultEnvImpl) EnumerateDevices(matcher netlink.Matcher) ([]SysfsDevice, error) {
	queue := make(chan crawler.Device)
	errs := make(chan error)
	crawlerExistingDevices(queue, errs, matcher)

	var devices []SysfsDevice

	for {
		select {
		case dev, more := <-queue:
			if !more {
				return devices, nil
			}
			devices = append(devices, &defaultEnvSysfsDevice{
				path:      dev.KObj,
				props:     dev.Env,
				subsystem: dev.Env["SUBSYSTEM"],
			})
			// The "SUBSYSTEM" field isn't really part of the device environment
			// from the kernel in sysfs, it's added synthetically by go-udev for
			// rule matching. We delete it here because we expose the subsystem
			// for the device separately.
			delete(dev.Env, "SUBSYSTEM")
		case err := <-errs:
			return nil, err
		}
	}
}

// DefaultEnv corresponds to the environment associated with the host
// machine.
var DefaultEnv = defaultEnvImpl{}

type defaultEnvAMD64Impl struct{}

// CPUVendorIdentificator implements [HostEnvironmentAMD64.CPUVendorIdentificator].
func (defaultEnvAMD64Impl) CPUVendorIdentificator() string {
	return cpuidVendorIdentificator()
}

// CPUFamily implements [HostEnvironmentAMD64.CPUFamily].
func (defaultEnvAMD64Impl) CPUFamily() uint32 {
	return cpuidFamily()
}

// HasCPUIDFeature implements [HostEnvironmentAMD64.HasCPUIDFeature].
func (defaultEnvAMD64Impl) HasCPUIDFeature(feature uint64) bool {
	return cpuidHasFeature(feature)
}

// ReadMSRs implements [HostEnvironmentAMD64.ReadMSRs].
func (defaultEnvAMD64Impl) ReadMSRs(msr uint32) (map[uint32]uint64, error) {
	dir, err := os.Open(devcpuPath)
	switch {
	case os.IsNotExist(err):
		return nil, ErrNoKernelMSRSupport
	case err != nil:
		return nil, err
	}
	defer dir.Close()

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	out := make(map[uint32]uint64)

	for _, entry := range entries {
		cpuNo, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid CPU number for name %s: %w", entry.Name(), err)
		}

		val, err := func(name string) (uint64, error) {
			f, err := os.Open(filepath.Join(dir.Name(), name, "msr"))
			switch {
			case os.IsNotExist(err):
				return 0, ErrNoKernelMSRSupport
			case errors.Is(err, syscall.EIO):
				return 0, ErrNoMSRSupport
			case err != nil:
				return 0, err
			}
			defer f.Close()

			var data [8]byte
			_, err = f.ReadAt(data[:], int64(msr))
			switch {
			case errors.Is(err, syscall.EIO): // I think the kernel returns -EIO if the MSR is not supported, but this is poorly documented.
				return 0, ErrNoMSRSupport
			case err != nil:
				return 0, fmt.Errorf("cannot read from MSR device: %w", err)
			}

			return binary.LittleEndian.Uint64(data[:]), nil
		}(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("cannot read value for CPU %s: %w", entry.Name(), err)
		}

		out[uint32(cpuNo)] = val
	}

	return out, nil
}

// AMD64 implements [HostEnvironment.AMD64].
//
// The architecture is checked at runtime (rather than by build constraint) so
// that this implementation is compiled and unit tested on every architecture.
func (defaultEnvImpl) AMD64() (HostEnvironmentAMD64, error) {
	if runtimeGOARCH != "amd64" {
		return nil, ErrNotAMD64Host
	}
	return defaultEnvAMD64Impl{}, nil
}

type defaultEnvARM64Impl struct{}

// smbiosType4ManufacturerOffset is the byte offset of the Manufacturer string
// index within an SMBIOS type 4 (Processor Information) formatted area.
const smbiosType4ManufacturerOffset = 0x07

// smbiosType4VersionOffset is the byte offset of the Version string index
// within an SMBIOS type 4 (Processor Information) formatted area.
const smbiosType4VersionOffset = 0x10

// decodeSMBIOSType4Field decodes a string field from an SMBIOS type 4
// (Processor Information) structure blob. data is the raw binary blob read
// from the kernel's DMI entries sysfs interface. fieldOffset is the byte
// offset within the formatted area that holds the 1-based string index.
//
// Layout (DMTF SMBIOS specification):
//   - byte 0:   structure type (must be 4)
//   - byte 1:   length of the formatted area including the header
//   - bytes 2-3: handle
//   - bytes 4…: remaining formatted area
//   - after the formatted area: NUL-terminated strings; string set ends
//     with an additional NUL (empty string sentinel)
func decodeSMBIOSType4Field(data []byte, fieldOffset uint8) (string, error) {
	if len(data) < 4 {
		return "", fmt.Errorf("SMBIOS structure too short for header: have %d bytes", len(data))
	}
	structType := data[0]
	formattedLen := data[1]
	if structType != 4 {
		return "", fmt.Errorf("unexpected SMBIOS structure type %d (expected 4)", structType)
	}
	if int(formattedLen) <= int(fieldOffset) {
		return "", fmt.Errorf("SMBIOS structure too short to contain field at offset 0x%02x: formatted area length is %d", fieldOffset, formattedLen)
	}
	if len(data) < int(formattedLen) {
		return "", fmt.Errorf("SMBIOS structure data truncated: have %d bytes, formatted area length is %d", len(data), formattedLen)
	}
	strIdx := data[fieldOffset]
	if strIdx == 0 {
		return "", fmt.Errorf("SMBIOS field at offset 0x%02x is unset", fieldOffset)
	}
	stringsData := data[formattedLen:]
	var n uint8
	for i := 0; i < len(stringsData); {
		end := i
		for end < len(stringsData) && stringsData[end] != 0 {
			end++
		}
		if i == end {
			// Empty string: end-of-string-set sentinel.
			break
		}
		n++
		if n == strIdx {
			return strings.TrimSpace(string(stringsData[i:end])), nil
		}
		i = end + 1
	}
	return "", fmt.Errorf("SMBIOS string index %d is out of range", strIdx)
}

// CPUManufacturer implements [HostEnvironmentARM64.CPUManufacturer].
func (defaultEnvARM64Impl) CPUManufacturer() (string, error) {
	data, err := osReadFile(dmiProcessorInfoPath)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", dmiProcessorInfoPath, err)
	}
	return decodeSMBIOSType4Field(data, smbiosType4ManufacturerOffset)
}

// CPUVersion implements [HostEnvironmentARM64.CPUVersion].
func (defaultEnvARM64Impl) CPUVersion() (string, error) {
	data, err := osReadFile(dmiProcessorInfoPath)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", dmiProcessorInfoPath, err)
	}
	return decodeSMBIOSType4Field(data, smbiosType4VersionOffset)
}

// ARM64 implements [HostEnvironment.ARM64].
// The architecture is checked at runtime (rather than by build constraint) so
// that this implementation is compiled and unit tested on every architecture.
func (defaultEnvImpl) ARM64() (HostEnvironmentARM64, error) {
	if runtimeGOARCH != "arm64" {
		return nil, ErrNotARM64Host
	}
	return defaultEnvARM64Impl{}, nil
}
