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

package efitest

import (
	"bytes"
	"context"
	"errors"
	"io"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	"github.com/pilebones/go-udev/netlink"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/tpm2_device"
)

// MockHostEnvironment provides a mock host environment that can be used by both
// the efi and efi/preinstall packages.
type MockHostEnvironment struct {
	Vars MockVars
	Log  *tcglog.Log

	TPM2Device tpm2_device.TPMDevice

	VirtMode               string
	VirtModeType           internal_efi.DetectVirtMode
	VirtModeErr            error
	DelayedVirtModeOptions []MockHostEnvironmentOption

	Devices map[string]internal_efi.SysfsDevice

	AMD64Env internal_efi.HostEnvironmentAMD64
}

func NewMockHostEnvironment(vars MockVars, log *tcglog.Log) *MockHostEnvironment {
	return &MockHostEnvironment{
		Vars:     vars,
		Log:      log,
		VirtMode: internal_efi.VirtModeNone,
	}
}

// MockHostEnvironmentOption is an option supplied to [NewMockHostEnvironmentWithOpts].
type MockHostEnvironmentOption func(*MockHostEnvironment)

// WithMockVars adds the supplied mock EFI variables to a [MockHostEnvironment].
func WithMockVars(vars MockVars) MockHostEnvironmentOption {
	return func(env *MockHostEnvironment) {
		env.Vars = vars
	}
}

// WithLog adds the supplied TCG log to a [MockHostEnvironment].
func WithLog(log *tcglog.Log) MockHostEnvironmentOption {
	return func(env *MockHostEnvironment) {
		env.Log = log
	}
}

// WithTPMDevice adds the specified TPM device to a [MockHostEnvironment].
func WithTPMDevice(device tpm2_device.TPMDevice) MockHostEnvironmentOption {
	return func(env *MockHostEnvironment) {
		env.TPM2Device = device
	}
}

// WithVirtMode adds the supplied virtualization mode and type to a [MockHostEnvironment].
func WithVirtMode(mode string, modeType internal_efi.DetectVirtMode) MockHostEnvironmentOption {
	return func(env *MockHostEnvironment) {
		env.VirtMode = mode
		env.VirtModeType = modeType
	}
}

// WithVirtModeError makes [MockHostEnvironment.DetectVirtMode] return an error.
func WithVirtModeError(err error) MockHostEnvironmentOption {
	return func(env *MockHostEnvironment) {
		env.VirtModeErr = err
	}
}

// WithDelayedVirtMode queues to add the supplied virtualization mode and type to a [MockHostEnvironment].
// These will be applied in turn on each call to [MockHostEnvironment.DetectVirtMode].
func WithDelayedVirtMode(mode string, modeType internal_efi.DetectVirtMode) MockHostEnvironmentOption {
	return func(env *MockHostEnvironment) {
		env.DelayedVirtModeOptions = append(env.DelayedVirtModeOptions, WithVirtMode(mode, modeType))
	}
}

// WithVirtModeError queues to make [MockHostEnvironment.DetectVirtMode] return an error. These will be
// applied in turn on each call to [MockHostEnvironment.DetectVirtMode].
func WithDelayedVirtModeError(err error) MockHostEnvironmentOption {
	return func(env *MockHostEnvironment) {
		env.DelayedVirtModeOptions = append(env.DelayedVirtModeOptions, WithVirtModeError(err))
	}
}

type mockHostEnvironmentAMD64 struct {
	vendorIdentificator string
	features            map[uint64]struct{}
	cpus                uint32
	msrs                map[uint32]uint64
}

func (e *mockHostEnvironmentAMD64) CPUVendorIdentificator() string {
	return e.vendorIdentificator
}

func (e *mockHostEnvironmentAMD64) HasCPUIDFeature(feature uint64) bool {
	_, has := e.features[feature]
	return has
}

func (e *mockHostEnvironmentAMD64) ReadMSRs(msr uint32) (map[uint32]uint64, error) {
	if e.msrs == nil || e.cpus == 0 {
		return nil, internal_efi.ErrNoKernelMSRSupport
	}
	val, exists := e.msrs[msr]
	if !exists {
		return nil, internal_efi.ErrNoMSRSupport
	}
	out := make(map[uint32]uint64)
	for i := uint32(0); i < e.cpus; i++ {
		out[i] = val
	}
	return out, nil
}

// MockSysfsDevice is a mock implementation of [internal_efi.SysfsDevice].
type MockSysfsDevice struct {
	DevicePath       string
	DeviceProperties map[string]string
	DeviceSubsystem  string

	DeviceAttributeVals map[string][]byte

	DeviceParent *MockSysfsDevice
}

func (d *MockSysfsDevice) Path() string                  { return d.DevicePath }
func (d *MockSysfsDevice) Properties() map[string]string { return d.DeviceProperties }
func (d *MockSysfsDevice) Subsystem() string             { return d.DeviceSubsystem }

func (d *MockSysfsDevice) Parent() (internal_efi.SysfsDevice, error) {
	return d.DeviceParent, nil
}

func (d *MockSysfsDevice) AttributeReader(attr string) (rc io.ReadCloser, err error) {
	if d.DeviceAttributeVals == nil {
		return nil, internal_efi.ErrNoDeviceAttribute
	}
	data, exists := d.DeviceAttributeVals[attr]
	if !exists {
		return nil, internal_efi.ErrNoDeviceAttribute
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// NewMockSysfsDevice returns a new MockSysfsDevice.
func NewMockSysfsDevice(path string, properties map[string]string, subsystem string, attributeVals map[string][]byte, parent *MockSysfsDevice) *MockSysfsDevice {
	if properties == nil {
		properties = make(map[string]string)
	}
	return &MockSysfsDevice{
		DevicePath:          path,
		DeviceProperties:    properties,
		DeviceSubsystem:     subsystem,
		DeviceAttributeVals: attributeVals,
		DeviceParent:        parent,
	}
}

// WithSysfsDevices adds the supplied devices, keyed by class, to the [MockHostEnvironment].
func WithSysfsDevices(devices ...internal_efi.SysfsDevice) MockHostEnvironmentOption {
	return func(env *MockHostEnvironment) {
		env.Devices = make(map[string]internal_efi.SysfsDevice)
		for _, dev := range devices {
			env.Devices[dev.Path()] = dev
		}
	}
}

// WithAMD64Environment adds a [github.com/snapcore/secboot/efi/internal.HostEnvironmentAMD64] to the [MockHostEnvironment].
// Whilst this supports mocking MSRs, it only supports the same value for every CPU.
func WithAMD64Environment(cpuVendorIdentificator string, cpuidFeatures []uint64, cpus uint32, msrs map[uint32]uint64) MockHostEnvironmentOption {
	return func(env *MockHostEnvironment) {
		features := make(map[uint64]struct{})
		for _, feature := range cpuidFeatures {
			features[feature] = struct{}{}
		}
		env.AMD64Env = &mockHostEnvironmentAMD64{
			vendorIdentificator: cpuVendorIdentificator,
			features:            features,
			cpus:                cpus,
			msrs:                msrs,
		}
	}
}

// NewMockHostEnvironmentWithOpts returns a new MockHostEnvironment.
func NewMockHostEnvironmentWithOpts(options ...MockHostEnvironmentOption) *MockHostEnvironment {
	env := &MockHostEnvironment{
		VirtMode: internal_efi.VirtModeNone,
	}
	for _, opt := range options {
		opt(env)
	}
	return env
}

// VarContext implements [github.com/snapcore/secboot/internal/efi.HostEnvironmentEFI.VarContext].
func (e *MockHostEnvironment) VarContext(parent context.Context) context.Context {
	return context.WithValue(parent, efi.VarsBackendKey{}, e.Vars)
}

// ReadEventLog implements [github.com/snapcore/secboot/internal/efi.HostEnvironmentEFI.ReadEventLog].
func (e *MockHostEnvironment) ReadEventLog() (*tcglog.Log, error) {
	if e.Log == nil {
		return nil, errors.New("nil log")
	}
	return e.Log, nil
}

// TPMDevice implements [github.com/snapcore/secboot/internal/efi.HostEnvironment.TPMDevice].
func (e *MockHostEnvironment) TPMDevice() (tpm2_device.TPMDevice, error) {
	if e.TPM2Device == nil {
		return nil, internal_efi.ErrNoTPM2Device
	}
	return e.TPM2Device, nil
}

// DetectVirtMode implements [github.com/snapcore/secboot/internal/efi.HostEnvironment.DetectVirtMode].
func (e *MockHostEnvironment) DetectVirtMode(mode internal_efi.DetectVirtMode) (string, error) {
	if len(e.DelayedVirtModeOptions) > 0 {
		opt := e.DelayedVirtModeOptions[0]
		e.DelayedVirtModeOptions = e.DelayedVirtModeOptions[1:]
		opt(e)
	}

	if e.VirtModeErr != nil {
		return "", e.VirtModeErr
	}

	switch mode {
	case internal_efi.DetectVirtModeAll:
		return e.VirtMode, nil
	case internal_efi.DetectVirtModeContainer, internal_efi.DetectVirtModeVM:
		if e.VirtModeType == mode {
			return e.VirtMode, nil
		}
	}
	return internal_efi.VirtModeNone, nil
}

// EnumerateDevices implements [github.com/snapcore/secboot/internal/efi.HostEnvironment.EnumerateDevices].
func (e *MockHostEnvironment) EnumerateDevices(matcher netlink.Matcher) ([]internal_efi.SysfsDevice, error) {
	if e.Devices == nil {
		return nil, errors.New("nil devices")
	}

	var devices []internal_efi.SysfsDevice
	for _, dev := range e.Devices {
		env := make(map[string]string)
		for k, v := range dev.Properties() {
			env[k] = v
		}
		subsystem := dev.Subsystem()
		if subsystem != "" {
			env["SUBSYSTEM"] = subsystem
		}

		if matcher.EvaluateEnv(env) {
			devices = append(devices, dev)
		}
	}

	return devices, nil
}

// AMD64 implements [github.com/snapcore/secboot/internal/efi.HostEnvironment.AMD64].
func (e *MockHostEnvironment) AMD64() (internal_efi.HostEnvironmentAMD64, error) {
	if e.AMD64Env == nil {
		return nil, internal_efi.ErrNotAMD64Host
	}
	return e.AMD64Env, nil
}
