// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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
	"context"
	"errors"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
)

// XXX: Some of the interfaces here are really public, but they are here because they are shared by
// the public efi and efi/preinstall packages. I wonder if there needs to be a public efi/common
// package for these interfaces to live in.

// HostEnvironmentEFI is an interface that abstracts out an EFI environment, so that
// consumers of the API can provide a custom mechanism to read EFI variables or parse
// the TCG event log.
type HostEnvironmentEFI interface {
	// VarContext returns a copy of parent containing a VarsBackend, keyed by efi.VarsBackendKey,
	// for interacting with EFI variables via go-efilib. This context can be passed to any
	// go-efilib function that interacts with EFI variables. Right now, go-efilib doesn't
	// support any other uses of the context such as cancelation or deadlines. The efivarfs
	// backend will support this eventually for variable writes because it currently implements
	// a retry loop that has a potential to race with other processes. Cancelation and / or
	// deadlines for sections of code that performs multiple reads using efivarfs may be useful
	// in the future because the kernel rate-limits reads per-user.
	VarContext(parent context.Context) context.Context

	// ReadEventLog reads the TCG event log
	ReadEventLog() (*tcglog.Log, error)
}

// SysfsDevice corresponds to a device in the sysfs tree.
type SysfsDevice interface {
	Name() string      // the name of the device
	Path() string      // the fully evaluated sysfs path for the device
	Subsystem() string // the device subsystem name

	// AttributeReader returns an io.ReadCloser to read the specified
	// attribute for the device. The caller should call Close when
	// finished.
	AttributeReader(attr string) (io.ReadCloser, error)
}

// HostEnvironmentAMD64 is an interface that abstracts out a host environment specific
// to AMD64 platforms.
type HostEnvironmentAMD64 interface {
	// CPUVendorIdentificator returns the CPU vendor.
	CPUVendorIdentificator() string

	// HasCPUIDFeature returns if feature from FeatureNames map in the
	// github.com/intel-go/cpuid package is available.
	HasCPUIDFeature(feature uint64) bool

	// ReadMSRs reads the value of the specified MSR for all CPUs,
	// returning a map of the result for all CPU numbers
	ReadMSRs(msr uint32) (map[uint32]uint64, error)
}

// DetectVirtMode controls what type of virtualization to test for.
type DetectVirtMode int

const (
	// DetectVirtModeAll detects for all types of virtualization.
	DetectVirtModeAll DetectVirtMode = iota

	// DetectVirtModeContainer detects for container types of virtualization.
	DetectVirtModeContainer

	// DetectVirtModeVM detects for fully virtualized types of environments.
	DetectVirtModeVM
)

// VirtModeNone corresponds to no virtualization.
const VirtModeNone = "none"

var (
	// ErrNoTPM2Device is returned from HostEnvironment.TPMDevice if no TPM2
	// device is available.
	ErrNoTPM2Device = errors.New("no TPM2 device is available")

	// ErrNoDeviceAttribute is returned from SysfsDevice.Attribute if the supplied attribute
	// does not exist.
	ErrNoDeviceAttribute = errors.New("device attribute does not exist")

	// ErrNotAMD64Host is returned from HostEnvironment.AMD64 on environments that
	// are not AMD64.
	ErrNotAMD64Host = errors.New("not a AMD64 host")

	// ErrNoKernelMSRSupport is returned from HostEnvironmentAMD64.ReadMSRs if there is
	// no support for reading MSRs.
	ErrNoKernelMSRSupport = errors.New("missing kernel support for reading MSRs")

	// ErrNoMSRSupport is returned from HostEnvironmentAMD64.ReadMSRs if there is
	// no MSR support or the specified MSR cannot be read.
	ErrNoMSRSupport = errors.New("missing MSR support")
)

// HostEnvironment is an interface that abstracts out a host environment, so that
// consumers of the API can provide ways to mock parts of an environment.
type HostEnvironment interface {
	HostEnvironmentEFI

	// TPMDevice returns a TPMDevice that can be used to open a tpm2.TPMContext.
	TPMDevice() (tpm2.TPMDevice, error)

	// DetectVirtMode returns whether the environment is virtualized. If not, it returns
	// (VirtModeNone, nil). The mode can be used to choose what type of virtualization to
	// test for.
	DetectVirtMode(mode DetectVirtMode) (string, error)

	// DevicesForClass returns a list of devices with the specified class.
	DevicesForClass(class string) ([]SysfsDevice, error)

	// AMD64 returns an interface that can be used to mock some parts of an AMD64 platform.
	// This will return ErrNotAMD64CPU on non-AMD64 platforms.
	AMD64() (HostEnvironmentAMD64, error)
}
