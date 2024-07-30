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

package preinstall

import (
	"errors"

	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// Errors related to checking platform firmware protections.

// NoHardwareRootOfTrustError is returned wrapped from [RunChecks] if the platform
// firmware is not protected by a hardware root-of-trust. This won't be returned if
// the PermitVirtualMachine flag is supplied to [RunChecks] and the current
// environment is a virtual machine.
type NoHardwareRootOfTrustError struct {
	err error
}

func (e *NoHardwareRootOfTrustError) Error() string {
	return "no hardware root-of-trust properly configured: " + e.err.Error()
}

func (e *NoHardwareRootOfTrustError) Unwrap() error {
	return e.err
}

// UnsupportedPlatformError is returned wrapped from [RunChecks] if this platform
// is not supported for FDE.
type UnsupportedPlatformError struct {
	err error
}

func (e *UnsupportedPlatformError) Error() string {
	return "unsupported platform: " + e.err.Error()
}

func (e *UnsupportedPlatformError) Unwrap() error {
	return e.err
}

var (
	// ErrCPUDebuggingNotLocked is returned wrapped from RunChecks if the CPU
	// has silicon debugging features but these have not been disabled and
	// locked by the platform firmware. This won't be returned if the
	// PermitVirtualMachine flag is supplied to RunChecks and the current
	// environment is a virtual machine.
	ErrCPUDebuggingNotLocked = errors.New("CPU debugging features are not disabled and locked")

	// ErrInsufficientDMAProtection is returned wrapped from RunChecks if the platform
	// firmware indicates that I/O DMA protection was disabled at some point. This won't
	// be returned if the PermitVirtualMachine flag is supplied to RunChecks and the current
	// environment is a virtual machine.
	ErrInsufficientDMAProtection = errors.New("the platform firmware indicates that DMA protections are insufficient")

	// ErrNoKernelIOMMU is returned wrapped from RunChecks if there is no IOMMU active. This
	// won't be returned if the PermitVirtualMachine flag is supplied to RunChecks and
	// the current environment is a virtual machine.
	ErrNoKernelIOMMU = errors.New("no kernel IOMMU support was detected")

	// ErrUEFIDebuggingEnabled is returned wrapped from RunChecks if the platform firmware
	// has a debugging endpoint enabled. This won't be returned if the PermitVirtualMachine
	// flag is supplied to RunChecks and the current environment is a virtual machine.
	ErrUEFIDebuggingEnabled = errors.New("the platform firmware contains a debugging endpoint enabled")
)

// Errors related to checking the TPM device.

var (
	// ErrNoTPM2Device is returned wrapped from RunChecks if there is no
	// TPM2 device available.
	ErrNoTPM2Device = internal_efi.ErrNoTPM2Device

	// ErrTPMLockout is returned wrapped from RunChecks if the TPM is in DA
	// lockout mode. If the existing lockout hierarchy authorization value is not
	// known then the TPM will most likely need to be cleared in order to fix this.
	ErrTPMLockout = errors.New("TPM is in DA lockout mode")

	// ErrTPMLockoutAlreadyOwned is returned wrapped from RunChecks if the authorization
	// value for the lockout hierarchy is already set but the PostInstallChecks flag isn't
	// supplied. If the lockout hierarchy is set at pre-install time, then the TPM will
	// most likely need to be cleared.
	ErrTPMLockoutAlreadyOwned = errors.New("TPM lockout hierarchy is already owned")

	// ErrUnsupportedTPMOwnership is returned wrapped from RunChecks if the authorization
	// value for the owner or endorsement hierarchies are set, which currently isn't
	// supported by snapd. Snapd needs the use of both of these hierarchies, so if we
	// want to support something other than snapd taking ownership of these in the future,
	// this will need coordination with snapd.
	// Unless the authorization values are known, clearing this will most likely require
	// the TPM to be cleared.
	ErrUnsupportedTPMOwnership = errors.New("either the TPM's storage or endorsement hierarchy is owned and this isn't currently supported")

	// ErrTPMInsufficientNVCounters is returned wrapped from RunChecks if there are
	// insufficient NV counters available for PCR policy revocation. If this is still
	// the case after a TPM clear then it means that the platform firmware is using
	// most of the allocation of available counters for itself, and maybe the
	// feature needs to be disabled by snapd.
	ErrTPMInsufficientNVCounters = errors.New("insufficient NV counters available")

	// ErrNoPCClientTPM is returned wrapped from RunChecks if a TPM2 device exists
	// but it doesn't claim to be meet the requirements for PC-Client. Note that swtpm
	// used by VM's don't behave correctly here, so we account for that instead of
	// returning an error.
	ErrNoPCClientTPM = errors.New("TPM2 device is present but it is not a PC-Client TPM")

	// ErrTPMDisabled is returned wrapped from RunChecks if a TPM2 device exists but
	// it is currently disabled. It can be reenabled by the firmware by making use of the
	// [github.com/canonical/go-tpm2/ppi.PPI] interface, obtained by using
	// [github.com/canonical/go-tpm2/linux/RawDevice.PhysicalPresenceInterface].
	ErrTPMDisabled = errors.New("TPM2 device is present but is currently disabled by the platform firmware")
)
