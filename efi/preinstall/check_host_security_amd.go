//go:build amd64

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

package preinstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/pilebones/go-udev/netlink"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

func readAMDPSPBooleanAttribute(dev internal_efi.SysfsDevice, name string) (bool, error) {
	rc, err := dev.AttributeReader(name)
	if err != nil {
		return false, err
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return false, err
	}

	return strconv.ParseBool(string(bytes.TrimSuffix(data, []byte("\n"))))
}

func checkHostSecurityAMDPSP(env internal_efi.HostEnvironment) (platformFirmwareIntegrityConfig, error) {
	// Enumerate the PCI devices that are bound to the ccp driver.
	devices, err := env.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "pci",
			"DRIVER":    "ccp",
		},
	})
	if err != nil {
		return platformFirmwareIntegrityNone, fmt.Errorf("cannot obtain PCI devices that are bound to the ccp driver: %w", err)
	}

	if len(devices) == 0 {
		// We didn't find any devices, so try to find an AMD cryptographic
		// coporocessor PCI device.
		devices, err := env.EnumerateDevices(&netlink.RuleDefinition{
			Env: map[string]string{
				"SUBSYSTEM": "pci",
				"PCI_CLASS": "108000",
				"PCI_ID":    "1022:[[:xdigit:]]{4}",
			},
		})
		if err != nil {
			return platformFirmwareIntegrityNone, fmt.Errorf("cannot enumerate AMD PCI CCP devices: %w", err)
		}
		if len(devices) == 0 {
			// We can't find the PSP device, so this platform is unsupported.
			return platformFirmwareIntegrityNone, &UnsupportedPlatformError{errors.New("no PSP PCI device")}
		}

		// We found the PSP device, so indicate that the ccp module should
		// be loaded.
		return platformFirmwareIntegrityNone, MissingKernelModuleError("ccp")
	}

	device := devices[0]

	amd64Env, err := env.AMD64()
	if err != nil {
		return platformFirmwareIntegrityNone, fmt.Errorf("cannot obtain AMD64 environment: %w", err)
	}
	if amd64Env.CPUFamily() < 0x17 {
		// Require at least Zen.
		return platformFirmwareIntegrityNone, &UnsupportedPlatformError{errors.New("unsupported CPU family")}
	}

	switch debugLock, err := readAMDPSPBooleanAttribute(device, "debug_lock_on"); {
	case errors.Is(err, internal_efi.ErrNoDeviceAttribute):
		return platformFirmwareIntegrityNone, &NoHardwareRootOfTrustError{errors.New("PSP security reporting not available")}
	case err != nil:
		return platformFirmwareIntegrityNone, fmt.Errorf("cannot determine if debug lock is on: %w", err)
	case !debugLock:
		return platformFirmwareIntegrityNone, &NoHardwareRootOfTrustError{errors.New("PSP debug lock is not enabled")}
	}

	switch fused, err := readAMDPSPBooleanAttribute(device, "fused_part"); {
	case err != nil:
		return platformFirmwareIntegrityNone, fmt.Errorf("cannot determine if part is fused: %w", err)
	case !fused:
		return platformFirmwareIntegrityMeasured, nil
	}

	switch integrity, err := readAMDPSPBooleanAttribute(device, "boot_integrity"); {
	case errors.Is(err, internal_efi.ErrNoDeviceAttribute):
		// Only exists since https://lore.kernel.org/linux-crypto/20260123033457.645189-1-superm1@kernel.org/
		return platformFirmwareIntegrityMeasured, nil
	case err != nil:
		return platformFirmwareIntegrityNone, fmt.Errorf("cannot determine if PSB is enabled: %w", err)
	case !integrity:
		return platformFirmwareIntegrityMeasured, nil
	}

	return platformFirmwareIntegrityVerified, nil
}
