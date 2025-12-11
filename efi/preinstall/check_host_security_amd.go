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

func checkHostSecurityAMDPSP(env internal_efi.HostEnvironment) error {
	// Enumerate the PCI devices that are bound to the ccp driver.
	devices, err := env.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "pci",
			"DRIVER":    "ccp",
		},
	})
	if err != nil {
		return fmt.Errorf("cannot obtain PCI devices that are bound to the ccp driver: %w", err)
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
			return fmt.Errorf("cannot enumerate AMD PCI CCP devices: %w", err)
		}
		if len(devices) == 0 {
			// We can't find the PSP device, so this platform is unsupported.
			return &UnsupportedPlatformError{errors.New("no PSP PCI device")}
		}

		// We found the PSP device, so indicate that the ccp module should
		// be loaded.
		return MissingKernelModuleError("ccp")
	}

	device := devices[0]

	debugLock, err := readAMDPSPBooleanAttribute(device, "debug_lock_on")
	switch {
	case errors.Is(err, internal_efi.ErrNoDeviceAttribute):
		return &NoHardwareRootOfTrustError{errors.New("PSP security reporting not available")}
	case err != nil:
		return fmt.Errorf("cannot determine if debug lock is on: %w", err)
	case !debugLock:
		return &NoHardwareRootOfTrustError{errors.New("PSP debug lock is not enabled")}
	}

	fused, err := readAMDPSPBooleanAttribute(device, "fused_part")
	switch {
	case errors.Is(err, internal_efi.ErrNoDeviceAttribute):
		return &NoHardwareRootOfTrustError{errors.New("PSP security reporting not available")}
	case err != nil:
		return fmt.Errorf("cannot determine if PSB is enabled: %w", err)
	case !fused:
		return &NoHardwareRootOfTrustError{errors.New("Platform Secure Boot is not enabled")}
	}

	return nil
}
