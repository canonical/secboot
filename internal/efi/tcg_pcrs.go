// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

import "github.com/canonical/go-tpm2"

const (
	// PlatformFirmarePCR is the SRTM, POST BIOS, and Embedded Drivers PCR
	PlatformFirmwarePCR tpm2.Handle = 0

	// HostPlatformConfigPCR is the Host Platform Configuration PCR
	PlatformFirmwareConfigPCR tpm2.Handle = 1

	// DriversAndAppsPCR is the UEFI Drivers and UEFI Applications PCR
	DriversAndAppsPCR tpm2.Handle = 2

	// DriversAndAppsConfigPCR is the UEFI driver and application Configuration and Data PCR
	DriversAndAppsConfigPCR tpm2.Handle = 3

	// BootManagerCodePCR is the Boot Manager Code and Boot Attempts PCR
	BootManagerCodePCR tpm2.Handle = 4

	// BootManagerCodeConfigPCR is the Boot Manager Code Configuration and Data
	// (for use by the Boot Manager Code) and GPT/Partition Table PCR.
	BootManagerCodeConfigPCR tpm2.Handle = 5

	// PlatformManufacturerPCR is the Host Platform Manufacturer Specific PCR
	PlatformManufacturerPCR tpm2.Handle = 6

	// SecureBootPolicyPCR is the Secure Boot Policy Measurements PCR
	SecureBootPolicyPCR tpm2.Handle = 7
)

func IsTCGDefinedPCR(pcr tpm2.Handle) bool {
	return pcr <= SecureBootPolicyPCR
}
