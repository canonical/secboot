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
	HostPlatformConfigPCR tpm2.Handle = 1

	// DriversAndAppsPCR is the UEFI Drivers and UEFI Applications PCR
	DriversAndAppsPCR tpm2.Handle = 2

	// BootManagerCodePCR is the Boot Manager Code and Boot Attempts PCR
	BootManagerCodePCR tpm2.Handle = 4

	// SecureBootPolicyPCR is the Secure Boot Policy Measurements PCR
	SecureBootPolicyPCR tpm2.Handle = 7
)
