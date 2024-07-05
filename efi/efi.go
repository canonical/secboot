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
	platformFirmwarePCR tpm2.Handle = 0 // SRTM, POST BIOS, and Embedded Drivers
	driversAndAppsPCR   tpm2.Handle = 2 // UEFI Drivers and UEFI Applications
	bootManagerCodePCR  tpm2.Handle = 4 // Boot Manager Code and Boot Attempts PCR
	secureBootPolicyPCR tpm2.Handle = 7 // Secure Boot Policy Measurements PCR
	kernelConfigPCR     tpm2.Handle = 12
)

// pcrFlags corresponds to a set of PCRs. This can only represent actual PCRs, it
// cannot represent extendable NV indices (handle type 0x01) if we have a use for
// these in the future
type pcrFlags tpm2.Handle

func makePcrFlags(pcrs ...tpm2.Handle) pcrFlags {
	var out pcrFlags
	for _, pcr := range pcrs {
		if pcr >= 32 {
			panic("invalid PCR")
		}
		out |= 1 << pcr
	}
	return out
}

// PCRs returns a list of all of the PCRs represented by these flags
func (f pcrFlags) PCRs() (out tpm2.HandleList) {
	for n := tpm2.Handle(0); n < 32; n++ {
		if (f & (1 << n)) > 0 {
			out = append(out, n)
		}
	}
	return out
}

func (f pcrFlags) Contains(pcrs ...tpm2.Handle) bool {
	for _, pcr := range pcrs {
		if pcr >= 32 {
			panic("invalid PCR")
		}
		if f&(1<<pcr) == 0 {
			return false
		}
	}
	return true
}
