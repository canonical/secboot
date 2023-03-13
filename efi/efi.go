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

import (
	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
)

const (
	bootManagerCodePCR = 4 // Boot Manager Code and Boot Attempts PCR

	certTableIndex = 4 // Index of the Certificate Table entry in the Data Directory of a PE image optional header
)

var (
	eventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements" // Path of the TCG event log for the default TPM, in binary form
)

// HostEnvironment is an interface that abstracts out an EFI environment, so that
// consumers of the API can provide a custom mechanism to read EFI variables or parse
// the TCG event log.
type HostEnvironment interface {
	ReadVar(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error)

	ReadEventLog() (*tcglog.Log, error)
}
