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
	"github.com/canonical/go-efilib"
)

var (
	EventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements" // Path of the TCG event log for the default TPM, in binary form
	EFIVarsPath  = "/sys/firmware/efi/efivars"                          // Default mount point for efivarfs

	ReadVar = efi.ReadVar
)
