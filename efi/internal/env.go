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

package internal

import (
	"context"

	"github.com/canonical/tcglog-parser"
)

// HostEnvironment is an interface that abstracts out an EFI environment, so that
// consumers of the API can provide a custom mechanism to read EFI variables or parse
// the TCG event log. This needs to be kept in sync with [efi.HostEnvironment].
type HostEnvironment interface {
	// VarContext returns a context containing a VarsBackend, keyed by efi.VarsBackendKey,
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
