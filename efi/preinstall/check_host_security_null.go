//go:build !amd64

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
	"fmt"
	"runtime"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"

	internal_efi "github.com/snapcore/secboot/internal/efi"
)

func checkHostSecurity(env internal_efi.HostEnvironment, log *tcglog.Log) (protectedStartupLocalities tpm2.Locality, err error) {
	return 0, &UnsupportedPlatformError{fmt.Errorf("checking host security is not implemented on %s", runtime.GOARCH)}
}
