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

	"github.com/canonical/tcglog-parser"
)

func checkPlatformFirmwareProtections(env HostEnvironment, log *tcglog.Log) (result firmwareProtectionResultFlags, err error) {
	return 0, &UnsupportedPlatformError{fmt.Errorf("checking platform firmware protections is not implemented on %s", runtime.GOARCH)}
}