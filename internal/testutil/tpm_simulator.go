// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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

package testutil

import (
	"fmt"
	"os"
	"path/filepath"
)

func GetTpmSimulatorWorkDir() string {
	// Choose a working directory that is allowed by the snap confinement.
	// This is a workaround as go-tpm2 does not correctly set the correct snap run directory.
	// See https://github.com/canonical/go-tpm2/issues/21
	runDir := os.Getenv("XDG_RUNTIME_DIR")
	if runDir == "" {
		fmt.Fprintf(os.Stderr, "Cannot get TPM simulator work dir: XDG_RUNTIME_DIR not set\n")
		return ""
	}
	mssimSnapName := "tpm2-simulator-chrisccoulson"
	return filepath.Join(runDir, "snap."+mssimSnapName)
}
