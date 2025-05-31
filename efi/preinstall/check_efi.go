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
	"context"
	"errors"

	efi "github.com/canonical/go-efilib"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// checkSystemIsEFI checks if the host system is an EFI system by ensuring that there
// is a mechanism to read the SecureBoot global variable using go-efilib's variable
// reading API.
func checkSystemIsEFI(ctx context.Context, env internal_efi.HostEnvironment) error {
	_, _, err := efi.ReadVariable(env.VarContext(ctx), "SecureBoot", efi.GlobalVariable)
	switch {
	case errors.Is(err, efi.ErrVarsUnavailable):
		return ErrSystemNotEFI
	case isEFIVariableAccessError(err):
		return &EFIVariableAccessError{err: err}
	default:
		return err
	}
}
