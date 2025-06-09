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
	"encoding/json"
	"errors"
	"fmt"

	efi "github.com/canonical/go-efilib"
)

// EFIVariableAccessErrorArg represents an EFI variable access error that
// can be serialized to JSON.
type EFIVariableAccessErrorArg string

const (
	EFIVarsUnavailable      EFIVariableAccessErrorArg = "vars-unavailable"
	EFIVarNotExist          EFIVariableAccessErrorArg = "not-exist"
	EFIVarInvalidParam      EFIVariableAccessErrorArg = "invalid-param"
	EFIVarDeviceError       EFIVariableAccessErrorArg = "device-error"
	EFIVarPermission        EFIVariableAccessErrorArg = "permission"
	EFIVarInsufficientSpace EFIVariableAccessErrorArg = "insufficient-space"
	EFIVarWriteProtected    EFIVariableAccessErrorArg = "write-protected"

	EFIVarUnrecognizedError EFIVariableAccessErrorArg = "unrecognized-error"
)

// MakeEFIVariableAccessErrorArg makes an EFIVariableAccessErrorArg from the supplied
// error. If the supplied error is not a recognized EFI variable access error (from the
// github.com/canonical/go-efilib package), EFIVarUnrecognizedError will be returned.
func MakeEFIVariableAccessErrorArg(err error) EFIVariableAccessErrorArg {
	efiErrs := map[error]EFIVariableAccessErrorArg{
		efi.ErrVarsUnavailable:      EFIVarsUnavailable,      // no variable backend (eg, efivarfs) is available
		efi.ErrVarNotExist:          EFIVarNotExist,          // variable runtime service likely returned EFI_NOT_FOUND, or some other backend-specific error occurred (ENOENT for efivarfs).
		efi.ErrVarInvalidParam:      EFIVarInvalidParam,      // variable runtime service likely returned EFI_INVALID_PARAMETER, or some other backend-specific error occurred (EINVAL for efivarfs).
		efi.ErrVarDeviceError:       EFIVarDeviceError,       // variable runtime service likely returned EFI_DEVICE_ERROR, or some other backend-specific error occurred (EIO for efivarfs).
		efi.ErrVarPermission:        EFIVarPermission,        // variable runtime service likely returned EFI_SECURITY_VIOLATION, or some other backend-specific permission error occurred (EACCES for efivarfs).
		efi.ErrVarInsufficientSpace: EFIVarInsufficientSpace, // variable runtime service likely returned EFI_OUT_OF_RESOURCES, or some other backend-specific error occurred (ENOSPC for efivarfs).
		efi.ErrVarWriteProtected:    EFIVarWriteProtected,    // variable runtime service likely returned EFI_WRITE_PROTECTED, or some other backend-specific read-only error occurred (EROFS for efivarfs).
	}

	for efiErr, arg := range efiErrs {
		if !errors.Is(err, efiErr) {
			// The supplied error is not this efiErr.
			continue
		}

		// The supplied error is this efiErr, so return the appropriate EFIVariableAccessErrorArg.
		return arg
	}

	// The supplied error is not a recognized EFI variable access error.
	return EFIVarUnrecognizedError
}

// isEFIVariableAccessError indicates whether the supplied error indicates
// an EFI variable access error, returned from github.com/canonical/go-efilib.
func isEFIVariableAccessError(err error) bool {
	return MakeEFIVariableAccessErrorArg(err) != EFIVarUnrecognizedError
}

// MarshalJSON implements [json.Marshaler].
func (a EFIVariableAccessErrorArg) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"err": string(a)})
}

// UnmarshalJSON implements [json.Unmarshaler].
func (a *EFIVariableAccessErrorArg) UnmarshalJSON(data []byte) error {
	var arg map[string]string
	if err := json.Unmarshal(data, &arg); err != nil {
		return err
	}
	efiErr, exists := arg["err"]
	if !exists {
		return errors.New("no \"err\" field")
	}
	*a = EFIVariableAccessErrorArg(efiErr)
	return nil
}

// Error returns the error associated with this argument. Note that
// this is not an implementation of [error].
func (a EFIVariableAccessErrorArg) Error() error {
	switch a {
	case EFIVarsUnavailable:
		return efi.ErrVarsUnavailable
	case EFIVarNotExist:
		return efi.ErrVarNotExist
	case EFIVarInvalidParam:
		return efi.ErrVarInvalidParam
	case EFIVarDeviceError:
		return efi.ErrVarDeviceError
	case EFIVarPermission:
		return efi.ErrVarPermission
	case EFIVarInsufficientSpace:
		return efi.ErrVarInsufficientSpace
	case EFIVarWriteProtected:
		return efi.ErrVarWriteProtected
	case EFIVarUnrecognizedError:
		return errors.New("unrecognized EFI variable access error")
	default:
		return fmt.Errorf("unrecognized EFI variable access error code %q", string(a))
	}
}
