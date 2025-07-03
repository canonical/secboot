// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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

package keyring

import (
	"errors"
	"syscall"
)

var (
	ErrExpectedKeyring = errors.New("cannot complete operation because one or more key ID arguments was expected to reference a keyring but didn't")
	ErrInvalidArgs     = errors.New("cannot complete operation because one or more arguments is invalid")
	ErrKeyExpired      = errors.New("cannot complete operation because an expired key was specified")
	ErrKeyNotExist     = errors.New("cannot complete operation because a specified key does not exist")
	ErrKeyExists       = errors.New("cannot complete operation because a key with a specified ID already exists")
	ErrKeyRevoked      = errors.New("cannot complete operation because a revoked key was specified")
	ErrPermission      = errors.New("cannot complete operation because of insufficient permissions")
	ErrQuota           = errors.New("cannot complete operation because it would cause the user's quota to be exceeded")
	ErrUnsupported     = errors.New("cannot complete unsupported operation on specified key")
)

func processSyscallError(err error) error {
	switch {
	case errors.Is(err, syscall.ENOTDIR):
		return ErrExpectedKeyring
	case errors.Is(err, syscall.EINVAL):
		return ErrInvalidArgs
	case errors.Is(err, syscall.EKEYEXPIRED):
		return ErrKeyExpired
	case errors.Is(err, syscall.ENOKEY) || errors.Is(err, syscall.ENOENT):
		return ErrKeyNotExist
	case errors.Is(err, syscall.EEXIST):
		return ErrKeyExists
	case errors.Is(err, syscall.EKEYREVOKED):
		return ErrKeyRevoked
	case errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM):
		return ErrPermission
	case errors.Is(err, syscall.EDQUOT):
		return ErrQuota
	case errors.Is(err, syscall.EOPNOTSUPP):
		return ErrUnsupported
	}

	return err
}
