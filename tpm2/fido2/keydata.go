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

package tpm2_fido2

import (
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/fido2"
	"github.com/snapcore/secboot/tpm2"
)

var (
	secbootNewKeyData                         = secboot.NewKeyData
	fido2NewFIDO2ProtectedKeyWithSaltProvider = fido2.NewFIDO2ProtectedKeyWithSaltProvider
)

func NewTPM2FIDO2ProtectedKey(tpm *tpm2.Connection, params *tpm2.ProtectKeyParams, authenticator *fido2.FIDO2Authenticator) (protectedKey *secboot.KeyData, primaryKey secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
	tkd, primaryKey, _, err := tpm2.NewTPMProtectedKey(tpm, params)
	return fido2NewFIDO2ProtectedKeyWithSaltProvider(authenticator, tkd, primaryKey)
}

// TODO
// func NewTPM2FIDO2PassphraseProtectedKey(tpm *tpm2.Connection, params *ProtectKeyParams) (protectedKey *secboot.KeyData, primaryKey secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
// }
