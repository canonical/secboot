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
)

const (
	PlatformName = platformName
)

func MockSecbootNewKeyData(fn func(*secboot.KeyParams) (*secboot.KeyData, error)) (restore func()) {
	orig := secbootNewKeyData
	secbootNewKeyData = fn
	return func() {
		secbootNewKeyData = orig
	}
}

func MockFido2NewFIDO2ProtectedKeyWithSaltProvider(fn func()) (restore func()) {
	orig := fido2NewFIDO2ProtectedKeyWithSaltProvider
	fido2NewFIDO2ProtectedKeyWithSaltProvider = func(authenticator *fido2.FIDO2Authenticator, kd *secboot.KeyData, primaryKey secboot.PrimaryKey) (*secboot.KeyData, secboot.PrimaryKey, secboot.DiskUnlockKey, error) {
		fn()
		return orig(authenticator, kd, primaryKey)
	}
	return func() {
		fido2NewFIDO2ProtectedKeyWithSaltProvider = orig
	}
}

func MockSecbootNewSystemdAuthRequestor(authRequestor secboot.AuthRequestor) (restore func()) {
	orig := secbootNewSystemdAuthRequestor
	secbootNewSystemdAuthRequestor = func(string, string) secboot.AuthRequestor {
		return authRequestor
	}
	return func() {
		secbootNewSystemdAuthRequestor = orig
	}
}
