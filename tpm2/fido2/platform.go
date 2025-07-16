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
	"errors"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/fido2"
)

const (
	platformName = "tpm2-fido2"
)

var (
	fido2RecoverKeysWithFIDOProvider = fido2.RecoverKeysWithFIDOProvider
	secbootNewSystemdAuthRequestor   = secboot.NewSystemdAuthRequestor
)

type platformKeyDataHandler struct{}

func (pkdh *platformKeyDataHandler) RecoverKeys(data *secboot.PlatformKeyData, encryptedPayload []byte) ([]byte, error) {
	authRequestor := secbootNewSystemdAuthRequestor("", "")
	authenticator, err := fido2.ConnectToFIDO2Authenticator(authRequestor)
	if err != nil {
		return nil, err
	}
	return fido2RecoverKeysWithFIDOProvider("tpm2", data, encryptedPayload, authenticator)
}

func (*platformKeyDataHandler) RecoverKeysWithAuthKey(data *secboot.PlatformKeyData, encryptedPayload, key []byte) ([]byte, error) {
	return nil, errors.New("unsupported action")
}

func (*platformKeyDataHandler) ChangeAuthKey(data *secboot.PlatformKeyData, old, new []byte, context any) ([]byte, error) {
	return nil, errors.New("unsupported action")
}

func init() {
	secbootPlatformFlags := secboot.PlatformKeyDataHandlerFlags(0).AddPlatformFlags(3)
	secboot.RegisterPlatformKeyDataHandler(platformName, new(platformKeyDataHandler), secbootPlatformFlags)
}
