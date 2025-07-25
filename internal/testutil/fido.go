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

package testutil

import (
	"errors"
	"fmt"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/fido2"
)

var (
	secbootNewSystemdAuthRequestor   = secboot.NewSystemdAuthRequestor
	fido2RecoverKeysWithFIDOProvider = fido2.RecoverKeysWithFIDOProvider
)

type MockFidoAuthRequestor struct {
	Pin string
}

func (r *MockFidoAuthRequestor) RequestPassphrase(volumeName, sourceDevicePath string) (string, error) {
	fmt.Println("Enter PIN (autofilled): ", r.Pin)
	return r.Pin, nil
}

// TODO: This is temporarily used to prompt the user to touch the key. It doesn't return anything
func (r *MockFidoAuthRequestor) RequestRecoveryKey(volumeName, sourceDevicePath string) (secboot.RecoveryKey, error) {
	fmt.Println("Touch key", volumeName)
	return secboot.RecoveryKey{}, nil
}

type platformKeyDataHandler struct {
	salt          []byte
	authRequestor secboot.AuthRequestor
}

func (h *platformKeyDataHandler) RecoverKeys(data *secboot.PlatformKeyData, encryptedPayload []byte) ([]byte, error) {
	authenticator, err := fido2.ConnectToFIDO2Authenticator(h.authRequestor)
	if err != nil {
		return nil, err
	}

	return fido2.RecoverKeys(data, encryptedPayload, h.salt, authenticator)

}

func (h *platformKeyDataHandler) RecoverKeysWithAuthKey(data *secboot.PlatformKeyData, encryptedPayload, key []byte) ([]byte, error) {
	return nil, errors.New("unsupported action")
}

func (h *platformKeyDataHandler) ChangeAuthKey(data *secboot.PlatformKeyData, old, new []byte, context any) ([]byte, error) {
	return nil, errors.New("unsupported action")
}

func (h *platformKeyDataHandler) GetSymmetricKey(data *secboot.PlatformKeyData, authKey []byte) ([]byte, error) {
	return h.salt, nil
}

func NewPlainFidoSaltProvider(salt []byte, authRequestor secboot.AuthRequestor) *platformKeyDataHandler {
	return &platformKeyDataHandler{
		salt:          salt,
		authRequestor: authRequestor,
	}
}
