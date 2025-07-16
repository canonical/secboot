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

package fido2

import (
	"errors"
	"fmt"
	"log"
	"slices"

	"github.com/keys-pub/go-libfido2"
	"github.com/snapcore/secboot"
)

const (
	rpId     = "com.ubuntu"       // Relying Party ID
	rpName   = "Canonical Ubuntu" // Relying Party Name
	userName = "secboot"          // User name
)

var (
	ErrNoFIDO2DevicesFound = errors.New("no FIDO2 devices found")
)

type FIDO2Authenticator struct {
	device        *libfido2.Device
	info          *libfido2.DeviceInfo
	authRequestor secboot.AuthRequestor
	// clientPin
	// uv built-in
	// bio capabilities
}

func (f *FIDO2Authenticator) ClientPinRequired() bool {
	pinSet := false
	bioEnrolled := false
	for _, option := range f.info.Options {
		switch option.Value == "true" {
		case option.Name == "clientPin":
			pinSet = true
		case option.Name == "bioEnroll":
			bioEnrolled = true
		}
	}

	if bioEnrolled {
		return false
	}

	if pinSet {
		return true
	}

	return false
}

func (f *FIDO2Authenticator) maybeRequestPin(purpose string) (string, error) {
	var pin string
	if f.ClientPinRequired() {
		// TODO this should be implemented by a more fido specific interface
		pin, err := f.authRequestor.RequestPassphrase(purpose, "")
		if err != nil {
			return pin, err
		}
	}

	return pin, nil
}

func (f *FIDO2Authenticator) requestTouch(purpose string) error {
	// TODO this should be implemented by a more fido specific interface
	_, err := f.authRequestor.RequestRecoveryKey(purpose, "")

	return err
}

func (f *FIDO2Authenticator) MakeFDECredential(salt []byte) (credentialID []byte, secret []byte, err error) {
	pin, err := f.maybeRequestPin("to create FDE credential")
	if err != nil {
		return nil, nil, err
	}

	// TODO: This is used for contextual binding of the credential, what can we use it for?
	// is also signed with the pinUvAuthToken and passed to the make credential call in the
	// pinUvAuthParam parameter. Mostly used by webauthn. Set it to empty for now.
	// cdh := libfido2.RandBytes(32)
	cdh := make([]byte, 32)

	// TODO: This can be the identifier of the device if any
	// userID := libfido2.RandBytes(32)
	userID := make([]byte, 32)

	f.requestTouch("to create FDE credential")

	attest, err := f.device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID:   rpId,
			Name: rpName,
		},
		libfido2.User{
			ID:          userID,
			Name:        userName,
			DisplayName: userName,
		},
		libfido2.ES256, // Algorithm
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
		},
	)
	if err != nil {
		return nil, nil, err
	}

	// TODO Here we can verify attest.AuthData using the attest.Sig against attest.Cert to ensure the
	// credential was created by a trusted authenticator.
	// This is defined in https://www.w3.org/TR/webauthn-2/#sctn-attestation and is used by RPs in the
	// full WebAuthn flow.

	// TODO Using AuthData we can verify:
	// the user present bit
	// the user verified bit
	// that the extension data indeed included (hmac-secret: true)
	// log.Printf("AuthData: %s\n", hex.EncodeToString(attest.AuthData))

	secret, err = f.GetHmacSecret(attest.CredentialID, salt)

	return attest.CredentialID, secret, err
}

func (f *FIDO2Authenticator) GetHmacSecret(credentialID []byte, salt []byte) (secret []byte, err error) {
	pin, err := f.maybeRequestPin("to create FDE credential")
	if err != nil {
		return nil, err
	}

	cdh := make([]byte, 32)

	f.requestTouch("to retrieve secret")

	assertion, err := f.device.Assertion(
		rpId,
		cdh,
		[][]byte{credentialID},
		pin,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			UP:         libfido2.True,
			HMACSalt:   salt,
		},
	)
	if err != nil {
		return nil, err
	}

	return assertion.HMACSecret, nil
}

func verify(device *libfido2.Device) (*libfido2.DeviceInfo, error) {
	devType, err := device.Type()
	if err != nil {
		return nil, err
	}
	if devType != libfido2.FIDO2 {
		return nil, fmt.Errorf("device is not a FIDO2 device: %v", devType)
	}

	info, err := device.Info()
	if err != nil {
		return nil, err
	}

	if !slices.Contains(info.Versions, "FIDO_2_0") {
		return nil, fmt.Errorf("device does not support CTAP 2.1: %v", device)
	}

	if !slices.Contains(info.Extensions, "hmac-secret") {
		return nil, fmt.Errorf("device does not support hmac-secret extension: %v", device)
	}

	return info, nil
}

func NewFIDO2Authenticator(authRequestor secboot.AuthRequestor) (*FIDO2Authenticator, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("cannot find devices: %v", err)
	}
	if len(locs) == 0 {
		return nil, ErrNoFIDO2DevicesFound
	}

	fmt.Printf("Using device: %+v\n", locs[0])

	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		return nil, err
	}

	info, err := verify(device)
	if err != nil {
		return nil, fmt.Errorf("device verification failed: %v", err)
	}

	return &FIDO2Authenticator{
		device:        device,
		info:          info,
		authRequestor: authRequestor,
	}, nil
}

func ConnectToFIDO2Authenticator(authRequestor secboot.AuthRequestor) (*FIDO2Authenticator, error) {

	fido2Authenticator, err := NewFIDO2Authenticator(authRequestor)
	if err != nil {
		return nil, err
	}

	log.Printf("Info: %+v\n", fido2Authenticator.info)

	return fido2Authenticator, err
}
