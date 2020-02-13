// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package secboot

import (
	"errors"
	"fmt"
)

var (
	// ErrTPMProvisioning indicates that the TPM is not provisioned correctly for the requested operation. Please note that other errors
	// that can be returned may also be caused by incomplete provisioning, as it is not always possible to detect incomplete or
	// incorrect provisioning in all contexts.
	ErrTPMProvisioning = errors.New("the TPM is not correctly provisioned")
)

// EkCertVerificationError is returned from SecureConnectToDefaultTPM if verification of the EK certificate against the built-in
// root CA certificates fails, or the EK certificate does not have the correct properties, or the supplied certificate data cannot
// be unmarshalled correctly because it is invalid.
type EkCertVerificationError struct {
	msg string
}

func (e EkCertVerificationError) Error() string {
	return fmt.Sprintf("cannot verify the endorsement key certificate: %s", e.msg)
}

// TPMVerificationError is returned from SecureConnectToDefaultTPM if the TPM cannot prove it is the device for which the verified
// EK certificate was issued.
type TPMVerificationError struct {
	msg string
}

func (e TPMVerificationError) Error() string {
	return fmt.Sprintf("cannot verify that the TPM is the device for which the supplied EK certificate was issued: %s", e.msg)
}
