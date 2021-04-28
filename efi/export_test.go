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

package efi

import (
	"github.com/canonical/tcglog-parser"
)

// Export constants for testing
const (
	SigDbUpdateQuirkModeNone              = sigDbUpdateQuirkModeNone
	SigDbUpdateQuirkModeDedupIgnoresOwner = sigDbUpdateQuirkModeDedupIgnoresOwner
)

// Export variables and unexported functions for testing
var (
	CertTypePkcs7Guid                  = certTypePkcs7Guid
	CertX509Guid                       = certX509Guid
	ComputeDbUpdate                       = computeDbUpdate
	ComputePeImageDigest                  = computePeImageDigest
	DecodeSecureBootDb                    = decodeSecureBootDb
	DecodeWinCertificate                  = decodeWinCertificate
	ReadShimVendorCert                    = readShimVendorCert
	WinCertTypePKCSSignedData             = winCertTypePKCSSignedData
	WinCertTypeEfiGuid                    = winCertTypeEfiGuid
)

// Alias some unexported types for testing. These are required in order to pass these between functions in tests, or to access
// unexported members of some unexported types.
type EFISignatureData = efiSignatureData

func (s *EFISignatureData) SignatureType() tcglog.EFIGUID {
	return s.signatureType
}

func (s *EFISignatureData) Owner() tcglog.EFIGUID {
	return s.owner
}

func (s *EFISignatureData) Data() []byte {
	return s.data
}

type SigDbUpdateQuirkMode = sigDbUpdateQuirkMode

type WinCertificateAuthenticode = winCertificateAuthenticode
type WinCertificateUefiGuid = winCertificateUefiGuid

// Export some helpers for testing.
func GetWinCertificateType(cert winCertificate) uint16 {
	return cert.wCertificateType()
}
