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
	"github.com/chrisccoulson/go-tpm2"
)

const (
	// Default RSA2048 SRK handle, see section 7.8 of "TCG TPM v2.0 Provisioning Guidance" Version 1.0, Revision 1.0, 15 March 2017
	srkHandle tpm2.Handle = 0x81000001

	// Default RSA2048 EK handle, see section 7.8 of "TCG TPM v2.0 Provisioning Guidance" Version 1.0, Revision 1.0, 15 March 2017
	ekHandle tpm2.Handle = 0x81010001

	lockNVHandle     tpm2.Handle = 0x01801100 // Global NV handle for locking access to sealed key objects
	lockNVDataHandle tpm2.Handle = 0x01801101 // NV index containing policy data for lockNVHandle

	// SHA-256 is mandatory to exist on every PC-Client TPM
	// XXX: Maybe dynamically select algorithms based on what's available on the device?
	defaultSessionHashAlgorithm tpm2.HashAlgorithmId = tpm2.HashAlgorithmSHA256
)

var (
	// Default RSA2048 EK template, see section B.3.3 of "TCG EK Credential Profile For TPM Family 2.0; Level 0", Version 2.1, Revision 13, 10 December 2018
	ekTemplate = tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrAdminWithPolicy | tpm2.AttrRestricted |
			tpm2.AttrDecrypt,
		AuthPolicy: []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7,
			0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa},
		Params: tpm2.PublicParamsU{
			Data: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.SymKeyBitsU{Data: uint16(128)},
					Mode:      tpm2.SymModeU{Data: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}},
		Unique: tpm2.PublicIDU{Data: make(tpm2.PublicKeyRSA, 256)}}
)
