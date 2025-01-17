// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package efitest

import (
	"bytes"
	"crypto"

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
)

// ReadSignatureDatabaseUpdate reads a signed signature database update from the supplied
// data and returns its authentication header and the decoded database.
func ReadSignatureDatabaseUpdate(c *C, data []byte) (*efi.VariableAuthentication2, efi.SignatureDatabase) {
	r := bytes.NewReader(data)
	auth, err := efi.ReadTimeBasedVariableAuthentication(r)
	c.Assert(err, IsNil)
	db, err := efi.ReadSignatureDatabase(r)
	c.Assert(err, IsNil)
	return auth, db
}

// NewSignatureListX509 returns a ESL for the supplied X.509 certificate.
func NewSignatureListX509(c *C, cert []byte, owner efi.GUID) *efi.SignatureList {
	return &efi.SignatureList{
		Type: efi.CertX509Guid,
		Signatures: []*efi.SignatureData{
			{
				Owner: owner,
				Data:  cert,
			},
		},
	}
}

// NewSignatureListNullSHA256 returns a ESL containing a single SHA-256 digest generated
// from an empty message.
func NewSignatureListNullSHA256(owner efi.GUID) *efi.SignatureList {
	h := crypto.SHA256.New()
	return &efi.SignatureList{
		Type: efi.CertSHA256Guid,
		Signatures: []*efi.SignatureData{
			{
				Owner: owner,
				Data:  h.Sum(nil),
			},
		},
	}
}

func NewSignatureListDigests(c *C, alg crypto.Hash, owner efi.GUID, digests ...[]byte) *efi.SignatureList {
	var eslType efi.GUID
	switch alg {
	case crypto.SHA1:
		eslType = efi.CertSHA1Guid
	case crypto.SHA256:
		eslType = efi.CertSHA256Guid
	case crypto.SHA384:
		eslType = efi.CertSHA384Guid
	case crypto.SHA512:
		eslType = efi.CertSHA512Guid
	default:
		c.Fatal("unsupported digest")
	}

	esl := &efi.SignatureList{Type: eslType}
	for _, digest := range digests {
		esl.Signatures = append(esl.Signatures, &efi.SignatureData{Owner: owner, Data: digest})
	}
	return esl
}
