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
	"crypto/rand"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"time"

	efi "github.com/canonical/go-efilib"
	. "gopkg.in/check.v1"
)

type efiTime struct {
	Year       uint16
	Month      uint8
	Day        uint8
	Hour       uint8
	Minute     uint8
	Second     uint8
	Pad1       uint8
	Nanosecond uint32
	Timezone   int16
	Daylight   uint8
	Pad2       uint8
}

func toEfiTime(t time.Time) efiTime {
	return efiTime{
		Year:   uint16(t.Year()),
		Month:  uint8(t.Month()),
		Day:    uint8(t.Day()),
		Hour:   uint8(t.Hour()),
		Minute: uint8(t.Minute()),
		Second: uint8(t.Second())}
}

type efiVariableAuthentication2 struct {
	TimeStamp efiTime
	AuthInfo  winCertificateGUIDHdr
}

// GenerateSignedVariableUpdate generates a mock signed authenticated variable payload.
func GenerateSignedVariableUpdate(c *C, key crypto.Signer, signer *x509.Certificate, name string, guid efi.GUID, attrs efi.VariableAttributes, timestamp time.Time, data []byte, certs ...*x509.Certificate) []byte {
	h := crypto.SHA256.New()
	binary.Write(h, binary.LittleEndian, efi.ConvertUTF8ToUCS2(name))
	h.Write(guid[:])
	binary.Write(h, binary.LittleEndian, attrs)
	binary.Write(h, binary.LittleEndian, toEfiTime(timestamp))
	h.Write(data)

	// Sign the variable uppdate
	sig, err := key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	c.Assert(err, IsNil)

	// Create the PKCS7 structure
	pk7 := generatePKCS7SignedData(c, signer, oidData, nil, nil, sig, oidSHA256, oidRSAEncryption, certs...)

	// Add the header
	hdr := &efiVariableAuthentication2{
		TimeStamp: toEfiTime(timestamp),
		AuthInfo: winCertificateGUIDHdr{
			winCertificateHdr: winCertificateHdr{
				Length:          uint32(binary.Size(winCertificateGUIDHdr{}) + len(pk7)),
				Revision:        0x0200,
				CertificateType: 0x0ef1, // WIN_CERT_TYPE_EFI_GUID
			},
			CertType: efi.CertTypePKCS7Guid,
		},
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, hdr)
	buf.Write(pk7)
	buf.Write(data)

	return buf.Bytes()
}
