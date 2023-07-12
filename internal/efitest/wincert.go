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
	"encoding/asn1"
	"encoding/binary"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
)

type winCertificateHdr struct {
	Length          uint32
	Revision        uint16
	CertificateType uint16
}

type winCertificateGUIDHdr struct {
	winCertificateHdr
	CertType efi.GUID
}

type winCertificateAuthenticodeHdr struct {
	winCertificateHdr
}

// ReadWinCertificateAuthenticodeDetached creates a new [efi.WinCertificateAuthenticode]
// structure from the supplied detached Authenticode signature. It's expected that this
// doesn't have the WIN_CERTIFICATE header.
func ReadWinCertificateAuthenticodeDetached(c *C, der []byte) *efi.WinCertificateAuthenticode {
	hdr := &winCertificateAuthenticodeHdr{
		winCertificateHdr: winCertificateHdr{
			Length:          uint32(binary.Size(winCertificateAuthenticodeHdr{}) + len(der)),
			Revision:        0x0200,
			CertificateType: 0x0002, // WIN_CERT_TYPE_PKCS_SIGNED_DATA
		},
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, hdr)
	buf.Write(der)

	sig, err := efi.ReadWinCertificate(buf)
	c.Assert(err, IsNil)
	return sig.(*efi.WinCertificateAuthenticode)
}

var (
	oidSpcIndirectData   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcPeImageDataobj = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
)

// GenerateWinCertificateAuthenticode generates a mock detached authenticode signature
// for an image with the specified digest, signed by the supplied key.
func GenerateWinCertificateAuthenticodeDetached(c *C, key crypto.Signer, signer *x509.Certificate, digest []byte, digestAlg crypto.Hash, certs ...*x509.Certificate) []byte {
	// Create the content (SpcIndirectDataContent, as described in Microsoft's
	// Authenticode spec).
	// We only encode the OID for SHA256
	c.Assert(digestAlg, Equals, crypto.SHA256)

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // SpcIndirectDataContent ::= SEQUENCE
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // data SpcAttributeTypeAndOptionalValue
			b.AddASN1ObjectIdentifier(oidSpcPeImageDataobj)                   // type OBJECT IDENTIFIER
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // value ANY DEFINED BY type OPTIONAL
				b.AddASN1BitString([]byte{0})                                                                   // flags SpcPeImageFlags DEFAULT { includeResources }
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // file SpcLink [0] EXPLICIT
					b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // file [2] EXPLICIT SpcString
						b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { // unicode [0] IMPLICIT BMPSTRING
							str := new(bytes.Buffer)
							binary.Write(str, binary.LittleEndian, efi.ConvertUTF8ToUCS2("<<<Obsolete>>>"))
							b.AddBytes(str.Bytes())
						})
					})
				})
			})
		})
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // messageDigest digestInfo
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // digestAlgorithm AlgorithmIdentifier
				b.AddASN1ObjectIdentifier(oidSHA256) // algorithm OBJECT IDENTIFIER
			})
			// Add the PE image digest
			b.AddASN1OctetString(digest) // digest OCTETSTRING
		})
	})
	content, err := b.Bytes()
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	h.Write(content)

	// Create the authenticated attributes
	b = cryptobyte.NewBuilder(nil)
	b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) { // Attributes := SET OF Attribute
		// Add the content type
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidContentType)
			b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidSpcIndirectData)
			})
		})
		// Add the content digest
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidMessageDigest)
			b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(h.Sum(nil))
			})
		})
	})
	attrs, err := b.Bytes()
	c.Assert(err, IsNil)

	h = crypto.SHA256.New()
	h.Write(attrs)

	// Sign the authenticated attributes
	sig, err := key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	c.Assert(err, IsNil)

	// Create the PKCS7 structure
	return generatePKCS7SignedData(c, signer, oidSpcIndirectData, content, attrs, sig, oidSHA256, oidRSAEncryption, certs...)
}
