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
	"crypto/x509"
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	. "gopkg.in/check.v1"
)

var (
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

func generatePKCS7SignedData(c *C, signer *x509.Certificate, contentType asn1.ObjectIdentifier, content, authAttrs, sig []byte, digestAlg, digestEncAlg asn1.ObjectIdentifier, certs ...*x509.Certificate) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // ContentInfo ::= SEQUENCE
		b.AddASN1ObjectIdentifier(oidSignedData)                                                        // contentType ContentType
		b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // content [0] EXPLICIT DEFINED BY contentType OPTIONAL
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // SignedData ::= SEQUENCE
				b.AddASN1Int64(1)                                            // version Version
				b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) { // digestAlgorithms DigestAlgorithmIdentifiers
					b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // AlgorithmIdentifier ::= SEQUENCE
						b.AddASN1ObjectIdentifier(digestAlg) // algorithm OBJECT IDENTIFIER
						b.AddASN1NULL()                      // parameters ANY DEFINED BY algorithm OPTIONAL
					})
				})
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // contentInfo ContentInfo
					b.AddASN1ObjectIdentifier(contentType) // contentType ContentType
					if len(content) > 0 {
						b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // content [0] EXPLICIT DEFINED BY contentType OPTIONAL
							// Add the content
							b.AddBytes(content)
						})
					}
				})
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL
					b.AddBytes(signer.Raw)
					for _, cert := range certs {
						b.AddBytes(cert.Raw)
					}
				})
				b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) { // signerInfos SignerInfos
					b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // SignerInfo ::= SEQUENCE
						b.AddASN1Int64(1)                                                 // version Version
						b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // issuerAndSerialNumber IssuerAndSerialNumber
							b.AddBytes(signer.RawIssuer)
							b.AddASN1BigInt(signer.SerialNumber)
						})
						b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // digestAlgorithm DigestAlgorithmIdentifier
							b.AddASN1ObjectIdentifier(digestAlg) // algorithm OBJECT IDENTIFIER
							b.AddASN1NULL()                      // parameters ANY DEFINED BY algorithm OPTIONAL
						})
						if len(authAttrs) > 0 {
							b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL
								// Add the authenticated attributes
								attrsOuter := cryptobyte.String(authAttrs)
								var attrsInner cryptobyte.String
								attrsOuter.ReadASN1(&attrsInner, cryptobyte_asn1.SET)
								b.AddBytes(attrsInner)
							})
						}
						b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier
							b.AddASN1ObjectIdentifier(digestEncAlg) // algorithm OBJECT IDENTIFIER
							b.AddASN1NULL()                         // parameters ANY DEFINED BY algorithm OPTIONAL
						})
						b.AddASN1OctetString(sig) // encryptedDigest EncryptedDigest
					})
				})
			})
		})
	})

	pk7, err := b.Bytes()
	c.Assert(err, IsNil)

	return pk7
}
