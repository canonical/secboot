// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package bootenv

import (
	"crypto"
	"encoding/asn1"
	"encoding/base64"

	"github.com/snapcore/secboot"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/xerrors"
)

var sha3_384oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}

func computeSnapModelHash(alg crypto.Hash, model secboot.SnapModel) ([]byte, error) {
	signKeyId, err := base64.RawURLEncoding.DecodeString(model.SignKeyID())
	if err != nil {
		return nil, xerrors.Errorf("cannot decode signing key ID: %w", err)
	}

	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // SnapModel ::= SEQUENCE {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // signer DigestInfo
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // digestAlgorithm AlgorithmIdentifier
				b.AddASN1ObjectIdentifier(sha3_384oid) // algorithm OBJECT IDENTIFIER
				b.AddASN1NULL()                        // parameters ANY DEFINED BY algorithm OPTIONAL
			})
			b.AddASN1OctetString(signKeyId) // digest OCTET STRING
		})
		b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) { // brand UTF8String
			b.AddBytes([]byte(model.BrandID()))
		})
		b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) { // model UTF8String
			b.AddBytes([]byte(model.Model()))
		})
		b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) { // series UTF8String
			b.AddBytes([]byte(model.Series()))
		})
		b.AddASN1Enum(int64(model.Grade().Code())) // grade ENUMERATED
		b.AddASN1Boolean(model.Classic())          // classic BOOLEAN
	})

	b, err := builder.Bytes()
	if err != nil {
		return nil, xerrors.Errorf("cannot serialize model properties: %w", err)
	}

	h := alg.New()
	h.Write(b)
	return h.Sum(nil), nil
}
