// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2021 Canonical Ltd
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

package tpm2test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/canonical/go-tpm2"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/truststore"
)

// CreateTestCA creates a snakeoil TPM manufacturer CA certificate.
func CreateTestCA() ([]byte, crypto.PrivateKey, error) {
	serial := big.NewInt(rand.Int63())

	keyId := make([]byte, 32)
	if _, err := rand.Read(keyId); err != nil {
		return nil, nil, fmt.Errorf("cannot obtain random key ID: %w", err)
	}

	key, err := rsa.GenerateKey(testutil.RandReader, 768)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate RSA key: %w", err)
	}

	t := time.Now()

	template := x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		SerialNumber:       serial,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Snake Oil TPM Manufacturer"},
			CommonName:   "Snake Oil TPM Manufacturer EK Root CA"},
		NotBefore:             t.Add(time.Hour * -24),
		NotAfter:              t.Add(time.Hour * 240),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyId}

	cert, err := x509.CreateCertificate(testutil.RandReader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create certificate: %w", err)
	}

	return cert, key, nil
}

// CreateTestEKCert creates a snakeoil EK certificate for the TPM associated with the supplied TPMContext.
func CreateTestEKCert(tpm *tpm2.TPMContext, caCert []byte, caKey crypto.PrivateKey) ([]byte, error) {
	ek, pub, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), nil, tcg.EKTemplate, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create EK: %w", err)
	}
	defer tpm.FlushContext(ek)

	serial := big.NewInt(rand.Int63())

	key := rsa.PublicKey{
		N: new(big.Int).SetBytes(pub.Unique.RSA),
		E: 65537}

	keyId := make([]byte, 32)
	if _, err := rand.Read(keyId); err != nil {
		return nil, fmt.Errorf("cannot obtain random key ID for EK cert: %w", err)
	}

	t := time.Now()

	tpmDeviceAttrValues := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: tcg.OIDTcgAttributeTpmManufacturer, Value: "id:49424d00"},
			pkix.AttributeTypeAndValue{Type: tcg.OIDTcgAttributeTpmModel, Value: "FakeTPM"},
			pkix.AttributeTypeAndValue{Type: tcg.OIDTcgAttributeTpmVersion, Value: "id:00010002"}}}
	tpmDeviceAttrData, err := asn1.Marshal(tpmDeviceAttrValues)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal SAN value: %2", err)
	}
	sanData, err := asn1.Marshal([]asn1.RawValue{
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tcg.SANDirectoryNameTag, IsCompound: true, Bytes: tpmDeviceAttrData}})
	if err != nil {
		return nil, fmt.Errorf("cannot marshal SAN value: %w", err)
	}
	sanExtension := pkix.Extension{
		Id:       tcg.OIDExtensionSubjectAltName,
		Critical: true,
		Value:    sanData}

	template := x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          serial,
		NotBefore:             t.Add(time.Hour * -24),
		NotAfter:              t.Add(time.Hour * 240),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{tcg.OIDTcgKpEkCertificate},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          keyId,
		ExtraExtensions:       []pkix.Extension{sanExtension}}

	root, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CA certificate: %w", err)
	}

	cert, err := x509.CreateCertificate(testutil.RandReader, &template, root, &key, caKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create EK certificate: %w", err)
	}

	return cert, nil
}

// CertifyTPM certifies the TPM associated with the provided context with a EK certificate.
func CertifyTPM(tpm *tpm2.TPMContext, ekCert []byte) error {
	nvPub := tpm2.NVPublic{
		Index:   tcg.EKCertHandle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPPWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVPlatformCreate),
		Size:    uint16(len(ekCert))}
	index, err := tpm.NVDefineSpace(tpm.PlatformHandleContext(), nil, &nvPub, nil)
	if err != nil {
		return fmt.Errorf("cannot define NV index for EK certificate: %w", err)
	}
	if err := tpm.NVWrite(tpm.PlatformHandleContext(), index, tpm2.MaxNVBuffer(ekCert), 0, nil); err != nil {
		return fmt.Errorf("cannot write EK certificate to NV index: %w", err)
	}
	return nil
}

// TrustCA adds the supplied TPM manufacturer CA certificate to the list of built-in roots.
func TrustCA(cert []byte) (restore func()) {
	h := crypto.SHA256.New()
	h.Write(cert)
	truststore.RootCAHashes = append(truststore.RootCAHashes, h.Sum(nil))
	return func() {
		truststore.RootCAHashes = truststore.RootCAHashes[:len(truststore.RootCAHashes)-1]
	}
}
