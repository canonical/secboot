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

package efi_test

import (
	"crypto"
	_ "crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	drbg "github.com/canonical/go-sp800.90a-drbg"
	"github.com/snapcore/secboot/internal/testutil"
)

var (
	msKEKCert       []byte
	msPCACert       []byte
	msUefiCACert    []byte
	canonicalCACert []byte

	testPKCert1            []byte
	testPKKey1             []byte
	testPKCert2            []byte
	testPKKey2             []byte
	testRootCert           []byte
	testRootKey            []byte
	testKEKCert            []byte
	testKEKKey             []byte
	testUefiCACert1        []byte
	testUefiCAKey1         []byte
	testUefiSigningCert1_1 []byte
	testUefiSigningKey1_1  []byte
	testUefiCACert2        []byte
	testUefiCAKey2         []byte
)

func initTestCertificate(key []byte, subject pkix.Name, serialNumber *big.Int, isCA bool, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, issuerCert []byte, issuerKey []byte) []byte {
	template := &x509.Certificate{
		BasicConstraintsValid: true,
		ExtKeyUsage:           extKeyUsage,
		IsCA:                  isCA,
		KeyUsage:              keyUsage,
		NotAfter:              time.Date(2120, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:             time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		Subject:               subject,
	}

	privKey, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		panic(err)
	}
	pubKey := &privKey.PublicKey

	issuer := template
	if len(issuerCert) > 0 {
		issuer, err = x509.ParseCertificate(issuerCert)
		if err != nil {
			panic(err)
		}
		privKey, err = x509.ParsePKCS1PrivateKey(issuerKey)
		if err != nil {
			panic(err)
		}
	}

	h := crypto.SHA1.New()
	h.Write(x509.MarshalPKCS1PublicKey(pubKey))
	pubKeySha1 := h.Sum(nil)

	if !isCA {
		template.SubjectKeyId = pubKeySha1
	}

	rng, err := drbg.NewCTRWithExternalEntropy(
		32,
		[]byte{0x45, 0xef, 0xa4, 0xe4, 0x6a, 0xb7, 0x55, 0x14, 0xcd, 0xce, 0xc2, 0x17, 0x59, 0x77, 0x1a, 0x95,
			0x2e, 0x35, 0x55, 0xfd, 0x94, 0x39, 0x0e, 0x9d, 0x90, 0xbf, 0x7a, 0x3c, 0xc2, 0xe3, 0x9a, 0x84,
		},
		pubKeySha1,
		[]byte("CERT-SIGN"),
		nil)
	if err != nil {
		panic(err)
	}
	cert, err := x509.CreateCertificate(rng, template, issuer, pubKey, privKey)
	if err != nil {
		panic(err)
	}

	return cert
}

func init() {
	msKEKCert = testutil.MustDecodePEMType("CERTIFICATE", msKEKCertPEM)
	msPCACert = testutil.MustDecodePEMType("CERTIFICATE", msPCACertPEM)
	msUefiCACert = testutil.MustDecodePEMType("CERTIFICATE", msUefiCACertPEM)
	canonicalCACert = testutil.MustDecodePEMType("CERTIFICATE", canonicalCACertPEM)

	testPKKey1 = testutil.MustDecodePEMType("RSA PRIVATE KEY", testPKKey1PEM)
	testPKKey2 = testutil.MustDecodePEMType("RSA PRIVATE KEY", testPKKey2PEM)
	testRootKey = testutil.MustDecodePEMType("RSA PRIVATE KEY", testRootKeyPEM)
	testKEKKey = testutil.MustDecodePEMType("RSA PRIVATE KEY", testKEKKeyPEM)
	testUefiCAKey1 = testutil.MustDecodePEMType("RSA PRIVATE KEY", testUefiCAKey1PEM)
	testUefiSigningKey1_1 = testutil.MustDecodePEMType("RSA PRIVATE KEY", testUefiSigningKey1_1PEM)
	testUefiCAKey2 = testutil.MustDecodePEMType("RSA PRIVATE KEY", testUefiCAKey2PEM)

	testPKCert1 = initTestCertificate(
		testPKKey1,
		pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test Platform Key",
		},
		big.NewInt(1),
		true,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment,
		nil,
		nil, nil)
	testPKCert2 = initTestCertificate(
		testPKKey2,
		pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test Platform Key 2",
		},
		big.NewInt(1),
		true,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment,
		nil,
		nil, nil)
	testRootCert = initTestCertificate(
		testRootKey,
		pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test Root CA",
		},
		big.NewInt(1),
		true,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign,
		nil,
		nil, nil)
	testKEKCert = initTestCertificate(
		testKEKKey,
		pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test KEK 1",
		},
		big.NewInt(1001),
		true,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign,
		nil,
		testRootCert, testRootKey)
	testUefiCACert1 = initTestCertificate(
		testUefiCAKey1,
		pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI CA 1",
		},
		big.NewInt(1002),
		true,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign,
		nil,
		testRootCert, testRootKey)
	testUefiSigningCert1_1 = initTestCertificate(
		testUefiSigningKey1_1,
		pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI Secure Boot Signing 1",
		},
		big.NewInt(1),
		false,
		x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		testUefiCACert1, testUefiCAKey1)
	testUefiCACert2 = initTestCertificate(
		testUefiCAKey2,
		pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI CA 2",
		},
		big.NewInt(1003),
		true,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign,
		nil,
		testRootCert, testRootKey)
}
