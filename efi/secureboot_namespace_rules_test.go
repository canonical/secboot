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
	"crypto/x509"
	"errors"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type secureBootNamespaceRulesSuite struct{}

var _ = Suite(&secureBootNamespaceRulesSuite{})

func (s *secureBootNamespaceRulesSuite) TestRulesMatch1(c *C) {
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)).newPeImageHandle()

	cert := testutil.ParseCertificate(c, msUefiCACert)

	rules := NewSecureBootNamespaceRules(
		"test",
		WithAuthority(cert.RawSubject, cert.SubjectKeyId, cert.PublicKeyAlgorithm),
		WithImageRule(
			"rule1",
			&mockImagePredicate{result: true},
			func(i PeImageHandle) (ImageLoadHandler, error) {
				c.Check(i, Equals, image)

				return newMockLoadHandler(), nil
			},
		),
	)
	handler, err := rules.NewImageLoadHandler(image)
	c.Check(err, IsNil)
	c.Check(handler, DeepEquals, newMockLoadHandler())
}

func (s *secureBootNamespaceRulesSuite) TestRulesMatch2(c *C) {
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)
	image := newMockImage().withDigest(sig.DigestAlgorithm(), sig.Digest()).sign(c, testutil.ParsePKCS1PrivateKey(c, testUefiSigningKey1_1), testutil.ParseCertificate(c, testUefiSigningCert1_1)).appendSignatures(sig).newPeImageHandle()

	cert := testutil.ParseCertificate(c, msUefiCACert)

	rules := NewSecureBootNamespaceRules(
		"test",
		WithAuthority(cert.RawSubject, cert.SubjectKeyId, cert.PublicKeyAlgorithm),
		WithImageRule(
			"rule1",
			&mockImagePredicate{result: true},
			func(i PeImageHandle) (ImageLoadHandler, error) {
				c.Check(i, Equals, image)

				return newMockLoadHandler(), nil
			},
		),
	)
	handler, err := rules.NewImageLoadHandler(image)
	c.Check(err, IsNil)
	c.Check(handler, DeepEquals, newMockLoadHandler())
}

func (s *secureBootNamespaceRulesSuite) TestRulesMatch3(c *C) {
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)
	image := newMockImage().withDigest(sig.DigestAlgorithm(), sig.Digest()).sign(c, testutil.ParsePKCS1PrivateKey(c, testUefiSigningKey1_1), testutil.ParseCertificate(c, testUefiSigningCert1_1)).newPeImageHandle()

	cert := testutil.ParseCertificate(c, testUefiCACert1)

	rules := NewSecureBootNamespaceRules(
		"test",
		WithAuthority(cert.RawSubject, cert.SubjectKeyId, cert.PublicKeyAlgorithm),
		WithImageRule(
			"rule1",
			&mockImagePredicate{result: true},
			func(i PeImageHandle) (ImageLoadHandler, error) {
				c.Check(i, Equals, image)

				return newMockLoadHandler(), nil
			},
		),
	)
	handler, err := rules.NewImageLoadHandler(image)
	c.Check(err, IsNil)
	c.Check(handler, DeepEquals, newMockLoadHandler())
}

func (s *secureBootNamespaceRulesSuite) TestRulesNoMatch1(c *C) {
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)
	image := newMockImage().withDigest(sig.DigestAlgorithm(), sig.Digest()).sign(c, testutil.ParsePKCS1PrivateKey(c, testUefiSigningKey1_1), testutil.ParseCertificate(c, testUefiSigningCert1_1)).newPeImageHandle()

	cert := testutil.ParseCertificate(c, msUefiCACert)

	rules := NewSecureBootNamespaceRules(
		"test",
		WithAuthority(cert.RawSubject, cert.SubjectKeyId, cert.PublicKeyAlgorithm),
		WithImageRule(
			"rule1",
			&mockImagePredicate{result: true},
			func(i PeImageHandle) (ImageLoadHandler, error) {
				return nil, errors.New("not reached")
			},
		),
	)
	_, err := rules.NewImageLoadHandler(image)
	c.Check(err, Equals, ErrNoHandler)
}

func (s *secureBootNamespaceRulesSuite) TestRulesNoMatch2(c *C) {
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)).newPeImageHandle()

	cert := testutil.ParseCertificate(c, msUefiCACert)

	rules := NewSecureBootNamespaceRules(
		"test",
		WithAuthority(cert.RawSubject, cert.SubjectKeyId, cert.PublicKeyAlgorithm),
		WithImageRule(
			"rule1",
			new(mockImagePredicate),
			func(i PeImageHandle) (ImageLoadHandler, error) {
				return nil, errors.New("not reached")
			},
		),
	)
	_, err := rules.NewImageLoadHandler(image)
	c.Check(err, Equals, ErrNoHandler)
}

func (s *secureBootNamespaceRulesSuite) TestRulesNoMatch3(c *C) {
	image := newMockImage().newPeImageHandle()

	cert := testutil.ParseCertificate(c, msUefiCACert)

	rules := NewSecureBootNamespaceRules(
		"test",
		WithAuthority(cert.RawSubject, cert.SubjectKeyId, cert.PublicKeyAlgorithm),
		WithImageRule(
			"rule1",
			new(mockImagePredicate),
			func(i PeImageHandle) (ImageLoadHandler, error) {
				return nil, errors.New("not reached")
			},
		),
	)
	_, err := rules.NewImageLoadHandler(image)
	c.Check(err, Equals, ErrNoHandler)
}

type mockLoadHandlerWithVendorAuthorities struct {
	*mockLoadHandler
	vendorCerts []*x509.Certificate
}

func (h *mockLoadHandlerWithVendorAuthorities) VendorAuthorities() ([]*x509.Certificate, error) {
	return h.vendorCerts, nil
}

func (s *secureBootNamespaceRulesSuite) TestAddAuthorities(c *C) {
	cert := testutil.ParseCertificate(c, msUefiCACert)
	rules := NewSecureBootNamespaceRules(
		"test",
		WithAuthority(cert.RawSubject, cert.SubjectKeyId, cert.PublicKeyAlgorithm),
		WithImageRule(
			"rule1",
			&mockImagePredicate{result: true},
			func(i PeImageHandle) (ImageLoadHandler, error) {
				return &mockLoadHandlerWithVendorAuthorities{
					newMockLoadHandler(),
					[]*x509.Certificate{testutil.ParseCertificate(c, canonicalCACert)},
				}, nil
			},
		),
	)

	expected := &mockLoadHandlerWithVendorAuthorities{
		newMockLoadHandler(),
		[]*x509.Certificate{testutil.ParseCertificate(c, canonicalCACert)},
	}

	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)).newPeImageHandle()
	handler, err := rules.NewImageLoadHandler(image)
	c.Check(err, IsNil)
	c.Check(handler, DeepEquals, expected)

	image = newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)).newPeImageHandle()
	handler, err = rules.NewImageLoadHandler(image)
	c.Check(err, IsNil)
	c.Check(handler, DeepEquals, expected)
}
