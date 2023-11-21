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

package efi

import (
	"bytes"
	"crypto/x509"

	"github.com/snapcore/snapd/snapdenv"
	"golang.org/x/xerrors"
)

// vendorAuthorityGetter provides a way for an imageLoadHandler created by
// secureBootNamespaceRules to supplement the CA's associated with a secure
// boot namespace in the case where the associated image contains a delegated
// signing authority (eg, shim's vendor certificate). This allows the extra
// authorities to become part of the same namespace and permits components
// signed by these extra authorities to be recognized by the same set of
// rules without having to embed multiple certificates.
type vendorAuthorityGetter interface {
	VendorAuthorities() ([]*x509.Certificate, error)
}

// secureBootAuthorityIdentity corresponds to the identify of a secure boot
// authority. A secure boot namespace has one or more of these.
type secureBootAuthorityIdentity struct {
	subject            []byte
	subjectKeyId       []byte
	publicKeyAlgorithm x509.PublicKeyAlgorithm

	issuer             []byte
	authorityKeyId     []byte
	signatureAlgorithm x509.SignatureAlgorithm
}

// withAuthority adds the specified secure boot authority to a secureBootNamespaceRules.
func withAuthority(subject, subjectKeyId []byte, publicKeyAlgorithm x509.PublicKeyAlgorithm) secureBootNamespaceOption {
	return func(ns *secureBootNamespaceRules) {
		ns.authorities = append(ns.authorities, &secureBootAuthorityIdentity{
			subject:            subject,
			subjectKeyId:       subjectKeyId,
			publicKeyAlgorithm: publicKeyAlgorithm})
	}
}

// withSigner adds the specified secure boot authority to a secureBootNamespaceRules,
// only during testing.
func withSelfSignedSignerOnlyForTesting(subject, subjectKeyId []byte, publicKeyAlgorithm x509.PublicKeyAlgorithm, signatureAlgorithm x509.SignatureAlgorithm) secureBootNamespaceOption {
	if !snapdenv.Testing() {
		return func(_ *secureBootNamespaceRules) {}
	}
	return func(ns *secureBootNamespaceRules) {
		ns.authorities = append(ns.authorities, &secureBootAuthorityIdentity{
			subject:            subject,
			subjectKeyId:       subjectKeyId,
			publicKeyAlgorithm: publicKeyAlgorithm,
			issuer:             subject,
			authorityKeyId:     subjectKeyId,
			signatureAlgorithm: signatureAlgorithm})
	}
}

// withImageRule adds the specified rule to a secureBootNamespaceRules.
func withImageRule(name string, match imagePredicate, create newImageLoadHandlerFn) secureBootNamespaceOption {
	return func(ns *secureBootNamespaceRules) {
		ns.rules = append(ns.rules, newImageRule(name, match, create))
	}
}

// withImageRule adds the specified rule to a secureBootNamespaceRules,
// only during testing.
func withImageRuleOnlyForTesting(name string, match imagePredicate, create newImageLoadHandlerFn) secureBootNamespaceOption {
	if !snapdenv.Testing() {
		return func(_ *secureBootNamespaceRules) {}
	}
	return withImageRule(name, match, create)
}

type secureBootNamespaceOption func(*secureBootNamespaceRules)

// secureBootNamespaceRules is used to construct an imageLoadHandler from a
// peImageHandle using a set of rules that are scoped to a secure boot
// hierarchy.
type secureBootNamespaceRules struct {
	authorities []*secureBootAuthorityIdentity
	*imageRules
}

// newSecureBootNamespaceRules constructs a secure boot namespace with the specified
// options.
func newSecureBootNamespaceRules(name string, options ...secureBootNamespaceOption) *secureBootNamespaceRules {
	out := &secureBootNamespaceRules{
		imageRules: newImageRules(name + " secure boot namespace"),
	}
	for _, option := range options {
		option(out)
	}
	return out
}

func (r *secureBootNamespaceRules) AddAuthorities(certs ...*x509.Certificate) {
	for _, cert := range certs {
		found := false
		for _, authority := range r.authorities {
			if bytes.Equal(authority.subject, cert.RawSubject) &&
				bytes.Equal(authority.subjectKeyId, cert.SubjectKeyId) &&
				authority.publicKeyAlgorithm == cert.PublicKeyAlgorithm &&
				bytes.Equal(authority.issuer, cert.RawIssuer) &&
				bytes.Equal(authority.authorityKeyId, cert.AuthorityKeyId) &&
				authority.signatureAlgorithm == cert.SignatureAlgorithm {
				found = true
				break
			}
		}
		if !found {
			r.authorities = append(r.authorities, &secureBootAuthorityIdentity{
				subject:            cert.RawSubject,
				subjectKeyId:       cert.SubjectKeyId,
				publicKeyAlgorithm: cert.PublicKeyAlgorithm,
				issuer:             cert.RawIssuer,
				authorityKeyId:     cert.AuthorityKeyId,
				signatureAlgorithm: cert.SignatureAlgorithm,
			})
		}
	}
}

func (r *secureBootNamespaceRules) NewImageLoadHandler(image peImageHandle) (imageLoadHandler, error) {
	// This may return no signatures, but that's ok - in the case, we just return
	// errNoHandler.
	sigs, err := image.SecureBootSignatures()
	if err != nil {
		// Reject any image with a badly formed security directory entry
		return nil, xerrors.Errorf("cannot obtain secure boot signatures: %w", err)
	}

	for _, authority := range r.authorities {
		cert := &x509.Certificate{
			RawSubject:         authority.subject,
			SubjectKeyId:       authority.subjectKeyId,
			PublicKeyAlgorithm: authority.publicKeyAlgorithm,
			RawIssuer:          authority.issuer,
			AuthorityKeyId:     authority.authorityKeyId,
			SignatureAlgorithm: authority.signatureAlgorithm}
		for _, sig := range sigs {
			if !sig.CertLikelyTrustAnchor(cert) {
				continue
			}

			handler, err := r.imageRules.NewImageLoadHandler(image)
			if err != nil {
				return nil, err
			}

			if v, ok := handler.(vendorAuthorityGetter); ok {
				certs, err := v.VendorAuthorities()
				if err != nil {
					return nil, xerrors.Errorf("cannot obtain vendor authorities: %w", err)
				}
				r.AddAuthorities(certs...)
			}

			return handler, nil
		}
	}

	return nil, errNoHandler
}
