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

	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/snapd/snapdenv"
	"golang.org/x/xerrors"
)

var (
	snapdenvTesting = snapdenv.Testing
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
type secureBootAuthorityIdentity = internal_efi.SecureBootAuthorityIdentity

// withAuthority adds the specified secure boot authority to a secureBootNamespaceRules.
// Note that this won't match if the specified authority directly signs things.
func withAuthority(subject, subjectKeyId []byte, publicKeyAlgorithm x509.PublicKeyAlgorithm) secureBootNamespaceOption {
	return func(ns *secureBootNamespaceRules) {
		ns.authorities = append(ns.authorities, &secureBootAuthorityIdentity{
			Subject:            subject,
			SubjectKeyId:       subjectKeyId,
			PublicKeyAlgorithm: publicKeyAlgorithm})
	}
}

// withSelfSignedSignerOnlyForTesting adds the specified secure boot authority to a
// secureBootNamespaceRules, only during testing. This also supports the case where the
// specified authority directly signs things. This is used to ensure that binaries signed
// by a production CA that are re-signed during testing by a testing-only CA are still
// detected correctly, in the same way that the production binary would be.
func withSelfSignedSignerOnlyForTesting(subject, subjectKeyId []byte, publicKeyAlgorithm x509.PublicKeyAlgorithm, signatureAlgorithm x509.SignatureAlgorithm) secureBootNamespaceOption {
	if !snapdenvTesting() {
		return func(_ *secureBootNamespaceRules) {}
	}
	return func(ns *secureBootNamespaceRules) {
		ns.authorities = append(ns.authorities, &secureBootAuthorityIdentity{
			Subject:            subject,
			SubjectKeyId:       subjectKeyId,
			PublicKeyAlgorithm: publicKeyAlgorithm,
			Issuer:             subject,
			AuthorityKeyId:     subjectKeyId,
			SignatureAlgorithm: signatureAlgorithm})
	}
}

// withImageRule adds the specified rule to a secureBootNamespaceRules.
func withImageRule(name string, match imagePredicate, create newImageLoadHandlerFn) secureBootNamespaceOption {
	return func(ns *secureBootNamespaceRules) {
		ns.rules = append(ns.rules, newImageRule(name, match, create))
	}
}

// withImageRuleOnlyForTesting adds the specified rule to a secureBootNamespaceRules,
// only during testing.
func withImageRuleOnlyForTesting(name string, match imagePredicate, create newImageLoadHandlerFn) secureBootNamespaceOption {
	if !snapdenvTesting() {
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
		// Avoid adding duplicates. Note that this is only guaranteed to de-duplicate
		// those certificates added via this API, as the built-in certificates only
		// have a minimal set of fields populated and we don't try to handle that case.
		found := false
		for _, authority := range r.authorities {
			if bytes.Equal(authority.Subject, cert.RawSubject) &&
				bytes.Equal(authority.SubjectKeyId, cert.SubjectKeyId) &&
				authority.PublicKeyAlgorithm == cert.PublicKeyAlgorithm &&
				bytes.Equal(authority.Issuer, cert.RawIssuer) &&
				bytes.Equal(authority.AuthorityKeyId, cert.AuthorityKeyId) &&
				authority.SignatureAlgorithm == cert.SignatureAlgorithm {
				found = true
				break
			}
		}
		if !found {
			r.authorities = append(r.authorities, &secureBootAuthorityIdentity{
				Subject:            cert.RawSubject,
				SubjectKeyId:       cert.SubjectKeyId,
				PublicKeyAlgorithm: cert.PublicKeyAlgorithm,
				Issuer:             cert.RawIssuer,
				AuthorityKeyId:     cert.AuthorityKeyId,
				SignatureAlgorithm: cert.SignatureAlgorithm,
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
			RawSubject:         authority.Subject,
			SubjectKeyId:       authority.SubjectKeyId,
			PublicKeyAlgorithm: authority.PublicKeyAlgorithm,
			RawIssuer:          authority.Issuer,
			AuthorityKeyId:     authority.AuthorityKeyId,
			SignatureAlgorithm: authority.SignatureAlgorithm}
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
