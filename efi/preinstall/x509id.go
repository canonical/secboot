// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package preinstall

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
)

type x509CertificateIdJSON struct {
	Subject            []byte `json:"subject"`
	SubjectKeyId       []byte `json:"subject-key-id"`
	PublicKeyAlgorithm string `json:"pubkey-algorithm"`

	Issuer             []byte `json:"issuer"`
	AuthorityKeyId     []byte `json:"authority-key-id"`
	SignatureAlgorithm string `json:"signature-algorithm"`
}

func newX509CertificateIdJSON(cert *X509CertificateID) (*x509CertificateIdJSON, error) {
	out := &x509CertificateIdJSON{
		Subject:        cert.subject,
		SubjectKeyId:   cert.subjectKeyId,
		Issuer:         cert.issuer,
		AuthorityKeyId: cert.authorityKeyId,
	}

	switch cert.publicKeyAlgorithm {
	case x509.RSA:
		out.PublicKeyAlgorithm = "RSA"
	default:
		return nil, fmt.Errorf("unrecognized public key algorithm %q", cert.publicKeyAlgorithm)
	}

	switch cert.signatureAlgorithm {
	case x509.SHA256WithRSA:
		out.SignatureAlgorithm = "SHA256-RSA"
	case x509.SHA384WithRSA:
		out.SignatureAlgorithm = "SHA384-RSA"
	case x509.SHA512WithRSA:
		out.SignatureAlgorithm = "SHA512-RSA"
	case x509.SHA256WithRSAPSS:
		out.SignatureAlgorithm = "SHA256-RSAPSS"
	case x509.SHA384WithRSAPSS:
		out.SignatureAlgorithm = "SHA384-RSAPSS"
	case x509.SHA512WithRSAPSS:
		out.SignatureAlgorithm = "SHA512-RSAPSS"
	default:
		return nil, fmt.Errorf("unrecognized signature algorithm %v", cert.signatureAlgorithm)
	}

	return out, nil
}

func (id *x509CertificateIdJSON) toPublic() (*X509CertificateID, error) {
	out := &X509CertificateID{
		subject:        id.Subject,
		subjectKeyId:   id.SubjectKeyId,
		issuer:         id.Issuer,
		authorityKeyId: id.AuthorityKeyId,
	}

	switch id.PublicKeyAlgorithm {
	case "RSA":
		out.publicKeyAlgorithm = x509.RSA
	default:
		return nil, fmt.Errorf("unrecognized public key algorithm %q", id.PublicKeyAlgorithm)
	}

	switch id.SignatureAlgorithm {
	case "SHA256-RSA":
		out.signatureAlgorithm = x509.SHA256WithRSA
	case "SHA384-RSA":
		out.signatureAlgorithm = x509.SHA384WithRSA
	case "SHA512-RSA":
		out.signatureAlgorithm = x509.SHA512WithRSA
	case "SHA256-RSAPSS":
		out.signatureAlgorithm = x509.SHA256WithRSAPSS
	case "SHA384-RSAPSS":
		out.signatureAlgorithm = x509.SHA384WithRSAPSS
	case "SHA512-RSAPSS":
		out.signatureAlgorithm = x509.SHA512WithRSAPSS
	default:
		return nil, fmt.Errorf("unrecognized signature algorithm %q", id.SignatureAlgorithm)
	}

	return out, nil
}

// X509CertificateID corresponds to the identity of a X.509 certificate.
// It is JSON serializable and avoids the need to persist an entire certificate
// when we only use the parts that identify it.
type X509CertificateID struct {
	subject            []byte
	subjectKeyId       []byte
	publicKeyAlgorithm x509.PublicKeyAlgorithm

	issuer             []byte
	authorityKeyId     []byte
	signatureAlgorithm x509.SignatureAlgorithm
}

func newX509CertificateID(cert *x509.Certificate) *X509CertificateID {
	return &X509CertificateID{
		subject:            cert.RawSubject,
		subjectKeyId:       cert.SubjectKeyId,
		publicKeyAlgorithm: cert.PublicKeyAlgorithm,
		issuer:             cert.RawIssuer,
		authorityKeyId:     cert.AuthorityKeyId,
		signatureAlgorithm: cert.SignatureAlgorithm,
	}
}

// Subject returns the readable form of the certificate's subject.
func (id *X509CertificateID) Subject() pkix.Name {
	rdns, err := parseName(id.subject)
	if err != nil {
		return pkix.Name{}
	}

	var res pkix.Name
	res.FillFromRDNSequence(rdns)
	return res
}

// RawSubject returns the certificate's raw DER encoded subject.
// It implements [github.com/canonical/go-efilib.X509CertID.RawSubject].
func (id *X509CertificateID) RawSubject() []byte {
	return id.subject
}

// SubjectKeyID returns the ID of the subject's public key. It implements
// [github.com/canonical/go-efilib.X509CertID.SubjectKeyID].
func (id *X509CertificateID) SubjectKeyId() []byte {
	return id.subjectKeyId
}

// PublicKeyAlgorithm returns the algorithm of the public key. It implements
// [github.com/canonical/go-efilib.X509CertID.PublicKeyAlgorithm].
func (id *X509CertificateID) PublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	return id.publicKeyAlgorithm
}

// Issuer returns the readable form of the certificate's issuer.
func (id *X509CertificateID) Issuer() pkix.Name {
	rdns, err := parseName(id.issuer)
	if err != nil {
		return pkix.Name{}
	}

	var res pkix.Name
	res.FillFromRDNSequence(rdns)
	return res
}

// RawIssuer returns the certificate's raw DER encoded issuer.
// It implements [github.com/canonical/go-efilib.X509CertID.RawIssuer].
func (id *X509CertificateID) RawIssuer() []byte {
	return id.issuer
}

// AuthorityKeyID returns the ID of the issuer's public key. It implements
// [github.com/canonical/go-efilib.X509CertID.AuthorityKeyID].
func (id *X509CertificateID) AuthorityKeyId() []byte {
	return id.authorityKeyId
}

// SignatureAlgorithm indicates the algorithm that the issuer used
// to sign the subject certificate. It implements
// [github.com/canonical/go-efilib.X509CertID.SignatureAlgorithm].
func (id *X509CertificateID) SignatureAlgorithm() x509.SignatureAlgorithm {
	return id.signatureAlgorithm
}

// MarshalJSON implements [json.Marshaler].
func (id X509CertificateID) MarshalJSON() ([]byte, error) {
	j, err := newX509CertificateIdJSON(&id)
	if err != nil {
		return nil, fmt.Errorf("cannot encode X509CertificateID: %w", err)
	}
	return json.Marshal(j)
}

// UnmarshalJSON implements [json.Unmarshaler].
func (id *X509CertificateID) UnmarshalJSON(data []byte) error {
	var j *x509CertificateIdJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	pub, err := j.toPublic()
	if err != nil {
		return fmt.Errorf("cannot decode X509CertificateID: %w", err)
	}

	*id = *pub
	return nil
}
