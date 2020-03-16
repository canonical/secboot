// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package secboot

import (
	"bytes"
	"crypto/rsa"
	"fmt"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

// isResourceUnavailableError indicates whether the specified error is tpm2.ResourceUnavailableError
func isResourceUnavailableError(err error) bool {
	var e tpm2.ResourceUnavailableError
	return xerrors.As(err, &e)
}

// isAuthFailError indicates whether the specified error is a TPM authorization check failure, with or without DA implications.
func isAuthFailError(err error) bool {
	var sessionErr *tpm2.TPMSessionError
	if !xerrors.As(err, &sessionErr) {
		return false
	}
	switch sessionErr.Code() {
	case tpm2.ErrorAuthFail: // With DA implications
		return true
	case tpm2.ErrorBadAuth: // Without DA implications
		return true
	}
	return false
}

// isLockoutError indicates whether the specific error is a TPM lockout failure.
func isLockoutError(err error) bool {
	var warning *tpm2.TPMWarning
	return xerrors.As(err, &warning) && warning.Code == tpm2.WarningLockout
}

type nvIndexDefinedError struct {
	handle tpm2.Handle
}

func (e *nvIndexDefinedError) Error() string {
	return fmt.Sprintf("NV index defined at 0x%08x", e.handle)
}

// isNVIndexDefinedWithHandleError indicates whether the specified error is a *nvIndexDefinedError.
func isNVIndexDefinedWithHandleError(err error) bool {
	var e *nvIndexDefinedError
	return xerrors.As(err, &e)
}

// isNVIndexDefinedError indicates whether the specified error is a TPM error indicating that it tried to create a NV resource
// at a handle that is already in use.
func isNVIndexDefinedError(err error) bool {
	var tpmErr *tpm2.TPMError
	return xerrors.As(err, &tpmErr) && tpmErr.Code == tpm2.ErrorNVDefined
}

// isObjectPrimaryKeyWithTemplate checks whether the object associated with context is primary key in the specified hierarchy with
// the specified template.
//
// This isn't completely accurate as the unique field of the template is used to seed the primary object, and this function can't
// detect if the unique field of the specified template was actually used to create the object. As a consequnce, it should be used
// with caution. This function returning true is no guarantee that recreating the object with the specified template would create
// the same object.
func isObjectPrimaryKeyWithTemplate(tpm *tpm2.TPMContext, hierarchy, object tpm2.ResourceContext, template *tpm2.Public,
	session tpm2.SessionContext) (bool, error) {
	if session != nil {
		session = session.IncludeAttrs(tpm2.AttrAudit)
	}

	pub, _, qualifiedName, err := tpm.ReadPublic(object, session)
	if err != nil {
		var he *tpm2.TPMHandleError
		if xerrors.As(err, &he) && he.Code() == tpm2.ErrorHandle {
			return false, nil
		}
		return false, xerrors.Errorf("cannot read public area of object: %w", err)
	}

	pub.Unique = template.Unique

	pubBytes, _ := tpm2.MarshalToBytes(pub)
	templateBytes, _ := tpm2.MarshalToBytes(template)
	if !bytes.Equal(pubBytes, templateBytes) {
		// For RSA keys, the default exponent (2^^16 - 1) is normally indicated by the value 0, but handle a TPM that actually
		// returns 65537 by trying again.
		if template.Type == tpm2.ObjectTypeRSA && template.Params.RSADetail().Exponent == 0 {
			var templateCopy *tpm2.Public
			tpm2.UnmarshalFromBytes(templateBytes, &templateCopy)
			templateCopy.Params.RSADetail().Exponent = 65537
			templateBytes, _ = tpm2.MarshalToBytes(templateCopy)
			if !bytes.Equal(pubBytes, templateBytes) {
				return false, nil
			}
		} else {
			return false, nil
		}
	}

	// Determine if this is a primary key by validating its qualified name. From the spec, the qualified name
	// of key B (QNb) which is a child of key A is QNb = Hb(QNa || NAMEb). Key A in this case should be
	// the storage primary seed, which has a qualified name matching its name (and the name is the handle
	// for the storage hierarchy)
	h := pub.NameAlg.NewHash()
	h.Write(hierarchy.Name())
	h.Write(object.Name())

	expectedQualifiedName, _ := tpm2.MarshalToBytes(pub.NameAlg, tpm2.RawBytes(h.Sum(nil)))
	if !bytes.Equal(expectedQualifiedName, qualifiedName) {
		return false, nil
	}

	return true, nil
}

// createPublicAreaForRSASigningKey creates a *tpm2.Public from a go *rsa.PublicKey, which is suitable for loading
// in to a TPM with TPMContext.LoadExternal.
func createPublicAreaForRSASigningKey(key *rsa.PublicKey) *tpm2.Public {
	return &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:   uint16(key.N.BitLen()),
				Exponent:  uint32(key.E)}},
		Unique: tpm2.PublicIDU{Data: tpm2.PublicKeyRSA(key.N.Bytes())}}
}

// digestListContains indicates whether the specified digest is present in the list of digests.
func digestListContains(list tpm2.DigestList, digest tpm2.Digest) bool {
	for _, d := range list {
		if bytes.Equal(d, digest) {
			return true
		}
	}
	return false
}
