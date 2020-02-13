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

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

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

	expectedQualifiedName, _ := tpm2.MarshalToBytes(pub.NameAlg, h.Sum(nil))
	if !bytes.Equal(expectedQualifiedName, qualifiedName) {
		return false, nil
	}

	return true, nil
}
