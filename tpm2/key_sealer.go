// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2022 Canonical Ltd
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

package tpm2

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/templates"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"
)

// keySealer is an abstraction for creating a sealed key object
type keySealer interface {
	CreateSealedObject(data []byte, nameAlg tpm2.HashAlgorithmId, policy tpm2.Digest) (tpm2.Private, *tpm2.Public, tpm2.EncryptedSecret, error)
}

// sealedObjectKeySealer is an implementation of keySealer that seals keys to
// a TPM.
type sealedObjectKeySealer struct {
	tpm *Connection
}

func (s *sealedObjectKeySealer) CreateSealedObject(data []byte, nameAlg tpm2.HashAlgorithmId, policy tpm2.Digest) (tpm2.Private, *tpm2.Public, tpm2.EncryptedSecret, error) {
	// Obtain a context for the SRK now. If we're called immediately after ProvisionTPM without
	// closing the Connection, we use the context cached by ProvisionTPM, which corresponds to
	// the object provisioned. If not, we just unconditionally provision a new SRK as this function
	// requires knowledge of the owner hierarchy authorization anyway. This way, we know that the
	// primary key we seal to is good and future calls to ProvisionTPM won't provision an object
	// that cannot unseal the key we protect.
	srk := s.tpm.provisionedSrk
	if srk == nil {
		var err error
		srk, err = provisionStoragePrimaryKey(s.tpm.TPMContext, s.tpm.HmacSession())
		switch {
		case isAuthFailError(err, tpm2.AnyCommandCode, 1):
			return nil, nil, nil, AuthFailError{tpm2.HandleOwner}
		case err != nil:
			return nil, nil, nil, xerrors.Errorf("cannot provision storage root key: %w", err)
		}
	}

	// Create the sensitive data
	sensitive := tpm2.SensitiveCreate{Data: data}

	// Define the template
	template := templates.NewSealedObject(nameAlg)
	template.Attrs &^= tpm2.AttrUserWithAuth
	template.AuthPolicy = policy

	// Now create the sealed key object. The command is integrity protected so if the object
	// at the handle we expect the SRK to reside at has a different name (ie, if we're
	// connected via a resource manager and somebody swapped the object with another one), this
	// command will fail.
	priv, pub, _, _, _, err := s.tpm.Create(srk, &sensitive, template, nil, nil,
		s.tpm.HmacSession().IncludeAttrs(tpm2.AttrCommandEncrypt))
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create sealed object: %w", err)
	}
	return priv, pub, nil, err
}

// importableObjectKeySealer is an implementation of keySealer that seals keys to
// a storage key in the form of an importable object.
type importableObjectKeySealer struct {
	tpmKey *tpm2.Public
}

func (s *importableObjectKeySealer) CreateSealedObject(data []byte, nameAlg tpm2.HashAlgorithmId, policy tpm2.Digest) (tpm2.Private, *tpm2.Public, tpm2.EncryptedSecret, error) {
	pub, sensitive := util.NewExternalSealedObject(nameAlg, nil, data)
	pub.Attrs &^= tpm2.AttrUserWithAuth
	pub.AuthPolicy = policy

	// Now create the importable sealed key object (duplication object).
	_, priv, importSymSeed, err := util.CreateDuplicationObjectFromSensitive(sensitive, pub, s.tpmKey, nil, nil)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create duplication object: %w", err)
	}
	return priv, pub, importSymSeed, nil
}
