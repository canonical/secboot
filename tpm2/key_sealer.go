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
	"crypto/rand"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"

	"golang.org/x/xerrors"
)

// keySealer is an abstraction for creating a sealed key object
type keySealer interface {
	// CreateSealedObject creates a new sealed object containing the supplied data
	// and with the specified name algorithm and authorization policy. It returns
	// the private and public parts of the object, and an optional secret value if
	// the returned object has to be imported.
	CreateSealedObject(data []byte, nameAlg tpm2.HashAlgorithmId, policy tpm2.Digest, noDA bool) (tpm2.Private, *tpm2.Public, tpm2.EncryptedSecret, error)
}

// sealedObjectKeySealer is an implementation of keySealer that seals data to
// to the storage primary key of the associated TPM.
type sealedObjectKeySealer struct {
	tpm *Connection
}

func (s *sealedObjectKeySealer) CreateSealedObject(data []byte, nameAlg tpm2.HashAlgorithmId, policy tpm2.Digest, noDA bool) (tpm2.Private, *tpm2.Public, tpm2.EncryptedSecret, error) {
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

	// Begin session for parameter encryption, salted with the SRK.
	symmetric := &tpm2.SymDef{
		Algorithm: tpm2.SymAlgorithmAES,
		KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
		Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB},
	}
	session, err := s.tpm.StartAuthSession(srk, nil, tpm2.SessionTypeHMAC, symmetric, defaultSessionHashAlgorithm, nil)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create session: %w", err)
	}
	defer s.tpm.FlushContext(session)

	// Create the sensitive data
	sensitive := tpm2.SensitiveCreate{Data: data}

	// Define the template
	opts := []objectutil.PublicTemplateOption{
		objectutil.WithNameAlg(nameAlg),
		objectutil.WithUserAuthMode(objectutil.RequirePolicy),
		objectutil.WithAuthPolicy(policy),
	}
	if noDA {
		opts = append(opts, objectutil.WithoutDictionaryAttackProtection())
	} else {
		opts = append(opts, objectutil.WithDictionaryAttackProtection())
	}
	template := objectutil.NewSealedObjectTemplate(opts...)

	// Now create the sealed key object. The command is integrity protected so if the object
	// at the handle we expect the SRK to reside at has a different name (ie, if we're
	// connected via a resource manager and somebody swapped the object with another one), this
	// command will fail.
	priv, pub, _, _, _, err := s.tpm.Create(srk, &sensitive, template, nil, nil, session.WithAttrs(tpm2.AttrCommandEncrypt))
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create sealed object: %w", err)
	}
	return priv, pub, nil, err
}

// importableObjectKeySealer is an implementation of keySealer that seals data to
// an object that can be imported to the hierarchy protected by the specified storage
// key, which should correspond to the TPM's storage primary key. This is suitable in
// environments that don't have access to the TPM but do have access to the public part
// of its storage primary key.
type importableObjectKeySealer struct {
	tpmKey *tpm2.Public
}

func (s *importableObjectKeySealer) CreateSealedObject(data []byte, nameAlg tpm2.HashAlgorithmId, policy tpm2.Digest, noDA bool) (tpm2.Private, *tpm2.Public, tpm2.EncryptedSecret, error) {
	opts := []objectutil.PublicTemplateOption{
		objectutil.WithNameAlg(nameAlg),
		objectutil.WithUserAuthMode(objectutil.RequirePolicy),
		objectutil.WithAuthPolicy(policy),
	}
	if noDA {
		opts = append(opts, objectutil.WithoutDictionaryAttackProtection())
	} else {
		opts = append(opts, objectutil.WithDictionaryAttackProtection())
	}
	pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, data, nil, opts...)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create external sealed object: %w", err)
	}

	// Now create the importable sealed key object (duplication object).
	_, priv, importSymSeed, err := objectutil.CreateImportable(rand.Reader, sensitive, pub, s.tpmKey, nil, nil)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create duplication object: %w", err)
	}
	return priv, pub, importSymSeed, nil
}
