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

package tpm2

import (
	"errors"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/snapcore/secboot"
)

// keyData_v2 represents version 2 of keyData.
type keyData_v2 struct {
	KeyPrivate       tpm2.Private
	KeyPublic        *tpm2.Public
	Unused           uint8 // previously AuthModeHint
	KeyImportSymSeed tpm2.EncryptedSecret
	PolicyData       *keyDataPolicy_v2
}

func readKeyDataV2(r io.Reader) (keyData, error) {
	var d *keyData_v2
	if _, err := mu.UnmarshalFromReader(r, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *keyData_v2) AsV1() keyData {
	if d.KeyImportSymSeed != nil {
		panic("importable object cannot be converted to v1")
	}
	return &keyData_v1{
		KeyPrivate: d.KeyPrivate,
		KeyPublic:  d.KeyPublic,
		PolicyData: d.PolicyData}
}

func (d *keyData_v2) Version() uint32 {
	if d.KeyImportSymSeed == nil {
		// The only difference between v1 and v2 is support for
		// importable objects. Pretend to be v1 if the object
		// doesn't need importing.
		return 1
	}
	return 2
}

func (d *keyData_v2) Private() tpm2.Private {
	return d.KeyPrivate
}

func (d *keyData_v2) SetPrivate(priv tpm2.Private) {
	panic("not supported")
}

func (d *keyData_v2) Public() *tpm2.Public {
	return d.KeyPublic
}

func (d *keyData_v2) ImportSymSeed() tpm2.EncryptedSecret {
	return d.KeyImportSymSeed
}

func (d *keyData_v2) Imported(priv tpm2.Private) {
	if d.KeyImportSymSeed == nil {
		panic("does not need to be imported")
	}
	d.KeyPrivate = priv
	d.KeyImportSymSeed = nil
}

func (d *keyData_v2) ValidateData(tpm *tpm2.TPMContext, role []byte, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	if d.KeyImportSymSeed != nil {
		return nil, errors.New("cannot validate importable key data")
	}
	return d.AsV1().ValidateData(tpm, role, session)
}

func (d *keyData_v2) Write(w io.Writer) error {
	if d.KeyImportSymSeed == nil {
		// The only difference between v1 and v2 is support for
		// importable objects. Implicitly downgrade to v1 on write
		// if the object doesn't need importing.
		return d.AsV1().Write(w)
	}

	_, err := mu.MarshalToWriter(w, d)
	return err
}

func (d *keyData_v2) Policy() keyDataPolicy {
	return d.PolicyData
}

func (d *keyData_v2) Decrypt(key, payload []byte, baseVersion uint32, kdfAlg tpm2.HashAlgorithmId, authMode secboot.AuthMode) ([]byte, error) {
	return nil, errors.New("not supported")
}
