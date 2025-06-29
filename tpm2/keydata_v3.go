// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2023 Canonical Ltd
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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/policyutil"
	"github.com/snapcore/secboot"

	"golang.org/x/xerrors"
)

type additionalData_v3 struct {
	Generation uint32
	Role       []byte
	KDFAlg     tpm2.HashAlgorithmId
	AuthMode   secboot.AuthMode
}

func (d additionalData_v3) Marshal(w io.Writer) error {
	_, err := mu.MarshalToWriter(w,
		uint32(3), // The TPM2 platform keydata version
		d.Generation, d.Role, d.KDFAlg, d.AuthMode)
	return err
}

func (d *additionalData_v3) Unmarshal(r io.Reader) error {
	return errors.New("not supported")
}

// keyData_v3 represents version 3 of keyData.
type keyData_v3 struct {
	KeyPrivate       tpm2.Private
	KeyPublic        *tpm2.Public
	KeyImportSymSeed tpm2.EncryptedSecret
	PolicyData       *keyDataPolicy_v3
}

func readKeyDataV3(r io.Reader) (keyData, error) {
	var d *keyData_v3
	if _, err := mu.UnmarshalFromReader(r, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *keyData_v3) Version() uint32 {
	return 3
}

func (d *keyData_v3) Private() tpm2.Private {
	return d.KeyPrivate
}

func (d *keyData_v3) SetPrivate(priv tpm2.Private) {
	d.KeyPrivate = priv
}

func (d *keyData_v3) Public() *tpm2.Public {
	return d.KeyPublic
}

func (d *keyData_v3) ImportSymSeed() tpm2.EncryptedSecret {
	return d.KeyImportSymSeed
}

func (d *keyData_v3) Imported(priv tpm2.Private) {
	if d.KeyImportSymSeed == nil {
		panic("does not need to be imported")
	}
	d.KeyPrivate = priv
	d.KeyImportSymSeed = nil
}

func (d *keyData_v3) ValidateData(tpm *tpm2.TPMContext, role []byte) (tpm2.ResourceContext, error) {
	if d.KeyImportSymSeed != nil {
		return nil, errors.New("cannot validate importable key data")
	}

	// Validate the type and scheme of the dynamic authorization policy signing key.
	authPublicKey := d.PolicyData.StaticData.AuthPublicKey
	if authPublicKey.Type != tpm2.ObjectTypeECC {
		return nil, keyDataError{errors.New("public area of dynamic authorization policy signing key has the wrong type")}
	}
	authKeyScheme := authPublicKey.AsymDetail().Scheme
	if authKeyScheme.Scheme != tpm2.AsymSchemeNull {
		if authKeyScheme.Scheme != tpm2.AsymSchemeECDSA {
			return nil, keyDataError{errors.New("dynamic authorization policy signing key has unexpected scheme")}
		}
		if authKeyScheme.AnyDetails().HashAlg != authPublicKey.NameAlg {
			return nil, keyDataError{errors.New("dynamic authorization policy signing key algorithm must match name algorithm")}
		}
	}

	// Create a context for the PCR policy counter.
	pcrPolicyCounterHandle := d.PolicyData.StaticData.PCRPolicyCounterHandle
	var pcrPolicyCounter tpm2.ResourceContext
	switch {
	case pcrPolicyCounterHandle != tpm2.HandleNull && pcrPolicyCounterHandle.Type() != tpm2.HandleTypeNVIndex:
		return nil, keyDataError{errors.New("PCR policy counter handle is invalid")}
	case pcrPolicyCounterHandle != tpm2.HandleNull:
		var err error
		pcrPolicyCounter, err = tpm.NewResourceContext(pcrPolicyCounterHandle)
		if err != nil {
			if tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle) {
				return nil, keyDataError{errors.New("PCR policy counter is unavailable")}
			}
			return nil, xerrors.Errorf("cannot create context for PCR policy counter: %w", err)
		}
	}

	// Make sure the saved PCR policy ref matches what we expect
	if !authPublicKey.NameAlg.Available() {
		return nil, keyDataError{fmt.Errorf("name algorithm for signing key is invalid or not available: %v", authPublicKey.NameAlg)}
	}
	pcrPolicyRef := computeV3PcrPolicyRefFromCounterContext(authPublicKey.NameAlg, role, pcrPolicyCounter)
	// We don't check p.PolicyData.StaticData.PCRPolicyRef here because it gets updated
	// in UpdatePCRProtectionPolicy.

	// Make sure that the static authorization policy data is consistent with the sealed key object's policy.
	if !d.KeyPublic.NameAlg.Available() {
		return nil, keyDataError{fmt.Errorf("cannot determine if static authorization policy matches sealed key object: algorithm %v unavailable", d.KeyPublic.NameAlg)}
	}
	builder := policyutil.NewPolicyBuilder(d.KeyPublic.NameAlg)
	builder.RootBranch().PolicyAuthorize(pcrPolicyRef, authPublicKey)
	if d.PolicyData.StaticData.RequireAuthValue {
		builder.RootBranch().PolicyAuthValue()
	}
	expectedDigest, err := builder.Digest()
	if err != nil {
		return nil, keyDataError{fmt.Errorf("cannot compute expected static authorization policy digest: %w", err)}
	}

	if !bytes.Equal(expectedDigest, d.KeyPublic.AuthPolicy) {
		return nil, keyDataError{errors.New("the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")}
	}

	return pcrPolicyCounter, nil
}

func (d *keyData_v3) Write(w io.Writer) error {
	_, err := mu.MarshalToWriter(w, d)
	return err
}

func (d *keyData_v3) Policy() keyDataPolicy {
	return d.PolicyData
}

func (d *keyData_v3) Decrypt(key, payload []byte, generation uint32, role []byte, kdfAlg tpm2.HashAlgorithmId, authMode secboot.AuthMode) ([]byte, error) {
	// We only support AES-256-GCM with a 12-byte nonce, so we expect 44 bytes here
	if len(key) != 32+12 {
		return nil, errors.New("invalid symmetric key size")
	}

	aad, err := mu.MarshalToBytes(&additionalData_v3{
		Generation: generation,
		Role:       role,
		KDFAlg:     kdfAlg,
		AuthMode:   authMode,
	})
	if err != nil {
		return nil, xerrors.Errorf("cannot create AAD: %w", err)
	}

	b, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, xerrors.Errorf("cannot create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(b)
	if err != nil {
		return nil, xerrors.Errorf("cannot create AEAD cipher: %w", err)
	}

	return aead.Open(nil, key[32:], payload, aad)
}
