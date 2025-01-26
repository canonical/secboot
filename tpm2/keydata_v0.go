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
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/policyutil"
	"github.com/snapcore/secboot"

	"golang.org/x/xerrors"
)

const keyPolicyUpdateDataHeader uint32 = 0x55534b50

// keyPolicyUpdateData_v0 corresponds to the private part of a sealed key object that is required in order to create new dynamic
// authorization policies.
type keyPolicyUpdateData_v0 struct {
	AuthKey        []byte
	CreationData   *tpm2.CreationData // unused
	CreationTicket *tpm2.TkCreation   // unused
}

// decodeKeyPolicyUpdateData deserializes keyPolicyUpdateData_v0 from the provided io.Reader.
func decodeKeyPolicyUpdateData(r io.Reader) (*keyPolicyUpdateData_v0, error) {
	var header uint32
	var version uint32
	if _, err := mu.UnmarshalFromReader(r, &header, &version); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal header: %w", err)
	}
	if header != keyPolicyUpdateDataHeader {
		return nil, fmt.Errorf("unexpected header (%d)", header)
	}
	if version != 0 {
		return nil, fmt.Errorf("unexpected version number (%d)", version)
	}

	var d keyPolicyUpdateData_v0
	if _, err := mu.UnmarshalFromReader(r, &d); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal data: %w", err)
	}

	return &d, nil
}

// keyData_v0 represents version 0 of keyData
type keyData_v0 struct {
	KeyPrivate tpm2.Private
	KeyPublic  *tpm2.Public
	Unused     uint8 // previously AuthModeHint
	PolicyData *keyDataPolicy_v0
}

func readKeyDataV0(r io.Reader) (keyData, error) {
	var d *keyData_v0
	if _, err := mu.UnmarshalFromReader(r, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func (_ *keyData_v0) Version() uint32 { return 0 }

func (d *keyData_v0) Private() tpm2.Private {
	return d.KeyPrivate
}

func (d *keyData_v0) SetPrivate(priv tpm2.Private) {
	panic("not supported")
}

func (d *keyData_v0) Public() *tpm2.Public {
	return d.KeyPublic
}

func (_ *keyData_v0) ImportSymSeed() tpm2.EncryptedSecret { return nil }

func (_ *keyData_v0) Imported(_ tpm2.Private) {
	panic("not supported")
}

func (d *keyData_v0) ValidateData(tpm *tpm2.TPMContext, role []byte) (tpm2.ResourceContext, error) {
	if len(role) > 0 {
		return nil, errors.New("unexpected role")
	}

	// Obtain the name of the legacy lock NV index.
	lockNV, err := tpm.NewResourceContext(lockNVHandle)
	if err != nil {
		if tpm2.IsResourceUnavailableError(err, lockNVHandle) {
			return nil, keyDataError{errors.New("lock NV index is unavailable")}
		}
		return nil, xerrors.Errorf("cannot create context for lock NV index: %w", err)
	}
	lockNVPub, _, err := tpm.NVReadPublic(lockNV)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of lock NV index: %w", err)
	}
	lockNVPub.Attrs &^= tpm2.AttrNVReadLocked

	// Validate the type and scheme of the dynamic authorization policy signing key.
	authPublicKey := d.PolicyData.StaticData.AuthPublicKey
	if authPublicKey.Type != tpm2.ObjectTypeRSA {
		return nil, keyDataError{errors.New("public area of dynamic authorization policy signing key has the wrong type")}
	}
	authKeyScheme := authPublicKey.AsymDetail().Scheme
	if authKeyScheme.Scheme != tpm2.AsymSchemeNull {
		if authKeyScheme.Scheme != tpm2.AsymSchemeRSAPSS {
			return nil, keyDataError{errors.New("dynamic authorization policy signing key has unexpected scheme")}
		}
		if authKeyScheme.AnyDetails().HashAlg != authPublicKey.NameAlg {
			return nil, keyDataError{errors.New("dynamic authorization policy signing key algorithm must match name algorithm")}
		}
	}

	// Create a context for the PCR policy counter.
	pcrPolicyCounterHandle := d.PolicyData.StaticData.PCRPolicyCounterHandle
	if pcrPolicyCounterHandle.Type() != tpm2.HandleTypeNVIndex {
		return nil, keyDataError{errors.New("PCR policy counter handle is invalid")}
	}
	pcrPolicyCounter, err := tpm.NewResourceContext(pcrPolicyCounterHandle)
	if err != nil {
		if tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle) {
			return nil, keyDataError{errors.New("PCR policy counter is unavailable")}
		}
		return nil, xerrors.Errorf("cannot create context for PCR policy counter: %w", err)
	}

	// Make sure that the static authorization policy data is consistent with the sealed key object's policy.
	if !d.KeyPublic.NameAlg.Available() {
		return nil, keyDataError{errors.New("cannot determine if static authorization policy matches sealed key object: algorithm unavailable")}
	}
	builder := policyutil.NewPolicyBuilder(d.KeyPublic.NameAlg)
	builder.RootBranch().PolicyAuthorize(nil, authPublicKey)
	builder.RootBranch().PolicySecret(pcrPolicyCounter, nil)
	builder.RootBranch().PolicyNV(lockNVPub, nil, 0, tpm2.OpEq)
	expectedDigest, err := builder.Digest()
	if err != nil {
		return nil, keyDataError{fmt.Errorf("cannot compute expected static authorization policy digest: %w", err)}
	}

	if !bytes.Equal(expectedDigest, d.KeyPublic.AuthPolicy) {
		return nil, keyDataError{errors.New("the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")}
	}

	// Validate that the OR policy digests for the PCR policy counter match the public area of the index.
	pcrPolicyCounterPub, _, err := tpm.NVReadPublic(pcrPolicyCounter)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of PCR policy counter: %w", err)
	}
	if !pcrPolicyCounterPub.NameAlg.Available() {
		return nil, keyDataError{errors.New("cannot determine if PCR policy counter has a valid authorization policy: algorithm unavailable")}
	}
	pcrPolicyCounterAuthPolicies := d.PolicyData.StaticData.PCRPolicyCounterAuthPolicies
	expectedPCRPolicyCounterAuthPolicies, err := computeV0PinNVIndexPostInitAuthPolicies(pcrPolicyCounterPub.NameAlg, authPublicKey)
	if err != nil {
		return nil, keyDataError{fmt.Errorf("cannot compute OR policy digests for PCR policy counter: %w", err)}
	}
	if len(pcrPolicyCounterAuthPolicies)-1 != len(expectedPCRPolicyCounterAuthPolicies) {
		return nil, keyDataError{errors.New("unexpected number of OR policy digests for PCR policy counter")}
	}
	for i, expected := range expectedPCRPolicyCounterAuthPolicies {
		if !bytes.Equal(expected, pcrPolicyCounterAuthPolicies[i+1]) {
			return nil, keyDataError{errors.New("unexpected OR policy digest for PCR policy counter")}
		}
	}

	builder = policyutil.NewPolicyBuilder(pcrPolicyCounterPub.NameAlg)
	builder.RootBranch().PolicyOR(pcrPolicyCounterAuthPolicies...)
	expectedDigest, err = builder.Digest()
	if err != nil {
		return nil, keyDataError{fmt.Errorf("cannot compute expected PCR policy counter authorization policy digest: %w", err)}
	}
	if !bytes.Equal(pcrPolicyCounterPub.AuthPolicy, expectedDigest) {
		return nil, keyDataError{errors.New("PCR policy counter has unexpected authorization policy")}
	}

	return pcrPolicyCounter, nil
}

func (d *keyData_v0) Write(w io.Writer) error {
	_, err := mu.MarshalToWriter(w, d)
	return err
}

func (d *keyData_v0) Policy() keyDataPolicy {
	return d.PolicyData
}

func (d *keyData_v0) Decrypt(key, payload []byte, generation uint32, kdfAlg tpm2.HashAlgorithmId, authMode secboot.AuthMode) ([]byte, error) {
	return nil, errors.New("not supported")
}
