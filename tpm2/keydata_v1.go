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
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/util"
	"github.com/snapcore/secboot"

	"golang.org/x/xerrors"
)

// keyData_v1 represents version 1 of keyData.
type keyData_v1 struct {
	KeyPrivate tpm2.Private
	KeyPublic  *tpm2.Public
	Unused     uint8 // previously AuthModeHint
	PolicyData *keyDataPolicy_v1
}

func readKeyDataV1(r io.Reader) (keyData, error) {
	var d *keyData_v1
	if _, err := mu.UnmarshalFromReader(r, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func (_ *keyData_v1) Version() uint32 { return 1 }

func (d *keyData_v1) Private() tpm2.Private {
	return d.KeyPrivate
}

func (d *keyData_v1) SetPrivate(priv tpm2.Private) {
	panic("not supported")
}

func (d *keyData_v1) Public() *tpm2.Public {
	return d.KeyPublic
}

func (_ *keyData_v1) ImportSymSeed() tpm2.EncryptedSecret { return nil }

func (_ *keyData_v1) Imported(_ tpm2.Private) {
	panic("not supported")
}

func (d *keyData_v1) ValidateData(tpm *tpm2.TPMContext, role []byte, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	if len(role) > 0 {
		return nil, errors.New("unexpected role")
	}

	// Validate the type and scheme of the dynamic authorization policy signing key.
	authPublicKey := d.PolicyData.StaticData.AuthPublicKey
	authKeyName, err := authPublicKey.ComputeName()
	if err != nil {
		return nil, keyDataError{xerrors.Errorf("cannot compute name of dynamic authorization policy key: %w", err)}
	}
	if authPublicKey.Type != tpm2.ObjectTypeECC {
		return nil, keyDataError{errors.New("public area of dynamic authorization policy signing key has the wrong type")}
	}
	authKeyScheme := authPublicKey.Params.AsymDetail(authPublicKey.Type).Scheme
	if authKeyScheme.Scheme != tpm2.AsymSchemeNull {
		if authKeyScheme.Scheme != tpm2.AsymSchemeECDSA {
			return nil, keyDataError{errors.New("dynamic authorization policy signing key has unexpected scheme")}
		}
		if authKeyScheme.Details.Any(authKeyScheme.Scheme).HashAlg != authPublicKey.NameAlg {
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
		pcrPolicyCounter, err = tpm.CreateResourceContextFromTPM(pcrPolicyCounterHandle, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			if tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle) {
				return nil, keyDataError{errors.New("PCR policy counter is unavailable")}
			}
			return nil, xerrors.Errorf("cannot create context for PCR policy counter: %w", err)
		}
	}

	// Make sure that the static authorization policy data is consistent with the sealed key object's policy.
	if !d.KeyPublic.NameAlg.Available() {
		return nil, keyDataError{errors.New("cannot determine if static authorization policy matches sealed key object: algorithm unavailable")}
	}
	trial := util.ComputeAuthPolicy(d.KeyPublic.NameAlg)
	trial.PolicyAuthorize(computeV1PcrPolicyRefFromCounterContext(pcrPolicyCounter), authKeyName)
	trial.PolicyAuthValue()

	if !bytes.Equal(trial.GetDigest(), d.KeyPublic.AuthPolicy) {
		return nil, keyDataError{errors.New("the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")}
	}

	return pcrPolicyCounter, nil
}

func (d *keyData_v1) Write(w io.Writer) error {
	_, err := mu.MarshalToWriter(w, d)
	return err
}

func (d *keyData_v1) Policy() keyDataPolicy {
	return d.PolicyData
}

func (d *keyData_v1) Decrypt(key, payload []byte, baseVersion uint32, kdfAlg tpm2.HashAlgorithmId, authMode secboot.AuthMode) ([]byte, error) {
	return nil, errors.New("not supported")
}
