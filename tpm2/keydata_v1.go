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
	"crypto"
	"crypto/ecdsa"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"
)

// keyDataRaw_v1 is version 1 of the on-disk format of keyData.
type keyDataRaw_v1 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	Unused            uint8 // previously AuthModeHint
	StaticPolicyData  *staticPolicyDataRaw_v1
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

type keyDataValidatorV1 struct {
	keyPrivate       tpm2.Private
	keyPublic        *tpm2.Public
	staticPolicyData *staticPolicyData
}

func newKeyDataValidatorV1(priv tpm2.Private, pub *tpm2.Public, static *staticPolicyData) keyDataValidator {
	return &keyDataValidatorV1{
		keyPrivate:       priv,
		keyPublic:        pub,
		staticPolicyData: static}
}

func (v *keyDataValidatorV1) validateData(tpm *tpm2.TPMContext, pcrPolicyCounter tpm2.ResourceContext, session tpm2.SessionContext) error {
	// Validate the type and scheme of the dynamic authorization policy signing key.
	authPublicKey := v.staticPolicyData.authPublicKey
	authKeyName, err := authPublicKey.Name()
	if err != nil {
		return keyDataError{xerrors.Errorf("cannot compute name of dynamic authorization policy key: %w", err)}
	}
	if authPublicKey.Type != tpm2.ObjectTypeECC {
		return keyDataError{errors.New("public area of dynamic authorization policy signing key has the wrong type")}
	}
	authKeyScheme := authPublicKey.Params.AsymDetail(authPublicKey.Type).Scheme
	if authKeyScheme.Scheme != tpm2.AsymSchemeNull {
		if authKeyScheme.Scheme != tpm2.AsymSchemeECDSA {
			return keyDataError{errors.New("dynamic authorization policy signing key has unexpected scheme")}
		}
		if authKeyScheme.Details.Any(authKeyScheme.Scheme).HashAlg != authPublicKey.NameAlg {
			return keyDataError{errors.New("dynamic authorization policy signing key algorithm must match name algorithm")}
		}
	}

	// Make sure that the static authorization policy data is consistent with the sealed key object's policy.
	if !v.keyPublic.NameAlg.Available() {
		return keyDataError{errors.New("cannot determine if static authorization policy matches sealed key object: algorithm unavailable")}
	}
	trial := util.ComputeAuthPolicy(v.keyPublic.NameAlg)
	trial.PolicyAuthorize(computePcrPolicyRefFromCounterContext(pcrPolicyCounter), authKeyName)
	trial.PolicyAuthValue()

	if !bytes.Equal(trial.GetDigest(), v.keyPublic.AuthPolicy) {
		return keyDataError{errors.New("the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")}
	}

	return nil
}

func (v *keyDataValidatorV1) validateAuthKey(key crypto.PrivateKey) error {
	k, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("unexpected dynamic authorization policy signing private key type")
	}
	expectedX, expectedY := k.Curve.ScalarBaseMult(k.D.Bytes())
	if expectedX.Cmp(k.X) != 0 || expectedY.Cmp(k.Y) != 0 {
		return keyDataError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
	}
	return nil
}
