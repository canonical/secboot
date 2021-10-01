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
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"
)

// keyData_v2 represents version 2 of keyData.
type keyData_v2 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	Unused            uint8 // previously AuthModeHint
	ImportSymSeed     tpm2.EncryptedSecret
	StaticPolicyData  *staticPolicyDataRaw_v1
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

func readKeyDataV2(r io.Reader) (keyData, error) {
	var d *keyData_v2
	if _, err := mu.UnmarshalFromReader(r, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func newKeyData(keyPrivate tpm2.Private, keyPublic *tpm2.Public, importSymSeed tpm2.EncryptedSecret,
	staticPolicyData *staticPolicyDataRaw_v1, dynamicPolicyData *dynamicPolicyDataRaw_v0) keyData {
	return &keyData_v2{
		KeyPrivate:        keyPrivate,
		KeyPublic:         keyPublic,
		ImportSymSeed:     importSymSeed,
		StaticPolicyData:  staticPolicyData,
		DynamicPolicyData: dynamicPolicyData}
}

func (d *keyData_v2) version() uint32 { return 2 }

func (d *keyData_v2) keyPrivate() tpm2.Private {
	return d.KeyPrivate
}

func (d *keyData_v2) keyPublic() *tpm2.Public {
	return d.KeyPublic
}

func (d *keyData_v2) importSymSeed() tpm2.EncryptedSecret {
	return d.ImportSymSeed
}

func (d *keyData_v2) imported(priv tpm2.Private) {
	d.KeyPrivate = priv
	d.ImportSymSeed = nil
}

func (d *keyData_v2) validateData(tpm *tpm2.TPMContext, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	// Validate the type and scheme of the dynamic authorization policy signing key.
	authPublicKey := d.StaticPolicyData.AuthPublicKey
	authKeyName, err := authPublicKey.Name()
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
	pcrPolicyCounterHandle := d.StaticPolicyData.PCRPolicyCounterHandle
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
	trial.PolicyAuthorize(computePcrPolicyRefFromCounterContext(pcrPolicyCounter), authKeyName)
	trial.PolicyAuthValue()

	if !bytes.Equal(trial.GetDigest(), d.KeyPublic.AuthPolicy) {
		return nil, keyDataError{errors.New("the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")}
	}

	return pcrPolicyCounter, nil
}

func (d *keyData_v2) write(w io.Writer) error {
	_, err := mu.MarshalToWriter(w, d)
	return err
}

func (d *keyData_v2) pcrPolicyCounterHandle() tpm2.Handle {
	return d.StaticPolicyData.PCRPolicyCounterHandle
}

func (d *keyData_v2) validateAuthKey(key crypto.PrivateKey) error {
	pub, ok := d.StaticPolicyData.AuthPublicKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return keyDataError{errors.New("unexpected dynamic authorization policy public key type")}
	}

	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("unexpected dynamic authorization policy signing private key type")
	}

	expectedX, expectedY := priv.Curve.ScalarBaseMult(priv.D.Bytes())
	if expectedX.Cmp(pub.X) != 0 || expectedY.Cmp(pub.Y) != 0 {
		return keyDataError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
	}

	return nil
}

func (d *keyData_v2) staticPolicyData() *staticPolicyData {
	return d.StaticPolicyData.data()
}

func (d *keyData_v2) dynamicPolicyData() *dynamicPolicyData {
	return d.DynamicPolicyData.data()
}

func (d *keyData_v2) setDynamicPolicyData(data *dynamicPolicyData) {
	d.DynamicPolicyData = makeDynamicPolicyDataRaw_v0(data)
}
