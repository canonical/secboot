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
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"
)

const keyPolicyUpdateDataHeader uint32 = 0x55534b50

// keyPolicyUpdateDataRaw_v0 is version 0 of the on-disk format of keyPolicyUpdateData.
type keyPolicyUpdateDataRaw_v0 struct {
	AuthKey        []byte
	CreationData   *tpm2.CreationData
	CreationTicket *tpm2.TkCreation
}

// keyPolicyUpdateData corresponds to the private part of a sealed key object that is required in order to create new dynamic
// authorization policies.
type keyPolicyUpdateData struct {
	version        uint32
	authKey        crypto.PrivateKey
	creationInfo   tpm2.Data
	creationData   *tpm2.CreationData
	creationTicket *tpm2.TkCreation
}

func (d keyPolicyUpdateData) Marshal(w io.Writer) error {
	panic("not implemented")
}

func (d *keyPolicyUpdateData) Unmarshal(r mu.Reader) error {
	var version uint32
	if _, err := mu.UnmarshalFromReader(r, &version); err != nil {
		return xerrors.Errorf("cannot unmarshal version number: %w", err)
	}

	switch version {
	case 0:
		var raw keyPolicyUpdateDataRaw_v0
		if _, err := mu.UnmarshalFromReader(r, &raw); err != nil {
			return xerrors.Errorf("cannot unmarshal data: %w", err)
		}

		authKey, err := x509.ParsePKCS1PrivateKey(raw.AuthKey)
		if err != nil {
			return xerrors.Errorf("cannot parse dynamic authorization policy signing key: %w", err)
		}

		h := crypto.SHA256.New()
		if _, err := mu.MarshalToWriter(h, raw.AuthKey); err != nil {
			panic(fmt.Sprintf("cannot marshal dynamic authorization policy signing key: %v", err))
		}

		*d = keyPolicyUpdateData{
			version:        version,
			authKey:        authKey,
			creationInfo:   h.Sum(nil),
			creationData:   raw.CreationData,
			creationTicket: raw.CreationTicket}
	default:
		return fmt.Errorf("unexpected version number (%d)", version)
	}
	return nil
}

// decodeKeyPolicyUpdateData deserializes keyPolicyUpdateData from the provided io.Reader.
func decodeKeyPolicyUpdateData(r io.Reader) (*keyPolicyUpdateData, error) {
	var header uint32
	if _, err := mu.UnmarshalFromReader(r, &header); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal header: %w", err)
	}
	if header != keyPolicyUpdateDataHeader {
		return nil, fmt.Errorf("unexpected header (%d)", header)
	}

	var d keyPolicyUpdateData
	if _, err := mu.UnmarshalFromReader(r, &d); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal data: %w", err)
	}

	return &d, nil
}

// keyDataRaw_v0 is version 0 of the on-disk format of keyData.
type keyDataRaw_v0 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	Unused            uint8 // previously AuthModeHint
	StaticPolicyData  *staticPolicyDataRaw_v0
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

type keyDataValidatorV0 struct {
	keyPrivate       tpm2.Private
	keyPublic        *tpm2.Public
	staticPolicyData *staticPolicyData
}

func newKeyDataValidatorV0(priv tpm2.Private, pub *tpm2.Public, static *staticPolicyData) keyDataValidator {
	return &keyDataValidatorV0{
		keyPrivate:       priv,
		keyPublic:        pub,
		staticPolicyData: static}
}

func (v *keyDataValidatorV0) validateData(tpm *tpm2.TPMContext, pcrPolicyCounter tpm2.ResourceContext, session tpm2.SessionContext) error {
	// Obtain the name of the legacy lock NV index.
	lockNV, err := tpm.CreateResourceContextFromTPM(lockNVHandle, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		if tpm2.IsResourceUnavailableError(err, lockNVHandle) {
			return keyDataError{errors.New("lock NV index is unavailable")}
		}
		return xerrors.Errorf("cannot create context for lock NV index: %w", err)
	}
	lockNVPub, _, err := tpm.NVReadPublic(lockNV, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area of lock NV index: %w", err)
	}
	lockNVPub.Attrs &^= tpm2.AttrNVReadLocked
	lockNVName, err := lockNVPub.Name()
	if err != nil {
		return xerrors.Errorf("cannot compute name of lock NV index: %w", err)
	}

	// Validate the type and scheme of the dynamic authorization policy signing key.
	authPublicKey := v.staticPolicyData.authPublicKey
	authKeyName, err := authPublicKey.Name()
	if err != nil {
		return keyDataError{xerrors.Errorf("cannot compute name of dynamic authorization policy key: %w", err)}
	}
	if authPublicKey.Type != tpm2.ObjectTypeRSA {
		return keyDataError{errors.New("public area of dynamic authorization policy signing key has the wrong type")}
	}
	authKeyScheme := authPublicKey.Params.AsymDetail(authPublicKey.Type).Scheme
	if authKeyScheme.Scheme != tpm2.AsymSchemeNull {
		if authKeyScheme.Scheme != tpm2.AsymSchemeRSAPSS {
			return keyDataError{errors.New("dynamic authorization policy signing key has unexpected scheme")}
		}
		if authKeyScheme.Details.Any(authKeyScheme.Scheme).HashAlg != authPublicKey.NameAlg {
			return keyDataError{errors.New("dynamic authorization policy signing key algorithm must match name algorithm")}
		}
	}

	// v0 keydata always has a PCR policy counter, used for PIN integration.
	if pcrPolicyCounter == nil {
		return keyDataError{errors.New("PCR policy counter handle is invalid")}
	}

	// Make sure that the static authorization policy data is consistent with the sealed key object's policy.
	if !v.keyPublic.NameAlg.Available() {
		return keyDataError{errors.New("cannot determine if static authorization policy matches sealed key object: algorithm unavailable")}
	}
	trial := util.ComputeAuthPolicy(v.keyPublic.NameAlg)
	trial.PolicyAuthorize(nil, authKeyName)
	trial.PolicySecret(pcrPolicyCounter.Name(), nil)
	trial.PolicyNV(lockNVName, nil, 0, tpm2.OpEq)

	if !bytes.Equal(trial.GetDigest(), v.keyPublic.AuthPolicy) {
		return keyDataError{errors.New("the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")}
	}

	// Validate that the OR policy digests for the PCR policy counter match the public area of the index.
	pcrPolicyCounterPub, _, err := tpm.NVReadPublic(pcrPolicyCounter, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area of PCR policy counter: %w", err)
	}
	if !pcrPolicyCounterPub.NameAlg.Available() {
		return keyDataError{errors.New("cannot determine if PCR policy counter has a valid authorization policy: algorithm unavailable")}
	}
	pcrPolicyCounterAuthPolicies := v.staticPolicyData.v0PinIndexAuthPolicies
	expectedPcrPolicyCounterAuthPolicies := computeV0PinNVIndexPostInitAuthPolicies(pcrPolicyCounterPub.NameAlg, authKeyName)
	if len(pcrPolicyCounterAuthPolicies)-1 != len(expectedPcrPolicyCounterAuthPolicies) {
		return keyDataError{errors.New("unexpected number of OR policy digests for PCR policy counter")}
	}
	for i, expected := range expectedPcrPolicyCounterAuthPolicies {
		if !bytes.Equal(expected, pcrPolicyCounterAuthPolicies[i+1]) {
			return keyDataError{errors.New("unexpected OR policy digest for PCR policy counter")}
		}
	}

	trial = util.ComputeAuthPolicy(pcrPolicyCounterPub.NameAlg)
	trial.PolicyOR(pcrPolicyCounterAuthPolicies)
	if !bytes.Equal(pcrPolicyCounterPub.AuthPolicy, trial.GetDigest()) {
		return keyDataError{errors.New("PCR policy counter has unexpected authorization policy")}
	}

	return nil
}

func (v *keyDataValidatorV0) validateAuthKey(key crypto.PrivateKey) error {
	k, ok := key.(*rsa.PrivateKey)
	if !ok {
		return errors.New("unexpected dynamic authorization policy signing private key type")
	}

	authPublicKey := v.staticPolicyData.authPublicKey

	goAuthPublicKey := rsa.PublicKey{
		N: new(big.Int).SetBytes(authPublicKey.Unique.RSA),
		E: int(authPublicKey.Params.RSADetail.Exponent)}
	if k.E != goAuthPublicKey.E || k.N.Cmp(goAuthPublicKey.N) != 0 {
		return keyDataError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
	}

	return nil
}
