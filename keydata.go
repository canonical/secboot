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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"
)

const (
	currentMetadataVersion    uint32 = 0
	keyDataHeader             uint32 = 0x55534b24
	keyPolicyUpdateDataHeader uint32 = 0x55534b50
)

// AuthMode corresponds to an authentication mechanism.
type AuthMode uint8

const (
	AuthModeNone AuthMode = iota
	AuthModePIN
)

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
	authKey        *rsa.PrivateKey
	creationInfo   tpm2.Data
	creationData   *tpm2.CreationData
	creationTicket *tpm2.TkCreation
}

func (d *keyPolicyUpdateData) Marshal(w io.Writer) error {
	raw := &keyPolicyUpdateDataRaw_v0{
		AuthKey:        x509.MarshalPKCS1PrivateKey(d.authKey),
		CreationData:   d.creationData,
		CreationTicket: d.creationTicket}
	_, err := mu.MarshalToWriter(w, d.version, raw)
	return err
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
			version:        0,
			authKey:        authKey,
			creationInfo:   h.Sum(nil),
			creationData:   raw.CreationData,
			creationTicket: raw.CreationTicket}
	default:
		return fmt.Errorf("unexpected version number (%d)", version)
	}
	return nil
}

// write serializes keyPolicyUpdateData to the provided io.Writer.
func (d *keyPolicyUpdateData) write(buf io.Writer) error {
	if d.version != currentMetadataVersion {
		return errors.New("writing old metadata versions is not supported")
	}

	if _, err := mu.MarshalToWriter(buf, keyPolicyUpdateDataHeader, d); err != nil {
		return err
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

// keyDataRaw_v0 is version 0 of the on-disk format of keyDataRaw.
type keyDataRaw_v0 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	AuthModeHint      AuthMode
	StaticPolicyData  *staticPolicyDataRaw_v0
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

// keyData corresponds to the part of a sealed key object that contains the TPM sealed object and associated metadata required
// for executing authorization policy assertions.
type keyData struct {
	version           uint32
	keyPrivate        tpm2.Private
	keyPublic         *tpm2.Public
	authModeHint      AuthMode
	staticPolicyData  *staticPolicyData
	dynamicPolicyData *dynamicPolicyData
}

func (d *keyData) Marshal(w io.Writer) error {
	if _, err := mu.MarshalToWriter(w, d.version); err != nil {
		return xerrors.Errorf("cannot marshal version number: %w", err)
	}

	switch d.version {
	case 0:
		raw := keyDataRaw_v0{
			KeyPrivate:        d.keyPrivate,
			KeyPublic:         d.keyPublic,
			AuthModeHint:      d.authModeHint,
			StaticPolicyData:  makeStaticPolicyDataRaw_v0(d.staticPolicyData),
			DynamicPolicyData: makeDynamicPolicyDataRaw_v0(d.dynamicPolicyData)}
		if _, err := mu.MarshalToWriter(w, raw); err != nil {
			return xerrors.Errorf("cannot marshal raw data: %w", err)
		}
	default:
		return fmt.Errorf("unexpected version number (%d)", d.version)
	}
	return nil
}

func (d *keyData) Unmarshal(r mu.Reader) error {
	var version uint32
	if _, err := mu.UnmarshalFromReader(r, &version); err != nil {
		return xerrors.Errorf("cannot unmarshal version number: %w", err)
	}

	switch version {
	case 0:
		var raw keyDataRaw_v0
		if _, err := mu.UnmarshalFromReader(r, &raw); err != nil {
			return xerrors.Errorf("cannot unmarshal data: %w", err)
		}
		*d = keyData{
			version:           0,
			keyPrivate:        raw.KeyPrivate,
			keyPublic:         raw.KeyPublic,
			authModeHint:      raw.AuthModeHint,
			staticPolicyData:  raw.StaticPolicyData.data(),
			dynamicPolicyData: raw.DynamicPolicyData.data()}
	default:
		return fmt.Errorf("unexpected version number (%d)", version)
	}
	return nil
}

// load loads the TPM sealed object associated with this keyData in to the storage hierarchy of the TPM, and returns the newly
// created tpm2.ResourceContext.
func (d *keyData) load(tpm *tpm2.TPMContext, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	srkContext, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	keyContext, err := tpm.Load(srkContext, d.keyPrivate, d.keyPublic, session)
	if err != nil {
		invalidObject := false
		switch {
		case tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandLoad, tpm2.AnyParameterIndex):
			invalidObject = true
		case tpm2.IsTPMError(err, tpm2.ErrorSensitive, tpm2.CommandLoad):
			invalidObject = true
		}
		if invalidObject {
			return nil, keyFileError{errors.New("cannot load sealed key object in to TPM: bad sealed key object or TPM owner changed")}
		}
		return nil, xerrors.Errorf("cannot load sealed key object in to TPM: %w", err)
	}

	return keyContext, nil
}

// validate performs some correctness checking on the provided keyData and keyPolicyUpdateData. On success, it returns the validated
// public area for the PIN NV index.
func (d *keyData) validate(tpm *tpm2.TPMContext, policyUpdateData *keyPolicyUpdateData, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	srkContext, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	sealedKeyTemplate := makeSealedKeyTemplate()

	keyPublic := d.keyPublic

	// Perform some initial checks on the sealed data object's public area
	if keyPublic.Type != sealedKeyTemplate.Type {
		return nil, keyFileError{errors.New("sealed key object has the wrong type")}
	}
	if keyPublic.Attrs != sealedKeyTemplate.Attrs {
		return nil, keyFileError{errors.New("sealed key object has the wrong attributes")}
	}

	// Load the sealed data object in to the TPM for integrity checking
	keyContext, err := tpm.Load(srkContext, d.keyPrivate, keyPublic, session)
	if err != nil {
		invalidObject := false
		switch {
		case tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandLoad, tpm2.AnyParameterIndex):
			invalidObject = true
		case tpm2.IsTPMError(err, tpm2.ErrorSensitive, tpm2.CommandLoad):
			invalidObject = true
		}
		if invalidObject {
			return nil, keyFileError{errors.New("cannot load sealed key object in to TPM: bad sealed key object or TPM owner changed")}
		}
		return nil, xerrors.Errorf("cannot load sealed key object in to TPM: %w", err)
	}
	// It's loaded ok, so we know that the private and public parts are consistent.
	defer tpm.FlushContext(keyContext)

	lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for lock NV index: %v", err)
	}
	lockIndexPub, err := readAndValidateLockNVIndexPublic(tpm, lockIndex, session)
	if err != nil {
		return nil, xerrors.Errorf("cannot determine if NV index at %v is global lock index: %w", lockNVHandle, err)
	}
	if lockIndexPub == nil {
		return nil, xerrors.Errorf("NV index at %v is not a valid global lock index", lockNVHandle)
	}
	lockIndexName, err := lockIndexPub.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute lock NV index name: %w", err)
	}

	// Obtain a ResourceContext for the PIN NV index. Go-tpm2 calls TPM2_NV_ReadPublic twice here. The second time is with a session, and
	// there is also verification that the returned public area is for the specified handle so that we know that the returned
	// ResourceContext corresponds to an actual entity on the TPM at PinIndexHandle.
	pinIndexHandle := d.staticPolicyData.PinIndexHandle
	if pinIndexHandle.Type() != tpm2.HandleTypeNVIndex {
		return nil, keyFileError{errors.New("PIN NV index handle is invalid")}
	}
	pinIndex, err := tpm.CreateResourceContextFromTPM(pinIndexHandle, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		if tpm2.IsResourceUnavailableError(err, pinIndexHandle) {
			return nil, keyFileError{errors.New("PIN NV index is unavailable")}
		}
		return nil, xerrors.Errorf("cannot create context for PIN NV index: %w", err)
	}

	authPublicKey := d.staticPolicyData.AuthPublicKey
	authKeyName, err := authPublicKey.Name()
	if err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot compute name of dynamic authorization policy key: %w", err)}
	}
	if authPublicKey.Type != tpm2.ObjectTypeRSA {
		return nil, keyFileError{errors.New("public area of dynamic authorization policy signing key has the wrong type")}
	}

	// Make sure that the static authorization policy data is consistent with the sealed key object's policy.
	trial, err := tpm2.ComputeAuthPolicy(keyPublic.NameAlg)
	if err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot determine if static authorization policy matches sealed key object: %w", err)}
	}
	trial.PolicyAuthorize(nil, authKeyName)
	trial.PolicySecret(pinIndex.Name(), nil)
	trial.PolicyNV(lockIndexName, nil, 0, tpm2.OpEq)

	if !bytes.Equal(trial.GetDigest(), keyPublic.AuthPolicy) {
		return nil, keyFileError{errors.New("the sealed key object's authorization policy is inconsistent with the associatedc metadata or persistent TPM resources")}
	}

	pinIndexPublic, _, err := tpm.NVReadPublic(pinIndex, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of PIN NV index: %w", err)
	}

	pinIndexAuthPolicies := d.staticPolicyData.PinIndexAuthPolicies
	expectedPinIndexAuthPolicies, err := computePinNVIndexPostInitAuthPolicies(pinIndexPublic.NameAlg, authKeyName)
	if err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot determine if PIN NV index has a valid authorization policy: %w", err)}
	}
	if len(pinIndexAuthPolicies)-1 != len(expectedPinIndexAuthPolicies) {
		return nil, keyFileError{errors.New("unexpected number of OR policy digests for PIN NV index")}
	}
	for i, expected := range expectedPinIndexAuthPolicies {
		if !bytes.Equal(expected, pinIndexAuthPolicies[i+1]) {
			return nil, keyFileError{errors.New("unexpected OR policy digest for PIN NV index")}
		}
	}

	trial, _ = tpm2.ComputeAuthPolicy(pinIndexPublic.NameAlg)
	trial.PolicyOR(pinIndexAuthPolicies)
	if !bytes.Equal(pinIndexPublic.AuthPolicy, trial.GetDigest()) {
		return nil, keyFileError{errors.New("PIN NV index has unexpected authorization policy")}
	}

	// At this point, we know that the sealed object is an object with an authorization policy created by this package and with
	// matching static metadata and persistent TPM resources.

	if policyUpdateData == nil {
		// If we weren't passed a private data structure, we're done.
		return pinIndexPublic, nil
	}

	// Verify that the private data structure is bound to the key data structure.
	h := keyPublic.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(h, policyUpdateData.creationData); err != nil {
		panic(fmt.Sprintf("cannot marshal creation data: %v", err))
	}

	if _, _, err := tpm.CertifyCreation(nil, keyContext, nil, h.Sum(nil), nil, policyUpdateData.creationTicket, nil,
		session.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorTicket, tpm2.CommandCertifyCreation, 4) {
			return nil, keyFileError{errors.New("key data file and dynamic authorization policy update data file mismatch: invalid creation ticket")}
		}
		return nil, xerrors.Errorf("cannot validate creation data for sealed data object: %w", err)
	}

	if !bytes.Equal(policyUpdateData.creationInfo, policyUpdateData.creationData.OutsideInfo) {
		return nil, keyFileError{errors.New("key data file and dynamic authorization policy update data file mismatch: digest doesn't match creation data")}
	}

	authKey := policyUpdateData.authKey
	goAuthPublicKey := rsa.PublicKey{
		N: new(big.Int).SetBytes(authPublicKey.Unique.RSA()),
		E: int(authPublicKey.Params.RSADetail().Exponent)}
	if authKey.E != goAuthPublicKey.E || authKey.N.Cmp(goAuthPublicKey.N) != 0 {
		return nil, keyFileError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
	}

	return pinIndexPublic, nil
}

// write serializes keyData in to the provided io.Writer.
func (d *keyData) write(w io.Writer) error {
	if _, err := mu.MarshalToWriter(w, keyDataHeader, d); err != nil {
		return err
	}
	return nil
}

// writeToFileAtomic serializes keyData and writes it atomically to the file at the specified path.
func (d *keyData) writeToFileAtomic(dest string) error {
	f, err := osutil.NewAtomicFile(dest, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return xerrors.Errorf("cannot create new atomic file: %w", err)
	}
	defer f.Cancel()

	if err := d.write(f); err != nil {
		return xerrors.Errorf("cannot write to temporary file: %w", err)
	}

	if err := f.Commit(); err != nil {
		return xerrors.Errorf("cannot atomically replace file: %w", err)
	}

	return nil
}

// decodeKeyData deserializes keyData from the provided io.Reader.
func decodeKeyData(r io.Reader) (*keyData, error) {
	var header uint32
	if _, err := mu.UnmarshalFromReader(r, &header); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal header: %w", err)
	}
	if header != keyDataHeader {
		return nil, fmt.Errorf("unexpected header (%d)", header)
	}

	var d keyData
	if _, err := mu.UnmarshalFromReader(r, &d); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal data: %w", err)
	}

	return &d, nil
}

type keyFileError struct {
	err error
}

func (e keyFileError) Error() string {
	return e.err.Error()
}

func (e keyFileError) Unwrap() error {
	return e.err
}

func isKeyFileError(err error) bool {
	var e keyFileError
	return xerrors.As(err, &e)
}

// decodeAndValidateKeyData will deserialize keyData and keyPolicyUpdateData from the provided io.Readers and then perform some correctness
// checking. On success, it returns the keyData, keyPolicyUpdateData and the validated public area of the PIN NV index.
func decodeAndValidateKeyData(tpm *tpm2.TPMContext, keyFile, keyPolicyUpdateFile io.Reader, session tpm2.SessionContext) (*keyData, *keyPolicyUpdateData, *tpm2.NVPublic, error) {
	// Read the key data
	data, err := decodeKeyData(keyFile)
	if err != nil {
		return nil, nil, nil, keyFileError{xerrors.Errorf("cannot read key data: %w", err)}
	}

	var policyUpdateData *keyPolicyUpdateData
	if keyPolicyUpdateFile != nil {
		var err error
		policyUpdateData, err = decodeKeyPolicyUpdateData(keyPolicyUpdateFile)
		if err != nil {
			return nil, nil, nil, keyFileError{xerrors.Errorf("cannot read dynamic policy update data: %w", err)}
		}
	}

	pinNVPublic, err := data.validate(tpm, policyUpdateData, session)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot validate key data: %w", err)
	}

	return data, policyUpdateData, pinNVPublic, nil
}

// SealedKeyObject corresponds to a sealed key data file and exists to provide access to some read only operations on the underlying
// file without having to read and deserialize the key data file more than once.
type SealedKeyObject struct {
	data *keyData
}

// AuthMode2F indicates the 2nd-factor authentication type for this sealed key object.
func (k *SealedKeyObject) AuthMode2F() AuthMode {
	return k.data.authModeHint
}

// PINIndexHandle indicates the handle of the NV index used for PIN support for this sealed key object.
func (k *SealedKeyObject) PINIndexHandle() tpm2.Handle {
	return k.data.staticPolicyData.PinIndexHandle
}

// ReadSealedKeyObject loads a sealed key data file created by SealKeyToTPM from the specified path. If the file cannot be opened,
// a wrapped *os.PathError error is returned. If the key data file cannot be deserialized successfully, a InvalidKeyFileError error
// will be returned.
func ReadSealedKeyObject(path string) (*SealedKeyObject, error) {
	// Open the key data file
	f, err := os.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("cannot open key data file: %w", err)
	}
	defer f.Close()

	data, err := decodeKeyData(f)
	if err != nil {
		return nil, InvalidKeyFileError{err.Error()}
	}

	return &SealedKeyObject{data: data}, nil
}
