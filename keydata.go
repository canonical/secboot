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
	"hash"
	"io"
	"math/big"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"

	"maze.io/x/crypto/afis"
)

const (
	currentMetadataVersion    uint32 = 1
	keyDataHeader             uint32 = 0x55534b24
	keyPolicyUpdateDataHeader uint32 = 0x55534b50
)

// AuthMode corresponds to an authentication mechanism.
type AuthMode uint8

const (
	AuthModeNone AuthMode = iota
	AuthModePIN
)

type afSplitDataRawHdr struct {
	Stripes uint32
	HashAlg tpm2.HashAlgorithmId
	Size    uint32
}

type afSplitDataRaw struct {
	Hdr  afSplitDataRawHdr
	Data tpm2.RawBytes
}

func (d *afSplitDataRaw) Marshal(w io.Writer) (nbytes int, err error) {
	return tpm2.MarshalToWriter(w, d.Hdr, d.Data)
}

func (d *afSplitDataRaw) Unmarshal(r io.Reader) (nbytes int, err error) {
	var h afSplitDataRawHdr
	n, err := tpm2.UnmarshalFromReader(r, &h)
	nbytes += n
	if err != nil {
		return nbytes, xerrors.Errorf("cannot unmarshal header: %w", err)
	}

	data := make([]byte, h.Size)
	n, err = io.ReadFull(r, data)
	nbytes += n
	if err != nil {
		return nbytes, xerrors.Errorf("cannot read data: %w", err)
	}

	d.Hdr = h
	d.Data = data
	return
}

func (d *afSplitDataRaw) data() *afSplitData {
	return &afSplitData{
		stripes: d.Hdr.Stripes,
		hashAlg: d.Hdr.HashAlg,
		data:    d.Data}
}

func makeAfSplitDataRaw(d *afSplitData) *afSplitDataRaw {
	return &afSplitDataRaw{
		Hdr: afSplitDataRawHdr{
			Stripes: d.stripes,
			HashAlg: d.hashAlg,
			Size:    uint32(len(d.data))},
		Data: d.data}
}

type afSplitData struct {
	stripes uint32
	hashAlg tpm2.HashAlgorithmId
	data    []byte
}

func (d *afSplitData) merge() ([]byte, error) {
	if d.stripes < 1 {
		return nil, errors.New("invalid number of stripes")
	}
	if !d.hashAlg.Supported() {
		return nil, errors.New("unsupported digest algorithm")
	}
	return afis.MergeHash(d.data, int(d.stripes), func() hash.Hash { return d.hashAlg.NewHash() })
}

func makeAfSplitData(data []byte, sz int, hashAlg tpm2.HashAlgorithmId) (*afSplitData, error) {
	stripes := uint32((sz / len(data)) + 1)

	split, err := afis.SplitHash(data, int(stripes), func() hash.Hash { return hashAlg.NewHash() })
	if err != nil {
		return nil, err
	}

	return &afSplitData{stripes: stripes, hashAlg: hashAlg, data: split}, nil
}

func (d *afSplitData) Marshal(w io.Writer) (nbytes int, err error) {
	panic("cannot be marshalled")
}

func (d *afSplitData) Unmarshal(r io.Reader) (nbytes int, err error) {
	panic("cannot be unmarshalled")
}

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

func (d *keyPolicyUpdateData) Marshal(w io.Writer) (nbytes int, err error) {
	raw := &keyPolicyUpdateDataRaw_v0{
		AuthKey:        x509.MarshalPKCS1PrivateKey(d.authKey),
		CreationData:   d.creationData,
		CreationTicket: d.creationTicket}
	return tpm2.MarshalToWriter(w, d.version, raw)
}

func (d *keyPolicyUpdateData) Unmarshal(r io.Reader) (nbytes int, err error) {
	var version uint32
	n, err := tpm2.UnmarshalFromReader(r, &version)
	nbytes += n
	if err != nil {
		return nbytes, xerrors.Errorf("cannot unmarshal version number: %w", err)
	}

	switch version {
	case 0, 1:
		var raw keyPolicyUpdateDataRaw_v0
		n, err := tpm2.UnmarshalFromReader(r, &raw)
		nbytes += n
		if err != nil {
			return nbytes, xerrors.Errorf("cannot unmarshal data: %w", err)
		}

		authKey, err := x509.ParsePKCS1PrivateKey(raw.AuthKey)
		if err != nil {
			return nbytes, xerrors.Errorf("cannot parse dynamic authorization policy signing key: %w", err)
		}

		h := crypto.SHA256.New()
		if _, err := tpm2.MarshalToWriter(h, raw.AuthKey); err != nil {
			panic(fmt.Sprintf("cannot marshal dynamic authorization policy signing key: %v", err))
		}

		*d = keyPolicyUpdateData{
			version:        version,
			authKey:        authKey,
			creationInfo:   h.Sum(nil),
			creationData:   raw.CreationData,
			creationTicket: raw.CreationTicket}
	default:
		return nbytes, fmt.Errorf("unexpected version number (%d)", version)
	}
	return
}

// write serializes keyPolicyUpdateData to the provided io.Writer.
func (d *keyPolicyUpdateData) write(buf io.Writer) error {
	if d.version != currentMetadataVersion {
		return errors.New("writing old metadata versions is not supported")
	}

	if _, err := tpm2.MarshalToWriter(buf, keyPolicyUpdateDataHeader, d); err != nil {
		return err
	}

	return nil
}

// decodeKeyPolicyUpdateData deserializes keyPolicyUpdateData from the provided io.Reader.
func decodeKeyPolicyUpdateData(r io.Reader) (*keyPolicyUpdateData, error) {
	var header uint32
	if _, err := tpm2.UnmarshalFromReader(r, &header); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal header: %w", err)
	}
	if header != keyPolicyUpdateDataHeader {
		return nil, fmt.Errorf("unexpected header (%d)", header)
	}

	var d keyPolicyUpdateData
	if _, err := tpm2.UnmarshalFromReader(r, &d); err != nil {
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

// keyDataRaw_v1 is version 1 of the on-disk format of keyDataRaw.
type keyDataRaw_v1 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	AuthModeHint      AuthMode
	StaticPolicyData  *staticPolicyDataRaw_v1
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

func (d *keyData) Marshal(w io.Writer) (nbytes int, err error) {
	n, err := tpm2.MarshalToWriter(w, d.version)
	nbytes += n
	if err != nil {
		return nbytes, xerrors.Errorf("cannot marshal version number: %w", err)
	}

	switch d.version {
	case 0:
		raw := keyDataRaw_v0{
			KeyPrivate:        d.keyPrivate,
			KeyPublic:         d.keyPublic,
			AuthModeHint:      d.authModeHint,
			StaticPolicyData:  makeStaticPolicyDataRaw_v0(d.staticPolicyData),
			DynamicPolicyData: makeDynamicPolicyDataRaw_v0(d.dynamicPolicyData)}
		n, err := tpm2.MarshalToWriter(w, raw)
		return nbytes + n, err
	case 1:
		var tmpW bytes.Buffer
		raw := keyDataRaw_v1{
			KeyPrivate:        d.keyPrivate,
			KeyPublic:         d.keyPublic,
			AuthModeHint:      d.authModeHint,
			StaticPolicyData:  makeStaticPolicyDataRaw_v1(d.staticPolicyData),
			DynamicPolicyData: makeDynamicPolicyDataRaw_v0(d.dynamicPolicyData)}
		if _, err := tpm2.MarshalToWriter(&tmpW, raw); err != nil {
			return 0, xerrors.Errorf("cannot marshal data: %w", err)
		}
		splitData, err := makeAfSplitData(tmpW.Bytes(), 128*1204, tpm2.HashAlgorithmSHA256)
		if err != nil {
			return 0, xerrors.Errorf("cannot split data: %w", err)
		}
		n, err := tpm2.MarshalToWriter(w, makeAfSplitDataRaw(splitData))
		return nbytes + n, err
	default:
		return 0, fmt.Errorf("unexpected version number (%d)", d.version)
	}
}

func (d *keyData) Unmarshal(r io.Reader) (nbytes int, err error) {
	var version uint32
	n, err := tpm2.UnmarshalFromReader(r, &version)
	nbytes += n
	if err != nil {
		return nbytes, xerrors.Errorf("cannot unmarshal version number: %w", err)
	}

	switch version {
	case 0:
		var raw keyDataRaw_v0
		n, err := tpm2.UnmarshalFromReader(r, &raw)
		nbytes += n
		if err != nil {
			return nbytes, xerrors.Errorf("cannot unmarshal data: %w", err)
		}
		*d = keyData{
			version:           version,
			keyPrivate:        raw.KeyPrivate,
			keyPublic:         raw.KeyPublic,
			authModeHint:      raw.AuthModeHint,
			staticPolicyData:  raw.StaticPolicyData.data(),
			dynamicPolicyData: raw.DynamicPolicyData.data()}
	case 1:
		var splitData afSplitDataRaw
		n, err := tpm2.UnmarshalFromReader(r, &splitData)
		nbytes += n
		if err != nil {
			return nbytes, xerrors.Errorf("cannot unmarshal split data: %w", err)
		}

		merged, err := splitData.data().merge()
		if err != nil {
			return nbytes, xerrors.Errorf("cannot merge data: %w", err)
		}

		var raw keyDataRaw_v1
		if _, err := tpm2.UnmarshalFromBytes(merged, &raw); err != nil {
			return nbytes, xerrors.Errorf("cannot unmarshal data: %w", err)
		}
		*d = keyData{
			version:           version,
			keyPrivate:        raw.KeyPrivate,
			keyPublic:         raw.KeyPublic,
			authModeHint:      raw.AuthModeHint,
			staticPolicyData:  raw.StaticPolicyData.data(),
			dynamicPolicyData: raw.DynamicPolicyData.data()}
	default:
		return nbytes, fmt.Errorf("unexpected version number (%d)", version)
	}
	return
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
// public area for the dynamic policy counter.
func (d *keyData) validate(tpm *tpm2.TPMContext, policyUpdateData *keyPolicyUpdateData, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	if d.version > currentMetadataVersion {
		return nil, keyFileError{errors.New("invalid metadata version")}
	}

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

	// Obtain a ResourceContext for the lock NV index and validate it.
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

	// Obtain a ResourceContext for the dynamic authorization policy counter. Go-tpm2 calls TPM2_NV_ReadPublic twice here. The second
	// time is with a session, and there is also verification that the returned public area is for the specified handle so that we know
	// that the returned ResourceContext corresponds to an actual entity on the TPM at the specified handle. This index is used for
	// dynamic authorization policy revocation, and also for PIN integration with v0 metadata only.
	policyCounterHandle := d.staticPolicyData.policyCounterHandle
	if (policyCounterHandle != tpm2.HandleNull || d.version == 0) && policyCounterHandle.Type() != tpm2.HandleTypeNVIndex {
		return nil, keyFileError{errors.New("dynamic authorization policy counter handle is invalid")}
	}

	var policyCounter tpm2.ResourceContext
	if policyCounterHandle != tpm2.HandleNull {
		policyCounter, err = tpm.CreateResourceContextFromTPM(policyCounterHandle, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			if tpm2.IsResourceUnavailableError(err, policyCounterHandle) {
				return nil, keyFileError{errors.New("dynamic authorization policy counter is unavailable")}
			}
			return nil, xerrors.Errorf("cannot create context for dynamic authorization policy counter: %w", err)
		}
	}

	// Validate the type and scheme of the dynamic authorization policy signing key.
	authPublicKey := d.staticPolicyData.authPublicKey
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

	dynamicPolicyRef := d.staticPolicyData.dynamicPolicyRef

	trial.PolicyAuthorize(dynamicPolicyRef, authKeyName)
	if d.version == 0 {
		trial.PolicySecret(policyCounter.Name(), nil)
	} else {
		// v1 metadata and later
		trial.PolicyAuthValue()
	}
	trial.PolicyNV(lockIndexName, nil, 0, tpm2.OpEq)

	if !bytes.Equal(trial.GetDigest(), keyPublic.AuthPolicy) {
		return nil, keyFileError{errors.New("the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")}
	}

	// Read the public area of the dynamic authorization policy counter
	var policyCounterPub *tpm2.NVPublic
	if policyCounter != nil {
		policyCounterPub, _, err = tpm.NVReadPublic(policyCounter, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			return nil, xerrors.Errorf("cannot read public area of dynamic authorization policy counter: %w", err)
		}
	}

	// For > v0 metadata, validate that the dynamic policy reference computed from the dynamic policy counter name matches
	// the validated reference in the static metadata. If this checks out, then the counter has the same name as the one
	// that was created when the key was initially sealed. This is important because if an adversary creates a new counter
	// and modifies the static metadata to point to it and force a recovery, and then we recreate and sign a new dynamic
	// authorization policy using the new counter, the previous policy won't be revoked.
	if d.version > 0 {
		expectedDynamicPolicyRef, err := computeDynamicPolicyRef(keyPublic.NameAlg, policyCounterPub)
		if err != nil {
			return nil, xerrors.Errorf("cannot compute expected dynamic authorization policy ref: %w", err)
		}
		if !bytes.Equal(expectedDynamicPolicyRef, dynamicPolicyRef) {
			return nil, keyFileError{errors.New("the dynamic authorization policy counter is inconsistent with the metadata")}
		}
	}

	// For v0 metadata, validate that the OR policy digests for the dynamic authorization policy counter match the public area of the
	// index.
	if d.version == 0 {
		policyCounterAuthPolicies := d.staticPolicyData.v0PinIndexAuthPolicies
		expectedPolicyCounterAuthPolicies, err := computeV0PinNVIndexPostInitAuthPolicies(policyCounterPub.NameAlg, authKeyName)
		if err != nil {
			return nil, keyFileError{xerrors.Errorf("cannot determine if dynamic authorization policy counter has a valid authorization policy: %w", err)}
		}
		if len(policyCounterAuthPolicies)-1 != len(expectedPolicyCounterAuthPolicies) {
			return nil, keyFileError{errors.New("unexpected number of OR policy digests for dynamic authorization policy counter")}
		}
		for i, expected := range expectedPolicyCounterAuthPolicies {
			if !bytes.Equal(expected, policyCounterAuthPolicies[i+1]) {
				return nil, keyFileError{errors.New("unexpected OR policy digest for dynamic authorization policy counter")}
			}
		}

		trial, _ = tpm2.ComputeAuthPolicy(policyCounterPub.NameAlg)
		trial.PolicyOR(policyCounterAuthPolicies)
		if !bytes.Equal(policyCounterPub.AuthPolicy, trial.GetDigest()) {
			return nil, keyFileError{errors.New("dynamic authorization policy counter has unexpected authorization policy")}
		}
	}

	// At this point, we know that the sealed object is an object with an authorization policy created by this package and with
	// matching static metadata and persistent TPM resources.

	if policyUpdateData == nil {
		// If we weren't passed a private data structure, we're done.
		return policyCounterPub, nil
	}

	// Verify that the private data structure is bound to the key data structure.
	h := keyPublic.NameAlg.NewHash()
	if _, err := tpm2.MarshalToWriter(h, policyUpdateData.creationData); err != nil {
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

	return policyCounterPub, nil
}

// write serializes keyData in to the provided io.Writer.
func (d *keyData) write(w io.Writer) error {
	if _, err := tpm2.MarshalToWriter(w, keyDataHeader, d); err != nil {
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
	if _, err := tpm2.UnmarshalFromReader(r, &header); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal header: %w", err)
	}
	if header != keyDataHeader {
		return nil, fmt.Errorf("unexpected header (%d)", header)
	}

	var d keyData
	if _, err := tpm2.UnmarshalFromReader(r, &d); err != nil {
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

// decodeAndValidateKeyData will deserialize keyData and keyPolicyUpdateData from the provided io.Readers and then perform some
// correctness checking. On success, it returns the keyData, keyPolicyUpdateData and the validated public area of the dynamic
// authorization policy counter.
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

// PolicyCounterHandle indicates the handle of the NV counter used for dynamic authorization policy revocation for this sealed key
// object (and for PIN integration for version 0 key files).
func (k *SealedKeyObject) PolicyCounterHandle() tpm2.Handle {
	return k.data.staticPolicyData.policyCounterHandle
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
