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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"

	"maze.io/x/crypto/afis"
)

const (
	currentMetadataVersion    uint32 = 2
	keyDataHeader             uint32 = 0x55534b24
	keyPolicyUpdateDataHeader uint32 = 0x55534b50
)

type authMode uint8

const (
	authModeNone authMode = iota
	authModePIN
)

// TPMPolicyAuthKey corresponds to the private part of the key used for signing updates to the authorization policy for a sealed key.
type TPMPolicyAuthKey []byte

type sealedData struct {
	Key            []byte
	AuthPrivateKey TPMPolicyAuthKey
}

type afSplitDataRawHdr struct {
	Stripes uint32
	HashAlg tpm2.HashAlgorithmId
	Size    uint32
}

// afSlitDataRaw is the on-disk version of afSplitData.
type afSplitDataRaw struct {
	Hdr  afSplitDataRawHdr
	Data mu.RawBytes
}

func (d afSplitDataRaw) Marshal(w io.Writer) error {
	_, err := mu.MarshalToWriter(w, d.Hdr, d.Data)
	return err
}

func (d *afSplitDataRaw) Unmarshal(r mu.Reader) error {
	var h afSplitDataRawHdr
	if _, err := mu.UnmarshalFromReader(r, &h); err != nil {
		return xerrors.Errorf("cannot unmarshal header: %w", err)
	}

	data := make([]byte, h.Size)
	if _, err := io.ReadFull(r, data); err != nil {
		return xerrors.Errorf("cannot read data: %w", err)
	}

	d.Hdr = h
	d.Data = data
	return nil
}

func (d *afSplitDataRaw) data() *afSplitData {
	return &afSplitData{
		stripes: d.Hdr.Stripes,
		hashAlg: d.Hdr.HashAlg,
		data:    d.Data}
}

// makeAfSplitDataRaw converts afSplitData to its on disk form.
func makeAfSplitDataRaw(d *afSplitData) *afSplitDataRaw {
	return &afSplitDataRaw{
		Hdr: afSplitDataRawHdr{
			Stripes: d.stripes,
			HashAlg: d.hashAlg,
			Size:    uint32(len(d.data))},
		Data: d.data}
}

// afSplitData is a container for data that has been passed through an Anti-Forensic Information Splitter, to support
// secure destruction of on-disk key material by increasing the size of the data stored and requiring every bit to survive
// in order to recover the original data.
type afSplitData struct {
	stripes uint32
	hashAlg tpm2.HashAlgorithmId
	data    []byte
}

// merge recovers the original data from this container.
func (d *afSplitData) merge() ([]byte, error) {
	if d.stripes < 1 {
		return nil, errors.New("invalid number of stripes")
	}
	if !d.hashAlg.Supported() {
		return nil, errors.New("unsupported digest algorithm")
	}
	return afis.MergeHash(d.data, int(d.stripes), func() hash.Hash { return d.hashAlg.NewHash() })
}

// makeAfSplitData passes the supplied data through an Anti-Forensic Information Splitter to increase the size of the data to at
// least the size specified by the minSz argument.
func makeAfSplitData(data []byte, minSz int, hashAlg tpm2.HashAlgorithmId) (*afSplitData, error) {
	stripes := uint32((minSz / len(data)) + 1)

	split, err := afis.SplitHash(data, int(stripes), func() hash.Hash { return hashAlg.NewHash() })
	if err != nil {
		return nil, err
	}

	return &afSplitData{stripes: stripes, hashAlg: hashAlg, data: split}, nil
}

func (d afSplitData) Marshal(w io.Writer) (nbytes int, err error) {
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

// keyDataRaw_v0 is version 0 of the on-disk format of keyDataRaw.
type keyDataRaw_v0 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	AuthModeHint      authMode
	StaticPolicyData  *staticPolicyDataRaw_v0
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

// keyDataRaw_v1 is version 1 of the on-disk format of keyDataRaw.
type keyDataRaw_v1 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	AuthModeHint      authMode
	StaticPolicyData  *staticPolicyDataRaw_v1
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

// keyDataRaw_v2 is version 2 of the on-disk format of keyDataRaw.
type keyDataRaw_v2 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	AuthModeHint      authMode
	ImportSymSeed     tpm2.EncryptedSecret
	StaticPolicyData  *staticPolicyDataRaw_v1
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

// tpmKeyData corresponds to the part of a sealed key object that contains the TPM sealed object and associated metadata required
// for executing authorization policy assertions.
// XXX: This is temporarily named tpmKeyData until this code is moved in to secboot/tpm
type tpmKeyData struct {
	version           uint32
	keyPrivate        tpm2.Private
	keyPublic         *tpm2.Public
	authModeHint      authMode
	importSymSeed     tpm2.EncryptedSecret
	staticPolicyData  *staticPolicyData
	dynamicPolicyData *dynamicPolicyData
}

func (d tpmKeyData) Marshal(w io.Writer) error {
	// We can upgrade v1 to v2 automatically
	if d.version == 1 {
		d.version = 2
	}

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
	case 2:
		var tmpW bytes.Buffer
		raw := keyDataRaw_v2{
			KeyPrivate:        d.keyPrivate,
			KeyPublic:         d.keyPublic,
			AuthModeHint:      d.authModeHint,
			ImportSymSeed:     d.importSymSeed,
			StaticPolicyData:  makeStaticPolicyDataRaw_v1(d.staticPolicyData),
			DynamicPolicyData: makeDynamicPolicyDataRaw_v0(d.dynamicPolicyData)}
		if _, err := mu.MarshalToWriter(&tmpW, raw); err != nil {
			return xerrors.Errorf("cannot marshal raw data: %w", err)
		}
		splitData, err := makeAfSplitData(tmpW.Bytes(), 128*1024, tpm2.HashAlgorithmSHA256)
		if err != nil {
			return xerrors.Errorf("cannot split data: %w", err)
		}
		if _, err := mu.MarshalToWriter(w, makeAfSplitDataRaw(splitData)); err != nil {
			return xerrors.Errorf("cannot marshal split data: %w", err)
		}
	default:
		return fmt.Errorf("unexpected version number (%d)", d.version)
	}
	return nil
}

func (d *tpmKeyData) Unmarshal(r mu.Reader) error {
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
		*d = tpmKeyData{
			version:           version,
			keyPrivate:        raw.KeyPrivate,
			keyPublic:         raw.KeyPublic,
			authModeHint:      raw.AuthModeHint,
			staticPolicyData:  raw.StaticPolicyData.data(),
			dynamicPolicyData: raw.DynamicPolicyData.data()}
	case 1:
		var splitData afSplitDataRaw
		if _, err := mu.UnmarshalFromReader(r, &splitData); err != nil {
			return xerrors.Errorf("cannot unmarshal split data: %w", err)
		}

		merged, err := splitData.data().merge()
		if err != nil {
			return xerrors.Errorf("cannot merge data: %w", err)
		}

		var raw keyDataRaw_v1
		if _, err := mu.UnmarshalFromBytes(merged, &raw); err != nil {
			return xerrors.Errorf("cannot unmarshal data: %w", err)
		}
		*d = tpmKeyData{
			version:           version,
			keyPrivate:        raw.KeyPrivate,
			keyPublic:         raw.KeyPublic,
			authModeHint:      raw.AuthModeHint,
			staticPolicyData:  raw.StaticPolicyData.data(),
			dynamicPolicyData: raw.DynamicPolicyData.data()}
	case 2:
		var splitData afSplitDataRaw
		if _, err := mu.UnmarshalFromReader(r, &splitData); err != nil {
			return xerrors.Errorf("cannot unmarshal split data: %w", err)
		}

		merged, err := splitData.data().merge()
		if err != nil {
			return xerrors.Errorf("cannot merge data: %w", err)
		}

		var raw keyDataRaw_v2
		if _, err := mu.UnmarshalFromBytes(merged, &raw); err != nil {
			return xerrors.Errorf("cannot unmarshal data: %w", err)
		}
		*d = tpmKeyData{
			version:           version,
			keyPrivate:        raw.KeyPrivate,
			keyPublic:         raw.KeyPublic,
			authModeHint:      raw.AuthModeHint,
			importSymSeed:     raw.ImportSymSeed,
			staticPolicyData:  raw.StaticPolicyData.data(),
			dynamicPolicyData: raw.DynamicPolicyData.data()}
	default:
		return fmt.Errorf("unexpected version number (%d)", version)
	}
	return nil
}

func (d *tpmKeyData) ensureImported(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	if len(d.importSymSeed) == 0 {
		return nil
	}

	srkContext, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		return xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	priv, err := tpm.Import(srkContext, nil, d.keyPublic, d.keyPrivate, d.importSymSeed, nil, session)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandImport, tpm2.AnyParameterIndex) {
			return keyFileError{errors.New("cannot import sealed key object in to TPM: bad sealed key object, invalid symmetric seed, TPM owner changed or wrong TPM")}
		}
		return xerrors.Errorf("cannot import sealed key object in to TPM: %w", err)
	}

	d.keyPrivate = priv
	d.importSymSeed = nil

	return nil
}

// load loads the TPM sealed object associated with this tpmKeyData in to the storage hierarchy of the TPM, and returns the newly
// created tpm2.ResourceContext.
func (d *tpmKeyData) load(tpm *tpm2.TPMContext, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	if err := d.ensureImported(tpm, session); err != nil {
		return nil, err
	}

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

// validate performs some correctness checking on the provided tpmKeyData and authKey. On success, it returns the validated public area
// for the PCR policy counter.
func (d *tpmKeyData) validate(tpm *tpm2.TPMContext, authKey crypto.PrivateKey, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	if d.version > currentMetadataVersion {
		return nil, keyFileError{errors.New("invalid metadata version")}
	}

	sealedKeyTemplate := makeImportableSealedKeyTemplate()

	keyPublic := d.keyPublic

	// Perform some initial checks on the sealed data object's public area
	if keyPublic.Type != sealedKeyTemplate.Type {
		return nil, keyFileError{errors.New("sealed key object has the wrong type")}
	}
	if keyPublic.Attrs&^(tpm2.AttrFixedTPM|tpm2.AttrFixedParent) != sealedKeyTemplate.Attrs {
		return nil, keyFileError{errors.New("sealed key object has the wrong attributes")}
	}

	// Load the sealed data object in to the TPM for integrity checking
	keyContext, err := d.load(tpm, session)
	if err != nil {
		return nil, err
	}
	// It's loaded ok, so we know that the private and public parts are consistent.
	tpm.FlushContext(keyContext)

	var legacyLockIndexName tpm2.Name
	if d.version == 0 {
		index, err := tpm.CreateResourceContextFromTPM(lockNVHandle, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			if tpm2.IsResourceUnavailableError(err, lockNVHandle) {
				return nil, keyFileError{errors.New("lock NV index is unavailable")}
			}
			return nil, xerrors.Errorf("cannot create context for lock NV index: %w", err)
		}
		indexPub, _, err := tpm.NVReadPublic(index, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			return nil, xerrors.Errorf("cannot read public area of lock NV index: %w", err)
		}
		indexPub.Attrs &^= tpm2.AttrNVReadLocked
		legacyLockIndexName, err = indexPub.Name()
		if err != nil {
			return nil, xerrors.Errorf("cannot compute name of lock NV index: %w", err)
		}
	}

	// Obtain a ResourceContext for the PCR policy counter. Go-tpm2 calls TPM2_NV_ReadPublic twice here. The second time is with a
	// session, and there is also verification that the returned public area is for the specified handle so that we know that the
	// returned ResourceContext corresponds to an actual entity on the TPM at the specified handle. This index is used for PCR policy
	// revocation, and also for PIN integration with v0 metadata only.
	pcrPolicyCounterHandle := d.staticPolicyData.pcrPolicyCounterHandle
	if (pcrPolicyCounterHandle != tpm2.HandleNull || d.version == 0) && pcrPolicyCounterHandle.Type() != tpm2.HandleTypeNVIndex {
		return nil, keyFileError{errors.New("PCR policy counter handle is invalid")}
	}

	var pcrPolicyCounter tpm2.ResourceContext
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		pcrPolicyCounter, err = tpm.CreateResourceContextFromTPM(pcrPolicyCounterHandle, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			if tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle) {
				return nil, keyFileError{errors.New("PCR policy counter is unavailable")}
			}
			return nil, xerrors.Errorf("cannot create context for PCR policy counter: %w", err)
		}
	}

	var pcrPolicyRef tpm2.Nonce
	if d.version > 0 {
		pcrPolicyRef = computePcrPolicyRefFromCounterContext(pcrPolicyCounter)
	}

	// Validate the type and scheme of the dynamic authorization policy signing key.
	authPublicKey := d.staticPolicyData.authPublicKey
	authKeyName, err := authPublicKey.Name()
	if err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot compute name of dynamic authorization policy key: %w", err)}
	}
	var expectedAuthKeyType tpm2.ObjectTypeId
	var expectedAuthKeyScheme tpm2.AsymSchemeId
	switch d.version {
	case 0:
		expectedAuthKeyType = tpm2.ObjectTypeRSA
		expectedAuthKeyScheme = tpm2.AsymSchemeRSAPSS
	default:
		expectedAuthKeyType = tpm2.ObjectTypeECC
		expectedAuthKeyScheme = tpm2.AsymSchemeECDSA
	}
	if authPublicKey.Type != expectedAuthKeyType {
		return nil, keyFileError{errors.New("public area of dynamic authorization policy signing key has the wrong type")}
	}
	authKeyScheme := authPublicKey.Params.AsymDetail().Scheme
	if authKeyScheme.Scheme != tpm2.AsymSchemeNull {
		if authKeyScheme.Scheme != expectedAuthKeyScheme {
			return nil, keyFileError{errors.New("dynamic authorization policy signing key has unexpected scheme")}
		}
		if authKeyScheme.Details.Any().HashAlg != authPublicKey.NameAlg {
			return nil, keyFileError{errors.New("dynamic authorization policy signing key algorithm must match name algorithm")}
		}
	}

	// Make sure that the static authorization policy data is consistent with the sealed key object's policy.
	trial, err := tpm2.ComputeAuthPolicy(keyPublic.NameAlg)
	if err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot determine if static authorization policy matches sealed key object: %w", err)}
	}

	trial.PolicyAuthorize(pcrPolicyRef, authKeyName)
	if d.version == 0 {
		trial.PolicySecret(pcrPolicyCounter.Name(), nil)
		trial.PolicyNV(legacyLockIndexName, nil, 0, tpm2.OpEq)
	} else {
		// v1 metadata and later
		trial.PolicyAuthValue()
	}

	if !bytes.Equal(trial.GetDigest(), keyPublic.AuthPolicy) {
		return nil, keyFileError{errors.New("the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")}
	}

	// Read the public area of the PCR policy counter
	var pcrPolicyCounterPub *tpm2.NVPublic
	if pcrPolicyCounter != nil {
		pcrPolicyCounterPub, _, err = tpm.NVReadPublic(pcrPolicyCounter, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			return nil, xerrors.Errorf("cannot read public area of PCR policy counter: %w", err)
		}
	}

	// For v0 metadata, validate that the OR policy digests for the PCR policy counter match the public area of the index.
	if d.version == 0 {
		pcrPolicyCounterAuthPolicies := d.staticPolicyData.v0PinIndexAuthPolicies
		expectedPcrPolicyCounterAuthPolicies, err := computeV0PinNVIndexPostInitAuthPolicies(pcrPolicyCounterPub.NameAlg, authKeyName)
		if err != nil {
			return nil, keyFileError{xerrors.Errorf("cannot determine if PCR policy counter has a valid authorization policy: %w", err)}
		}
		if len(pcrPolicyCounterAuthPolicies)-1 != len(expectedPcrPolicyCounterAuthPolicies) {
			return nil, keyFileError{errors.New("unexpected number of OR policy digests for PCR policy counter")}
		}
		for i, expected := range expectedPcrPolicyCounterAuthPolicies {
			if !bytes.Equal(expected, pcrPolicyCounterAuthPolicies[i+1]) {
				return nil, keyFileError{errors.New("unexpected OR policy digest for PCR policy counter")}
			}
		}

		trial, _ = tpm2.ComputeAuthPolicy(pcrPolicyCounterPub.NameAlg)
		trial.PolicyOR(pcrPolicyCounterAuthPolicies)
		if !bytes.Equal(pcrPolicyCounterPub.AuthPolicy, trial.GetDigest()) {
			return nil, keyFileError{errors.New("PCR policy counter has unexpected authorization policy")}
		}
	}

	// At this point, we know that the sealed object is an object with an authorization policy created by this package and with
	// matching static metadata and persistent TPM resources.

	switch k := authKey.(type) {
	case *rsa.PrivateKey:
		goAuthPublicKey := rsa.PublicKey{
			N: new(big.Int).SetBytes(authPublicKey.Unique.RSA),
			E: int(authPublicKey.Params.RSADetail.Exponent)}
		if k.E != goAuthPublicKey.E || k.N.Cmp(goAuthPublicKey.N) != 0 {
			return nil, keyFileError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
		}
	case *ecdsa.PrivateKey:
		if d.version == 0 {
			return nil, keyFileError{errors.New("unexpected dynamic authorization policy signing private key type")}
		}
		expectedX, expectedY := k.Curve.ScalarBaseMult(k.D.Bytes())
		if expectedX.Cmp(k.X) != 0 || expectedY.Cmp(k.Y) != 0 {
			return nil, keyFileError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
		}
	case nil:
	default:
		return nil, keyFileError{errors.New("unexpected dynamic authorization policy signing private key type")}
	}

	return pcrPolicyCounterPub, nil
}

// write serializes tpmKeyData in to the provided io.Writer.
func (d *tpmKeyData) write(w io.Writer) error {
	if _, err := mu.MarshalToWriter(w, keyDataHeader, d); err != nil {
		return err
	}
	return nil
}

// writeToFileAtomic serializes tpmKeyData and writes it atomically to the file at the specified path.
func (d *tpmKeyData) writeToFileAtomic(dest string) error {
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

// decodeKeyData deserializes tpmKeyData from the provided io.Reader.
func decodeKeyData(r io.Reader) (*tpmKeyData, error) {
	var header uint32
	if _, err := mu.UnmarshalFromReader(r, &header); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal header: %w", err)
	}
	if header != keyDataHeader {
		return nil, fmt.Errorf("unexpected header (%d)", header)
	}

	var d tpmKeyData
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

// decodeAndValidateKeyData will deserialize tpmKeyData from the provided io.Reader and then perform some correctness checking. On
// success, it returns the tpmKeyData, dynamic authorization policy signing key (if authData is provided) and the validated public area
// of the PCR policy counter index.
func decodeAndValidateKeyData(tpm *tpm2.TPMContext, keyFile io.Reader, authData interface{}, session tpm2.SessionContext) (*tpmKeyData, crypto.PrivateKey, *tpm2.NVPublic, error) {
	// Read the key data
	data, err := decodeKeyData(keyFile)
	if err != nil {
		return nil, nil, nil, keyFileError{xerrors.Errorf("cannot read key data: %w", err)}
	}

	var authKey crypto.PrivateKey

	switch a := authData.(type) {
	case io.Reader:
		// If we were called with an io.Reader, then we're expecting to load a legacy version-0 keydata and associated
		// private key file.
		policyUpdateData, err := decodeKeyPolicyUpdateData(a)
		if err != nil {
			return nil, nil, nil, keyFileError{xerrors.Errorf("cannot read dynamic policy update data: %w", err)}
		}
		if policyUpdateData.version != data.version {
			return nil, nil, nil, keyFileError{errors.New("mismatched metadata versions")}
		}
		authKey = policyUpdateData.authKey
	case TPMPolicyAuthKey:
		if len(a) > 0 {
			// If we were called with a byte slice, then we're expecting to load the current keydata version and the byte
			// slice is the private part of the elliptic auth key.
			authKey, err = createECDSAPrivateKeyFromTPM(data.staticPolicyData.authPublicKey, tpm2.ECCParameter(a))
			if err != nil {
				return nil, nil, nil, keyFileError{xerrors.Errorf("cannot create auth key: %w", err)}
			}
		}
	case nil:
	default:
		panic("invalid type")
	}

	pcrPolicyCounterPub, err := data.validate(tpm, authKey, session)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot validate key data: %w", err)
	}

	return data, authKey, pcrPolicyCounterPub, nil
}

// SealedKeyObject corresponds to a sealed key data file and exists to provide access to some read only operations on the underlying
// file without having to read and deserialize the key data file more than once.
type SealedKeyObject struct {
	data *tpmKeyData
}

// Version returns the version number that this sealed key object was created with.
func (k *SealedKeyObject) Version() uint32 {
	return k.data.version
}

// AuthMode2F indicates the 2nd-factor authentication type for this sealed key object.
func (k *SealedKeyObject) AuthMode2F() AuthMode {
	if k.data.authModeHint == authModePIN {
		return AuthModePassphrase
	}
	return AuthModeNone
}

// PCRPolicyCounterHandle indicates the handle of the NV counter used for PCR policy revocation for this sealed key object (and for
// PIN integration for version 0 key files).
func (k *SealedKeyObject) PCRPolicyCounterHandle() tpm2.Handle {
	return k.data.staticPolicyData.pcrPolicyCounterHandle
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
