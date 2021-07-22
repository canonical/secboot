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

package tpm2

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
	"github.com/canonical/go-tpm2/util"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"

	"maze.io/x/crypto/afis"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
)

const (
	currentMetadataVersion    uint32 = 2
	keyDataHeader             uint32 = 0x55534b24
	keyPolicyUpdateDataHeader uint32 = 0x55534b50
)

// PolicyAuthKey corresponds to the private part of the key used for signing updates to the authorization policy for a sealed key.
type PolicyAuthKey []byte

type sealedData struct {
	Key            []byte
	AuthPrivateKey PolicyAuthKey
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
	Unused            uint8 // previously AuthModeHint
	StaticPolicyData  *staticPolicyDataRaw_v0
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

// keyDataRaw_v1 is version 1 of the on-disk format of keyDataRaw.
type keyDataRaw_v1 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	Unused            uint8 // previously AuthModeHint
	StaticPolicyData  *staticPolicyDataRaw_v1
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

// keyDataRaw_v2 is version 2 of the on-disk format of keyDataRaw.
type keyDataRaw_v2 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	Unused            uint8 // previously AuthModeHint
	ImportSymSeed     tpm2.EncryptedSecret
	StaticPolicyData  *staticPolicyDataRaw_v1
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

// for executing authorization policy assertions.
// XXX: This is temporarily named keyData until this code is moved in to secboot/tpm
type keyData struct {
	version           uint32
	keyPrivate        tpm2.Private
	keyPublic         *tpm2.Public
	importSymSeed     tpm2.EncryptedSecret
	staticPolicyData  *staticPolicyData
	dynamicPolicyData *dynamicPolicyData
}

func (d keyData) Marshal(w io.Writer) error {
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
			StaticPolicyData:  makeStaticPolicyDataRaw_v0(d.staticPolicyData),
			DynamicPolicyData: makeDynamicPolicyDataRaw_v0(d.dynamicPolicyData)}
		if _, err := mu.MarshalToWriter(w, raw); err != nil {
			return xerrors.Errorf("cannot marshal raw data: %w", err)
		}
	case 2:
		raw := keyDataRaw_v2{
			KeyPrivate:        d.keyPrivate,
			KeyPublic:         d.keyPublic,
			ImportSymSeed:     d.importSymSeed,
			StaticPolicyData:  makeStaticPolicyDataRaw_v1(d.staticPolicyData),
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
			version:           version,
			keyPrivate:        raw.KeyPrivate,
			keyPublic:         raw.KeyPublic,
			staticPolicyData:  raw.StaticPolicyData.data(),
			dynamicPolicyData: raw.DynamicPolicyData.data()}
	case 1:
		var raw keyDataRaw_v1
		if _, err := mu.UnmarshalFromReader(r, &raw); err != nil {
			return xerrors.Errorf("cannot unmarshal data: %w", err)
		}
		*d = keyData{
			version:           version,
			keyPrivate:        raw.KeyPrivate,
			keyPublic:         raw.KeyPublic,
			staticPolicyData:  raw.StaticPolicyData.data(),
			dynamicPolicyData: raw.DynamicPolicyData.data()}
	case 2:
		var raw keyDataRaw_v2
		if _, err := mu.UnmarshalFromReader(r, &raw); err != nil {
			return xerrors.Errorf("cannot unmarshal data: %w", err)
		}
		*d = keyData{
			version:           version,
			keyPrivate:        raw.KeyPrivate,
			keyPublic:         raw.KeyPublic,
			importSymSeed:     raw.ImportSymSeed,
			staticPolicyData:  raw.StaticPolicyData.data(),
			dynamicPolicyData: raw.DynamicPolicyData.data()}
	default:
		return fmt.Errorf("unexpected version number (%d)", version)
	}
	return nil
}

// ensureImported will import the sealed key object into the TPM's storage hierarchy if
// required, as indicated by an import symmetric seed of non-zero length. The tpmKeyData
// structure will be updated with the newly imported private area and the import
// symmetric seed will be cleared.
func (d *keyData) ensureImported(tpm *tpm2.TPMContext, parent tpm2.ResourceContext, session tpm2.SessionContext) error {
	if len(d.importSymSeed) == 0 {
		return nil
	}

	priv, err := tpm.Import(parent, nil, d.keyPublic, d.keyPrivate, d.importSymSeed, nil, session)
	if err != nil {
		return err
	}

	d.keyPrivate = priv
	d.importSymSeed = nil

	return nil
}

// load loads the TPM sealed object associated with this keyData in to the storage hierarchy of the TPM, and returns the newly
// created tpm2.ResourceContext.
func (d *keyData) load(tpm *tpm2.TPMContext, parent tpm2.ResourceContext, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	if err := d.ensureImported(tpm, parent, session); err != nil {
		return nil, err
	}

	return tpm.Load(parent, d.keyPrivate, d.keyPublic, session)
}

// validate performs some correctness checking on the provided keyData and authKey. On success, it returns the validated public area
// for the PCR policy counter.
func (d *keyData) validate(tpm *tpm2.TPMContext, authKey crypto.PrivateKey, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	if d.version > currentMetadataVersion {
		return nil, keyDataError{errors.New("invalid metadata version")}
	}

	sealedKeyTemplate := makeImportableSealedKeyTemplate()

	keyPublic := d.keyPublic

	// Perform some initial checks on the sealed data object's public area
	if keyPublic.Type != sealedKeyTemplate.Type {
		return nil, keyDataError{errors.New("sealed key object has the wrong type")}
	}
	if keyPublic.Attrs&^(tpm2.AttrFixedTPM|tpm2.AttrFixedParent) != sealedKeyTemplate.Attrs {
		return nil, keyDataError{errors.New("sealed key object has the wrong attributes")}
	}

	srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	// Load the sealed data object in to the TPM for integrity checking
	keyContext, err := d.load(tpm, srk, session)
	switch {
	case isLoadInvalidParamError(err) || isImportInvalidParamError(err):
		return nil, keyDataError{xerrors.Errorf("cannot load sealed key object into TPM (sealed key object is bad or TPM owner has changed): %w", err)}
	case err != nil:
		return nil, xerrors.Errorf("cannot load sealed key object into TPM: %w", err)
	}
	// It's loaded ok, so we know that the private and public parts are consistent.
	tpm.FlushContext(keyContext)

	var legacyLockIndexName tpm2.Name
	if d.version == 0 {
		index, err := tpm.CreateResourceContextFromTPM(lockNVHandle, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			if tpm2.IsResourceUnavailableError(err, lockNVHandle) {
				return nil, keyDataError{errors.New("lock NV index is unavailable")}
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
		return nil, keyDataError{errors.New("PCR policy counter handle is invalid")}
	}

	var pcrPolicyCounter tpm2.ResourceContext
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		pcrPolicyCounter, err = tpm.CreateResourceContextFromTPM(pcrPolicyCounterHandle, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			if tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle) {
				return nil, keyDataError{errors.New("PCR policy counter is unavailable")}
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
		return nil, keyDataError{xerrors.Errorf("cannot compute name of dynamic authorization policy key: %w", err)}
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
		return nil, keyDataError{errors.New("public area of dynamic authorization policy signing key has the wrong type")}
	}
	authKeyScheme := authPublicKey.Params.AsymDetail(authPublicKey.Type).Scheme
	if authKeyScheme.Scheme != tpm2.AsymSchemeNull {
		if authKeyScheme.Scheme != expectedAuthKeyScheme {
			return nil, keyDataError{errors.New("dynamic authorization policy signing key has unexpected scheme")}
		}
		if authKeyScheme.Details.Any(authKeyScheme.Scheme).HashAlg != authPublicKey.NameAlg {
			return nil, keyDataError{errors.New("dynamic authorization policy signing key algorithm must match name algorithm")}
		}
	}

	// Make sure that the static authorization policy data is consistent with the sealed key object's policy.
	if !keyPublic.NameAlg.Available() {
		return nil, keyDataError{errors.New("cannot determine if static authorization policy matches sealed key object: algorithm unavailable")}
	}
	trial := util.ComputeAuthPolicy(keyPublic.NameAlg)

	trial.PolicyAuthorize(pcrPolicyRef, authKeyName)
	if d.version == 0 {
		trial.PolicySecret(pcrPolicyCounter.Name(), nil)
		trial.PolicyNV(legacyLockIndexName, nil, 0, tpm2.OpEq)
	} else {
		// v1 metadata and later
		trial.PolicyAuthValue()
	}

	if !bytes.Equal(trial.GetDigest(), keyPublic.AuthPolicy) {
		return nil, keyDataError{errors.New("the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")}
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
		if !pcrPolicyCounterPub.NameAlg.Available() {
			return nil, keyDataError{errors.New("cannot determine if PCR policy counter has a valid authorization policy: algorithm unavailable")}
		}

		pcrPolicyCounterAuthPolicies := d.staticPolicyData.v0PinIndexAuthPolicies
		expectedPcrPolicyCounterAuthPolicies := computeV0PinNVIndexPostInitAuthPolicies(pcrPolicyCounterPub.NameAlg, authKeyName)
		if len(pcrPolicyCounterAuthPolicies)-1 != len(expectedPcrPolicyCounterAuthPolicies) {
			return nil, keyDataError{errors.New("unexpected number of OR policy digests for PCR policy counter")}
		}
		for i, expected := range expectedPcrPolicyCounterAuthPolicies {
			if !bytes.Equal(expected, pcrPolicyCounterAuthPolicies[i+1]) {
				return nil, keyDataError{errors.New("unexpected OR policy digest for PCR policy counter")}
			}
		}

		trial = util.ComputeAuthPolicy(pcrPolicyCounterPub.NameAlg)
		trial.PolicyOR(pcrPolicyCounterAuthPolicies)
		if !bytes.Equal(pcrPolicyCounterPub.AuthPolicy, trial.GetDigest()) {
			return nil, keyDataError{errors.New("PCR policy counter has unexpected authorization policy")}
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
			return nil, keyDataError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
		}
	case *ecdsa.PrivateKey:
		if d.version == 0 {
			return nil, keyDataError{errors.New("unexpected dynamic authorization policy signing private key type")}
		}
		expectedX, expectedY := k.Curve.ScalarBaseMult(k.D.Bytes())
		if expectedX.Cmp(k.X) != 0 || expectedY.Cmp(k.Y) != 0 {
			return nil, keyDataError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
		}
	case nil:
	default:
		return nil, keyDataError{errors.New("unexpected dynamic authorization policy signing private key type")}
	}

	return pcrPolicyCounterPub, nil
}

type keyDataError struct {
	err error
}

func (e keyDataError) Error() string {
	return e.err.Error()
}

func (e keyDataError) Unwrap() error {
	return e.err
}

func isKeyDataError(err error) bool {
	var e keyDataError
	return xerrors.As(err, &e)
}

// SealedKeyObject corresponds to a sealed key data file.
type SealedKeyObject struct {
	data *keyData
}

// Version returns the version number that this sealed key object was created with.
func (k *SealedKeyObject) Version() uint32 {
	return k.data.version
}

// PCRPolicyCounterHandle indicates the handle of the NV counter used for PCR policy revocation for this sealed key object (and for
// PIN integration for version 0 key files).
func (k *SealedKeyObject) PCRPolicyCounterHandle() tpm2.Handle {
	return k.data.staticPolicyData.pcrPolicyCounterHandle
}

// WriteAtomic will serialize this SealedKeyObject to the supplied writer.
func (k *SealedKeyObject) WriteAtomic(w secboot.KeyDataWriter) error {
	if _, err := mu.MarshalToWriter(w, k.data); err != nil {
		return err
	}
	return w.Commit()
}

// ReadSealedKeyObject reads a SealedKeyObject from the supplied io.Reader. If it
// cannot be correctly decoded, an InvalidKeyDataError error will be returned.
func ReadSealedKeyObject(r io.Reader) (*SealedKeyObject, error) {
	ko := new(SealedKeyObject)
	if _, err := mu.UnmarshalFromReader(r, &ko.data); err != nil {
		return nil, InvalidKeyDataError{err.Error()}
	}
	return ko, nil
}

type fileKeyDataHdr struct {
	Magic   uint32
	Version uint32
}

type stripedFileKeyDataHdr struct {
	Stripes uint32
	HashAlg tpm2.HashAlgorithmId
	Size    uint32
}

// NewFileSealedKeyObjectReader creates an io.Reader from the file at the specified
// path that can be passed to ReadSealedKeyObject. The file will have been previously
// created by SealKeyToTPM. If the file cannot be opened, an *os.PathError error will
// be returned.
//
// This function decodes part of the metadata specific to key files. If this fails,
// an InvalidKeyDataError error will be returned.
func NewFileSealedKeyObjectReader(path string) (io.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// v0 files contain the following structure:
	//  magic   uint32 // 0x55534b24
	//  version uint32 // 0
	//  data    []byte
	//
	// post-v0 files contain the following structure:
	//  magic	uint32 // 0x55534b24
	//  version	uint32
	//  stripes	uint32
	//  hashAlg	tpm2.HashAlgorithmId
	//  size	uint32
	//  stripedData [size]byte
	//
	// We want to use the version field to encode the keyData structure
	// version for all sources, but we only want to use the AF splitter
	// for files. Ideally the key data version would be after the afis
	// header, but it isn't. We do some manipulation here to move it so
	// that the keyData unmarshaller can access it.

	var hdr fileKeyDataHdr
	if _, err := mu.UnmarshalFromReader(f, &hdr); err != nil {
		return nil, InvalidKeyDataError{fmt.Sprintf("cannot unmarshal file header: %v", err)}
	}

	if hdr.Magic != keyDataHeader {
		return nil, InvalidKeyDataError{fmt.Sprintf("unexpected magic (%d)", hdr.Magic)}
	}

	// Prepare a buffer for unmarshalling keyData.
	buf := new(bytes.Buffer)
	mu.MarshalToWriter(buf, hdr.Version)

	if hdr.Version == 0 {
		if _, err := io.Copy(buf, f); err != nil {
			return nil, InvalidKeyDataError{fmt.Sprintf("cannot read data: %v", err)}
		}
		return buf, nil
	}

	var afisHdr stripedFileKeyDataHdr
	if _, err := mu.UnmarshalFromReader(f, &afisHdr); err != nil {
		return nil, InvalidKeyDataError{fmt.Sprintf("cannot unmarshal AFIS header: %v", err)}
	}

	if afisHdr.Stripes == 0 {
		return nil, InvalidKeyDataError{"invalid number of stripes"}
	}
	if !afisHdr.HashAlg.Available() {
		return nil, InvalidKeyDataError{"digest algorithm unavailable"}
	}

	data := make([]byte, afisHdr.Size)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, InvalidKeyDataError{fmt.Sprintf("cannot read striped data: %v", err)}
	}

	merged, err := afis.MergeHash(data, int(afisHdr.Stripes), func() hash.Hash { return afisHdr.HashAlg.NewHash() })
	if err != nil {
		return nil, InvalidKeyDataError{fmt.Sprintf("cannot merge data: %v", err)}
	}

	if _, err := buf.Write(merged); err != nil {
		return nil, err
	}

	return buf, nil
}

type FileSealedKeyObjectWriter struct {
	*bytes.Buffer
	path string
}

func (w *FileSealedKeyObjectWriter) Commit() (err error) {
	f, err := osutil.NewAtomicFile(w.path, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Cancel()
		} else {
			err = f.Commit()
		}
	}()

	hdr := fileKeyDataHdr{Magic: keyDataHeader}
	if _, err := mu.UnmarshalFromReader(w, &hdr.Version); err != nil {
		return err
	}

	if _, err := mu.MarshalToWriter(f, &hdr); err != nil {
		return err
	}

	if hdr.Version == 0 {
		if _, err := io.Copy(f, w); err != nil {
			return err
		}

		return nil
	}

	stripes := uint32((128 * 1024 / w.Len()) + 1)

	data, err := afis.SplitHash(w.Bytes(), int(stripes), func() hash.Hash { return crypto.SHA256.New() })
	if err != nil {
		return err
	}

	afisHdr := stripedFileKeyDataHdr{
		Stripes: stripes,
		HashAlg: tpm2.HashAlgorithmSHA256,
		Size:    uint32(len(data))}
	if _, err := mu.MarshalToWriter(f, &afisHdr); err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		return err
	}

	return nil
}

// NewFileSealedKeyObjectWriter creates a new writer for atomically updating a sealed key
// data file using SealedKeyObject.WriteAtomic.
func NewFileSealedKeyObjectWriter(path string) *FileSealedKeyObjectWriter {
	return &FileSealedKeyObjectWriter{new(bytes.Buffer), path}
}

// ReadSealedKeyObjectFromFile reads a SealedKeyObject from the file created by SealKeyToTPM at the specified path.
// If the file cannot be opened, an *os.PathError error is returned. If the file cannot be deserialized successfully,
// an InvalidKeyDataError error will be returned.
func ReadSealedKeyObjectFromFile(path string) (*SealedKeyObject, error) {
	r, err := NewFileSealedKeyObjectReader(path)
	if err != nil {
		return nil, err
	}
	return ReadSealedKeyObject(r)
}
