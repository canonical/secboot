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
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"

	"maze.io/x/crypto/afis"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
)

const (
	currentMetadataVersion uint32 = 2
	keyDataHeader          uint32 = 0x55534b24
)

// PolicyAuthKey corresponds to the private part of the key used for signing updates to the authorization policy for a sealed key.
type PolicyAuthKey []byte

type sealedData struct {
	Key            []byte
	AuthPrivateKey PolicyAuthKey
}

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

type keyDataValidator interface {
	validateData(tpm *tpm2.TPMContext, pcrPolicyCounter tpm2.ResourceContext, session tpm2.SessionContext) error
	validateAuthKey(key crypto.PrivateKey) error
}

type keyDataValidatorInvalidVersion struct{}

func (v keyDataValidatorInvalidVersion) validateData(tpm *tpm2.TPMContext, pcrPolicyCounter tpm2.ResourceContext, session tpm2.SessionContext) error {
	return keyDataError{errors.New("invalid metadata version")}
}

func (v keyDataValidatorInvalidVersion) validateAuthKey(key crypto.PrivateKey) error {
	return keyDataError{errors.New("invalid metadata version")}
}

func newKeyDataValidator(version uint32, priv tpm2.Private, pub *tpm2.Public, static *staticPolicyData) keyDataValidator {
	switch version {
	case 0:
		return newKeyDataValidatorV0(priv, pub, static)
	case 1:
		return newKeyDataValidatorV1(priv, pub, static)
	case 2:
		return newKeyDataValidatorV2(priv, pub, static)
	default:
		return keyDataValidatorInvalidVersion{}
	}
}

// SealedKeyObject corresponds to a sealed key data file.
type SealedKeyObject struct {
	data      *keyData
	validator keyDataValidator
}

func newSealedKeyObject(data *keyData) *SealedKeyObject {
	return &SealedKeyObject{
		data:      data,
		validator: newKeyDataValidator(data.version, data.keyPrivate, data.keyPublic, data.staticPolicyData)}
}

// ensureImported will import the sealed key object into the TPM's storage hierarchy if
// required, as indicated by an import symmetric seed of non-zero length. The tpmKeyData
// structure will be updated with the newly imported private area and the import
// symmetric seed will be cleared.
func (k *SealedKeyObject) ensureImported(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	if len(k.data.importSymSeed) == 0 {
		return nil
	}

	srkContext, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		return xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	priv, err := tpm.Import(srkContext, nil, k.data.keyPublic, k.data.keyPrivate, k.data.importSymSeed, nil, session)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandImport, tpm2.AnyParameterIndex) {
			return keyDataError{errors.New("cannot import sealed key object in to TPM: bad sealed key object, invalid symmetric seed, TPM owner changed or wrong TPM")}
		}
		return xerrors.Errorf("cannot import sealed key object in to TPM: %w", err)
	}

	k.data.keyPrivate = priv
	k.data.importSymSeed = nil

	return nil
}

// load loads the TPM sealed object associated with this keyData in to the storage hierarchy of the TPM, and returns the newly
// created tpm2.ResourceContext.
func (k *SealedKeyObject) load(tpm *tpm2.TPMContext, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	if err := k.ensureImported(tpm, session); err != nil {
		return nil, err
	}

	srkContext, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	keyContext, err := tpm.Load(srkContext, k.data.keyPrivate, k.data.keyPublic, session)
	if err != nil {
		invalidObject := false
		switch {
		case tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandLoad, tpm2.AnyParameterIndex):
			invalidObject = true
		case tpm2.IsTPMError(err, tpm2.ErrorSensitive, tpm2.CommandLoad):
			invalidObject = true
		}
		if invalidObject {
			return nil, keyDataError{errors.New("cannot load sealed key object in to TPM: bad sealed key object or TPM owner changed")}
		}
		return nil, xerrors.Errorf("cannot load sealed key object in to TPM: %w", err)
	}

	return keyContext, nil
}

// validateData performs correctness checks on this object.
func (k *SealedKeyObject) validateData(tpm *tpm2.TPMContext, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	sealedKeyTemplate := makeImportableSealedKeyTemplate()

	// Perform some initial checks on the sealed data object's public area to
	// make sure it's a sealed data object.
	if k.data.keyPublic.Type != sealedKeyTemplate.Type {
		return nil, keyDataError{errors.New("sealed key object has the wrong type")}
	}
	if k.data.keyPublic.Attrs&^(tpm2.AttrFixedTPM|tpm2.AttrFixedParent) != sealedKeyTemplate.Attrs {
		return nil, keyDataError{errors.New("sealed key object has the wrong attributes")}
	}

	// Load the sealed data object in to the TPM for integrity checking.
	keyContext, err := k.load(tpm, session)
	if err != nil {
		return nil, err
	}
	// It's loaded ok, so we know that the private and public parts are consistent.
	tpm.FlushContext(keyContext)

	// Create a context for the PCR policy counter.
	pcrPolicyCounterHandle := k.data.staticPolicyData.pcrPolicyCounterHandle
	var pcrPolicyCounter tpm2.ResourceContext
	if pcrPolicyCounterHandle.Type() == tpm2.HandleTypeNVIndex {
		pcrPolicyCounter, err = tpm.CreateResourceContextFromTPM(pcrPolicyCounterHandle, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			if tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle) {
				return nil, keyDataError{errors.New("PCR policy counter is unavailable")}
			}
			return nil, xerrors.Errorf("cannot create context for PCR policy counter: %w", err)
		}
	}

	// Version specific validation.
	if err := k.validator.validateData(tpm, pcrPolicyCounter, session); err != nil {
		return nil, err
	}

	if pcrPolicyCounter == nil {
		return nil, nil
	}

	// Read the public area of the PCR policy counter.
	pcrPolicyCounterPub, name, err := tpm.NVReadPublic(pcrPolicyCounter)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of PCR policy counter: %w", err)
	}
	if !bytes.Equal(name, pcrPolicyCounter.Name()) {
		return nil, errors.New("invalid PCR policy counter public area")
	}

	return pcrPolicyCounterPub, nil
}

// validateAuthKey checks that the supplied auth key is correct for this object.
func (k *SealedKeyObject) validateAuthKey(key crypto.PrivateKey) error {
	return k.validator.validateAuthKey(key)
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
	var data *keyData
	if _, err := mu.UnmarshalFromReader(r, &data); err != nil {
		return nil, InvalidKeyDataError{err.Error()}
	}
	return newSealedKeyObject(data), nil
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
