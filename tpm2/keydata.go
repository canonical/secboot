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
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
)

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

// keyData represents the actual data for a SealedKeyData or legacy SealedKeyObject.
type keyData interface {
	// Version is the metadata version. Note that the keyData
	// implementation is not responsible for serializing this.
	Version() uint32

	Private() tpm2.Private        // Private area of sealed key object
	SetPrivate(priv tpm2.Private) // Update the private area of sealed key object

	Public() *tpm2.Public // Public area of sealed key object

	// ImportSymSeed is the encrypted seed used for importing the
	// sealed key object. This will be nil if the sealed object does
	// not need to be imported.
	ImportSymSeed() tpm2.EncryptedSecret

	// Imported indicates that the sealed key object has been imported,
	// and that the keyData implementation should update its private
	// area and clear the encrypted import seed.
	Imported(priv tpm2.Private)

	// ValidateData performs consistency checks on the key data,
	// returning a validated context for the PCR policy counter, if
	// one is defined.
	ValidateData(tpm *tpm2.TPMContext, role []byte, session tpm2.SessionContext) (tpm2.ResourceContext, error)

	// Write serializes the key data to w
	Write(w io.Writer) error

	// Policy corresponds to the authorization policy for this key data.
	Policy() keyDataPolicy

	// Decrypt performs authenticated decryption of the encrypted payload and the associated data.
	// This is relevant only for keydata versions 3 and later.
	Decrypt(key, payload []byte, baseVersion uint32, kdfAlg tpm2.HashAlgorithmId, authMode secboot.AuthMode) ([]byte, error)
}

func readKeyData(r io.Reader, version uint32) (keyData, error) {
	switch version {
	case 0:
		return readKeyDataV0(r)
	case 1:
		return readKeyDataV1(r)
	case 2:
		return readKeyDataV2(r)
	case 3:
		return readKeyDataV3(r)
	default:
		return nil, fmt.Errorf("unexpected version number (%d)", version)
	}
}

func newKeyData(keyPrivate tpm2.Private, keyPublic *tpm2.Public, importSymSeed tpm2.EncryptedSecret, policy keyDataPolicy) (keyData, error) {
	switch p := policy.(type) {
	case *keyDataPolicy_v3:
		return &keyData_v3{
			KeyPrivate:       keyPrivate,
			KeyPublic:        keyPublic,
			KeyImportSymSeed: importSymSeed,
			PolicyData:       p}, nil
	case *keyDataPolicy_v2:
		return &keyData_v2{
			KeyPrivate:       keyPrivate,
			KeyPublic:        keyPublic,
			KeyImportSymSeed: importSymSeed,
			PolicyData:       p}, nil
	// v1 and v2 are the same. Always return v2 from here, as it's automatically
	// downgraded to v1 when serialized if it is not importable
	// case *keyDataPolicy_v1:
	case *keyDataPolicy_v0:
		return nil, errors.New("no support for creating v0 keys")
	default:
		panic("invalid policy")
	}
}

type sealedKeyDataBase struct {
	data keyData
}

// ensureImported will import the sealed key object into the TPM's storage hierarchy if
// required, as indicated by an import symmetric seed of non-zero length. The tpmKeyData
// structure will be updated with the newly imported private area and the import
// symmetric seed will be cleared.
func (k *sealedKeyDataBase) ensureImported(tpm *tpm2.TPMContext, parent tpm2.ResourceContext, session tpm2.SessionContext) error {
	if len(k.data.ImportSymSeed()) == 0 {
		return nil
	}

	priv, err := tpm.Import(parent, nil, k.data.Public(), k.data.Private(), k.data.ImportSymSeed(), nil, session)
	if err != nil {
		return err
	}

	k.data.Imported(priv)
	return nil
}

// load loads the TPM sealed object associated with this keyData in to the storage hierarchy of the TPM, and returns the newly
// created tpm2.ResourceContext.
func (k *sealedKeyDataBase) load(tpm *tpm2.TPMContext, parent tpm2.ResourceContext, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	if err := k.ensureImported(tpm, parent, session); err != nil {
		return nil, err
	}

	return tpm.Load(parent, k.data.Private(), k.data.Public(), session)
}

// validateData performs correctness checks on this object.
func (k *sealedKeyDataBase) validateData(tpm *tpm2.TPMContext, role string, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	sealedKeyTemplate := makeImportableSealedKeyTemplate()

	// Perform some initial checks on the sealed data object's public area to
	// make sure it's a sealed data object.
	if k.data.Public().Type != sealedKeyTemplate.Type {
		return nil, keyDataError{errors.New("sealed key object has the wrong type")}
	}
	if k.data.Public().Attrs&^(tpm2.AttrFixedTPM|tpm2.AttrFixedParent) != sealedKeyTemplate.Attrs {
		return nil, keyDataError{errors.New("sealed key object has the wrong attributes")}
	}

	srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	// Load the sealed data object in to the TPM for integrity checking
	keyContext, err := k.load(tpm, srk, session)
	switch {
	case isLoadInvalidParamError(err) || isImportInvalidParamError(err):
		return nil, keyDataError{xerrors.Errorf("cannot load sealed key object into TPM (sealed key object is bad or TPM owner has changed): %w", err)}
	case err != nil:
		return nil, xerrors.Errorf("cannot load sealed key object into TPM: %w", err)
	}
	// It's loaded ok, so we know that the private and public parts are consistent.
	tpm.FlushContext(keyContext)

	// Version specific validation.
	pcrPolicyCounter, err := k.data.ValidateData(tpm, []byte(role), session)
	if err != nil {
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

// SealedKeyData corresponds to a sealed key data object created by
// [ProtectKeyWithTPM], [ProtectKeysWithTPM], or [ProtectKeyWithExternalStorageKey].
type SealedKeyData struct {
	sealedKeyDataBase
	k *secboot.KeyData
}

// NewSealedKeyData returns a SealedKeyData from the supplied secboot.KeyData
// object.
func NewSealedKeyData(k *secboot.KeyData) (*SealedKeyData, error) {
	var skd *SealedKeyData
	if err := k.UnmarshalPlatformHandle(&skd); err != nil {
		return nil, InvalidKeyDataError{err.Error()}
	}
	skd.k = k

	return skd, nil
}

// Version returns the version number that this sealed key object was created with.
func (k *SealedKeyData) Version() uint32 {
	return k.data.Version()
}

// PCRPolicyCounterHandle indicates the handle of the NV counter used for PCR policy revocation for this sealed key object (and for
// PIN integration for version 0 key files).
func (k *SealedKeyData) PCRPolicyCounterHandle() tpm2.Handle {
	return k.data.Policy().PCRPolicyCounterHandle()
}

func (k *SealedKeyData) MarshalJSON() ([]byte, error) {
	w := new(bytes.Buffer)
	if _, err := mu.MarshalToWriter(w, k.data.Version()); err != nil {
		return nil, err
	}
	if err := k.data.Write(w); err != nil {
		return nil, err
	}
	return json.Marshal(w.Bytes())
}

func (k *SealedKeyData) UnmarshalJSON(data []byte) error {
	var b []byte
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}

	r := bytes.NewReader(b)

	var version uint32
	if _, err := mu.UnmarshalFromReader(r, &version); err != nil {
		return err
	}

	kd, err := readKeyData(r, version)
	if err != nil {
		return err
	}

	k.data = kd
	return nil
}
