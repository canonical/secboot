// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"

	drbg "github.com/canonical/go-sp800.90a-drbg"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/xerrors"
)

const (
	kdfType                            = "argon2i"
	nilHash                    hashAlg = 0
	passphraseEncryptionKeyLen         = 32
	passphraseEncryption               = "aes-cfb"
)

var (
	snapModelHMACKDFLabel = []byte("SNAP-MODEL-HMAC")
	sha1Oid               = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	sha224Oid             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	sha256Oid             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sha384Oid             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	sha512Oid             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// ErrNoPlatformHandlerRegistered is returned from KeyData methods if no
// appropriate platform handler is registered using the
// RegisterPlatformKeyDataHandler API.
var ErrNoPlatformHandlerRegistered = errors.New("no appropriate platform handler is registered")

// ErrInvalidPassphrase is returned from KeyData methods that require
// knowledge of a passphrase is the supplied passphrase is incorrect.
var ErrInvalidPassphrase = errors.New("the supplied passphrase is incorrect")

// InvalidKeyDataError is returned from KeyData methods if the key data
// is invalid in some way.
type InvalidKeyDataError struct {
	err error
}

func (e *InvalidKeyDataError) Error() string {
	return fmt.Sprintf("invalid key data: %v", e.err)
}

func (e *InvalidKeyDataError) Unwrap() error {
	return e.err
}

// PlatformUninitializedError is returned from KeyData methods if the
// platform's secure device has not been initialized properly.
type PlatformUninitializedError struct {
	err error
}

func (e *PlatformUninitializedError) Error() string {
	return fmt.Sprintf("the platform's secure device is not properly initialized: %v", e.err)
}

func (e *PlatformUninitializedError) Unwrap() error {
	return e.err
}

// PlatformDeviceUnavailableError is returned from KeyData methods if the
// platform's secure device is currently unavailable.
type PlatformDeviceUnavailableError struct {
	err error
}

func (e *PlatformDeviceUnavailableError) Error() string {
	return fmt.Sprintf("the platform's secure device is unavailable: %v", e.err)
}

func (e *PlatformDeviceUnavailableError) Unwrap() error {
	return e.err
}

// DiskUnlockKey is the key used to unlock a LUKS volume.
type DiskUnlockKey []byte

// PrimaryKey is an additional key used to modify properties of a KeyData
// object without having to create a new object.
type PrimaryKey []byte

// KeyPayload is the payload that should be encrypted by a platform's secure device.
type KeyPayload []byte

// Unmarshal obtains the keys from this payload.
func (c KeyPayload) Unmarshal() (key DiskUnlockKey, auxKey PrimaryKey, err error) {
	r := bytes.NewReader(c)

	var sz uint16
	if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
		return nil, nil, err
	}

	if sz > 0 {
		key = make(DiskUnlockKey, sz)
		if _, err := r.Read(key); err != nil {
			return nil, nil, err
		}
	}

	if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
		return nil, nil, err
	}

	if sz > 0 {
		auxKey = make(PrimaryKey, sz)
		if _, err := r.Read(auxKey); err != nil {
			return nil, nil, err
		}
	}

	if r.Len() > 0 {
		return nil, nil, fmt.Errorf("%v excess byte(s)", r.Len())
	}

	return
}

// AuthMode corresponds to a set of authentication mechanisms.
type AuthMode uint32

const (
	AuthModeNone       AuthMode = 0
	AuthModePassphrase AuthMode = 1 << iota
)

// KeyParams provides parameters required to create a new KeyData object.
// It should be produced by a platform implementation.
type KeyParams struct {
	// Handle contains metadata required by the platform in order to recover
	// this key. It is opaque to this go package. It should be a value that can
	// be encoded to JSON using go's encoding/json package, which could be
	// something as simple as binary data stored in a byte slice or a more complex
	// JSON object, depending on the requirements of the implementation. A handle
	// already encoded to JSON can be supplied using the json.RawMessage type.
	Handle interface{}

	EncryptedPayload []byte // The encrypted payload
	PlatformName     string // Name of the platform that produced this data

	// PrimaryKey is a key used to authorize changes to the key data.
	// It must match the key protected inside PlatformKeyData.EncryptedPayload.
	PrimaryKey PrimaryKey

	// SnapModelAuthHash is the digest algorithm used for HMACs of Snap
	// device models, and also the digest algorithm used to produce the
	// key digest.
	SnapModelAuthHash crypto.Hash
}

// KeyID is the unique ID for a KeyData object. It is used to facilitate the
// sharing of state between the early boot environment and OS runtime.
type KeyID []byte

// KeyDataWriter is an interface used by KeyData to write the data to
// persistent storage in an atomic way.
type KeyDataWriter interface {
	io.Writer
	Commit() error
}

// KeyDataReader is an interface used to read and decode a KeyData
// from persistent storage.
type KeyDataReader interface {
	io.Reader
	ReadableName() string
}

// hashAlg corresponds to a digest algorithm.
type hashAlg crypto.Hash

func (a hashAlg) Available() bool {
	return crypto.Hash(a).Available()
}

func (a hashAlg) New() hash.Hash {
	return crypto.Hash(a).New()
}

func (a hashAlg) Size() int {
	return crypto.Hash(a).Size()
}

func (a hashAlg) MarshalJSON() ([]byte, error) {
	var s string

	switch crypto.Hash(a) {
	case crypto.SHA1:
		s = "sha1"
	case crypto.SHA224:
		s = "sha224"
	case crypto.SHA256:
		s = "sha256"
	case crypto.SHA384:
		s = "sha384"
	case crypto.SHA512:
		s = "sha512"
	case crypto.Hash(nilHash):
		s = "null"
	default:
		return nil, fmt.Errorf("unknown hash algorithm: %v", crypto.Hash(a))
	}

	return json.Marshal(s)
}

func (a *hashAlg) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	switch s {
	case "sha1":
		*a = hashAlg(crypto.SHA1)
	case "sha224":
		*a = hashAlg(crypto.SHA224)
	case "sha256":
		*a = hashAlg(crypto.SHA256)
	case "sha384":
		*a = hashAlg(crypto.SHA384)
	case "sha512":
		*a = hashAlg(crypto.SHA512)
	default:
		// be permissive here and allow everything to be
		// unmarshalled.
		*a = nilHash
	}

	return nil
}

func (a hashAlg) marshalASN1(b *cryptobyte.Builder) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // AlgorithmIdentifier ::= SEQUENCE {
		var oid asn1.ObjectIdentifier

		switch crypto.Hash(a) {
		case crypto.SHA1:
			oid = sha1Oid
		case crypto.SHA224:
			oid = sha224Oid
		case crypto.SHA256:
			oid = sha256Oid
		case crypto.SHA384:
			oid = sha384Oid
		case crypto.SHA512:
			oid = sha512Oid
		default:
			b.SetError(fmt.Errorf("unknown hash algorithm: %v", crypto.Hash(a)))
			return
		}
		b.AddASN1ObjectIdentifier(oid) // algorithm OBJECT IDENTIFIER
		b.AddASN1NULL()                // parameters ANY DEFINED BY algorithm OPTIONAL
	})
}

type snapModelHMAC []byte

type snapModelHMACList []snapModelHMAC

func (l snapModelHMACList) contains(h snapModelHMAC) bool {
	for _, v := range l {
		if bytes.Equal(v, h) {
			return true
		}
	}
	return false
}

// keyDigest contains a salted digest to verify the correctness of a key.
type keyDigest struct {
	Alg    hashAlg `json:"alg"`
	Salt   []byte  `json:"salt"`
	Digest []byte  `json:"digest"`
}

// hkdfData contains the parameters used to derive a key using HKDF.
type hkdfData struct {
	Alg hashAlg `json:"alg"` // Digest algorithm to use for HKDF
}

type authorizedSnapModelsRaw struct {
	Alg       hashAlg           `json:"alg"`
	KDFAlg    hashAlg           `json:"kdf_alg,omitempty"`
	KeyDigest json.RawMessage   `json:"key_digest"`
	Hmacs     snapModelHMACList `json:"hmacs"`
}

// authorizedSnapModels defines the Snap models that have been
// authorized to access the data protected by a key.
type authorizedSnapModels struct {
	alg       hashAlg           // Digest algorithm used for the authorized model HMACs
	kdfAlg    hashAlg           // Digest algorithm used to derive the HMAC key with HKDF. Zero for legacy (DRBG) derivation.
	keyDigest keyDigest         // information used to validate the correctness of the HMAC key
	hmacs     snapModelHMACList // the list of HMACs of authorized models

	// legacyKeyDigest is true when keyDigest should be marshalled
	// as a plain key rather than a keyDigest object.
	legacyKeyDigest bool
}

// MarshalJSON implements custom marshalling to handle older key data
// objects where the key_digest field was just a base64 encoded key.
func (m authorizedSnapModels) MarshalJSON() ([]byte, error) {
	var digest json.RawMessage
	var err error
	if m.legacyKeyDigest {
		digest, err = json.Marshal(m.keyDigest.Digest)
	} else {
		digest, err = json.Marshal(&m.keyDigest)
	}
	if err != nil {
		return nil, err
	}

	return json.Marshal(&authorizedSnapModelsRaw{
		Alg:       m.alg,
		KDFAlg:    m.kdfAlg,
		KeyDigest: digest,
		Hmacs:     m.hmacs})
}

// UnmarshalJSON implements custom unmarshalling to handle older key data
// objects where the key_digest field was just a base64 encoded key.
func (m *authorizedSnapModels) UnmarshalJSON(b []byte) error {
	var raw authorizedSnapModelsRaw
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	*m = authorizedSnapModels{
		alg:    raw.Alg,
		kdfAlg: raw.KDFAlg,
		hmacs:  raw.Hmacs}

	token, err := json.NewDecoder(bytes.NewReader(raw.KeyDigest)).Token()
	switch {
	case err == io.EOF:
		// Empty field, ignore
		return nil
	case err != nil:
		return err
	}

	switch t := token.(type) {
	case json.Delim:
		// Newer data, where the KeyDigest field is an object.
		if t != '{' {
			return fmt.Errorf("invalid delim (%v) at start of key_digest field", t)
		}
		if err := json.Unmarshal(raw.KeyDigest, &m.keyDigest); err != nil {
			return err
		}
	case string:
		// Older data, where the KeyDigest field was a base64 encoded key.
		// Convert it to an object.
		_ = t
		m.keyDigest.Alg = raw.Alg
		m.legacyKeyDigest = true
		if err := json.Unmarshal(raw.KeyDigest, &m.keyDigest.Digest); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid token (%v) at start of key_digest field", token)
	}

	return nil
}

// kdfData corresponds to the arguments to a KDF and matches the
// corresponding object in the LUKS2 specification.
type kdfData struct {
	Type   string `json:"type"`
	Salt   []byte `json:"salt"`
	Time   int    `json:"time"`
	Memory int    `json:"memory"`
	CPUs   int    `json:"cpus"`
}

// passphraseData is the data associated with a passphrase protected
// key.
type passphraseData struct {
	// KDF contains the key derivation parameters used to derive
	// an encryption key from an input passphrase.
	KDF kdfData `json:"kdf"`

	Encryption string `json:"encryption"` // Encryption algorithm - currently only aes-cfb
	KeySize    int    `json:"key_size"`   // Size of encryption key to derive from passphrase

	// EncryptedPayload is the platform protected payload additionally
	// protected by a passphrase derived key using the parameters
	// of this structure.
	EncryptedPayload []byte `json:"encrypted_payload"`
}

type keyData struct {
	PlatformName string `json:"platform_name"` // used to identify a PlatformKeyDataHandler

	// PlatformHandle is an opaque blob of data used by the associated
	// PlatformKeyDataHandler to recover the cleartext keys from one of
	// the encrypted payloads.
	PlatformHandle json.RawMessage `json:"platform_handle"`

	// EncryptedPayload is the platform protected key payload.
	EncryptedPayload []byte `json:"encrypted_payload,omitempty"`

	// PassphraseProtectedPayload is the platform protected key
	// payload additionally protected by a passphrase.
	PassphraseProtectedPayload *passphraseData `json:"passphrase_protected_payload,omitempty"`

	// AuthorizedSnapModels contains information about the Snap models
	// that have been authorized to access the data protected by this key.
	AuthorizedSnapModels authorizedSnapModels `json:"authorized_snap_models"`
}

func processPlatformHandlerError(err error) error {
	var pe *PlatformHandlerError
	if xerrors.As(err, &pe) {
		switch pe.Type {
		case PlatformHandlerErrorInvalidData:
			return &InvalidKeyDataError{pe.Err}
		case PlatformHandlerErrorUninitialized:
			return &PlatformUninitializedError{pe.Err}
		case PlatformHandlerErrorUnavailable:
			return &PlatformDeviceUnavailableError{pe.Err}
		case PlatformHandlerErrorInvalidAuthKey:
			return ErrInvalidPassphrase
		}
	}

	return xerrors.Errorf("cannot perform action because of an unexpected error: %w", err)
}

// KeyData represents a disk unlock key and auxiliary key protected by a platform's
// secure device.
type KeyData struct {
	readableName string
	data         keyData
}

func (d *KeyData) snapModelAuthKeyLegacy(auxKey PrimaryKey) ([]byte, error) {
	rng, err := drbg.NewCTRWithExternalEntropy(32, auxKey, nil, snapModelHMACKDFLabel, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot instantiate DRBG: %w", err)
	}

	alg := d.data.AuthorizedSnapModels.alg
	if alg == nilHash {
		return nil, errors.New("invalid digest algorithm")
	}

	hmacKey := make([]byte, alg.Size())
	if _, err := rng.Read(hmacKey); err != nil {
		return nil, xerrors.Errorf("cannot derive key: %w", err)
	}

	return hmacKey, nil
}

func (d *KeyData) snapModelAuthKey(auxKey PrimaryKey) ([]byte, error) {
	kdfAlg := d.data.AuthorizedSnapModels.kdfAlg
	if kdfAlg == nilHash {
		return d.snapModelAuthKeyLegacy(auxKey)
	}
	if !kdfAlg.Available() {
		return nil, errors.New("invalid KDF digest algorithm")
	}

	alg := d.data.AuthorizedSnapModels.alg
	if alg == nilHash {
		return nil, errors.New("invalid digest algorithm")
	}

	r := hkdf.Expand(func() hash.Hash { return kdfAlg.New() }, auxKey, snapModelHMACKDFLabel)

	// Derive a key with a length matching the output size of the
	// algorithm used for the HMAC.
	hmacKey := make([]byte, alg.Size())
	if _, err := io.ReadFull(r, hmacKey); err != nil {
		return nil, err
	}

	return hmacKey, nil
}

func (d *KeyData) updatePassphrase(payload, oldKey []byte, passphrase string, kdfOptions *KDFOptions, kdf KDF) error {
	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return ErrNoPlatformHandlerRegistered
	}

	if kdfOptions == nil {
		var defaultOptions KDFOptions
		kdfOptions = &defaultOptions
	}

	// Derive both a key and an IV from the passphrase in a single pass.
	keyLen := passphraseEncryptionKeyLen + aes.BlockSize

	params, err := kdfOptions.deriveCostParams(keyLen, kdf)
	if err != nil {
		return xerrors.Errorf("cannot derive KDF cost parameters: %w", err)
	}

	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return xerrors.Errorf("cannot read salt for new passphrase: %w", err)
	}

	key, err := kdf.Derive(passphrase, salt[:], params, uint32(keyLen))
	if err != nil {
		return xerrors.Errorf("cannot derive key for new passphrase: %w", err)
	}
	if len(key) != keyLen {
		return errors.New("KDF returned unexpected key length")
	}

	handle, err := handler.ChangeAuthKey(d.data.PlatformHandle, oldKey, key)
	if err != nil {
		return err
	}

	c, err := aes.NewCipher(key[:passphraseEncryptionKeyLen])
	if err != nil {
		return xerrors.Errorf("cannot create cipher: %w", err)
	}

	d.data.PlatformHandle = handle
	d.data.PassphraseProtectedPayload = &passphraseData{
		KDF: kdfData{
			Type:   kdfType,
			Salt:   salt[:],
			Time:   int(params.Time),
			Memory: int(params.MemoryKiB),
			CPUs:   int(params.Threads)},
		Encryption:       passphraseEncryption,
		KeySize:          passphraseEncryptionKeyLen,
		EncryptedPayload: make([]byte, len(payload))}

	stream := cipher.NewCFBEncrypter(c, key[passphraseEncryptionKeyLen:])
	stream.XORKeyStream(d.data.PassphraseProtectedPayload.EncryptedPayload, payload)

	return nil
}

func (d *KeyData) openWithPassphrase(passphrase string, kdf KDF) (payload []byte, key []byte, err error) {
	if d.AuthMode()&AuthModePassphrase == 0 {
		return nil, nil, errors.New("passphrase is not enabled")
	}

	data := d.data.PassphraseProtectedPayload
	if data.KDF.Type != kdfType {
		// Only Argon2i is supported
		return nil, nil, fmt.Errorf("unexpected KDF type \"%s\"", data.KDF.Type)
	}
	if data.Encryption != passphraseEncryption {
		// Only AES-CFB is supported
		return nil, nil, fmt.Errorf("unexpected encryption algorithm \"%s\"", data.Encryption)
	}
	if data.KeySize > 32 {
		// The key size can't be larger than 32 with the supported cipher
		return nil, nil, fmt.Errorf("invalid key size (%d bytes)", data.KeySize)
	}

	// Derive both the key and IV from the passphrase in a single pass.
	keyLen := data.KeySize + aes.BlockSize

	params := &KDFCostParams{
		Time:      uint32(data.KDF.Time),
		MemoryKiB: uint32(data.KDF.Memory),
		Threads:   uint8(data.KDF.CPUs)}
	key, err = kdf.Derive(passphrase, data.KDF.Salt, params, uint32(keyLen))
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot derive key from passphrase: %w", err)
	}
	if len(key) != keyLen {
		return nil, nil, errors.New("KDF returned unexpected key length")
	}

	payload = make([]byte, len(data.EncryptedPayload))

	c, err := aes.NewCipher(key[:data.KeySize])
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create cipher: %w", err)
	}
	stream := cipher.NewCFBDecrypter(c, key[data.KeySize:])
	stream.XORKeyStream(payload, data.EncryptedPayload)

	return payload, key, nil
}

// ReadableName returns a human-readable name for this key data, useful for
// including in errors.
func (d *KeyData) ReadableName() string {
	return d.readableName
}

// UniqueID returns the unique ID for this key data.
func (d *KeyData) UniqueID() (KeyID, error) {
	h := crypto.SHA256.New()
	enc := json.NewEncoder(h)
	if err := enc.Encode(&d.data); err != nil {
		return nil, xerrors.Errorf("cannot compute ID: %w", err)
	}
	return KeyID(h.Sum(nil)), nil
}

// AuthMode indicates the authentication mechanisms enabled for this key data.
func (d *KeyData) AuthMode() (out AuthMode) {
	if len(d.data.EncryptedPayload) > 0 {
		return AuthModeNone
	}

	if d.data.PassphraseProtectedPayload != nil {
		out |= AuthModePassphrase
	}

	return out
}

// UnmarshalPlatformHandle unmarshals the JSON platform handle payload into the
// supplied handle, which must be a non-nil pointer.
func (d *KeyData) UnmarshalPlatformHandle(handle interface{}) error {
	if err := json.Unmarshal(d.data.PlatformHandle, handle); err != nil {
		return &InvalidKeyDataError{err}
	}
	return nil
}

// MarshalAndUpdatePlatformHandle marshals the supplied platform handle to JSON and updates
// this KeyData object. The changes will need to persisted afterwards using
// WriteAtomic.
func (d *KeyData) MarshalAndUpdatePlatformHandle(handle interface{}) error {
	b, err := json.Marshal(handle)
	if err != nil {
		return err
	}

	d.data.PlatformHandle = b
	return nil
}

// RecoverKeys recovers the disk unlock key and auxiliary key associated with this
// key data from the platform's secure device, for key data that doesn't have any
// additional authentication modes enabled (AuthMode returns AuthModeNone).
//
// If AuthMode returns anything other than AuthModeNone, then this will return an error.
//
// If no platform handler has been registered for this key data, an
// ErrNoPlatformHandlerRegistered error will be returned.
//
// If the keys cannot be recovered because the key data is invalid, a *InvalidKeyDataError
// error will be returned.
//
// If the keys cannot be recovered because the platform's secure device is not
// properly initialized, a *PlatformUninitializedError error will be returned.
//
// If the keys cannot be recovered because the platform's secure device is not
// available, a *PlatformDeviceUnavailableError error will be returned.
func (d *KeyData) RecoverKeys() (DiskUnlockKey, PrimaryKey, error) {
	if d.AuthMode() != AuthModeNone {
		return nil, nil, errors.New("cannot recover key without authorization")
	}

	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return nil, nil, ErrNoPlatformHandlerRegistered
	}

	c, err := handler.RecoverKeys(&PlatformKeyData{
		EncodedHandle:    d.data.PlatformHandle,
		EncryptedPayload: d.data.EncryptedPayload})
	if err != nil {
		return nil, nil, processPlatformHandlerError(err)
	}

	key, auxKey, err := c.Unmarshal()
	if err != nil {
		return nil, nil, &InvalidKeyDataError{xerrors.Errorf("cannot unmarshal cleartext key payload: %w", err)}
	}

	return key, auxKey, nil
}

func (d *KeyData) RecoverKeysWithPassphrase(passphrase string, kdf KDF) (DiskUnlockKey, PrimaryKey, error) {
	if d.AuthMode()&AuthModePassphrase == 0 {
		return nil, nil, errors.New("no passphrase is set")
	}

	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return nil, nil, ErrNoPlatformHandlerRegistered
	}

	payload, key, err := d.openWithPassphrase(passphrase, kdf)
	if err != nil {
		return nil, nil, err
	}

	data := &PlatformKeyData{
		EncodedHandle:    d.data.PlatformHandle,
		EncryptedPayload: payload}
	c, err := handler.RecoverKeysWithAuthKey(data, key)
	if err != nil {
		return nil, nil, processPlatformHandlerError(err)
	}

	key, auxKey, err := c.Unmarshal()
	if err != nil {
		return nil, nil, &InvalidKeyDataError{xerrors.Errorf("cannot unmarshal cleartext key payload: %w", err)}
	}

	return key, auxKey, nil
}

// IsSnapModelAuthorized indicates whether the supplied Snap device model is trusted to
// access the data on the encrypted volume protected by this key data.
//
// The supplied auxKey is obtained using one of the RecoverKeys* functions.
func (d *KeyData) IsSnapModelAuthorized(auxKey PrimaryKey, model SnapModel) (bool, error) {
	hmacKey, err := d.snapModelAuthKey(auxKey)
	if err != nil {
		return false, xerrors.Errorf("cannot obtain auth key: %w", err)
	}

	alg := d.data.AuthorizedSnapModels.alg
	if !alg.Available() {
		return false, errors.New("invalid digest algorithm")
	}

	h, err := computeSnapModelHMAC(crypto.Hash(alg), hmacKey, model)
	if err != nil {
		return false, xerrors.Errorf("cannot compute HMAC of model: %w", err)
	}

	return d.data.AuthorizedSnapModels.hmacs.contains(h), nil
}

// SetAuthorizedSnapModels marks the supplied Snap device models as trusted to access
// the data on the encrypted volume protected by this key data. This function replaces all
// previously trusted models.
//
// This makes changes to the key data, which will need to persisted afterwards using
// WriteAtomic.
//
// The supplied auxKey is obtained using one of the RecoverKeys* functions. If the
// supplied auxKey is incorrect, then an error will be returned.
func (d *KeyData) SetAuthorizedSnapModels(auxKey PrimaryKey, models ...SnapModel) error {
	hmacKey, err := d.snapModelAuthKey(auxKey)
	if err != nil {
		return xerrors.Errorf("cannot obtain auth key: %w", err)
	}

	alg := d.data.AuthorizedSnapModels.keyDigest.Alg
	if !alg.Available() {
		return errors.New("invalid digest algorithm")
	}

	h := alg.New()
	h.Write(hmacKey)
	h.Write(d.data.AuthorizedSnapModels.keyDigest.Salt)
	if !bytes.Equal(h.Sum(nil), d.data.AuthorizedSnapModels.keyDigest.Digest) {
		return errors.New("incorrect key supplied")
	}

	alg = d.data.AuthorizedSnapModels.alg
	if !alg.Available() {
		return errors.New("invalid digest algorithm")
	}

	var modelHMACs snapModelHMACList

	for _, model := range models {
		h, err := computeSnapModelHMAC(crypto.Hash(alg), hmacKey, model)
		if err != nil {
			return xerrors.Errorf("cannot compute HMAC of model: %w", err)
		}

		modelHMACs = append(modelHMACs, h)
	}

	d.data.AuthorizedSnapModels.hmacs = modelHMACs
	return nil
}

// SetPassphrase sets a passphrase on this key data, which can be used to recover
// the keys via the KeyData.RecoverKeysWithPassphrase API. This can only be called when
// KeyData.AuthMode returns AuthModeNone. Once a passphrase has been set, the
// KeyData.RecoverKeys API can no longer be used.
//
// The kdfOptions argument configures the Argon2 KDF settings. The kdf argument
// provides the Argon2 KDF implementation that will be used - this should ultimately
// execute the implementation returned by the Argon2iKDF function, but the caller
// can choose to execute this in a short-lived utility process.
func (d *KeyData) SetPassphrase(passphrase string, kdfOptions *KDFOptions, kdf KDF) error {
	if d.AuthMode() != AuthModeNone {
		return errors.New("cannot set passphrase without authorization")
	}

	if err := d.updatePassphrase(d.data.EncryptedPayload, nil, passphrase, kdfOptions, kdf); err != nil {
		return err
	}

	d.data.EncryptedPayload = nil
	return nil
}

// ChangePassphrase updates the passphrase used to recover the keys from this key data
// via the KeyData.RecoverKeysWithPassphraseAPI. This can only be called if a passhphrase
// has been set previously (KeyData.AuthMode returns AuthModePassphrase).
//
// The current passphrase must be supplied via the oldPassphrase argument.
//
// The kdfOptions argument configures the Argon2 KDF settings. The kdf argument
// provides the Argon2 KDF implementation that will be used - this should ultimately
// execute the implementation returned by the Argon2iKDF function, but the caller
// can choose to execute this in a short-lived utility process.
func (d *KeyData) ChangePassphrase(oldPassphrase, newPassphrase string, kdfOptions *KDFOptions, kdf KDF) error {
	if d.AuthMode()&AuthModePassphrase == 0 {
		return errors.New("cannot change passphrase without setting an initial passphrase")
	}

	payload, oldKey, err := d.openWithPassphrase(oldPassphrase, kdf)
	if err != nil {
		return err
	}

	if err := d.updatePassphrase(payload, oldKey, newPassphrase, kdfOptions, kdf); err != nil {
		return processPlatformHandlerError(err)
	}

	return nil
}

// ClearPassphraseWithPassphrase clears the passphrase from this key data so that the
// keys can be recovered via the KeyData.RecoverKeys API. This can only be called if a
// passhphrase has been set previously (KeyData.AuthMode returns AuthModePassphrase).
//
// The current passphrase must be supplied.
//
// The kdf argument provides the Argon2 KDF implementation that will be used - this
// should ultimately execute the implementation returned by the Argon2iKDF function,
// but the caller can choose to execute this in a short-lived utility process.
func (d *KeyData) ClearPassphraseWithPassphrase(passphrase string, kdf KDF) error {
	if d.AuthMode()&AuthModePassphrase == 0 {
		return errors.New("no passphrase is set")
	}

	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return ErrNoPlatformHandlerRegistered
	}

	payload, key, err := d.openWithPassphrase(passphrase, kdf)
	if err != nil {
		return err
	}

	handle, err := handler.ChangeAuthKey(d.data.PlatformHandle, key, nil)
	if err != nil {
		return processPlatformHandlerError(err)
	}

	d.data.PlatformHandle = handle
	d.data.EncryptedPayload = payload
	d.data.PassphraseProtectedPayload = nil
	return nil
}

// WriteAtomic saves this key data to the supplied KeyDataWriter.
func (d *KeyData) WriteAtomic(w KeyDataWriter) error {
	enc := json.NewEncoder(w)
	if err := enc.Encode(d.data); err != nil {
		return xerrors.Errorf("cannot encode keydata: %w", err)
	}

	if err := w.Commit(); err != nil {
		return xerrors.Errorf("cannot commit keydata: %w", err)
	}

	return nil
}

// ReadKeyData reads the key data from the supplied KeyDataReader, returning a
// new KeyData object.
func ReadKeyData(r KeyDataReader) (*KeyData, error) {
	d := &KeyData{readableName: r.ReadableName()}
	dec := json.NewDecoder(r)
	if err := dec.Decode(&d.data); err != nil {
		return nil, xerrors.Errorf("cannot decode key data: %w", err)
	}

	return d, nil
}

// NewKeyData creates a new KeyData object using the supplied KeyParams, which
// should be created by a platform-specific package, containing a payload encrypted by
// the platform's secure device and the associated handle required for subsequent
// recovery of the keys.
func NewKeyData(params *KeyParams) (*KeyData, error) {
	encodedHandle, err := json.Marshal(params.Handle)
	if err != nil {
		return nil, xerrors.Errorf("cannot encode platform handle: %w", err)
	}

	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, xerrors.Errorf("cannot read salt: %w", err)
	}

	kd := &KeyData{
		data: keyData{
			PlatformName:     params.PlatformName,
			PlatformHandle:   json.RawMessage(encodedHandle),
			EncryptedPayload: params.EncryptedPayload,
			AuthorizedSnapModels: authorizedSnapModels{
				alg:    hashAlg(params.SnapModelAuthHash),
				kdfAlg: hashAlg(params.SnapModelAuthHash),
				keyDigest: keyDigest{
					Alg:  hashAlg(params.SnapModelAuthHash),
					Salt: salt[:]}}}}

	authKey, err := kd.snapModelAuthKey(params.PrimaryKey)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute snap model auth key: %w", err)
	}

	h := kd.data.AuthorizedSnapModels.keyDigest.Alg.New()
	h.Write(authKey)
	h.Write(kd.data.AuthorizedSnapModels.keyDigest.Salt)
	kd.data.AuthorizedSnapModels.keyDigest.Digest = h.Sum(nil)

	return kd, nil
}

// MarshalKeys serializes the supplied disk unlock key and auxiliary key in
// to a format that is ready to be encrypted by a platform's secure device.
func MarshalKeys(key DiskUnlockKey, auxKey PrimaryKey) KeyPayload {
	w := new(bytes.Buffer)
	binary.Write(w, binary.BigEndian, uint16(len(key)))
	w.Write(key)
	binary.Write(w, binary.BigEndian, uint16(len(auxKey)))
	w.Write(auxKey)
	return w.Bytes()
}

type protectedKeys struct {
	primary PrimaryKey
	unique  []byte
}

func (k *protectedKeys) unlockKey(alg crypto.Hash) DiskUnlockKey {
	if alg == crypto.Hash(nilHash) {
		// This is to support the legacy TPM key data created
		// via tpm2.NewKeyDataFromSealedKeyObjectFile.
		return k.unique
	}

	unlockKey := make([]byte, len(k.primary))
	r := hkdf.New(func() hash.Hash { return alg.New() }, k.primary, k.unique, []byte("UNLOCK"))
	if _, err := io.ReadFull(r, unlockKey); err != nil {
		panic(err)
	}
	return unlockKey
}

func (k *protectedKeys) marshalASN1(builder *cryptobyte.Builder) {
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // ProtectedKeys ::= SEQUENCE {
		b.AddASN1OctetString(k.primary) // primary OCTETSTRING
		b.AddASN1OctetString(k.unique)  // unique OCTETSTRING
	})
}

func MakeDiskUnlockKey(rand io.Reader, alg crypto.Hash, primaryKey PrimaryKey) (unlockKey DiskUnlockKey, cleartextPayload []byte, err error) {
	unique := make([]byte, len(primaryKey))
	if _, err := io.ReadFull(rand, unique); err != nil {
		return nil, nil, xerrors.Errorf("cannot make unique ID: %w", err)
	}

	pk := &protectedKeys{
		primary: primaryKey,
		unique:  unique,
	}

	builder := cryptobyte.NewBuilder(nil)
	pk.marshalASN1(builder)
	cleartextPayload, err = builder.Bytes()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot marshal cleartext payload: %w", err)
	}

	return pk.unlockKey(alg), cleartextPayload, nil
}
