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
	nilHash                    HashAlg = 0
	passphraseKeyLen                   = 32
	passphraseEncryptionKeyLen         = 32
	passphraseEncryption               = "aes-cfb"
)

var (
	keyDataGeneration     int = 2
	snapModelHMACKDFLabel     = []byte("SNAP-MODEL-HMAC")
	sha1Oid                   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	sha224Oid                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	sha256Oid                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sha384Oid                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	sha512Oid                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
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

// AuthMode corresponds to an authentication mechanism.
type AuthMode uint8

const (
	AuthModeNone AuthMode = iota
	AuthModePassphrase
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

	// EncryptedPayload contains the encrypted and authenticated payload. The
	// plaintext payload should be created with [MakeDiskUnlockKey].
	EncryptedPayload []byte

	// PrimaryKey is a key used to authorize changes to the key data.
	// It must match the key protected inside PlatformKeyData.EncryptedPayload.
	PrimaryKey PrimaryKey

	// SnapModelAuthHash is the digest algorithm used for HMACs of Snap
	// device models, and also the digest algorithm used to produce the
	// key digest.
	SnapModelAuthHash crypto.Hash
	PlatformName      string // Name of the platform that produced this data

	// KDFAlg is the digest algorithm used to derive additional keys during
	// the use of the created KeyData. It must match the algorithm passed to
	// [MakeDiskUnlockKey]. The zero value here has a special meaning which
	// is reserved to support legacy TPM2 key data files, and tells the
	// KeyData to use the unique key as the unlock key rather than using it
	// to derive the unlock key.
	KDFAlg crypto.Hash
}

// KeyWithPassphraseParams provides parameters required to create a new KeyData
// object with a passphrase enabled. It should be produced by a platform
// implementation.
type KeyWithPassphraseParams struct {
	KeyParams
	KDFOptions *KDFOptions // The passphrase KDF options

	// AuthKeySize is the size of key to derive from the passphrase for
	// use by the platform implementation.
	AuthKeySize int
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

// HashAlg corresponds to a digest algorithm.
type HashAlg crypto.Hash

var hashAlgAvailable = (*HashAlg).Available

func (a HashAlg) Available() bool {
	return crypto.Hash(a).Available()
}

func (a HashAlg) New() hash.Hash {
	return crypto.Hash(a).New()
}

func (a HashAlg) Size() int {
	return crypto.Hash(a).Size()
}

func (a HashAlg) MarshalJSON() ([]byte, error) {
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

func (a *HashAlg) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	switch s {
	case "sha1":
		*a = HashAlg(crypto.SHA1)
	case "sha224":
		*a = HashAlg(crypto.SHA224)
	case "sha256":
		*a = HashAlg(crypto.SHA256)
	case "sha384":
		*a = HashAlg(crypto.SHA384)
	case "sha512":
		*a = HashAlg(crypto.SHA512)
	default:
		// be permissive here and allow everything to be
		// unmarshalled.
		*a = nilHash
	}

	return nil
}

func (a HashAlg) MarshalASN1(b *cryptobyte.Builder) {
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
	Alg    HashAlg `json:"alg"`
	Salt   []byte  `json:"salt"`
	Digest []byte  `json:"digest"`
}

// hkdfData contains the parameters used to derive a key using HKDF.
type hkdfData struct {
	Alg HashAlg `json:"alg"` // Digest algorithm to use for HKDF
}

type authorizedSnapModelsRaw struct {
	Alg       HashAlg           `json:"alg"`
	KDFAlg    HashAlg           `json:"kdf_alg,omitempty"`
	KeyDigest json.RawMessage   `json:"key_digest"`
	Hmacs     snapModelHMACList `json:"hmacs"`
}

// authorizedSnapModels defines the Snap models that have been
// authorized to access the data protected by a key.
type authorizedSnapModels struct {
	alg       HashAlg           // Digest algorithm used for the authorized model HMACs
	kdfAlg    HashAlg           // Digest algorithm used to derive the HMAC key with HKDF. Zero for legacy (DRBG) derivation.
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

// passphraseParams contains parameters for passphrase authentication.
type passphraseParams struct {
	// KDF contains the key derivation parameters used to derive
	// an intermediate key from an input passphrase.
	KDF kdfData `json:"kdf"`

	Encryption        string `json:"encryption"`          // Encryption algorithm - currently only aes-cfb
	DerivedKeySize    int    `json:"derived_key_size"`    // Size of key to derive from passphrase using the parameters of the KDF field.
	EncryptionKeySize int    `json:"encryption_key_size"` // Size of encryption key to derive from passphrase derived key
	AuthKeySize       int    `json:"auth_key_size"`       // Size of auth key to derive from passphrase derived key
}

type keyData struct {
	// Generation is a number used to differentiate between different key formats.
	// i.e Gen1 keys are binary serialized and include a primary and an unlock key while
	// Gen2 keys are ASN1 serialized and include a primary key and a unique key which is
	// used to derive the unlock key.
	Generation int `json:"generation,omitempty"`

	PlatformName string `json:"platform_name"` // used to identify a PlatformKeyDataHandler

	// PlatformHandle is an opaque blob of data used by the associated
	// PlatformKeyDataHandler to recover the cleartext keys from one of
	// the encrypted payloads.
	PlatformHandle json.RawMessage `json:"platform_handle"`

	// KDFAlg is the algorithm that is used to derive the unlock key from a primary key.
	// It is also used to derive additional keys from the passphrase derived key in
	// derivePassphraseKeys.
	KDFAlg HashAlg `json:"kdf_alg,omitempty"`

	// EncryptedPayload is the platform protected key payload.
	EncryptedPayload []byte `json:"encrypted_payload"`

	PassphraseParams *passphraseParams `json:"passphrase_params,omitempty"`

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

func (d *KeyData) derivePassphraseKeys(passphrase string, kdf KDF) (key, iv, auth []byte, err error) {
	if d.data.PassphraseParams == nil {
		return nil, nil, nil, errors.New("no passphrase params")
	}

	params := d.data.PassphraseParams
	if params.KDF.Type != kdfType {
		// Only Argon2i is supported
		return nil, nil, nil, fmt.Errorf("unexpected intermediate KDF type \"%s\"", params.KDF.Type)
	}
	if params.DerivedKeySize < 0 {
		return nil, nil, nil, fmt.Errorf("invalid derived key size (%d bytes)", params.DerivedKeySize)
	}
	if params.EncryptionKeySize < 0 || params.EncryptionKeySize > 32 {
		// The key size can't be larger than 32 with the supported cipher
		return nil, nil, nil, fmt.Errorf("invalid encryption key size (%d bytes)", params.EncryptionKeySize)
	}
	if params.AuthKeySize < 0 {
		return nil, nil, nil, fmt.Errorf("invalid auth key size (%d bytes)", params.AuthKeySize)
	}

	kdfAlg := d.data.KDFAlg
	if !hashAlgAvailable(&kdfAlg) {
		return nil, nil, nil, fmt.Errorf("unavailable leaf KDF digest algorithm %v", kdfAlg)
	}

	// Include derivation parameters in the Argon2 salt in order to protect them
	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // SEQUENCE {
		b.AddASN1OctetString(params.KDF.Salt)                               // salt OCTET STRING
		kdfAlg.MarshalASN1(b)                                               // kdfAlgorithm AlgorithmIdentifier
		b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) { // encryption UTF8String
			b.AddBytes([]byte(params.Encryption))
		})
		b.AddASN1Int64(int64(params.EncryptionKeySize)) // encryptionKeySize INTEGER
		b.AddASN1Int64(int64(params.AuthKeySize))       // authKeySize INTEGER
	})
	salt, err := builder.Bytes()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot serialize salt: %w", err)
	}

	costParams := &KDFCostParams{
		Time:      uint32(params.KDF.Time),
		MemoryKiB: uint32(params.KDF.Memory),
		Threads:   uint8(params.KDF.CPUs)}
	derived, err := kdf.Derive(passphrase, salt, costParams, uint32(params.DerivedKeySize))
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot derive key from passphrase: %w", err)
	}
	if len(derived) != params.DerivedKeySize {
		return nil, nil, nil, errors.New("KDF returned unexpected key length")
	}

	key = make([]byte, params.EncryptionKeySize)
	r := hkdf.Expand(func() hash.Hash { return kdfAlg.New() }, derived, []byte("PASSPHRASE-ENC"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot derive encryption key: %w", err)
	}

	iv = make([]byte, aes.BlockSize)
	r = hkdf.Expand(func() hash.Hash { return kdfAlg.New() }, derived, []byte("PASSPHRASE-IV"))
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot derive IV: %w", err)
	}

	auth = make([]byte, params.AuthKeySize)
	r = hkdf.Expand(func() hash.Hash { return kdfAlg.New() }, derived, []byte("PASSPHRASE-AUTH"))
	if _, err := io.ReadFull(r, auth); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot derive auth key: %w", err)
	}

	return key, iv, auth, nil
}

func (d *KeyData) updatePassphrase(payload, oldAuthKey []byte, passphrase string, kdf KDF) error {
	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return ErrNoPlatformHandlerRegistered
	}

	key, iv, authKey, err := d.derivePassphraseKeys(passphrase, kdf)
	if err != nil {
		return err
	}

	if d.data.PassphraseParams.Encryption != passphraseEncryption {
		// Only AES-CFB is supported
		return fmt.Errorf("unexpected encryption algorithm \"%s\"", d.data.PassphraseParams.Encryption)
	}

	handle, err := handler.ChangeAuthKey(d.platformKeyData(), oldAuthKey, authKey)
	if err != nil {
		return err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return xerrors.Errorf("cannot create cipher: %w", err)
	}

	d.data.PlatformHandle = handle
	d.data.EncryptedPayload = make([]byte, len(payload))

	stream := cipher.NewCFBEncrypter(c, iv)
	stream.XORKeyStream(d.data.EncryptedPayload, payload)

	return nil
}

func (d *KeyData) openWithPassphrase(passphrase string, kdf KDF) (payload []byte, authKey []byte, err error) {
	key, iv, authKey, err := d.derivePassphraseKeys(passphrase, kdf)
	if err != nil {
		return nil, nil, err
	}

	if d.data.PassphraseParams.Encryption != passphraseEncryption {
		// Only AES-CFB is supported
		return nil, nil, fmt.Errorf("unexpected encryption algorithm \"%s\"", d.data.PassphraseParams.Encryption)
	}

	payload = make([]byte, len(d.data.EncryptedPayload))

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create cipher: %w", err)
	}
	stream := cipher.NewCFBDecrypter(c, iv)
	stream.XORKeyStream(payload, d.data.EncryptedPayload)

	return payload, authKey, nil
}

func (d *KeyData) platformKeyData() *PlatformKeyData {
	return &PlatformKeyData{
		Generation:    d.Generation(),
		EncodedHandle: d.data.PlatformHandle,
		KDFAlg:        crypto.Hash(d.data.KDFAlg),
		AuthMode:      d.AuthMode(),
	}
}

func (d *KeyData) recoverKeysCommon(data []byte) (DiskUnlockKey, PrimaryKey, error) {
	switch d.Generation() {
	case 1:
		unlockKey, primaryKey, err := unmarshalV1KeyPayload(data)
		if err != nil {
			return nil, nil, &InvalidKeyDataError{xerrors.Errorf("cannot unmarshal cleartext key payload: %w", err)}
		}
		return unlockKey, primaryKey, nil
	case 2:
		if d.data.KDFAlg != nilHash && !d.data.KDFAlg.Available() {
			return nil, nil, fmt.Errorf("unavailable KDF digest algorithm %v", d.data.KDFAlg)
		}
		pk, err := unmarshalProtectedKeys(data)
		if err != nil {
			return nil, nil, &InvalidKeyDataError{xerrors.Errorf("cannot unmarshal cleartext key payload: %w", err)}
		}
		return pk.unlockKey(crypto.Hash(d.data.KDFAlg)), pk.Primary, nil
	default:
		return nil, nil, fmt.Errorf("invalid keydata generation %d", d.Generation())
	}
}

// Generation returns this keydata's generation. Since the generation field didn't exist
// for older keydata with generation < 2, we fake the generation returned to 1.
func (d *KeyData) Generation() int {
	switch d.data.Generation {
	case 0:
		// This field was missing in gen1
		return 1
	default:
		return d.data.Generation
	}
}

// PlatformName returns the name of the platform that handles this key data.
func (d *KeyData) PlatformName() string {
	return d.data.PlatformName
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
	switch {
	case d.data.PassphraseParams != nil:
		return AuthModePassphrase
	default:
		return AuthModeNone
	}
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

	c, err := handler.RecoverKeys(d.platformKeyData(), d.data.EncryptedPayload)
	if err != nil {
		return nil, nil, processPlatformHandlerError(err)
	}

	return d.recoverKeysCommon(c)
}

func (d *KeyData) RecoverKeysWithPassphrase(passphrase string, kdf KDF) (DiskUnlockKey, PrimaryKey, error) {
	if d.AuthMode() != AuthModePassphrase {
		return nil, nil, errors.New("cannot recover key with passphrase")
	}

	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return nil, nil, ErrNoPlatformHandlerRegistered
	}

	payload, key, err := d.openWithPassphrase(passphrase, kdf)
	if err != nil {
		return nil, nil, err
	}

	c, err := handler.RecoverKeysWithAuthKey(d.platformKeyData(), payload, key)
	if err != nil {
		return nil, nil, processPlatformHandlerError(err)
	}

	return d.recoverKeysCommon(c)
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

// ChangePassphrase updates the passphrase used to recover the keys from this key data
// via the KeyData.RecoverKeysWithPassphrase API. This can only be called if a passhphrase
// has been set previously (KeyData.AuthMode returns AuthModePassphrase).
//
// The current passphrase must be supplied via the oldPassphrase argument.
//
// The kdfOptions argument configures the Argon2 KDF settings. The kdf argument
// provides the Argon2 KDF implementation that will be used - this should ultimately
// execute the implementation returned by the Argon2iKDF function, but the caller
// can choose to execute this in a short-lived utility process.
func (d *KeyData) ChangePassphrase(oldPassphrase, newPassphrase string, kdf KDF) error {
	if d.AuthMode()&AuthModePassphrase == 0 {
		return errors.New("cannot change passphrase without setting an initial passphrase")
	}

	payload, oldKey, err := d.openWithPassphrase(oldPassphrase, kdf)
	if err != nil {
		return err
	}

	if err := d.updatePassphrase(payload, oldKey, newPassphrase, kdf); err != nil {
		return processPlatformHandlerError(err)
	}

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
			Generation:       keyDataGeneration,
			PlatformName:     params.PlatformName,
			PlatformHandle:   json.RawMessage(encodedHandle),
			KDFAlg:           HashAlg(params.KDFAlg),
			EncryptedPayload: params.EncryptedPayload,
			AuthorizedSnapModels: authorizedSnapModels{
				alg:    HashAlg(params.SnapModelAuthHash),
				kdfAlg: HashAlg(params.SnapModelAuthHash),
				keyDigest: keyDigest{
					Alg:  HashAlg(params.SnapModelAuthHash),
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

// NewKeyDataWithPassphrase is similar to NewKeyData but creates KeyData objects that are supported
// by a passphrase, which is passed as an extra argument. The supplied KeyWithPassphraseParams include
// in addition to the KeyParams fields, the KDFOptions and AuthKeySize fields which are used in the key
// derivation process.
func NewKeyDataWithPassphrase(params *KeyWithPassphraseParams, passphrase string, kdf KDF) (*KeyData, error) {
	kd, err := NewKeyData(&params.KeyParams)
	if err != nil {
		return nil, err
	}

	kdfOptions := params.KDFOptions
	if kdfOptions == nil {
		var defaultOptions KDFOptions
		kdfOptions = &defaultOptions
	}

	costParams, err := kdfOptions.deriveCostParams(passphraseEncryptionKeyLen+aes.BlockSize, kdf)
	if err != nil {
		return nil, xerrors.Errorf("cannot derive KDF cost parameters: %w", err)
	}

	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, xerrors.Errorf("cannot read salt: %w", err)
	}

	kd.data.PassphraseParams = &passphraseParams{
		KDF: kdfData{
			Type:   kdfType,
			Salt:   salt[:],
			Time:   int(costParams.Time),
			Memory: int(costParams.MemoryKiB),
			CPUs:   int(costParams.Threads),
		},
		Encryption:        passphraseEncryption,
		DerivedKeySize:    passphraseKeyLen,
		EncryptionKeySize: passphraseEncryptionKeyLen,
		AuthKeySize:       params.AuthKeySize,
	}

	if err := kd.updatePassphrase(kd.data.EncryptedPayload, make([]byte, params.AuthKeySize), passphrase, kdf); err != nil {
		return nil, xerrors.Errorf("cannot set passphrase: %w", err)
	}

	return kd, nil
}

// protectedKeys is used to pack a primary key and a unique value from which
// an unlock key is derived.
type protectedKeys struct {
	Primary PrimaryKey
	Unique  []byte
}

func unmarshalProtectedKeys(data []byte) (*protectedKeys, error) {
	s := cryptobyte.String(data)
	if !s.ReadASN1(&s, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("malformed input")
	}

	pk := new(protectedKeys)

	if !s.ReadASN1Bytes((*[]byte)(&pk.Primary), cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("malformed primary key")
	}
	if !s.ReadASN1Bytes(&pk.Unique, cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("malformed unique key")
	}

	return pk, nil
}

func (k *protectedKeys) unlockKey(alg crypto.Hash) DiskUnlockKey {
	if alg == crypto.Hash(nilHash) {
		// This is to support the legacy TPM key data created
		// via tpm2.NewKeyDataFromSealedKeyObjectFile.
		return k.Unique
	}

	unlockKey := make([]byte, len(k.Primary))
	r := hkdf.New(func() hash.Hash { return alg.New() }, k.Primary, k.Unique, []byte("UNLOCK"))
	if _, err := io.ReadFull(r, unlockKey); err != nil {
		panic(err)
	}
	return unlockKey
}

func (k *protectedKeys) marshalASN1(builder *cryptobyte.Builder) {
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // ProtectedKeys ::= SEQUENCE {
		b.AddASN1OctetString(k.Primary) // primary OCTETSTRING
		b.AddASN1OctetString(k.Unique)  // unique OCTETSTRING
	})
}

// MakeDiskUnlockKey derives a disk unlock key from a passed primary key and
// a random salt. It returns that key as well as a payload in cleartext containing
// the primary key and the generated salt.
func MakeDiskUnlockKey(rand io.Reader, alg crypto.Hash, primaryKey PrimaryKey) (unlockKey DiskUnlockKey, cleartextPayload []byte, err error) {
	unique := make([]byte, len(primaryKey))
	if _, err := io.ReadFull(rand, unique); err != nil {
		return nil, nil, xerrors.Errorf("cannot make unique ID: %w", err)
	}

	pk := &protectedKeys{
		Primary: primaryKey,
		Unique:  unique,
	}

	builder := cryptobyte.NewBuilder(nil)
	pk.marshalASN1(builder)
	cleartextPayload, err = builder.Bytes()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot marshal cleartext payload: %w", err)
	}

	return pk.unlockKey(alg), cleartextPayload, nil
}

// MarshalKeys serializes the supplied disk unlock key and auxiliary key in
// to a format that is ready to be encrypted by a platform's secure device.
func MarshalKeys(key DiskUnlockKey, auxKey PrimaryKey) []byte {
	w := new(bytes.Buffer)
	binary.Write(w, binary.BigEndian, uint16(len(key)))
	w.Write(key)
	binary.Write(w, binary.BigEndian, uint16(len(auxKey)))
	w.Write(auxKey)
	return w.Bytes()
}
