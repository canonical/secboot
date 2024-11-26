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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/snapcore/secboot/internal/pbkdf2"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/xerrors"
)

const (
	nilHash                    HashAlg = 0
	passphraseKeyLen                   = 32
	passphraseEncryptionKeyLen         = 32
	passphraseEncryption               = "aes-cfb"
)

var (
	sha1Oid   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	sha224Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	sha256Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sha384Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	sha512Oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

var (
	// KeyDataGeneration describes the generation number of new keys created by NewKeyData.
	// This will be supplied via PlatformKeyDataHandler and should generally be
	// authenticated by the platform code in order to protect against future key format
	// changes that might have security relevant implications.
	KeyDataGeneration = 2

	// ErrNoPlatformHandlerRegistered is returned from KeyData methods if no
	// appropriate platform handler is registered using the
	// RegisterPlatformKeyDataHandler API.
	ErrNoPlatformHandlerRegistered = errors.New("no appropriate platform handler is registered")

	// ErrInvalidPassphrase is returned from KeyData methods that require
	// knowledge of a passphrase is the supplied passphrase is incorrect.
	ErrInvalidPassphrase = errors.New("the supplied passphrase is incorrect")
)

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
	AuthModePIN
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

	Role string

	// EncryptedPayload contains the encrypted and authenticated payload. The
	// plaintext payload should be created with [MakeDiskUnlockKey].
	EncryptedPayload []byte

	PlatformName string // Name of the platform that produced this data

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
	KDFOptions KDFOptions // The passphrase KDF options

	// AuthKeySize is the size of key to derive from the passphrase for
	// use by the platform implementation.
	AuthKeySize int
}

type KeyWithPINParams struct {
	KeyParams
	KDFOptions *PBKDF2Options // The PIN KDF options

	// AuthKeySize is the size of key to derive from the PIN for
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

// HashAlg provides an abstraction for crypto.Hash that can be serialized to JSON and DER.
type HashAlg crypto.Hash

var hashAlgAvailable = (*HashAlg).Available

func (a HashAlg) Available() bool {
	return crypto.Hash(a).Available()
}

func (a HashAlg) New() hash.Hash {
	return crypto.Hash(a).New()
}

func (a HashAlg) HashFunc() crypto.Hash {
	return crypto.Hash(a)
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

type kdfParams struct {
	Type   string  `json:"type"`
	Time   int     `json:"time"`
	Memory int     `json:"memory"`
	CPUs   int     `json:"cpus"`
	Hash   HashAlg `json:"hash"`
}

// kdfData corresponds to the arguments to a KDF and matches the
// corresponding object in the LUKS2 specification.
type kdfData struct {
	Salt []byte `json:"salt"`
	kdfParams
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

type pinParams struct {
	KDF         kdfData `json:"kdf"`
	AuthKeySize int     `json:"auth_key_size"`
}

type keyData struct {
	// Generation is a number used to differentiate between different key formats.
	// i.e Gen1 keys are binary serialized and include a primary and an unlock key while
	// Gen2 keys are DER encoded and include a primary key and a unique key which is
	// used to derive the unlock key.
	Generation int `json:"generation,omitempty"`

	PlatformName string `json:"platform_name"` // used to identify a PlatformKeyDataHandler

	// PlatformHandle is an opaque blob of data used by the associated
	// PlatformKeyDataHandler to recover the cleartext keys from one of
	// the encrypted payloads.
	PlatformHandle json.RawMessage `json:"platform_handle"`

	// Role describes the role of this key, and is used to restrict the
	// scope of authorizations associated with it (such as PCR policies).
	// XXX: It's a bit strange having it here because it's not used by
	//  this package, but it does allow the configuration manager to filter
	//  keys by role without having to decode the platform specific part.
	//  Maybe in the future, KeyData should be an interface implemented
	//  entirely by each platform with some shared helpers rather than
	//  what we have now (a concrete KeyData implementation with an
	//  opaque blob).
	Role string `json:"role"`

	// KDFAlg is the algorithm that is used to derive the unlock key from a primary key.
	// It is also used to derive additional keys from the passphrase derived key in
	// derivePassphraseKeys.
	KDFAlg HashAlg `json:"kdf_alg,omitempty"`

	// EncryptedPayload is the platform protected key payload.
	EncryptedPayload []byte `json:"encrypted_payload"`

	PassphraseParams *passphraseParams `json:"passphrase_params,omitempty"`
	PINParams        *pinParams        `json:"pin_params,omitempty"`

	// AuthorizedSnapModels contains information about the Snap models
	// that have been authorized to access the data protected by this key.
	// This field is only used by gen 1 keys. Gen 2 keys handle authorized
	// snap models differently depending on the platform implementation.
	AuthorizedSnapModels *authorizedSnapModels `json:"authorized_snap_models,omitempty"`
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

func (d *KeyData) derivePassphraseKeys(passphrase string) (key, iv, auth []byte, err error) {
	if d.data.PassphraseParams == nil {
		return nil, nil, nil, errors.New("no passphrase params")
	}

	params := d.data.PassphraseParams
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
	if params.KDF.Time < 0 {
		return nil, nil, nil, fmt.Errorf("invalid KDF time (%d)", params.KDF.Time)
	}

	kdfAlg := d.data.KDFAlg
	if !hashAlgAvailable(&kdfAlg) {
		return nil, nil, nil, fmt.Errorf("unavailable leaf KDF digest algorithm %v", kdfAlg)
	}

	// Include derivation parameters in the KDF salt in order to protect them.
	// Ideally the extra parameters would be part of Argon2's additional data, but
	// the go package doesn't expose this.
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

	var derived []byte

	switch params.KDF.Type {
	case string(Argon2i), string(Argon2id):
		if params.KDF.Memory < 0 {
			return nil, nil, nil, fmt.Errorf("invalid argon2 memory (%d)", params.KDF.Memory)
		}
		if params.KDF.CPUs < 0 {
			return nil, nil, nil, fmt.Errorf("invalid argon2 threads (%d)", params.KDF.CPUs)
		}

		mode := Argon2Mode(params.KDF.Type)
		costParams := &Argon2CostParams{
			Time:      uint32(params.KDF.Time),
			MemoryKiB: uint32(params.KDF.Memory),
			Threads:   uint8(params.KDF.CPUs)}
		derived, err = argon2KDF().Derive(passphrase, salt, mode, costParams, uint32(params.DerivedKeySize))
		if err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot derive key from passphrase: %w", err)
		}
		if len(derived) != params.DerivedKeySize {
			return nil, nil, nil, errors.New("KDF returned unexpected key length")
		}
	case pbkdf2Type:
		pbkdfParams := &pbkdf2.Params{
			Iterations: uint(params.KDF.Time),
			HashAlg:    crypto.Hash(params.KDF.Hash),
		}
		derived, err = pbkdf2.Key(passphrase, salt, pbkdfParams, uint(params.DerivedKeySize))
		if err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot derive key from passphrase: %w", err)
		}
	default:
		return nil, nil, nil, fmt.Errorf("unexpected intermediate KDF type \"%s\"", params.KDF.Type)
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

func (d *KeyData) derivePINAuthKey(pin PIN) ([]byte, error) {
	if d.data.PINParams == nil {
		return nil, errors.New("no PIN params")
	}

	params := d.data.PINParams
	if params.AuthKeySize < 0 {
		return nil, fmt.Errorf("invalid auth key size (%d bytes)", params.AuthKeySize)
	}
	if params.KDF.Time < 0 {
		return nil, fmt.Errorf("invalid KDF time (%d)", params.KDF.Time)
	}
	if params.KDF.Type != pbkdf2Type {
		return nil, fmt.Errorf("unexpected KDF type \"%s\"", params.KDF.Type)
	}

	pbkdfParams := &pbkdf2.Params{
		Iterations: uint(params.KDF.Time),
		HashAlg:    crypto.Hash(params.KDF.Hash),
	}
	if !pbkdfParams.HashAlg.Available() {
		return nil, fmt.Errorf("unavailable pbkdf2 digest algorithm %v", pbkdfParams.HashAlg)
	}
	key, err := pbkdf2.Key(string(pin.Bytes()), params.KDF.Salt, pbkdfParams, uint(params.AuthKeySize))
	if err != nil {
		return nil, xerrors.Errorf("cannot derive auth key from PIN: %w", err)
	}
	return key, nil
}

func (d *KeyData) updatePassphrase(payload, oldAuthKey []byte, passphrase string) error {
	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return ErrNoPlatformHandlerRegistered
	}

	key, iv, authKey, err := d.derivePassphraseKeys(passphrase)
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

func (d *KeyData) updatePIN(oldAuthKey []byte, pin PIN) error {
	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return ErrNoPlatformHandlerRegistered
	}

	authKey, err := d.derivePINAuthKey(pin)
	if err != nil {
		return err
	}

	handle, err := handler.ChangeAuthKey(d.platformKeyData(), oldAuthKey, authKey)
	if err != nil {
		return err
	}

	d.data.PlatformHandle = handle
	return nil
}

func (d *KeyData) openWithPassphrase(passphrase string) (payload []byte, authKey []byte, err error) {
	key, iv, authKey, err := d.derivePassphraseKeys(passphrase)
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
	case d.data.PINParams != nil:
		return AuthModePIN
	default:
		return AuthModeNone
	}
}

func (d *KeyData) Role() string {
	return d.data.Role
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

func (d *KeyData) RecoverKeysWithPassphrase(passphrase string) (DiskUnlockKey, PrimaryKey, error) {
	if d.AuthMode() != AuthModePassphrase {
		return nil, nil, errors.New("cannot recover key with passphrase")
	}

	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return nil, nil, ErrNoPlatformHandlerRegistered
	}

	payload, key, err := d.openWithPassphrase(passphrase)
	if err != nil {
		return nil, nil, err
	}

	c, err := handler.RecoverKeysWithAuthKey(d.platformKeyData(), payload, key)
	if err != nil {
		return nil, nil, processPlatformHandlerError(err)
	}

	return d.recoverKeysCommon(c)
}

func (d *KeyData) RecoverKeysWithPIN(pin PIN) (DiskUnlockKey, PrimaryKey, error) {
	if d.AuthMode() != AuthModePIN {
		return nil, nil, errors.New("cannot recover key with PIN")
	}

	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return nil, nil, ErrNoPlatformHandlerRegistered
	}

	key, err := d.derivePINAuthKey(pin)
	if err != nil {
		return nil, nil, err
	}

	c, err := handler.RecoverKeysWithAuthKey(d.platformKeyData(), d.data.EncryptedPayload, key)
	if err != nil {
		return nil, nil, processPlatformHandlerError(err)
	}

	return d.recoverKeysCommon(c)
}

// ChangePassphrase updates the passphrase used to recover the keys from this key data
// via the KeyData.RecoverKeysWithPassphrase API. This can only be called if a passhphrase
// has been set previously (KeyData.AuthMode returns AuthModePassphrase).
//
// The current passphrase must be supplied via the oldPassphrase argument.
func (d *KeyData) ChangePassphrase(oldPassphrase, newPassphrase string) error {
	if d.AuthMode()&AuthModePassphrase == 0 {
		return errors.New("cannot change passphrase without setting an initial passphrase")
	}

	payload, oldKey, err := d.openWithPassphrase(oldPassphrase)
	if err != nil {
		return err
	}

	if err := d.updatePassphrase(payload, oldKey, newPassphrase); err != nil {
		return processPlatformHandlerError(err)
	}

	return nil
}

func (d *KeyData) ChangePIN(oldPIN, newPIN PIN) error {
	if d.AuthMode()&AuthModePIN == 0 {
		return errors.New("cannot change PIN without setting an initial PIN")
	}

	oldKey, err := d.derivePINAuthKey(oldPIN)
	if err != nil {
		return err
	}

	if err := d.updatePIN(oldKey, newPIN); err != nil {
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

	kd := &KeyData{
		data: keyData{
			Generation:       KeyDataGeneration,
			PlatformName:     params.PlatformName,
			Role:             params.Role,
			PlatformHandle:   json.RawMessage(encodedHandle),
			KDFAlg:           HashAlg(params.KDFAlg),
			EncryptedPayload: params.EncryptedPayload,
		},
	}

	return kd, nil
}

// NewKeyDataWithPassphrase is similar to NewKeyData but creates KeyData objects that are supported
// by a passphrase, which is passed as an extra argument. The supplied KeyWithPassphraseParams include
// in addition to the KeyParams fields, the KDFOptions and AuthKeySize fields which are used in the key
// derivation process.
func NewKeyDataWithPassphrase(params *KeyWithPassphraseParams, passphrase string) (*KeyData, error) {
	kd, err := NewKeyData(&params.KeyParams)
	if err != nil {
		return nil, err
	}

	kdfOptions := params.KDFOptions
	if kdfOptions == nil {
		var defaultOptions Argon2Options
		kdfOptions = &defaultOptions
	}

	kdfParams, err := kdfOptions.kdfParams(2*time.Second, passphraseKeyLen)
	if err != nil {
		return nil, xerrors.Errorf("cannot derive KDF cost parameters: %w", err)
	}

	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, xerrors.Errorf("cannot read salt: %w", err)
	}

	kd.data.PassphraseParams = &passphraseParams{
		KDF: kdfData{
			Salt:      salt[:],
			kdfParams: *kdfParams,
		},
		Encryption:        passphraseEncryption,
		DerivedKeySize:    passphraseKeyLen,
		EncryptionKeySize: passphraseEncryptionKeyLen,
		AuthKeySize:       params.AuthKeySize,
	}

	if err := kd.updatePassphrase(kd.data.EncryptedPayload, make([]byte, params.AuthKeySize), passphrase); err != nil {
		return nil, xerrors.Errorf("cannot set passphrase: %w", err)
	}

	return kd, nil
}

func NewKeyDataWithPIN(params *KeyWithPINParams, pin PIN) (*KeyData, error) {
	kd, err := NewKeyData(&params.KeyParams)
	if err != nil {
		return nil, err
	}

	kdfOptions := params.KDFOptions
	if kdfOptions == nil {
		var defaultOptions PBKDF2Options
		kdfOptions = &defaultOptions
	}

	if params.AuthKeySize < 0 {
		return nil, errors.New("invalid auth key size")
	}

	kdfParams, err := kdfOptions.kdfParams(200*time.Millisecond, uint32(params.AuthKeySize))
	if err != nil {
		return nil, xerrors.Errorf("cannot derive KDF cost parameters: %w", err)
	}

	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, xerrors.Errorf("cannot read salt: %w", err)
	}

	kd.data.PINParams = &pinParams{
		KDF: kdfData{
			Salt:      salt[:],
			kdfParams: *kdfParams,
		},
		AuthKeySize: params.AuthKeySize,
	}

	if err := kd.updatePIN(make([]byte, params.AuthKeySize), pin); err != nil {
		return nil, xerrors.Errorf("cannot set PIN: %w", err)
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
