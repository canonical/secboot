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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-sp800.90a-drbg"

	"golang.org/x/xerrors"
)

const (
	kdfType                 = "argon2i"
	passphraseDerivedKeyLen = 32
	passphraseEncryption    = "aes-cfb"
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

// AuxiliaryKey is an additional key used to modify properties of a KeyData
// object without having to create a new object.
type AuxiliaryKey []byte

// KeyPayload is the payload that should be encrypted by a platform's secure device.
type KeyPayload []byte

// Unmarshal obtains the keys from this payload.
func (c KeyPayload) Unmarshal() (key DiskUnlockKey, auxKey AuxiliaryKey, err error) {
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
		auxKey = make(AuxiliaryKey, sz)
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

// KeyCreationData is the data required to create a new KeyData object.
// It should be produced by a platform implementation.
type KeyCreationData struct {
	PlatformKeyData
	PlatformName string // Name of the platform that produced this data

	// AuxiliaryKey is a key used to authorize changes to the key data.
	// It must match the key protected inside PlatformKeyData.EncryptedPayload.
	AuxiliaryKey AuxiliaryKey

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

type hashAlg struct {
	crypto.Hash
}

func (a hashAlg) MarshalJSON() ([]byte, error) {
	var s string

	switch a.Hash {
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
	default:
		return nil, fmt.Errorf("unknown has algorithm: %v", a.Hash)
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
		a.Hash = crypto.SHA1
	case "sha224":
		a.Hash = crypto.SHA224
	case "sha256":
		a.Hash = crypto.SHA256
	case "sha384":
		a.Hash = crypto.SHA384
	case "sha512":
		a.Hash = crypto.SHA512
	default:
		a.Hash = crypto.Hash(0)
	}

	return nil
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

type authorizedSnapModels struct {
	Alg       hashAlg           `json:"alg"`
	KeyDigest []byte            `json:"key_digest"`
	Hmacs     snapModelHMACList `json:"hmacs"`
}

type kdfData struct {
	Type   string `json:"type"`
	Salt   []byte `json:"salt"`
	Time   int    `json:"time"`
	Memory int    `json:"memory"`
	CPUs   int    `json:"cpus"`
}

type passphraseData struct {
	KDF              kdfData `json:"kdf"`
	Encryption       string  `json:"encryption"`
	KeySize          int     `json:"key_size"`
	EncryptedPayload []byte  `json:"encrypted_payload"`
}

type keyData struct {
	PlatformName   string          `json:"platform_name"`
	PlatformHandle json.RawMessage `json:"platform_handle"`

	EncryptedPayload           []byte          `json:"encrypted_payload,omitempty"`
	PassphraseProtectedPayload *passphraseData `json:"passphrase_protected_payload,omitempty"`

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

func (d *KeyData) snapModelAuthKey(auxKey AuxiliaryKey) ([]byte, error) {
	rng, err := drbg.NewCTRWithExternalEntropy(32, auxKey, nil, []byte("SNAP-MODEL-HMAC"), nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot instantiate DRBG: %w", err)
	}

	alg := d.data.AuthorizedSnapModels.Alg
	if alg.Hash == crypto.Hash(0) {
		return nil, errors.New("invalid digest algorithm")
	}

	hmacKey := make([]byte, alg.Size())
	if _, err := rng.Read(hmacKey); err != nil {
		return nil, xerrors.Errorf("cannot derive key: %w", err)
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
	keyLen := passphraseDerivedKeyLen + aes.BlockSize

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

	c, err := aes.NewCipher(key[:passphraseDerivedKeyLen])
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
		KeySize:          passphraseDerivedKeyLen,
		EncryptedPayload: make([]byte, len(payload))}

	stream := cipher.NewCFBEncrypter(c, key[passphraseDerivedKeyLen:])
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
		// Only AES-256-CFB is supported
		return nil, nil, fmt.Errorf("unexpected encryption algorithm \"%s\"", data.Encryption)
	}

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

	c, err := aes.NewCipher(key[:passphraseDerivedKeyLen])
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create cipher: %w", err)
	}
	stream := cipher.NewCFBDecrypter(c, key[passphraseDerivedKeyLen:])
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
func (d *KeyData) RecoverKeys() (DiskUnlockKey, AuxiliaryKey, error) {
	if d.AuthMode() != AuthModeNone {
		return nil, nil, errors.New("cannot recover key without authorization")
	}

	handler := handlers[d.data.PlatformName]
	if handler == nil {
		return nil, nil, ErrNoPlatformHandlerRegistered
	}

	c, err := handler.RecoverKeys(&PlatformKeyData{
		Handle:           d.data.PlatformHandle,
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

func (d *KeyData) RecoverKeysWithPassphrase(passphrase string, kdf KDF) (DiskUnlockKey, AuxiliaryKey, error) {
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
		Handle:           d.data.PlatformHandle,
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
func (d *KeyData) IsSnapModelAuthorized(auxKey AuxiliaryKey, model SnapModel) (bool, error) {
	hmacKey, err := d.snapModelAuthKey(auxKey)
	if err != nil {
		return false, xerrors.Errorf("cannot obtain auth key: %w", err)
	}

	alg := d.data.AuthorizedSnapModels.Alg
	if alg.Hash == crypto.Hash(0) {
		return false, errors.New("invalid digest algorithm")
	}

	h, err := computeSnapModelHMAC(alg.Hash, hmacKey, model)
	if err != nil {
		return false, xerrors.Errorf("cannot compute HMAC of model: %w", err)
	}

	return d.data.AuthorizedSnapModels.Hmacs.contains(h), nil
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
func (d *KeyData) SetAuthorizedSnapModels(auxKey AuxiliaryKey, models ...SnapModel) error {
	hmacKey, err := d.snapModelAuthKey(auxKey)
	if err != nil {
		return xerrors.Errorf("cannot obtain auth key: %w", err)
	}

	alg := d.data.AuthorizedSnapModels.Alg
	if alg.Hash == crypto.Hash(0) {
		return errors.New("invalid digest algorithm")
	}

	h := alg.New()
	h.Write(hmacKey)
	if !bytes.Equal(h.Sum(nil), d.data.AuthorizedSnapModels.KeyDigest) {
		return errors.New("incorrect key supplied")
	}

	var modelHMACs snapModelHMACList

	for _, model := range models {
		h, err := computeSnapModelHMAC(alg.Hash, hmacKey, model)
		if err != nil {
			return xerrors.Errorf("cannot compute HMAC of model: %w", err)
		}

		modelHMACs = append(modelHMACs, h)
	}

	d.data.AuthorizedSnapModels.Hmacs = modelHMACs
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

// NewKeyData creates a new KeyData object using the supplied KeyCreationData, which
// should be created by a platform-specific package, containing a payload encrypted by
// the platform's secure device and the associated handle required for subsequent
// recovery of the keys.
func NewKeyData(creationData *KeyCreationData) (*KeyData, error) {
	if !json.Valid(creationData.Handle) {
		return nil, errors.New("handle is not valid JSON")
	}

	rng, err := drbg.NewCTRWithExternalEntropy(32, creationData.AuxiliaryKey, nil, []byte("SNAP-MODEL-HMAC"), nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot instantiate DRBG: %w", err)
	}

	h := creationData.SnapModelAuthHash.New()
	if _, err := io.CopyN(h, rng, int64(creationData.SnapModelAuthHash.Size())); err != nil {
		return nil, xerrors.Errorf("cannot create hash of snap model auth key: %w", err)
	}

	return &KeyData{
		data: keyData{
			PlatformName:     creationData.PlatformName,
			PlatformHandle:   json.RawMessage(creationData.Handle),
			EncryptedPayload: creationData.EncryptedPayload,
			AuthorizedSnapModels: authorizedSnapModels{
				Alg:       hashAlg{creationData.SnapModelAuthHash},
				KeyDigest: h.Sum(nil)}}}, nil
}

// MarshalKeys serializes the supplied disk unlock key and auxiliary key in
// to a format that is ready to be encrypted by a platform's secure device.
func MarshalKeys(key DiskUnlockKey, auxKey AuxiliaryKey) KeyPayload {
	w := new(bytes.Buffer)
	binary.Write(w, binary.BigEndian, uint16(len(key)))
	w.Write(key)
	binary.Write(w, binary.BigEndian, uint16(len(auxKey)))
	w.Write(auxKey)
	return w.Bytes()
}
