// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2022 Canonical Ltd
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

package secboot_test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math/rand"
	"reflect"
	"time"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/pbkdf2"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"

	. "gopkg.in/check.v1"
)

type mockPlatformKeyDataHandle struct {
	Key                []byte      `json:"key"`
	IV                 []byte      `json:"iv"`
	AuthKeyHMAC        []byte      `json:"auth-key-hmac"`
	ExpectedGeneration int         `json:"exp-generation"`
	ExpectedRole       string      `json:"exp-role"`
	ExpectedKDFAlg     crypto.Hash `json:"exp-kdf_alg"`
	ExpectedAuthMode   AuthMode    `json:"exp-auth-mode"`
}

const (
	mockPlatformDeviceStateOK = iota
	mockPlatformDeviceStateUnavailable
	mockPlatformDeviceStateUninitialized
)

type mockPlatformKeyDataHandler struct {
	state             int
	userAuthSupport   bool
	limitAuthFailures bool
	maxAuthFailures   int
	numAuthFailures   int
	permittedRoles    []string
}

func (h *mockPlatformKeyDataHandler) checkState() error {
	switch h.state {
	case mockPlatformDeviceStateUnavailable:
		return &PlatformHandlerError{Type: PlatformHandlerErrorUnavailable, Err: errors.New("the platform device is unavailable")}
	case mockPlatformDeviceStateUninitialized:
		return &PlatformHandlerError{Type: PlatformHandlerErrorUninitialized, Err: errors.New("the platform device is uninitialized")}
	default:
		return nil
	}
}

func (h *mockPlatformKeyDataHandler) unmarshalHandle(data *PlatformKeyData) (*mockPlatformKeyDataHandle, error) {
	var handle mockPlatformKeyDataHandle
	if err := json.Unmarshal(data.EncodedHandle, &handle); err != nil {
		return nil, &PlatformHandlerError{Type: PlatformHandlerErrorInvalidData, Err: fmt.Errorf("JSON decode error: %w", err)}
	}

	if data.Generation != handle.ExpectedGeneration {
		return nil, &PlatformHandlerError{Type: PlatformHandlerErrorInvalidData, Err: errors.New("unexpected generation")}
	}

	if data.Role != handle.ExpectedRole {
		return nil, &PlatformHandlerError{Type: PlatformHandlerErrorInvalidData, Err: errors.New("unexpected role")}
	}

	if data.Generation > 1 {
		if data.KDFAlg != handle.ExpectedKDFAlg {
			return nil, &PlatformHandlerError{Type: PlatformHandlerErrorInvalidData, Err: errors.New("unexpected KDFAlg")}
		}
	}

	if data.AuthMode != handle.ExpectedAuthMode {
		return nil, &PlatformHandlerError{Type: PlatformHandlerErrorInvalidData, Err: errors.New("unexpected AuthMode")}
	}

	return &handle, nil
}

func (h *mockPlatformKeyDataHandler) checkKey(handle *mockPlatformKeyDataHandle, key []byte) error {
	if h.limitAuthFailures && h.numAuthFailures >= h.maxAuthFailures {
		return &PlatformHandlerError{Type: PlatformHandlerErrorUserAuthUnavailable, Err: errors.New("too many auth failures")}
	}

	m := hmac.New(crypto.SHA256.New, handle.Key)
	m.Write(key)
	if !bytes.Equal(handle.AuthKeyHMAC, m.Sum(nil)) {
		if h.limitAuthFailures {
			h.numAuthFailures += 1
		}
		return &PlatformHandlerError{Type: PlatformHandlerErrorInvalidAuthKey, Err: errors.New("the supplied key is incorrect")}
	}

	return nil
}

func (h *mockPlatformKeyDataHandler) recoverKeys(handle *mockPlatformKeyDataHandle, payload []byte) ([]byte, error) {
	var permittedRole bool
	if len(h.permittedRoles) == 0 {
		// Only perform this check if the test defined any permitted roles.
		permittedRole = true
	} else {
		for _, role := range h.permittedRoles {
			if role == handle.ExpectedRole {
				permittedRole = true
				break
			}
		}
	}
	if !permittedRole {
		return nil, &PlatformHandlerError{Type: PlatformHandlerErrorIncompatibleRole, Err: errors.New("permission denied")}
	}

	b, err := aes.NewCipher(handle.Key)
	if err != nil {
		return nil, fmt.Errorf("cannot create cipher: %w", err)
	}

	s := cipher.NewCFBDecrypter(b, handle.IV)
	out := make([]byte, len(payload))
	s.XORKeyStream(out, payload)
	return out, nil
}

func (h *mockPlatformKeyDataHandler) RecoverKeys(data *PlatformKeyData, encryptedPayload []byte) ([]byte, error) {
	if err := h.checkState(); err != nil {
		return nil, err
	}

	handle, err := h.unmarshalHandle(data)
	if err != nil {
		return nil, err
	}

	return h.recoverKeys(handle, encryptedPayload)
}

func (h *mockPlatformKeyDataHandler) RecoverKeysWithAuthKey(data *PlatformKeyData, encryptedPayload []byte, key []byte) ([]byte, error) {
	if !h.userAuthSupport {
		return nil, errors.New("not supported")
	}

	if err := h.checkState(); err != nil {
		return nil, err
	}

	handle, err := h.unmarshalHandle(data)
	if err != nil {
		return nil, err
	}

	if err := h.checkKey(handle, key); err != nil {
		return nil, err
	}

	return h.recoverKeys(handle, encryptedPayload)
}

type mockChangeAuthKeyContextType struct{}

var mockChangeAuthKeyContext = mockChangeAuthKeyContextType{}

func (h *mockPlatformKeyDataHandler) ChangeAuthKey(data *PlatformKeyData, old, new []byte, context any) ([]byte, error) {
	if !h.userAuthSupport {
		return nil, errors.New("not supported")
	}

	if err := h.checkState(); err != nil {
		return nil, err
	}

	switch c := context.(type) {
	case nil:
	case mockChangeAuthKeyContextType:
		if c != mockChangeAuthKeyContext {
			return nil, errors.New("unexpected context value")
		}
	default:
		return nil, fmt.Errorf("unexpected context type: %v", reflect.TypeOf(context))
	}

	handle, err := h.unmarshalHandle(data)
	if err != nil {
		return nil, err
	}

	if err := h.checkKey(handle, old); err != nil {
		return nil, err
	}

	m := hmac.New(crypto.SHA256.New, handle.Key)
	m.Write(new)
	handle.AuthKeyHMAC = m.Sum(nil)

	return json.Marshal(&handle)
}

type mockKeyDataWriter struct {
	tmp   *bytes.Buffer
	final *bytes.Buffer
}

func (w *mockKeyDataWriter) Write(data []byte) (int, error) {
	if w.tmp == nil {
		return 0, errors.New("cancelled")
	}
	return w.tmp.Write(data)
}

func (w *mockKeyDataWriter) Cancel() error {
	w.tmp = nil
	return nil
}

func (w *mockKeyDataWriter) Commit() error {
	if w.tmp == nil {
		return errors.New("cancelled or already committed")
	}
	w.final = w.tmp
	w.tmp = nil
	return nil
}

// TODO: Give Reader and Bytes methods a *check.C argument
// so that they can abort the test if Commit hasn't been called.

func (w *mockKeyDataWriter) Reader() io.Reader {
	return w.final
}

func (w *mockKeyDataWriter) Bytes() []byte {
	return w.final.Bytes()
}

func makeMockKeyDataWriter() *mockKeyDataWriter {
	return &mockKeyDataWriter{tmp: new(bytes.Buffer)}
}

type mockKeyDataReader struct {
	readableName string
	io.Reader
}

func newMockKeyDataReader(name string, data []byte) *mockKeyDataReader {
	return &mockKeyDataReader{
		readableName: name,
		Reader:       bytes.NewReader(data),
	}
}

func (r *mockKeyDataReader) ReadableName() string {
	return r.readableName
}

func toHash(c *C, v interface{}) crypto.Hash {
	str, ok := v.(string)
	c.Assert(ok, testutil.IsTrue)
	switch str {
	case "null":
		return crypto.Hash(0)
	case "sha1":
		return crypto.SHA1
	case "sha224":
		return crypto.SHA224
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	default:
		c.Fatalf("unrecognized hash algorithm")
	}
	return crypto.Hash(0)
}

type pbkdf2BenchmarkArgs struct {
	targetDuration time.Duration
	hashAlg        crypto.Hash
}

type keyDataTestBase struct {
	handler                *mockPlatformKeyDataHandler
	mockPlatformName       string
	origArgon2KDF          Argon2KDF
	restorePBKDF2Benchmark func()
	expectedPBKDF2Hash     crypto.Hash
}

func (s *keyDataTestBase) SetUpSuite(c *C) {
	s.handler = &mockPlatformKeyDataHandler{}
	s.mockPlatformName = "mock"
	RegisterPlatformKeyDataHandler(s.mockPlatformName, s.handler, 0)
}

func (s *keyDataTestBase) SetUpTest(c *C) {
	s.handler.state = mockPlatformDeviceStateOK
	s.handler.userAuthSupport = false
	s.handler.limitAuthFailures = false
	s.handler.permittedRoles = nil
	s.origArgon2KDF = SetArgon2KDF(&testutil.MockArgon2KDF{})
	s.restorePBKDF2Benchmark = MockPBKDF2Benchmark(func(duration time.Duration, hashAlg crypto.Hash) (uint, error) {
		if hashAlg != s.expectedPBKDF2Hash {
			return 0, errors.New("unexpected hash")
		}
		return uint(duration / time.Microsecond), nil
	})
	s.expectedPBKDF2Hash = crypto.Hash(0)
}

func (s *keyDataTestBase) TearDownTest(c *C) {
	if s.restorePBKDF2Benchmark != nil {
		s.restorePBKDF2Benchmark()
		s.restorePBKDF2Benchmark = nil
	}
	SetArgon2KDF(s.origArgon2KDF)
}

func (s *keyDataTestBase) TearDownSuite(c *C) {
	RegisterPlatformKeyDataHandler(s.mockPlatformName, nil, 0)
}

func (s *keyDataTestBase) newPrimaryKey(c *C, sz1 int) PrimaryKey {
	primaryKey := make(PrimaryKey, sz1)
	_, err := rand.Read(primaryKey)
	c.Assert(err, IsNil)

	return primaryKey
}

func (s *keyDataTestBase) mockProtectKeys(c *C, primaryKey PrimaryKey, uniqueKey []byte, role string, kdfAlg crypto.Hash) (out *KeyParams, unlockKey DiskUnlockKey) {
	unlockKey, payload, err := MakeDiskUnlockKey(bytes.NewReader(uniqueKey), kdfAlg, primaryKey)
	c.Assert(err, IsNil)

	k := make([]byte, 48)
	_, err = rand.Read(k)
	c.Assert(err, IsNil)

	handle := mockPlatformKeyDataHandle{
		Key:                k[:32],
		IV:                 k[32:],
		ExpectedGeneration: KeyDataGeneration,
		ExpectedRole:       role,
		ExpectedKDFAlg:     kdfAlg,
		ExpectedAuthMode:   AuthModeNone,
	}

	h := hmac.New(crypto.SHA256.New, handle.Key)
	h.Write(make([]byte, 32))
	handle.AuthKeyHMAC = h.Sum(nil)

	b, err := aes.NewCipher(handle.Key)
	c.Assert(err, IsNil)
	stream := cipher.NewCFBEncrypter(b, handle.IV)

	out = &KeyParams{
		PlatformName:     s.mockPlatformName,
		Handle:           &handle,
		Role:             role,
		EncryptedPayload: make([]byte, len(payload)),
		KDFAlg:           kdfAlg}
	stream.XORKeyStream(out.EncryptedPayload, payload)

	return out, unlockKey
}

func (s *keyDataTestBase) mockProtectKeysRand(c *C, primaryKey PrimaryKey, role string, kdfAlg crypto.Hash) (out *KeyParams, unlockKey DiskUnlockKey) {
	unique := make([]byte, len(primaryKey))
	_, err := rand.Read(unique)
	c.Assert(err, IsNil)

	return s.mockProtectKeys(c, primaryKey, unique, role, kdfAlg)
}

func (s *keyDataTestBase) mockProtectKeysWithPassphrase(c *C, primaryKey PrimaryKey, uniqueKey []byte, role string, kdfOptions KDFOptions, authKeySize int, kdfAlg crypto.Hash) (out *KeyWithPassphraseParams, unlockKey DiskUnlockKey) {
	kp, unlockKey := s.mockProtectKeys(c, primaryKey, uniqueKey, role, kdfAlg)

	handle, ok := kp.Handle.(*mockPlatformKeyDataHandle)
	c.Assert(ok, testutil.IsTrue)

	handle.ExpectedAuthMode = AuthModePassphrase
	h := hmac.New(crypto.SHA256.New, handle.Key)
	h.Write(make([]byte, authKeySize))
	handle.AuthKeyHMAC = h.Sum(nil)

	if kdfOptions == nil {
		var defaultOptions Argon2Options
		kdfOptions = &defaultOptions
	}

	switch opt := kdfOptions.(type) {
	case *PBKDF2Options:
		s.expectedPBKDF2Hash = opt.HashAlg
		if opt.HashAlg == crypto.Hash(0) {
			s.expectedPBKDF2Hash = crypto.SHA256
			switch {
			case authKeySize >= 48 && authKeySize < 64:
				s.expectedPBKDF2Hash = crypto.SHA384
			case authKeySize >= 64:
				s.expectedPBKDF2Hash = crypto.SHA512
			}
		}
	}

	kpp := &KeyWithPassphraseParams{
		KeyParams:            *kp,
		KDFOptions:           kdfOptions,
		AuthKeySize:          authKeySize,
		ChangeAuthKeyContext: mockChangeAuthKeyContext,
	}

	return kpp, unlockKey
}

func (s *keyDataTestBase) mockProtectKeysWithPassphraseRand(c *C, primaryKey PrimaryKey, role string, kdfOptions KDFOptions, authKeySize int, kdfAlg crypto.Hash) (out *KeyWithPassphraseParams, unlockKey DiskUnlockKey) {
	unique := make([]byte, len(primaryKey))
	_, err := rand.Read(unique)
	c.Assert(err, IsNil)

	return s.mockProtectKeysWithPassphrase(c, primaryKey, unique, role, kdfOptions, authKeySize, kdfAlg)
}

func (s *keyDataTestBase) mockProtectKeysWithPIN(c *C, primaryKey PrimaryKey, uniqueKey []byte, role string, kdfOptions *PBKDF2Options, authKeySize int, kdfAlg crypto.Hash) (out *KeyWithPINParams, unlockKey DiskUnlockKey) {
	kp, unlockKey := s.mockProtectKeys(c, primaryKey, uniqueKey, role, kdfAlg)

	handle, ok := kp.Handle.(*mockPlatformKeyDataHandle)
	c.Assert(ok, testutil.IsTrue)

	handle.ExpectedAuthMode = AuthModePIN
	h := hmac.New(crypto.SHA256.New, handle.Key)
	h.Write(make([]byte, authKeySize))
	handle.AuthKeyHMAC = h.Sum(nil)

	if kdfOptions == nil {
		var defaultOptions PBKDF2Options
		kdfOptions = &defaultOptions
	}

	s.expectedPBKDF2Hash = kdfOptions.HashAlg
	if kdfOptions.HashAlg == crypto.Hash(0) {
		s.expectedPBKDF2Hash = crypto.SHA256
		switch {
		case authKeySize >= 48 && authKeySize < 64:
			s.expectedPBKDF2Hash = crypto.SHA384
		case authKeySize >= 64:
			s.expectedPBKDF2Hash = crypto.SHA512
		}
	}

	kpp := &KeyWithPINParams{
		KeyParams:            *kp,
		KDFOptions:           kdfOptions,
		AuthKeySize:          authKeySize,
		ChangeAuthKeyContext: mockChangeAuthKeyContext,
	}

	return kpp, unlockKey
}

func (s *keyDataTestBase) mockProtectKeysWithPINRand(c *C, primaryKey PrimaryKey, role string, kdfOptions *PBKDF2Options, authKeySize int, kdfAlg crypto.Hash) (out *KeyWithPINParams, unlockKey DiskUnlockKey) {
	unique := make([]byte, len(primaryKey))
	_, err := rand.Read(unique)
	c.Assert(err, IsNil)

	return s.mockProtectKeysWithPIN(c, primaryKey, unique, role, kdfOptions, authKeySize, kdfAlg)
}

func (s *keyDataTestBase) checkKeyDataJSONDecodedLegacyFields(c *C, j map[string]interface{}, creationParams *KeyParams, nmodels int) {
	snapModelAuthHash := crypto.SHA256

	m, ok := j["authorized_snap_models"].(map[string]interface{})
	c.Assert(ok, testutil.IsTrue)

	h := toHash(c, m["alg"])
	c.Check(h, Equals, snapModelAuthHash)

	c.Check(m, testutil.HasKey, "hmacs")
	if nmodels == 0 {
		c.Check(m["hmacs"], IsNil)
	} else {
		c.Check(m["hmacs"], HasLen, nmodels)
		hmacs, ok := m["hmacs"].([]interface{})
		c.Check(ok, testutil.IsTrue)
		for _, v := range hmacs {
			str, ok := v.(string)
			c.Check(ok, testutil.IsTrue)
			digest, err := base64.StdEncoding.DecodeString(str)
			c.Check(err, IsNil)
			c.Check(digest, HasLen, h.Size())
		}
	}

	h = toHash(c, m["kdf_alg"])
	c.Check(h, Equals, snapModelAuthHash)

	m1, ok := m["key_digest"].(map[string]interface{})
	c.Assert(ok, testutil.IsTrue)

	h = toHash(c, m1["alg"])
	c.Check(h, Equals, snapModelAuthHash)

	str, ok := m1["salt"].(string)
	c.Check(ok, testutil.IsTrue)
	salt, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)
	c.Check(salt, HasLen, 32)

	str, ok = m1["digest"].(string)
	c.Check(ok, testutil.IsTrue)
	digest, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)
	c.Check(digest, HasLen, h.Size())
}

func (s *keyDataTestBase) checkKeyDataJSONCommon(c *C, j map[string]interface{}, creationParams *KeyParams) {
	c.Check(j["platform_name"], Equals, creationParams.PlatformName)

	expectedHandle, ok := creationParams.Handle.(*mockPlatformKeyDataHandle)
	c.Assert(ok, testutil.IsTrue)

	handleBytes, err := json.Marshal(j["platform_handle"])
	c.Check(err, IsNil)

	var handle *mockPlatformKeyDataHandle
	c.Assert(json.Unmarshal(handleBytes, &handle), IsNil)

	c.Check(handle.Key, DeepEquals, expectedHandle.Key)
	c.Check(handle.IV, DeepEquals, expectedHandle.IV)
	c.Check(handle.ExpectedGeneration, Equals, expectedHandle.ExpectedGeneration)
	c.Check(handle.ExpectedRole, Equals, expectedHandle.ExpectedRole)
	c.Check(handle.ExpectedKDFAlg, Equals, expectedHandle.ExpectedKDFAlg)

	kdf, ok := j["kdf_alg"].(string)
	c.Check(ok, testutil.IsTrue)
	expectedKdfJSON, err := json.Marshal(HashAlg(creationParams.KDFAlg))
	c.Assert(err, IsNil)
	var expectedKdf string
	c.Assert(json.Unmarshal(expectedKdfJSON, &expectedKdf), IsNil)
	c.Check(kdf, Equals, expectedKdf)

	role, ok := j["role"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(role, Equals, creationParams.Role)

	generation, ok := j["generation"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(generation, Equals, float64(expectedHandle.ExpectedGeneration))
}

func (s *keyDataTestBase) checkKeyDataJSONDecodedAuthModeNone(c *C, j map[string]interface{}, creationParams *KeyParams) {
	s.checkKeyDataJSONCommon(c, j, creationParams)

	str, ok := j["encrypted_payload"].(string)
	c.Check(ok, testutil.IsTrue)
	encryptedPayload, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)
	c.Check(encryptedPayload, DeepEquals, creationParams.EncryptedPayload)

	c.Check(j, Not(testutil.HasKey), "passphrase_params")
	c.Check(j, Not(testutil.HasKey), "pin_params")

	handleBytes, err := json.Marshal(j["platform_handle"])
	c.Check(err, IsNil)

	var handle *mockPlatformKeyDataHandle
	c.Assert(json.Unmarshal(handleBytes, &handle), IsNil)

	c.Check(handle.ExpectedAuthMode, Equals, AuthModeNone)
}

func (s *keyDataTestBase) checkKeyDataJSONFromReaderAuthModeNone(c *C, r io.Reader, creationParams *KeyParams) {
	var j map[string]interface{}

	d := json.NewDecoder(r)
	c.Check(d.Decode(&j), IsNil)

	s.checkKeyDataJSONDecodedAuthModeNone(c, j, creationParams)
}

func (s *keyDataTestBase) checkKeyDataJSONDecodedAuthModePassphrase(c *C, j map[string]interface{}, creationParams *KeyWithPassphraseParams, passphrase string) {
	kdfOpts := creationParams.KDFOptions
	if kdfOpts == nil {
		var def Argon2Options
		kdfOpts = &def
	}

	kdfParams, err := KDFOptionsKdfParams(kdfOpts, 2*time.Second, uint32(creationParams.AuthKeySize))
	c.Assert(err, IsNil)

	s.checkKeyDataJSONCommon(c, j, &creationParams.KeyParams)

	c.Check(j, Not(testutil.HasKey), "pin_params")

	p, ok := j["passphrase_params"].(map[string]interface{})
	c.Assert(ok, testutil.IsTrue)

	encryption, ok := p["encryption"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(encryption, Equals, "aes-cfb")

	derivedKeySize, ok := p["derived_key_size"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(derivedKeySize, Equals, float64(32))

	encryptionKeySize, ok := p["encryption_key_size"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(encryptionKeySize, Equals, float64(32))

	authKeySize, ok := p["auth_key_size"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(authKeySize, Equals, float64(creationParams.AuthKeySize))

	k, ok := p["kdf"].(map[string]interface{})
	c.Assert(ok, testutil.IsTrue)

	str, ok := k["salt"].(string)
	c.Check(ok, testutil.IsTrue)
	salt, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)

	str, ok = k["type"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(str, Equals, string(kdfParams.Type))

	time, ok := k["time"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(time, Equals, float64(kdfParams.Time))

	memory, ok := k["memory"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(memory, Equals, float64(kdfParams.Memory))

	cpus, ok := k["cpus"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(cpus, Equals, float64(kdfParams.CPUs))

	h := toHash(c, k["hash"])
	c.Check(ok, testutil.IsTrue)
	c.Check(h, Equals, crypto.Hash(kdfParams.Hash))

	str, ok = j["encrypted_payload"].(string)
	c.Check(ok, testutil.IsTrue)
	encryptedPayload, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)

	// TODO properly unmarshal from field
	// and expose HashAlg helpers
	kdfAlg := crypto.SHA256
	sha256Oid := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // SEQUENCE {
		b.AddASN1OctetString(salt) // salt OCTET STRING
		// kdfAlg.marshalASN1(b)                                               // kdfAlgorithm AlgorithmIdentifier
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(sha256Oid) // algorithm OBJECT IDENTIFIER
			b.AddASN1NULL()                      // parameters ANY DEFINED BY algorithm OPTIONAL
		})
		b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) { // encryption UTF8String
			b.AddBytes([]byte(encryption))
		})
		b.AddASN1Int64(int64(encryptionKeySize)) // encryptionKeySize INTEGER
		b.AddASN1Int64(int64(authKeySize))       // authKeySize INTEGER
	})
	asnsalt, err := builder.Bytes()
	c.Assert(err, IsNil)

	var derived []byte
	switch o := kdfOpts.(type) {
	case *Argon2Options:
		_ = o
		var kdf testutil.MockArgon2KDF
		costParams := &Argon2CostParams{
			Time:      uint32(kdfParams.Time),
			MemoryKiB: uint32(kdfParams.Memory),
			Threads:   uint8(kdfParams.CPUs),
		}
		derived, _ = kdf.Derive(passphrase, asnsalt, Argon2Mode(kdfParams.Type), costParams, uint32(derivedKeySize))
	case *PBKDF2Options:
		_ = o
		var err error
		derived, err = pbkdf2.Key(passphrase, asnsalt, &pbkdf2.Params{Iterations: uint(kdfParams.Time), HashAlg: crypto.Hash(kdfParams.Hash)}, uint(derivedKeySize))
		c.Assert(err, IsNil)
	}

	key := make([]byte, int(encryptionKeySize))

	r := hkdf.Expand(kdfAlg.New, derived, []byte("PASSPHRASE-ENC"))
	_, err = io.ReadFull(r, key)
	c.Assert(err, IsNil)

	iv := make([]byte, aes.BlockSize)
	r = hkdf.Expand(kdfAlg.New, derived, []byte("PASSPHRASE-IV"))
	_, err = io.ReadFull(r, iv)
	c.Assert(err, IsNil)

	b, err := aes.NewCipher(key)
	c.Assert(err, IsNil)
	stream := cipher.NewCFBDecrypter(b, iv)
	payload := make([]byte, len(encryptedPayload))
	stream.XORKeyStream(payload, encryptedPayload)
	c.Check(payload, DeepEquals, creationParams.EncryptedPayload)

	auth := make([]byte, creationParams.AuthKeySize)
	r = hkdf.Expand(kdfAlg.New, derived, []byte("PASSPHRASE-AUTH"))
	_, err = io.ReadFull(r, auth)
	c.Assert(err, IsNil)

	handleBytes, err := json.Marshal(j["platform_handle"])
	c.Check(err, IsNil)

	var handle *mockPlatformKeyDataHandle
	c.Assert(json.Unmarshal(handleBytes, &handle), IsNil)

	c.Check(handle.ExpectedAuthMode, Equals, AuthModePassphrase)

	m := hmac.New(crypto.SHA256.New, handle.Key)
	m.Write(auth)
	c.Check(m.Sum(nil), DeepEquals, handle.AuthKeyHMAC)
}

func (s *keyDataTestBase) checkKeyDataJSONFromReaderAuthModePassphrase(c *C, r io.Reader, creationParams *KeyWithPassphraseParams, passphrase string) {
	var j map[string]interface{}

	d := json.NewDecoder(r)
	c.Check(d.Decode(&j), IsNil)

	s.checkKeyDataJSONDecodedAuthModePassphrase(c, j, creationParams, passphrase)
}

func (s *keyDataTestBase) checkKeyDataJSONDecodedAuthModePIN(c *C, j map[string]interface{}, creationParams *KeyWithPINParams, pin PIN) {
	kdfOpts := creationParams.KDFOptions
	if kdfOpts == nil {
		var def PBKDF2Options
		kdfOpts = &def
	}

	kdfParams, err := kdfOpts.KdfParams(200*time.Millisecond, uint32(creationParams.AuthKeySize))
	c.Assert(err, IsNil)

	s.checkKeyDataJSONCommon(c, j, &creationParams.KeyParams)

	c.Check(j, Not(testutil.HasKey), "passphrase_params")

	p, ok := j["pin_params"].(map[string]interface{})
	c.Check(ok, testutil.IsTrue)

	authKeySize, ok := p["auth_key_size"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(authKeySize, Equals, float64(creationParams.AuthKeySize))

	k, ok := p["kdf"].(map[string]interface{})
	c.Check(ok, testutil.IsTrue)

	str, ok := k["salt"].(string)
	c.Check(ok, testutil.IsTrue)
	salt, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)
	c.Check(salt, HasLen, 16)

	str, ok = k["type"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(str, Equals, string(kdfParams.Type))

	time, ok := k["time"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(time, Equals, float64(kdfParams.Time))

	memory, ok := k["memory"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(memory, Equals, float64(kdfParams.Memory))

	cpus, ok := k["cpus"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(cpus, Equals, float64(kdfParams.CPUs))

	h := toHash(c, k["hash"])
	c.Check(ok, testutil.IsTrue)
	c.Check(h, Equals, crypto.Hash(kdfParams.Hash))

	str, ok = j["encrypted_payload"].(string)
	c.Check(ok, testutil.IsTrue)
	encryptedPayload, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)
	c.Check(encryptedPayload, DeepEquals, creationParams.EncryptedPayload)

	handleBytes, err := json.Marshal(j["platform_handle"])
	c.Check(err, IsNil)

	var handle *mockPlatformKeyDataHandle
	c.Assert(json.Unmarshal(handleBytes, &handle), IsNil)

	c.Check(handle.ExpectedAuthMode, Equals, AuthModePIN)

	auth, err := pbkdf2.Key(string(pin.Bytes()), salt, &pbkdf2.Params{Iterations: uint(time), HashAlg: h}, uint(creationParams.AuthKeySize))
	c.Check(err, IsNil)
	m := hmac.New(crypto.SHA256.New, handle.Key)
	m.Write(auth)
	c.Check(m.Sum(nil), DeepEquals, handle.AuthKeyHMAC)
}

func (s *keyDataTestBase) checkKeyDataJSONFromReaderAuthModePIN(c *C, r io.Reader, creationParams *KeyWithPINParams, pin PIN) {
	var j map[string]interface{}

	d := json.NewDecoder(r)
	c.Check(d.Decode(&j), IsNil)

	s.checkKeyDataJSONDecodedAuthModePIN(c, j, creationParams, pin)
}

type keyDataSuite struct {
	snapd_testutil.BaseTest
	keyDataTestBase
}

func (s *keyDataSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.keyDataTestBase.SetUpTest(c)
}

func (s *keyDataSuite) TearDownTest(c *C) {
	s.BaseTest.TearDownTest(c)
	s.keyDataTestBase.TearDownTest(c)
}

var _ = Suite(&keyDataSuite{})

func (s *keyDataSuite) checkKeyDataJSONAuthModeNone(c *C, keyData *KeyData, creationParams *KeyParams) {
	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModeNone(c, w.Reader(), creationParams)
}

func (s *keyDataSuite) checkKeyDataJSONAuthModePassphrase(c *C, keyData *KeyData, creationParams *KeyWithPassphraseParams, passphrase string) {
	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModePassphrase(c, w.Reader(), creationParams, passphrase)
}

func (s *keyDataSuite) checkKeyDataJSONAuthModePIN(c *C, keyData *KeyData, creationParams *KeyWithPINParams, pin PIN) {
	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModePIN(c, w.Reader(), creationParams, pin)
}

type testKeyPayloadData struct {
	primary PrimaryKey
	unique  []byte
}

func marshalASN1(c *C, primary PrimaryKey, unique []byte) []byte {
	builder := cryptobyte.NewBuilder(nil)

	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // ProtectedKeys ::= SEQUENCE {
		b.AddASN1OctetString(primary) // primary OCTETSTRING
		b.AddASN1OctetString(unique)  // unique OCTETSTRING
	})

	b, err := builder.Bytes()
	c.Assert(err, IsNil)
	return b
}

func (s *keyDataSuite) testKeyPayload(c *C, data *testKeyPayloadData) {
	payload := marshalASN1(c, data.primary, data.unique)

	pk, err := UnmarshalProtectedKeys(payload)
	c.Check(err, IsNil)

	unique := data.unique
	if data.unique == nil {
		unique = []uint8{}
	}
	c.Check(pk, DeepEquals, &ProtectedKeys{Primary: data.primary, Unique: unique})
}

func (s *keyDataSuite) TestKeyPayload1(c *C) {
	primary := s.newPrimaryKey(c, 32)
	// Not really a primary key just using the same method
	// to generate a random value of the same size
	unique := s.newPrimaryKey(c, 32)

	s.testKeyPayload(c, &testKeyPayloadData{
		primary: primary,
		unique:  unique})
}

func (s *keyDataSuite) TestKeyPayload2(c *C) {
	primary := s.newPrimaryKey(c, 64)
	unique := s.newPrimaryKey(c, 32)

	s.testKeyPayload(c, &testKeyPayloadData{
		primary: primary,
		unique:  unique})
}

func (s *keyDataSuite) TestKeyPayload3(c *C) {
	primary := s.newPrimaryKey(c, 32)

	s.testKeyPayload(c, &testKeyPayloadData{
		primary: primary,
	})
}

func (s *keyDataSuite) TestKeyPayloadUnmarshalInvalid1(c *C) {
	payload := make([]byte, 66)
	for i := range payload {
		payload[i] = 0xff
	}

	pk, err := UnmarshalProtectedKeys(payload)
	c.Check(err, ErrorMatches, "malformed input")
	c.Check(pk, IsNil)
}

func (s *keyDataSuite) TestKeyPayloadUnmarshalInvalid2(c *C) {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // ProtectedKeys ::= SEQUENCE {
	})

	payload, err := builder.Bytes()
	c.Assert(err, IsNil)

	pk, err := UnmarshalProtectedKeys(payload)
	c.Check(err, ErrorMatches, "malformed primary key")
	c.Check(pk, IsNil)
}

func (s *keyDataSuite) TestKeyPayloadUnmarshalInvalid3(c *C) {
	random := s.newPrimaryKey(c, 32)

	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // ProtectedKeys ::= SEQUENCE {
		b.AddASN1OctetString(random) // primary OCTETSTRING
	})

	payload, err := builder.Bytes()
	c.Assert(err, IsNil)

	pk, err := UnmarshalProtectedKeys(payload)
	c.Check(err, ErrorMatches, "malformed unique key")
	c.Check(pk, IsNil)
}

type keyDataHasher struct {
	hash.Hash
}

func (h *keyDataHasher) Commit() error { return nil }

func (s *keyDataSuite) TestKeyDataID(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	h := &keyDataHasher{Hash: crypto.SHA256.New()}
	c.Check(keyData.WriteAtomic(h), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)
	c.Check(id, DeepEquals, KeyID(h.Sum(nil)))
}

func (s *keyDataSuite) TestNewKeyData(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected)
}

func (s *keyDataSuite) TestNewKeyDataDifferentRole(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "bar", crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected)
}

func (s *keyDataSuite) TestNewKeyDataDifferentKDFAlg(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA384)
	keyData, err := NewKeyData(protected)
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected)
}

func (s *keyDataSuite) TestNewKeyDataWithPassphrase(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", nil, 32, crypto.SHA256)
	keyData, err := NewKeyDataWithPassphrase(protected, "passphrase")
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, "passphrase")
}

func (s *keyDataSuite) TestNewKeyDataWithPassphraseDifferentPassphrase(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", nil, 32, crypto.SHA256)
	keyData, err := NewKeyDataWithPassphrase(protected, "secret")
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, "secret")
}

func (s *keyDataSuite) TestNewKeyDataWithPassphraseEmptyKDFOptions(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", new(Argon2Options), 32, crypto.SHA256)
	keyData, err := NewKeyDataWithPassphrase(protected, "passphrase")
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, "passphrase")
}

func (s *keyDataSuite) TestNewKeyDataWithPassphraseCustomKDFDuration(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", &Argon2Options{TargetDuration: 500 * time.Millisecond}, 32, crypto.SHA256)
	keyData, err := NewKeyDataWithPassphrase(protected, "passphrase")
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, "passphrase")
}

func (s *keyDataSuite) TestNewKeyDataWithPassphraseKDFForceIterations(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", &Argon2Options{ForceIterations: 3, MemoryKiB: 32 * 1024}, 32, crypto.SHA256)
	keyData, err := NewKeyDataWithPassphrase(protected, "passphrase")
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, "passphrase")
}

func (s *keyDataSuite) TestNewKeyDataWithPassphraseWithPBKDF2(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", new(PBKDF2Options), 32, crypto.SHA256)
	keyData, err := NewKeyDataWithPassphrase(protected, "passphrase")
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, "passphrase")
}

func (s *keyDataSuite) TestNewKeyDataWithPassphraseDifferentAuthKeySize(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", nil, 48, crypto.SHA256)
	keyData, err := NewKeyDataWithPassphrase(protected, "passphrase")
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, "passphrase")
}

func (s *keyDataSuite) TestNewKeyDataWithPIN(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPINRand(c, primaryKey, "foo", nil, 32, crypto.SHA256)
	keyData, err := NewKeyDataWithPIN(protected, makePIN(c, "1234"))
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePIN(c, keyData, protected, makePIN(c, "1234"))
}

func (s *keyDataSuite) TestNewKeyDataWithPINDifferentPIN(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPINRand(c, primaryKey, "foo", nil, 32, crypto.SHA256)
	keyData, err := NewKeyDataWithPIN(protected, makePIN(c, "87654321"))
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePIN(c, keyData, protected, makePIN(c, "87654321"))
}

func (s *keyDataSuite) TestNewKeyDataWithPINCustomKDFDuration(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPINRand(c, primaryKey, "foo", &PBKDF2Options{TargetDuration: 500 * time.Millisecond}, 32, crypto.SHA256)
	keyData, err := NewKeyDataWithPIN(protected, makePIN(c, "1234"))
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePIN(c, keyData, protected, makePIN(c, "1234"))
}

func (s *keyDataSuite) TestNewKeyDataWithPINDifferentAuthKeySize(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPINRand(c, primaryKey, "foo", nil, 48, crypto.SHA256)
	keyData, err := NewKeyDataWithPIN(protected, makePIN(c, "1234"))
	c.Check(err, IsNil)
	c.Assert(keyData, NotNil)

	s.checkKeyDataJSONAuthModePIN(c, keyData, protected, makePIN(c, "1234"))
}

func (s *keyDataSuite) TestNewKeyDataWithPINNotSupported(c *C) {
	// Test that creation of a new key data with PIN fails when the
	// platform handler doesn't have user auth support.
	primaryKey := s.newPrimaryKey(c, 32)
	pinParams, _ := s.mockProtectKeysWithPINRand(c, primaryKey, "", nil, 32, crypto.SHA256)

	_, err := NewKeyDataWithPIN(pinParams, makePIN(c, "0000"))
	c.Check(err, ErrorMatches, "cannot set PIN: cannot perform action because of an unexpected error: not supported")
}

func (s *keyDataSuite) TestKeyDataPlatformName(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	c.Check(keyData.PlatformName(), Equals, s.mockPlatformName)
}

func (s *keyDataSuite) TestKeyDataRole(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	c.Check(keyData.Role(), Equals, "foo")
}

func (s *keyDataSuite) TestUnmarshalPlatformHandle(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var handle *mockPlatformKeyDataHandle
	c.Check(keyData.UnmarshalPlatformHandle(&handle), IsNil)

	c.Check(handle, DeepEquals, protected.Handle)
}

func (s *keyDataSuite) TestMarshalAndUpdatePlatformHandle(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	handle := protected.Handle.(*mockPlatformKeyDataHandle)
	rand.Read(handle.AuthKeyHMAC)

	c.Check(keyData.MarshalAndUpdatePlatformHandle(&handle), IsNil)

	protected.Handle = handle

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected)
}

func (s *keyDataSuite) TestRecoverKeys(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeys()
	c.Assert(err, IsNil)

	c.Check(recoveredUnlockKey, DeepEquals, unlockKey)
	c.Check(recoveredPrimaryKey, DeepEquals, primaryKey)
}

func (s *keyDataSuite) TestRecoverKeysUnrecognizedPlatform(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)

	protected.PlatformName = "foo"

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "no appropriate platform handler is registered")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysInvalidData(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)

	protected.Handle = []byte("\"\"")

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: JSON decode error: json: cannot unmarshal string into Go value of type secboot_test.mockPlatformKeyDataHandle")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

type testRecoverKeysWithPassphraseParams struct {
	kdfOptions  KDFOptions
	authKeySize int
	passphrase  string
}

func (s *keyDataSuite) testRecoverKeysWithPassphrase(c *C, params *testRecoverKeysWithPassphraseParams) {
	s.handler.userAuthSupport = true

	authKeySize := params.authKeySize
	if authKeySize == 0 {
		authKeySize = 32
	}

	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", params.kdfOptions, authKeySize, crypto.SHA256)

	keyData, err := NewKeyDataWithPassphrase(protected, params.passphrase)
	c.Assert(err, IsNil)

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeysWithPassphrase(params.passphrase)
	c.Check(err, IsNil)
	c.Check(recoveredUnlockKey, DeepEquals, unlockKey)
	c.Check(recoveredPrimaryKey, DeepEquals, primaryKey)
}

func (s *keyDataSuite) TestRecoverKeysWithPassphrase(c *C) {
	s.testRecoverKeysWithPassphrase(c, &testRecoverKeysWithPassphraseParams{
		passphrase: "passphrase",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseDifferentPassphrase(c *C) {
	s.testRecoverKeysWithPassphrase(c, &testRecoverKeysWithPassphraseParams{
		passphrase: "secret",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphrasePBKDF2(c *C) {
	s.testRecoverKeysWithPassphrase(c, &testRecoverKeysWithPassphraseParams{
		kdfOptions: new(PBKDF2Options),
		passphrase: "passphrase",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseCustomAuthKeySize(c *C) {
	s.testRecoverKeysWithPassphrase(c, &testRecoverKeysWithPassphraseParams{
		authKeySize: 48,
		passphrase:  "passphrase",
	})
}

type testRecoverKeysWithPINParams struct {
	kdfOptions  *PBKDF2Options
	authKeySize int
	pin         PIN
}

func (s *keyDataSuite) testRecoverKeysWithPIN(c *C, params *testRecoverKeysWithPINParams) {
	s.handler.userAuthSupport = true

	authKeySize := params.authKeySize
	if authKeySize == 0 {
		authKeySize = 32
	}

	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeysWithPINRand(c, primaryKey, "foo", params.kdfOptions, authKeySize, crypto.SHA256)
	keyData, err := NewKeyDataWithPIN(protected, params.pin)
	c.Assert(err, IsNil)

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeysWithPIN(params.pin)
	c.Check(err, IsNil)
	c.Check(recoveredUnlockKey, DeepEquals, unlockKey)
	c.Check(recoveredPrimaryKey, DeepEquals, primaryKey)
}

func (s *keyDataSuite) TestRecoverKeysWithPIN(c *C) {
	s.testRecoverKeysWithPIN(c, &testRecoverKeysWithPINParams{
		pin: makePIN(c, "1234"),
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPINDifferentPIN(c *C) {
	s.testRecoverKeysWithPIN(c, &testRecoverKeysWithPINParams{
		pin: makePIN(c, "87654321"),
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPINDifferentAuthKeySize(c *C) {
	s.testRecoverKeysWithPIN(c, &testRecoverKeysWithPINParams{
		authKeySize: 48,
		pin:         makePIN(c, "1234"),
	})
}

type testRecoverKeysWithPassphraseKDFErrorHandlingData struct {
	kdfType           string
	errMsg            string
	derivedKeySize    int
	encryptionKeySize int
	authKeySize       int
	time              int
	memory            int
	cpus              int
}

func (s *keyDataSuite) testRecoverKeysWithPassphraseKDFErrorHandling(c *C, data *testRecoverKeysWithPassphraseKDFErrorHandlingData) {
	s.handler.userAuthSupport = true

	if data.kdfType == "" {
		data.kdfType = "argon2i"
	}

	if data.derivedKeySize == 0 {
		data.derivedKeySize = 32
	}

	if data.encryptionKeySize == 0 {
		data.encryptionKeySize = 32
	}

	if data.authKeySize == 0 {
		data.authKeySize = 32
	}

	if data.time == 0 {
		data.time = 4
	}

	if data.memory == 0 {
		data.memory = 1024063
	}

	if data.cpus == 0 {
		data.cpus = 4
	}

	j := []byte(
		`{` +
			`"generation":2,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"GtaI3cZX9H3Ig1YxSCPTxLshteV0AXK2pFgQuE5NRIQ=",` +
			`"iv":"0VUZD/yYi6PfRzdPB0a1GA==",` +
			`"auth-key-hmac":"7/AmPJvhwHNY/E1a3oEoqF5xjmt5FBr9YTppQvESUSY=",` +
			`"exp-generation":2,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":1},` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"m5Qz8plfHf+M51BJgTN35pUEKQhHLSz59y9miniM1pEeLeZMWSsLuUHRjL3n9azbxckIHOLYYmAyNg9bF7VoFcQWsHMeww==",` +
			`"passphrase_params":` +
			`{` +
			`"kdf":` +
			`{` +
			`"type":"` + data.kdfType + `",` +
			`"salt":"8A3SHdXVwCzEmD7YMKkyWw==",` +
			`"time":` + fmt.Sprint(data.time) + `,` +
			`"memory":` + fmt.Sprint(data.memory) + `,` +
			`"cpus":` + fmt.Sprint(data.cpus) + `},` +
			`"encryption":"aes-cfb",` +
			`"derived_key_size":` + fmt.Sprint(data.derivedKeySize) + `,` +
			`"encryption_key_size":` + fmt.Sprint(data.encryptionKeySize) + `,` +
			`"auth_key_size":` + fmt.Sprint(data.authKeySize) + `},` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"FvNTIAyRqLt3dHi0vboZR8xUM7JLG3J/tu8Xt7qY8/A=",` +
			`"digest":"2ueYVTxhTxFX64L4+afifv1G9Vaf97JdkyUZ7wxJgPs="},` +
			`"hmacs":null}}
	`)
	keyData, err := ReadKeyData(&mockKeyDataReader{"foo", bytes.NewReader(j)})
	c.Assert(err, IsNil)

	_, _, err = keyData.RecoverKeysWithPassphrase("passphrase")
	c.Check(err.Error(), Equals, data.errMsg)
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseNotSupportedKDF(c *C) {
	s.testRecoverKeysWithPassphraseKDFErrorHandling(c, &testRecoverKeysWithPassphraseKDFErrorHandlingData{
		kdfType: "other",
		errMsg:  "invalid key data: unexpected intermediate KDF type \"other\"",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseInvalidDerivedKeySize(c *C) {
	s.testRecoverKeysWithPassphraseKDFErrorHandling(c, &testRecoverKeysWithPassphraseKDFErrorHandlingData{
		derivedKeySize: -1,
		errMsg:         "invalid key data: invalid derived key size (-1 bytes)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseInvalidEncryptionKeySizeSmall(c *C) {
	s.testRecoverKeysWithPassphraseKDFErrorHandling(c, &testRecoverKeysWithPassphraseKDFErrorHandlingData{
		encryptionKeySize: -1,
		errMsg:            "invalid key data: invalid encryption key size (-1 bytes)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseInvalidEncryptionKeySizeBig(c *C) {
	s.testRecoverKeysWithPassphraseKDFErrorHandling(c, &testRecoverKeysWithPassphraseKDFErrorHandlingData{
		encryptionKeySize: 33,
		errMsg:            "invalid key data: invalid encryption key size (33 bytes)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseInvalidAuthKeySize(c *C) {
	s.testRecoverKeysWithPassphraseKDFErrorHandling(c, &testRecoverKeysWithPassphraseKDFErrorHandlingData{
		authKeySize: -1,
		errMsg:      "invalid key data: invalid auth key size (-1 bytes)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseInvalidTime(c *C) {
	s.testRecoverKeysWithPassphraseKDFErrorHandling(c, &testRecoverKeysWithPassphraseKDFErrorHandlingData{
		time:   -1,
		errMsg: "invalid key data: invalid KDF time (-1)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseUnavailableKDF(c *C) {
	restore := MockHashAlgAvailable()
	defer restore()
	s.testRecoverKeysWithPassphraseKDFErrorHandling(c, &testRecoverKeysWithPassphraseKDFErrorHandlingData{
		errMsg: fmt.Sprintf("unavailable leaf KDF digest algorithm %d", crypto.SHA256),
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseInvalidPassphrase(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", nil, 32, crypto.SHA256)

	keyData, err := NewKeyDataWithPassphrase(protected, "passphrase")
	c.Assert(err, IsNil)

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeysWithPassphrase("secret")
	c.Check(err, Equals, ErrInvalidPassphrase)
	c.Check(recoveredUnlockKey, IsNil)
	c.Check(recoveredPrimaryKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseAuthModeNone(c *C) {
	// Test that RecoverKeysWithPassphrase for a key without a passphrase set fails
	auxKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, auxKey, "", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeysWithPassphrase("")
	c.Check(err, ErrorMatches, "cannot recover key with passphrase - user auth required: none")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) TestNewKeyDataWithPassphraseNotSupported(c *C) {
	// Test that creation of a new key data with passphrase fails when the
	// platform handler doesn't have passphrase support.
	primaryKey := s.newPrimaryKey(c, 32)
	passphraseParams, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "", nil, 32, crypto.SHA256)

	_, err := NewKeyDataWithPassphrase(passphraseParams, "passphrase")
	c.Check(err, ErrorMatches, "cannot set passphrase: cannot perform action because of an unexpected error: not supported")
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseAuthModePIN(c *C) {
	// Test that RecoverKeysWithPassphrase for a key with a PIN set failsa
	s.handler.userAuthSupport = true

	auxKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPINRand(c, auxKey, "", nil, 32, crypto.SHA256)

	keyData, err := NewKeyDataWithPIN(protected, makePIN(c, "1234"))
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeysWithPassphrase("")
	c.Check(err, ErrorMatches, "cannot recover key with passphrase - user auth required: PIN")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseNotAvailable(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", nil, 32, crypto.SHA256)

	keyData, err := NewKeyDataWithPassphrase(protected, "passphrase")
	c.Assert(err, IsNil)

	s.handler.limitAuthFailures = true

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeysWithPassphrase("passphrase")
	c.Check(err, ErrorMatches, `user authorization is currently unavailable: too many auth failures`)
	c.Check(err, testutil.ConvertibleTo, &UserAuthUnavailableError{})
	c.Check(recoveredUnlockKey, IsNil)
	c.Check(recoveredPrimaryKey, IsNil)
}

type testRecoverKeysWithPINKDFErrorHandlingParams struct {
	authKeySize int
	time        int
	kdfType     string
	errMsg      string
}

func (s *keyDataSuite) testRecoverKeysWithPINKDFErrorHandling(c *C, params *testRecoverKeysWithPINKDFErrorHandlingParams) {
	s.handler.userAuthSupport = true

	if params.authKeySize == 0 {
		params.authKeySize = 32
	}
	if params.time == 0 {
		params.time = 200000
	}
	if params.kdfType == "" {
		params.kdfType = "pbkdf2"
	}

	// Valid keydata with PIN "1234"
	j := []byte(
		`{` +
			`"generation":2,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"fIt2mnOrQzbbItU+Lmy+s9paEnjFO4mnJfV/KFKIp2s=",` +
			`"iv":"OJfIMNZgNN30TY6n2PrZVg==",` +
			`"auth-key-hmac":"YUdEGlQ1ixmXZGMA3IEaDNZVgVw5V6d1CnZ2L8XuvPU=",` +
			`"exp-generation":2,` +
			`"exp-role":"foo",` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":2` +
			`},` +
			`"role":"foo",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"J034T3Z55qU6qA+mUnkQQX3gGtXtsQuFyb8bgUfQB6QzXkeho2mV3eFR+h1gUTsYHYTRa/qzv9J45vSQ4aT2Lnm/R3d70A==",` +
			`"pin_params":` +
			`{` +
			`"kdf":{"salt":"3vOcAGxpkdtGXF8WAX7c0g==",` +
			`"type":"` + params.kdfType + `",` +
			`"time":` + fmt.Sprint(params.time) + `,` +
			`"memory":0,` +
			`"cpus":0,` +
			`"hash":"sha256"` +
			`},` +
			`"auth_key_size":` + fmt.Sprint(params.authKeySize) + `}}`)

	keyData, err := ReadKeyData(&mockKeyDataReader{"foo", bytes.NewReader(j)})
	c.Assert(err, IsNil)

	_, _, err = keyData.RecoverKeysWithPIN(makePIN(c, "1234"))
	c.Check(err.Error(), Equals, params.errMsg)
}

func (s *keyDataSuite) TestRecoverKeysWithPINKDFErrorHandlingInvalidAuthKeySize(c *C) {
	s.testRecoverKeysWithPINKDFErrorHandling(c, &testRecoverKeysWithPINKDFErrorHandlingParams{
		authKeySize: -1,
		errMsg:      "invalid auth key size (-1 bytes)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPINKDFErrorHandlingInvalidTime(c *C) {
	s.testRecoverKeysWithPINKDFErrorHandling(c, &testRecoverKeysWithPINKDFErrorHandlingParams{
		time:   -1,
		errMsg: "invalid KDF time (-1)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPINKDFErrorHandlingInvalidKDFType(c *C) {
	s.testRecoverKeysWithPINKDFErrorHandling(c, &testRecoverKeysWithPINKDFErrorHandlingParams{
		kdfType: "other",
		errMsg:  "unexpected KDF type \"other\"",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPINKDFErrorHandlingUnavailableKDF(c *C) {
	restore := MockHashAlgAvailable()
	defer restore()
	s.testRecoverKeysWithPINKDFErrorHandling(c, &testRecoverKeysWithPINKDFErrorHandlingParams{
		errMsg: fmt.Sprintf("unavailable pbkdf2 digest algorithm %d", crypto.SHA256),
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPINInvalidPIN(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPINRand(c, primaryKey, "foo", nil, 32, crypto.SHA256)

	keyData, err := NewKeyDataWithPIN(protected, makePIN(c, "1234"))
	c.Assert(err, IsNil)

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeysWithPIN(makePIN(c, "00000"))
	c.Check(err, Equals, ErrInvalidPIN)
	c.Check(recoveredUnlockKey, IsNil)
	c.Check(recoveredPrimaryKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysWithPINAuthModeNone(c *C) {
	// Test that RecoverKeysWithPIN for a key without a pin set fails
	auxKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, auxKey, "", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeysWithPIN(makePIN(c, "0"))
	c.Check(err, ErrorMatches, "cannot recover key with PIN - user auth required: none")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysWithPINAuthModePassphrase(c *C) {
	// Test that RecoverKeysWithPIN for a key with a passphrase set fails
	s.handler.userAuthSupport = true

	auxKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, auxKey, "", nil, 32, crypto.SHA256)

	keyData, err := NewKeyDataWithPassphrase(protected, "passphrase")
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeysWithPIN(makePIN(c, "1234"))
	c.Check(err, ErrorMatches, "cannot recover key with PIN - user auth required: passphrase")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysWithPINUnsupported(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPINRand(c, primaryKey, "foo", nil, 32, crypto.SHA256)

	keyData, err := NewKeyDataWithPIN(protected, makePIN(c, "1234"))
	c.Assert(err, IsNil)

	s.handler.userAuthSupport = false

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeysWithPIN(makePIN(c, "1234"))
	c.Check(err, ErrorMatches, `cannot perform action because of an unexpected error: not supported`)
	c.Check(recoveredUnlockKey, IsNil)
	c.Check(recoveredPrimaryKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysWithPINNotAvailable(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPINRand(c, primaryKey, "foo", nil, 32, crypto.SHA256)

	keyData, err := NewKeyDataWithPIN(protected, makePIN(c, "1234"))
	c.Assert(err, IsNil)

	s.handler.limitAuthFailures = true

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeysWithPIN(makePIN(c, "1234"))
	c.Check(err, ErrorMatches, `user authorization is currently unavailable: too many auth failures`)
	c.Check(err, testutil.ConvertibleTo, &UserAuthUnavailableError{})
	c.Check(recoveredUnlockKey, IsNil)
	c.Check(recoveredPrimaryKey, IsNil)
}

func (s *keyDataSuite) TestChangePassphraseNotSupported(c *C) {
	// Test that changing passphrase of a key data with a passphrase set
	// fails when the platform handler doesn't have user auth support.
	j := []byte(
		`{` +
			`"generation":2,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"6yrcBpn9ZmjZgiLqFZtp1nns+3zjVo/yxrbSqwhTuf4=",` +
			`"iv":"HDEMeSzmDmsGZTzVTOxPOw==",` +
			`"auth-key-hmac":"WQ3rrqhi5TMVHYiP3j10UG0h2D8nKQ0cs9YvXZGzRA8="},` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"uAUgcV48QrqgOQL1dI+CRRdVTSzEnTguKW0HXQFnU2q1SjIi45AvbcawnUhQl2k8rl2SBDL2RS4uIBZDlFaWiAHbwmX9ig==",` +
			`"passphrase_params":` +
			`{` +
			`"kdf":` +
			`{` +
			`"type":"argon2i",` +
			`"salt":"Uj1araXwSDK+WlzQ8RNQMg==",` +
			`"time":4,` +
			`"memory":1024063,` +
			`"cpus":4},` +
			`"encryption":"aes-cfb",` +
			`"derived_key_size":32,` +
			`"encryption_key_size":32,` +
			`"auth_key_size":32},` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"KAToqFGUwszVEjyOmc0Pil5uuhouNhaVynRLllPx7dU=",` +
			`"digest":"GegPT/eBoSl1X9m5pSYcgdme/NtRA2/W4q38WDz4HHQ="},` +
			`"hmacs":null}}
		`)

	keyData, err := ReadKeyData(&mockKeyDataReader{Reader: bytes.NewReader(j)})
	c.Assert(err, IsNil)

	c.Check(keyData.ChangePassphrase("passphrase", ""), ErrorMatches, "cannot perform action because of an unexpected error: not supported")
}

func (s *keyDataSuite) TestChangePassphraseWithWrongAuthMode(c *C) {
	// Test that changing passphrase on a key data without a passphrase set fails.
	j := []byte(
		`{` +
			`"generation":2,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"6yrcBpn9ZmjZgiLqFZtp1nns+3zjVo/yxrbSqwhTuf4=",` +
			`"iv":"HDEMeSzmDmsGZTzVTOxPOw==",` +
			`"auth-key-hmac":"WQ3rrqhi5TMVHYiP3j10UG0h2D8nKQ0cs9YvXZGzRA8="},` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"uAUgcV48QrqgOQL1dI+CRRdVTSzEnTguKW0HXQFnU2q1SjIi45AvbcawnUhQl2k8rl2SBDL2RS4uIBZDlFaWiAHbwmX9ig==",` +
			`"encryption":"aes-cfb",` +
			`"derived_key_size":32,` +
			`"encryption_key_size":32,` +
			`"auth_key_size":32},` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"KAToqFGUwszVEjyOmc0Pil5uuhouNhaVynRLllPx7dU=",` +
			`"digest":"GegPT/eBoSl1X9m5pSYcgdme/NtRA2/W4q38WDz4HHQ="},` +
			`"hmacs":null}}
		`)

	keyData, err := ReadKeyData(&mockKeyDataReader{Reader: bytes.NewReader(j)})
	c.Assert(err, IsNil)

	c.Check(keyData.ChangePassphrase("passphrase", ""), ErrorMatches, "cannot change passphrase - user auth configured: none")
}

type testChangePassphraseData struct {
	passphrase1 string
	passphrase2 string
	kdfOptions  KDFOptions
	authKeySize int
}

func (s *keyDataSuite) testChangePassphrase(c *C, data *testChangePassphraseData) {
	s.handler.userAuthSupport = true

	authKeySize := data.authKeySize
	if authKeySize == 0 {
		authKeySize = 32
	}

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", data.kdfOptions, authKeySize, crypto.SHA256)

	keyData, err := NewKeyDataWithPassphrase(protected, data.passphrase1)
	c.Check(err, IsNil)

	c.Check(keyData.ChangePassphrase(data.passphrase1, data.passphrase2), IsNil)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, data.passphrase2)
}

func (s *keyDataSuite) TestChangePassphrase(c *C) {
	s.testChangePassphrase(c, &testChangePassphraseData{
		passphrase1: "passphrase",
		passphrase2: "secret"})
}

func (s *keyDataSuite) TestChangePassphraseDifferentPassphrase(c *C) {
	s.testChangePassphrase(c, &testChangePassphraseData{
		passphrase1: "secret",
		passphrase2: "passphrase"})
}

func (s *keyDataSuite) TestChangePassphrasePBKDF2(c *C) {
	s.testChangePassphrase(c, &testChangePassphraseData{
		passphrase1: "passphrase",
		passphrase2: "secret",
		kdfOptions:  new(PBKDF2Options)})
}

func (s *keyDataSuite) TestChangePassphraseCustomAuthKeySize(c *C) {
	s.testChangePassphrase(c, &testChangePassphraseData{
		passphrase1: "passphrase",
		passphrase2: "secret",
		authKeySize: 48})
}

func (s *keyDataSuite) TestChangePassphraseWrongPassphrase(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)

	kdfOptions := &Argon2Options{
		TargetDuration: 100 * time.Millisecond,
	}
	protected, _ := s.mockProtectKeysWithPassphraseRand(c, primaryKey, "foo", kdfOptions, 32, crypto.SHA256)

	keyData, err := NewKeyDataWithPassphrase(protected, "12345678")
	c.Check(err, IsNil)

	c.Check(keyData.ChangePassphrase("passphrase", "12345678"), Equals, ErrInvalidPassphrase)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, "12345678")
}

func (s *keyDataSuite) TestChangePINNotSupported(c *C) {
	// Test that changing PIN of a key data with a PIN set fails when the
	// platform handler doesn't have user auth support.
	// Valid keydata with PIN "1234"
	j := []byte(
		`{` +
			`"generation":2,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"fIt2mnOrQzbbItU+Lmy+s9paEnjFO4mnJfV/KFKIp2s=",` +
			`"iv":"OJfIMNZgNN30TY6n2PrZVg==",` +
			`"auth-key-hmac":"YUdEGlQ1ixmXZGMA3IEaDNZVgVw5V6d1CnZ2L8XuvPU=",` +
			`"exp-generation":2,` +
			`"exp-role":"foo",` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":2` +
			`},` +
			`"role":"foo",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"J034T3Z55qU6qA+mUnkQQX3gGtXtsQuFyb8bgUfQB6QzXkeho2mV3eFR+h1gUTsYHYTRa/qzv9J45vSQ4aT2Lnm/R3d70A==",` +
			`"pin_params":` +
			`{` +
			`"kdf":{"salt":"3vOcAGxpkdtGXF8WAX7c0g==",` +
			`"type":"pbkdf2",` +
			`"time":200000,` +
			`"memory":0,` +
			`"cpus":0,` +
			`"hash":"sha256"` +
			`},` +
			`"auth_key_size":32}}`)

	keyData, err := ReadKeyData(&mockKeyDataReader{Reader: bytes.NewReader(j)})
	c.Assert(err, IsNil)

	c.Check(keyData.ChangePIN(makePIN(c, "1234"), makePIN(c, "0000")), ErrorMatches, "cannot perform action because of an unexpected error: not supported")
}

func (s *keyDataSuite) TestChangePINWithWrongAuthMode(c *C) {
	// Test that changing PIN on a key data without a PIN set fails.
	j := []byte(
		`{` +
			`"generation":2,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"6yrcBpn9ZmjZgiLqFZtp1nns+3zjVo/yxrbSqwhTuf4=",` +
			`"iv":"HDEMeSzmDmsGZTzVTOxPOw==",` +
			`"auth-key-hmac":"WQ3rrqhi5TMVHYiP3j10UG0h2D8nKQ0cs9YvXZGzRA8="},` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"uAUgcV48QrqgOQL1dI+CRRdVTSzEnTguKW0HXQFnU2q1SjIi45AvbcawnUhQl2k8rl2SBDL2RS4uIBZDlFaWiAHbwmX9ig==",` +
			`"encryption":"aes-cfb",` +
			`"derived_key_size":32,` +
			`"encryption_key_size":32,` +
			`"auth_key_size":32},` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"KAToqFGUwszVEjyOmc0Pil5uuhouNhaVynRLllPx7dU=",` +
			`"digest":"GegPT/eBoSl1X9m5pSYcgdme/NtRA2/W4q38WDz4HHQ="},` +
			`"hmacs":null}}
		`)

	keyData, err := ReadKeyData(&mockKeyDataReader{Reader: bytes.NewReader(j)})
	c.Assert(err, IsNil)

	c.Check(keyData.ChangePIN(makePIN(c, "0000"), makePIN(c, "1234")), ErrorMatches, "cannot change PIN - user auth configured: none")
}

type testChangePINParams struct {
	pin1        PIN
	pin2        PIN
	kdfOptions  *PBKDF2Options
	authKeySize int
}

func (s *keyDataSuite) testChangePIN(c *C, params *testChangePINParams) {
	s.handler.userAuthSupport = true

	authKeySize := params.authKeySize
	if authKeySize == 0 {
		authKeySize = 32
	}

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPINRand(c, primaryKey, "foo", params.kdfOptions, authKeySize, crypto.SHA256)

	keyData, err := NewKeyDataWithPIN(protected, params.pin1)
	c.Check(err, IsNil)

	c.Check(keyData.ChangePIN(params.pin1, params.pin2), IsNil)

	s.checkKeyDataJSONAuthModePIN(c, keyData, protected, params.pin2)
}

func (s *keyDataSuite) TestChangePIN(c *C) {
	s.testChangePIN(c, &testChangePINParams{
		pin1: makePIN(c, "1234"),
		pin2: makePIN(c, "87654321"),
	})
}

func (s *keyDataSuite) TestChangePINWithDifferentPIN(c *C) {
	s.testChangePIN(c, &testChangePINParams{
		pin1: makePIN(c, "87654321"),
		pin2: makePIN(c, "1234"),
	})
}

func (s *keyDataSuite) TestChangePINWithCustomAuthKeySize(c *C) {
	s.testChangePIN(c, &testChangePINParams{
		pin1:        makePIN(c, "1234"),
		pin2:        makePIN(c, "87654321"),
		authKeySize: 48,
	})
}

func (s *keyDataSuite) TestChangePINWrongPIN(c *C) {
	s.handler.userAuthSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPINRand(c, primaryKey, "foo", nil, 32, crypto.SHA256)

	keyData, err := NewKeyDataWithPIN(protected, makePIN(c, "1234"))
	c.Check(err, IsNil)

	c.Check(keyData.ChangePIN(makePIN(c, "0000"), makePIN(c, "4321")), Equals, ErrInvalidPIN)

	s.checkKeyDataJSONAuthModePIN(c, keyData, protected, makePIN(c, "1234"))
}

type testWriteAtomicData struct {
	keyData *KeyData
	params  *KeyParams
	nmodels int
}

func (s *keyDataSuite) testWriteAtomic(c *C, data *testWriteAtomicData) {
	s.checkKeyDataJSONAuthModeNone(c, data.keyData, data.params)
}

func (s *keyDataSuite) TestWriteAtomic1(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	s.testWriteAtomic(c, &testWriteAtomicData{
		keyData: keyData,
		params:  protected})
}

type testReadKeyDataData struct {
	unlockKey  DiskUnlockKey
	primaryKey PrimaryKey
	id         KeyID
	r          KeyDataReader
	model      SnapModel
	authorized bool
}

func (s *keyDataSuite) testReadKeyData(c *C, data *testReadKeyDataData) {
	keyData, err := ReadKeyData(data.r)
	c.Assert(err, IsNil)
	c.Check(keyData.ReadableName(), Equals, data.r.ReadableName())

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)
	c.Check(id, DeepEquals, data.id)

	unlockKey, primaryKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(unlockKey, DeepEquals, data.unlockKey)
	c.Check(primaryKey, DeepEquals, data.primaryKey)
}

func (s *keyDataSuite) TestReadKeyData1(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	s.testReadKeyData(c, &testReadKeyDataData{
		unlockKey:  unlockKey,
		primaryKey: primaryKey,
		id:         id,
		r:          &mockKeyDataReader{"foo", w.Reader()},
	})
}

func (s *keyDataSuite) TestReadKeyData2(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	s.testReadKeyData(c, &testReadKeyDataData{
		unlockKey:  unlockKey,
		primaryKey: primaryKey,
		id:         id,
		r:          &mockKeyDataReader{"bar", w.Reader()},
	})
}

func (s *keyDataSuite) TestReadKeyData3(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	params := &testReadKeyDataData{
		unlockKey:  unlockKey,
		primaryKey: primaryKey,
		id:         id,
		r:          &mockKeyDataReader{"foo", w.Reader()},
	}

	s.testReadKeyData(c, params)
}

func (s *keyDataSuite) TestReadKeyData4(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	params := &testReadKeyDataData{
		unlockKey:  unlockKey,
		primaryKey: primaryKey,
		id:         id,
		r:          &mockKeyDataReader{"foo", w.Reader()},
	}

	s.testReadKeyData(c, params)
}

func (s *keyDataSuite) TestMakeDiskUnlockKey(c *C) {
	primaryKey := testutil.DecodeHexString(c, "1850fbecbe8b3db83a894cb975756c8b69086040f097b03bd4f3b1a3e19c4b86")
	kdfAlg := crypto.SHA256
	unique := testutil.DecodeHexString(c, "1850fbecbe8b3db83a894cb975756c8b69086040f097b03bd4f3b1a3e19c4b86")

	unlockKey, clearTextPayload, err := MakeDiskUnlockKey(bytes.NewReader(unique), kdfAlg, primaryKey)
	c.Assert(err, IsNil)

	knownGoodUnlockKey := testutil.DecodeHexString(c, "8b78ddabd8e38a6513e654638c0f7b8c738d5461a403564d19d98e7f8ed469cb")
	c.Check(unlockKey, DeepEquals, DiskUnlockKey(knownGoodUnlockKey))

	knownGoodPayload := testutil.DecodeHexString(c, "304404201850fbecbe8b3db83a894cb975756c8b69086040f097b03bd4f3b1a3e19c4b8604201850fbecbe8b3db83a894cb975756c8b69086040f097b03bd4f3b1a3e19c4b86")
	c.Check(clearTextPayload, DeepEquals, knownGoodPayload)

	st := cryptobyte.String(clearTextPayload)
	c.Assert(st.ReadASN1(&st, cryptobyte_asn1.SEQUENCE), Equals, true)

	var p PrimaryKey
	c.Assert(st.ReadASN1Bytes((*[]byte)(&p), cryptobyte_asn1.OCTET_STRING), Equals, true)
	c.Check(p, DeepEquals, PrimaryKey(primaryKey))

	var u []byte
	c.Assert(st.ReadASN1Bytes(&u, cryptobyte_asn1.OCTET_STRING), Equals, true)
	c.Check(u, DeepEquals, unique)
}

// Legacy tests
func (s *keyDataSuite) testLegacyWriteAtomic(c *C, data *testWriteAtomicData) {
	w := makeMockKeyDataWriter()
	c.Check(data.keyData.WriteAtomic(w), IsNil)

	var j map[string]interface{}

	d := json.NewDecoder(w.Reader())
	c.Check(d.Decode(&j), IsNil)

	s.checkKeyDataJSONDecodedAuthModeNone(c, j, data.params)
	s.checkKeyDataJSONDecodedLegacyFields(c, j, data.params, data.nmodels)
}

func (s *keyDataSuite) TestLegacyWriteAtomic1(c *C) {
	key, err := base64.StdEncoding.DecodeString("O+AgNjD0LZWfVfwrnicZLedbsJVSySR2HMr3dAPrdX0=")
	c.Assert(err, IsNil)
	iv, err := base64.StdEncoding.DecodeString("BIVYsrYcNuNzuMouhgi4YA==")
	c.Assert(err, IsNil)

	handle := mockPlatformKeyDataHandle{
		Key:                key,
		IV:                 iv,
		ExpectedGeneration: 1,
		ExpectedKDFAlg:     crypto.SHA256,
		ExpectedAuthMode:   AuthModeNone,
	}

	encPayload, err := base64.StdEncoding.DecodeString("tb68rp1ruzrFuuas86Nv8/Q9PzsxCt3brGRQNaArY8sFiUXz20oFHPyHa13Cz00NOZL04fD/1RSYvBcHUF/xOFe2SoA=")
	c.Assert(err, IsNil)

	protected := &KeyParams{
		PlatformName:     s.mockPlatformName,
		Handle:           &handle,
		EncryptedPayload: encPayload,
		KDFAlg:           crypto.SHA256}

	j := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"O+AgNjD0LZWfVfwrnicZLedbsJVSySR2HMr3dAPrdX0=",` +
			`"iv":"BIVYsrYcNuNzuMouhgi4YA==",` +
			`"auth-key-hmac":"DoOW+jLaY8T3eKGKvz3c125oRIpXGC2T7B0KWYzoajQ=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"tb68rp1ruzrFuuas86Nv8/Q9PzsxCt3brGRQNaArY8sFiUXz20oFHPyHa13Cz00NOZL04fD/1RSYvBcHUF/xOFe2SoA=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"dkyuuVDN7/b0IJ9bqrnFZstrA0ctFuOCVrbErt2PPnM=",` +
			`"digest":"sqSEkBclP9uIxT/vyCh8+gNByfhwN618j+Y8G3GgTqM="},` +
			`"hmacs":null}}
`)

	keyData, err := ReadKeyData(&mockKeyDataReader{Reader: bytes.NewReader(j)})
	c.Assert(err, IsNil)

	s.testLegacyWriteAtomic(c, &testWriteAtomicData{
		keyData: keyData,
		params:  protected})
}

func (s *keyDataSuite) TestLegacyKeyPayloadUnmarshalInvalid1(c *C) {
	payload := make([]byte, 66)
	for i := range payload {
		payload[i] = 0xff
	}

	key, auxKey, err := UnmarshalV1KeyPayload(payload)
	c.Check(err, ErrorMatches, "EOF")
	c.Check(key, IsNil)
	c.Check(auxKey, IsNil)
}

func (s *keyDataSuite) TestLegacyKeyPayloadUnmarshalInvalid2(c *C) {
	payload := marshalV1Keys(make(DiskUnlockKey, 32), make(PrimaryKey, 32))
	payload = append(payload, 0xff)

	key, auxKey, err := UnmarshalV1KeyPayload(payload)
	c.Check(err, ErrorMatches, "1 excess byte\\(s\\)")
	c.Check(key, IsNil)
	c.Check(auxKey, IsNil)
	return
}

type testLegacySnapModelAuthData struct {
	alg        crypto.Hash
	authModels []SnapModel
	model      SnapModel
	authorized bool
}

func (s *keyDataSuite) testLegacySnapModelAuth(c *C, data *testLegacySnapModelAuthData) {

	primaryKey := testutil.DecodeHexString(c, "cc4b23dbdd28fdabf80af71a68e50458621c632340978b08bd3b645f25e1b8c0")
	j := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"i7hWLt1p+iyBQOd/edg9qhC/8ylr4rYjkmqAYp5QSRk=",` +
			`"iv":"2+7pAYQIphbVAbbhegQJ7g==",` +
			`"auth-key-hmac":"EGPHpICORhpYywUDL31U19TWKRw0PQrgNuWCmDzjIfw=",` +
			`"exp-generation":2,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"mlcscFyWBjFHb3G2zxg1j4PZb/FGG2jxD9Vqu+Ds5qK4MIIYBq055ISCjI++evAkbWEp9+gqGW0mzu+c+hrQaGbd33w=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"uxHxz5z0cOBF/kIwI7TuJ+eGU6uwSHdW5VZjNpj+eE4=",` +
			`"digest":"uUfn0pt0h1jh4/Iel6UjRaH+aXwPCEKeA7Mac1B0Jdo="},` +
			`"hmacs":null}}
	`)

	keyData, err := ReadKeyData(&mockKeyDataReader{Reader: bytes.NewReader(j)})
	c.Assert(err, IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	c.Check(keyData.SetAuthorizedSnapModels(primaryKey, data.authModels...), IsNil)

	authorized, err := keyData.IsSnapModelAuthorized(primaryKey, data.model)
	c.Check(err, IsNil)
	c.Check(authorized, Equals, data.authorized)
}

func (s *keyDataSuite) TestLegacySnapModelAuth1(c *C) {
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	s.testLegacySnapModelAuth(c, &testLegacySnapModelAuthData{
		alg:        crypto.SHA256,
		authModels: models,
		model:      models[0],
		authorized: true})
}

func (s *keyDataSuite) TestLegacySnapModelAuth2(c *C) {
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	s.testLegacySnapModelAuth(c, &testLegacySnapModelAuthData{
		alg:        crypto.SHA256,
		authModels: models,
		model:      models[1],
		authorized: true})
}

func (s *keyDataSuite) TestLegacySnapModelAuth3(c *C) {
	s.testLegacySnapModelAuth(c, &testLegacySnapModelAuthData{
		alg: crypto.SHA256,
		authModels: []SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")},
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		authorized: false})
}

func (s *keyDataSuite) TestLegacySnapModelAuth4(c *C) {
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	s.testLegacySnapModelAuth(c, &testLegacySnapModelAuthData{
		alg:        crypto.SHA512,
		authModels: models,
		model:      models[0],
		authorized: true})
}

func (s *keyDataSuite) TestLegacySnapModelAuth5(c *C) {
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"classic":      "true",
			"distribution": "ubuntu",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"classic":      "true",
			"distribution": "ubuntu",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	s.testLegacySnapModelAuth(c, &testLegacySnapModelAuthData{
		alg:        crypto.SHA256,
		authModels: models,
		model:      models[1],
		authorized: true})
}

func (s *keyDataSuite) TestLegacySnapModelAuth6(c *C) {
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	s.testLegacySnapModelAuth(c, &testLegacySnapModelAuthData{
		alg:        crypto.SHA256,
		authModels: models,
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"classic":      "true",
			"distribution": "ubuntu",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		authorized: false})
}

func (s *keyDataSuite) TestLegacySnapModelAuthErrorHandling(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysRand(c, primaryKey, "foo", crypto.SHA256)
	keyData, err := NewKeyData(protected)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	authorized, err := keyData.IsSnapModelAuthorized(primaryKey, nil)
	c.Check(err, ErrorMatches, "unsupported key data generation number")
	c.Check(authorized, Equals, false)
}

func (s *keyDataSuite) TestLegacySetAuthorizedSnapModelsWithWrongKey(c *C) {
	j := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"csOUHfZ4qYJ5ga5fbW60bFt1HEI7C/RcHsfFZkgNUso=",` +
			`"iv":"L1J+Z+FlAxdq2MWkxPTRYw==",` +
			`"auth-key-hmac":"aC1HlXH/zlGEUWPpu9sehNBL7Zoz7e9RcRyrP7ph98s=",` +
			`"exp-generation":2,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"PBEOUTROv/kvHa8Gr4HVxJqRqrnqWqTTBQVHX9xIEYnLObXMJ7QXc/CjS5jbWFpIU88qw5NYgWawQB9ee/isXbC5F/4=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"AjCl21fNBTarpehNqnFdgcFmDteO6yAKd8kkw5kl7zQ=",` +
			`"digest":"wvTQvmHAt8szska7rcF2uEo8Vb/ntIQ268wbtn8wQHs="},` +
			`"hmacs":null}}
`)

	keyData, err := ReadKeyData(&mockKeyDataReader{Reader: bytes.NewReader(j)})
	c.Assert(err, IsNil)

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	c.Check(keyData.SetAuthorizedSnapModels(make(PrimaryKey, 32), models...), ErrorMatches, "incorrect key supplied")
}

func (s *keyDataSuite) TestKeyDataDerivePassphraseKeysExpectedInfoFields(c *C) {
	// Test that key derivation from passphrase is using expected info fields
	s.handler.userAuthSupport = true

	// Valid KeyData with passphrase "passphrase"
	j := []byte(
		`{` +
			`"generation":2,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"PNmzLCfVurOXSYAFaLAOdHuhBMo7fmrFS2RtNooe3fw=",` +
			`"iv":"D84HW2UYyF6nOMyfEPMtiQ==",` +
			`"auth-key-hmac":"EAMRNlNzn3Tz47uM9kLTgXBaM341G4D6W3f57PDc8xs=",` +
			`"exp-generation":2,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":1},` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"JV78CDs5AG/KQfJC/Q0kg9zrUX+3l7x9jDZyalg3+roBhkCEcNZiV4AMwreO01uDJyKdovTRHPoCYlNwpwfVBEuTlfvrpQ==",` +
			`"passphrase_params":` +
			`{` +
			`"kdf":` +
			`{` +
			`"type":"argon2i",` +
			`"salt":"cFP5Mb1Djp3EP160ejEClg==",` +
			`"time":4,` +
			`"memory":1024063,` +
			`"cpus":4},` +
			`"encryption":"aes-cfb",` +
			`"derived_key_size":32,` +
			`"encryption_key_size":32,` +
			`"auth_key_size":32},` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"g1zdFrK4+AKyQpaDiQ2Udwijdf/sKvfbRKKWxSBl7sc=",` +
			`"digest":"8sVvLZOkRD6RWjLFSp/pOPrKoibsr+VWyGhv4M2aph8="},` +
			`"hmacs":null}}
`)
	expectedKey := testutil.DecodeHexString(c, "89e97e7c427f54805a25c2bd1224865218aa5a985e5ac4c44fbc2c53b4bdfae2")
	expectedIV := testutil.DecodeHexString(c, "b5835d62838a8bef63f37389ae782308")
	expectedAuth := testutil.DecodeHexString(c, "2e46344ee30895da0d8e11cbb86bb67aeeccca0f6c6489009619593cca00722e")

	kd, err := ReadKeyData(&mockKeyDataReader{"foo", bytes.NewReader(j)})
	c.Assert(err, IsNil)

	key, iv, auth, err := kd.DerivePassphraseKeys("passphrase")
	c.Assert(err, IsNil)

	c.Check(key, DeepEquals, expectedKey)
	c.Check(iv, DeepEquals, expectedIV)
	c.Check(auth, DeepEquals, expectedAuth)
}

// Legacy tests
func (s *keyDataSuite) TestReadAndWriteWithUnsaltedKeyDigest(c *C) {
	// Verify that we can read an old key data with an unsalted HMAC key
	// digest. Also verify that writing it preserves the old format to
	// prevent writing a new format key data that can't be read by an old
	// initrd.
	auxKey := testutil.DecodeHexString(c, "8107f1c65c58934f0d59245d1d94d312ea803e69c8599a7bac8c67fe253232f2")
	j := []byte(
		`{` +
			`"platform_name":"mock",` +
			`"platform_handle":"iTnGw6iFTfDgGS+KMtDHx2yF0bpNaTWyzeLtsbaC9YaspcssRrHzcRsNrubyEVT9",` +
			// The new role field will be added as "" by default during unmarshalling
			// with ReadKeyData even if it is missing.
			// Explicitly adding the role field here so that the test passes.
			`"role":"",` +
			`"encrypted_payload":"fYM/SYjIRZj7JOJA710c9hSsxp5NpEchEVXgozd1KgxqZ/TOzIvWF9WYSrRcXiy1vsyjhkF0Svh3ihfApzvje7tTQRI=",` +
			`"authorized_snap_models":{` +
			`"alg":"sha256",` +
			`"key_digest":"ECpFZzxG8XWUKGylGggA2HR+8pERsmA891SmDvs3NiE=",` +
			`"hmacs":["pcYGJdlrxgn6M5Q4gq23cykD1D6X68XBZV+Ikzoyxo0="]}}
`)

	keyData, err := ReadKeyData(&mockKeyDataReader{Reader: bytes.NewReader(j)})
	c.Assert(err, IsNil)

	model1 := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	ok, err := keyData.IsSnapModelAuthorized(auxKey, model1)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	j2, err := ioutil.ReadAll(w.Reader())
	c.Check(err, IsNil)
	c.Check(j2, DeepEquals, j)

	model2 := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "other-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")
	c.Check(keyData.SetAuthorizedSnapModels(auxKey, model2), IsNil)
	ok, err = keyData.IsSnapModelAuthorized(auxKey, model1)
	c.Check(err, IsNil)
	c.Check(ok, Not(testutil.IsTrue))
	ok, err = keyData.IsSnapModelAuthorized(auxKey, model2)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)
}

func (s *keyDataSuite) TestReadAndWriteWithLegacySnapModelAuthKey(c *C) {
	//key := testutil.DecodeHexString(c, "b813218b7877f83ef305ee5704310d05f8a0e648a0fe190dc229e17448cd91ec")
	auxKey := testutil.DecodeHexString(c, "67bb324dd1b40a41c5db84e6248fdacea2505e19fa954b96580b77fadff1a257")

	j := []byte(
		`{` +
			`"platform_name":"mock",` +
			`"platform_handle":{` +
			`"key":"u2wBdkkDL0c5ovbM9z/3VoRVy6cHMs3YdwiUL+mNl/Q=",` +
			`"iv":"sXJZ9DUc26Qz5x4/FwjFzA==",` +
			`"auth-key-hmac":"JVayPium5JZZrEkqb7bsiQXPWJHEhX3r0aHjByulHXs="},` +
			// The new role field will be added as "" by default during unmarshalling
			// with ReadKeyData even if it is missing.
			// Explicitly adding the role field here so that the test passes.
			`"role":"",` +
			`"encrypted_payload":"eDTWEozwRLFh1td/i+eufBDIFHiYJoQqhw51jPuWAy0hfJaw22ywTau+UdqRXQTh4bTl8LZhaDpBGk3wBMjLO8Y3l4Q=",` +
			`"authorized_snap_models":{` +
			`"alg":"sha256",` +
			`"key_digest":{` +
			`"alg":"sha256",` +
			`"salt":"TLiHg00TtO6R8EKYavCxtxAwvivNncKn7z0F3ZvVZOU=",` +
			`"digest":"yRQPnWba/JE4uKB9oxVuhOcB/Ue0cW6H+X3epl1ldSQ="},` +
			`"hmacs":["mpjxUcFTqGpX+zDyFzDBwT77tZCqaktY9QQXswVNXKk="]}}
`)

	keyData, err := ReadKeyData(&mockKeyDataReader{Reader: bytes.NewReader(j)})
	c.Assert(err, IsNil)

	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	ok, err := keyData.IsSnapModelAuthorized(auxKey, model)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	j2, err := ioutil.ReadAll(w.Reader())
	c.Check(err, IsNil)
	c.Check(j2, DeepEquals, j)

	model2 := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "other-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")
	c.Check(keyData.SetAuthorizedSnapModels(auxKey, model2), IsNil)
	ok, err = keyData.IsSnapModelAuthorized(auxKey, model)
	c.Check(err, IsNil)
	c.Check(ok, Not(testutil.IsTrue))
	ok, err = keyData.IsSnapModelAuthorized(auxKey, model2)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)
}

func (s *keyDataSuite) TestLegacyKeyData(c *C) {
	unlockKey := testutil.DecodeHexString(c, "09a2e672131045221284e026b17de93b395581e82450a01e170150432f8cdf81")
	primaryKey := testutil.DecodeHexString(c, "1850fbecbe8b3db83a894cb975756c8b69086040f097b03bd4f3b1a3e19c4b86")

	j := []byte(
		`{` +
			`"platform_name":"mock",` +
			`"platform_handle":{` +
			`"key":"7AQQmeIwl5iv3V+yTszelcdF6MkJpKz+7EA0kKUJNEo=",` +
			`"iv":"i88WWEI7WyJ1gXX5LGhRSg==",` +
			`"auth-key-hmac":"WybrzR13ozdYwzyt4oyihIHSABZozpHyQSAn+NtQSkA=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":0,` +
			`"exp-auth-mode":0},` +
			// The new role field will be added as "" by default during unmarshalling
			// with ReadKeyData even if it is missing.
			// Explicitly adding the role field here so that the test passes.
			`"role":"",` +
			`"encrypted_payload":"eMeLrknRAi/dFBM607WPxFOCE1L9RZ4xxUs+Leodz78s/id7Eq+IHhZdOC/stXSNe+Gn/PWgPxcd0TfEPUs5TA350lo=",` +
			`"authorized_snap_models":{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":{` +
			`"alg":"sha256",` +
			`"salt":"IPDKKUOoRYwvMWX8LoCCtlGgzgzokAhsh42XnbGUn0s=",` +
			`"digest":"SSbv/yS8h5pqchVfV9AMHUjhS/vVateojNRRmo624qk="},` +
			`"hmacs":["OCxZPr5lqnwlNTMYXObK6cXlkcWw3Dx5v+/NRMrCzhw="]}}
`)

	keyData, err := ReadKeyData(&mockKeyDataReader{Reader: bytes.NewReader(j)})
	c.Assert(err, IsNil)

	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	ok, err := keyData.IsSnapModelAuthorized(primaryKey, model)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredUnlockKey, DeepEquals, DiskUnlockKey(unlockKey))
	c.Check(recoveredPrimaryKey, DeepEquals, PrimaryKey(primaryKey))

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	j2, err := ioutil.ReadAll(w.Reader())

	c.Check(err, IsNil)
	c.Check(j2, DeepEquals, j)

	model2 := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "other-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")
	c.Check(keyData.SetAuthorizedSnapModels(primaryKey, model2), IsNil)
	ok, err = keyData.IsSnapModelAuthorized(primaryKey, model)
	c.Check(err, IsNil)
	c.Check(ok, Not(testutil.IsTrue))
	ok, err = keyData.IsSnapModelAuthorized(primaryKey, model2)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)

	w = makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)
	c.Check(w.final.Bytes(), DeepEquals, []byte(
		`{`+
			`"platform_name":"mock",`+
			`"platform_handle":{`+
			`"key":"7AQQmeIwl5iv3V+yTszelcdF6MkJpKz+7EA0kKUJNEo=",`+
			`"iv":"i88WWEI7WyJ1gXX5LGhRSg==",`+
			`"auth-key-hmac":"WybrzR13ozdYwzyt4oyihIHSABZozpHyQSAn+NtQSkA=",`+
			`"exp-generation":1,`+
			`"exp-kdf_alg":0,`+
			`"exp-auth-mode":0},`+
			// The new role field will be added as "" by default during unmarshalling
			// with ReadKeyData even if it is missing.
			// Explicitly adding the role field here so that the test passes.
			`"role":"",`+
			`"encrypted_payload":"eMeLrknRAi/dFBM607WPxFOCE1L9RZ4xxUs+Leodz78s/id7Eq+IHhZdOC/stXSNe+Gn/PWgPxcd0TfEPUs5TA350lo=",`+
			`"authorized_snap_models":{`+
			`"alg":"sha256",`+
			`"kdf_alg":"sha256",`+
			`"key_digest":{`+
			`"alg":"sha256",`+
			`"salt":"IPDKKUOoRYwvMWX8LoCCtlGgzgzokAhsh42XnbGUn0s=",`+
			`"digest":"SSbv/yS8h5pqchVfV9AMHUjhS/vVateojNRRmo624qk="},`+
			`"hmacs":["JWziaukXiAIsPU22X1RTC/2wEkPN4IdNvgDEzSnWXIc="]}}
`))
}
