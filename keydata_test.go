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
	"time"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/xerrors"

	. "gopkg.in/check.v1"
)

type mockPlatformKeyDataHandle struct {
	Key              []byte      `json:"key"`
	IV               []byte      `json:"iv"`
	AuthKeyHMAC      []byte      `json:"auth-key-hmac"`
	ExpectedVersion  int         `json:"exp-version"`
	ExpectedKDFAlg   crypto.Hash `json:"exp-kdf_alg"`
	ExpectedAuthMode AuthMode    `json:"exp-auth-mode"`
}

const (
	mockPlatformDeviceStateOK = iota
	mockPlatformDeviceStateUnavailable
	mockPlatformDeviceStateUninitialized
)

type mockPlatformKeyDataHandler struct {
	state             int
	passphraseSupport bool
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
		return nil, &PlatformHandlerError{Type: PlatformHandlerErrorInvalidData, Err: xerrors.Errorf("JSON decode error: %w", err)}
	}

	if data.Version != handle.ExpectedVersion {
		return nil, &PlatformHandlerError{Type: PlatformHandlerErrorInvalidData, Err: errors.New("unexpected version")}
	}

	if data.Version > 1 {
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
	m := hmac.New(func() hash.Hash { return crypto.SHA256.New() }, handle.Key)
	m.Write(key)
	if !bytes.Equal(handle.AuthKeyHMAC, m.Sum(nil)) {
		return &PlatformHandlerError{Type: PlatformHandlerErrorInvalidAuthKey, Err: errors.New("the supplied key is incorrect")}
	}

	return nil
}

func (h *mockPlatformKeyDataHandler) recoverKeys(handle *mockPlatformKeyDataHandle, payload []byte) ([]byte, error) {
	b, err := aes.NewCipher(handle.Key)
	if err != nil {
		return nil, xerrors.Errorf("cannot create cipher: %w", err)
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
	if !h.passphraseSupport {
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

func (h *mockPlatformKeyDataHandler) ChangeAuthKey(data *PlatformKeyData, old, new []byte) ([]byte, error) {
	if !h.passphraseSupport {
		return nil, errors.New("not supported")
	}

	if err := h.checkState(); err != nil {
		return nil, err
	}

	handle, err := h.unmarshalHandle(data)
	if err != nil {
		return nil, err
	}

	if err := h.checkKey(handle, old); err != nil {
		return nil, err
	}

	m := hmac.New(func() hash.Hash { return crypto.SHA256.New() }, handle.Key)
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

func (w *mockKeyDataWriter) Reader() io.Reader {
	return w.final
}

func makeMockKeyDataWriter() *mockKeyDataWriter {
	return &mockKeyDataWriter{tmp: new(bytes.Buffer)}
}

type mockKeyDataReader struct {
	readableName string
	io.Reader
}

func (r *mockKeyDataReader) ReadableName() string {
	return r.readableName
}

func toHash(c *C, v interface{}) crypto.Hash {
	str, ok := v.(string)
	c.Assert(ok, testutil.IsTrue)
	switch str {
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

type keyDataTestBase struct {
	handler          *mockPlatformKeyDataHandler
	mockPlatformName string
}

func (s *keyDataTestBase) SetUpSuite(c *C) {
	s.handler = &mockPlatformKeyDataHandler{}
	s.mockPlatformName = "mock"
	RegisterPlatformKeyDataHandler(s.mockPlatformName, s.handler)
}

func (s *keyDataTestBase) SetUpTest(c *C) {
	s.handler.state = mockPlatformDeviceStateOK
	s.handler.passphraseSupport = false
}

func (s *keyDataTestBase) TearDownSuite(c *C) {
	RegisterPlatformKeyDataHandler(s.mockPlatformName, nil)
}

func (s *keyDataTestBase) newPrimaryKey(c *C, sz1 int) PrimaryKey {
	primaryKey := make(PrimaryKey, sz1)
	_, err := rand.Read(primaryKey)
	c.Assert(err, IsNil)

	return primaryKey
}

func (s *keyDataTestBase) mockProtectKeys(c *C, primaryKey PrimaryKey, kdfAlg crypto.Hash, modelAuthHash crypto.Hash) (out *KeyParams, unlockKey DiskUnlockKey) {
	unique := make([]byte, len(primaryKey))
	_, err := rand.Read(unique)
	c.Assert(err, IsNil)

	unlockKey, payload, err := MakeDiskUnlockKey(bytes.NewReader(unique), kdfAlg, primaryKey)
	c.Assert(err, IsNil)

	k := make([]byte, 48)
	_, err = rand.Read(k)
	c.Assert(err, IsNil)

	handle := mockPlatformKeyDataHandle{
		Key:              k[:32],
		IV:               k[32:],
		ExpectedVersion:  KeyDataVersion,
		ExpectedKDFAlg:   kdfAlg,
		ExpectedAuthMode: AuthModeNone,
	}

	h := hmac.New(func() hash.Hash { return crypto.SHA256.New() }, handle.Key)
	h.Write(make([]byte, 32))
	handle.AuthKeyHMAC = h.Sum(nil)

	b, err := aes.NewCipher(handle.Key)
	c.Assert(err, IsNil)
	stream := cipher.NewCFBEncrypter(b, handle.IV)

	out = &KeyParams{
		PlatformName:      s.mockPlatformName,
		Handle:            &handle,
		EncryptedPayload:  make([]byte, len(payload)),
		PrimaryKey:        primaryKey,
		KDFAlg:            kdfAlg,
		SnapModelAuthHash: modelAuthHash}
	stream.XORKeyStream(out.EncryptedPayload, payload)

	return out, unlockKey
}

func (s *keyDataTestBase) mockProtectKeysWithPassphrase(c *C, primaryKey PrimaryKey, kdfOptions *KDFOptions, authKeySize int, KDFAlg crypto.Hash, modelAuthHash crypto.Hash) (out *KeyWithPassphraseParams, unlockKey DiskUnlockKey) {
	kp, unlockKey := s.mockProtectKeys(c, primaryKey, KDFAlg, modelAuthHash)

	expectedHandle, ok := kp.Handle.(*mockPlatformKeyDataHandle)
	c.Assert(ok, testutil.IsTrue)

	expectedHandle.ExpectedAuthMode = AuthModePassphrase
	expectedHandle.ExpectedVersion = KeyDataVersion
	expectedHandle.ExpectedKDFAlg = KDFAlg

	if kdfOptions == nil {
		var defaultOptions KDFOptions
		kdfOptions = &defaultOptions
	}

	kpp := &KeyWithPassphraseParams{
		KeyParams:   *kp,
		KDFOptions:  kdfOptions,
		AuthKeySize: authKeySize,
	}

	return kpp, unlockKey
}

func (s *keyDataTestBase) checkKeyDataJSONCommon(c *C, j map[string]interface{}, creationParams *KeyParams, nmodels int) {
	c.Check(j["platform_name"], Equals, creationParams.PlatformName)

	expectedHandle, ok := creationParams.Handle.(*mockPlatformKeyDataHandle)
	c.Assert(ok, testutil.IsTrue)

	handleBytes, err := json.Marshal(j["platform_handle"])
	c.Check(err, IsNil)

	var handle *mockPlatformKeyDataHandle
	c.Check(json.Unmarshal(handleBytes, &handle), IsNil)

	c.Check(handle.Key, DeepEquals, expectedHandle.Key)
	c.Check(handle.IV, DeepEquals, expectedHandle.IV)

	_, ok = j["kdf_alg"].(string)
	c.Check(ok, testutil.IsTrue)

	version, ok := j["version"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(version, Equals, float64(2))

	m, ok := j["authorized_snap_models"].(map[string]interface{})
	c.Assert(ok, testutil.IsTrue)

	h := toHash(c, m["alg"])
	c.Check(h, Equals, creationParams.SnapModelAuthHash)

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
	c.Check(h, Equals, creationParams.SnapModelAuthHash)

	m1, ok := m["key_digest"].(map[string]interface{})
	c.Assert(ok, testutil.IsTrue)

	h = toHash(c, m1["alg"])
	c.Check(h, Equals, creationParams.SnapModelAuthHash)

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

func (s *keyDataTestBase) checkKeyDataJSONDecodedAuthModeNone(c *C, j map[string]interface{}, creationParams *KeyParams, nmodels int) {
	s.checkKeyDataJSONCommon(c, j, creationParams, nmodels)

	str, ok := j["encrypted_payload"].(string)
	c.Check(ok, testutil.IsTrue)
	encryptedPayload, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)
	c.Check(encryptedPayload, DeepEquals, creationParams.EncryptedPayload)

	c.Check(j, Not(testutil.HasKey), "passphrase_params")
}

func (s *keyDataTestBase) checkKeyDataJSONFromReaderAuthModeNone(c *C, r io.Reader, creationParams *KeyParams, nmodels int) {
	var j map[string]interface{}

	d := json.NewDecoder(r)
	c.Check(d.Decode(&j), IsNil)

	s.checkKeyDataJSONDecodedAuthModeNone(c, j, creationParams, nmodels)
}

func (s *keyDataTestBase) checkKeyDataJSONDecodedAuthModePassphrase(c *C, j map[string]interface{}, creationParams *KeyWithPassphraseParams, nmodels int, passphrase string, kdfOpts *KDFOptions) {
	if kdfOpts == nil {
		var def KDFOptions
		kdfOpts = &def
	}
	var kdf testutil.MockKDF

	costParams, err := kdfOpts.DeriveCostParams(0, &kdf)
	c.Assert(err, IsNil)

	s.checkKeyDataJSONCommon(c, j, &creationParams.KeyParams, nmodels)

	p, ok := j["passphrase_params"].(map[string]interface{})
	c.Check(ok, testutil.IsTrue)

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
	c.Check(authKeySize, Equals, float64(32))

	k, ok := p["kdf"].(map[string]interface{})
	c.Check(ok, testutil.IsTrue)

	str, ok := k["type"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(str, Equals, "argon2i")

	str, ok = k["salt"].(string)
	c.Check(ok, testutil.IsTrue)
	salt, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)

	time, ok := k["time"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(time, Equals, float64(costParams.Time))

	memory, ok := k["memory"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(memory, Equals, float64(costParams.MemoryKiB))

	cpus, ok := k["cpus"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(cpus, Equals, float64(costParams.Threads))

	str, ok = j["encrypted_payload"].(string)
	c.Check(ok, testutil.IsTrue)
	encryptedPayload, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)

	// TODO properly unmarshal from field
	// and expose hashAlg helpers
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

	derived, _ := kdf.Derive(passphrase, asnsalt, costParams, uint32(derivedKeySize))

	key := make([]byte, int(encryptionKeySize))

	r := hkdf.Expand(func() hash.Hash { return kdfAlg.New() }, derived, []byte("PASSPHRASE-ENC"))
	_, err = io.ReadFull(r, key)
	c.Assert(err, IsNil)

	iv := make([]byte, aes.BlockSize)
	r = hkdf.Expand(func() hash.Hash { return kdfAlg.New() }, derived, []byte("PASSPHRASE-IV"))
	_, err = io.ReadFull(r, iv)
	c.Assert(err, IsNil)

	b, err := aes.NewCipher(key)
	c.Assert(err, IsNil)
	stream := cipher.NewCFBDecrypter(b, iv)
	payload := make([]byte, len(encryptedPayload))
	stream.XORKeyStream(payload, encryptedPayload)
	c.Check(payload, DeepEquals, creationParams.EncryptedPayload)
}

func (s *keyDataTestBase) checkKeyDataJSONFromReaderAuthModePassphrase(c *C, r io.Reader, creationParams *KeyWithPassphraseParams, nmodels int, passphrase string, kdfOpts *KDFOptions) {
	var j map[string]interface{}

	d := json.NewDecoder(r)
	c.Check(d.Decode(&j), IsNil)

	s.checkKeyDataJSONDecodedAuthModePassphrase(c, j, creationParams, nmodels, passphrase, kdfOpts)
}

type keyDataSuite struct {
	keyDataTestBase
}

var _ = Suite(&keyDataSuite{})

func (s *keyDataSuite) checkKeyDataJSONAuthModeNone(c *C, keyData *KeyData, creationParams *KeyParams, nmodels int) {
	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModeNone(c, w.Reader(), creationParams, nmodels)
}

func (s *keyDataSuite) checkKeyDataJSONAuthModePassphrase(c *C, keyData *KeyData, creationParams *KeyWithPassphraseParams, nmodels int, passphrase string, kdfOpts *KDFOptions) {
	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModePassphrase(c, w.Reader(), creationParams, nmodels, passphrase, kdfOpts)
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
	protected, _ := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

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
	protected, _ := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Check(keyData, NotNil)
	c.Check(err, IsNil)
}

func (s *keyDataSuite) TestUnmarshalPlatformHandle(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var handle *mockPlatformKeyDataHandle
	c.Check(keyData.UnmarshalPlatformHandle(&handle), IsNil)

	c.Check(handle, DeepEquals, protected.Handle)
}

func (s *keyDataSuite) TestMarshalAndUpdatePlatformHandle(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	handle := protected.Handle.(*mockPlatformKeyDataHandle)
	rand.Read(handle.AuthKeyHMAC)

	c.Check(keyData.MarshalAndUpdatePlatformHandle(&handle), IsNil)

	protected.Handle = handle

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected, 0)
}

func (s *keyDataSuite) TestRecoverKeys(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredUnlockKey, DeepEquals, unlockKey)
	c.Check(recoveredPrimaryKey, DeepEquals, primaryKey)
}

func (s *keyDataSuite) TestRecoverKeysUnrecognizedPlatform(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

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
	protected, _ := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

	protected.Handle = []byte("\"\"")

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: JSON decode error: json: cannot unmarshal string into Go value of type secboot_test.mockPlatformKeyDataHandle")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) testRecoverKeysWithPassphrase(c *C, passphrase string) {
	s.handler.passphraseSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeysWithPassphrase(c, primaryKey, nil, 32, crypto.SHA256, crypto.SHA256)

	var kdf testutil.MockKDF
	keyData, err := NewKeyDataWithPassphrase(protected, passphrase, &kdf)
	c.Assert(err, IsNil)

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeysWithPassphrase(passphrase, &kdf)
	c.Check(err, IsNil)
	c.Check(recoveredUnlockKey, DeepEquals, unlockKey)
	c.Check(recoveredPrimaryKey, DeepEquals, primaryKey)
}

func (s *keyDataSuite) TestRecoverKeysWithPassphrase1(c *C) {
	s.testRecoverKeysWithPassphrase(c, "passphrase")
}

func (s *keyDataSuite) TestRecoverKeysWithPassphrase2(c *C) {
	s.testRecoverKeysWithPassphrase(c, "1234")
}

type testRecoverKeysWithPassphraseErrorHandlingData struct {
	kdfType           string
	errMsg            string
	derivedKeySize    int
	encryptionKeySize int
	authKeySize       int
}

func (s *keyDataSuite) testRecoverKeysWithPassphraseErrorHandling(c *C, data *testRecoverKeysWithPassphraseErrorHandlingData) {
	s.handler.passphraseSupport = true

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

	j := []byte(
		`{` +
			`"version":2,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"GtaI3cZX9H3Ig1YxSCPTxLshteV0AXK2pFgQuE5NRIQ=",` +
			`"iv":"0VUZD/yYi6PfRzdPB0a1GA==",` +
			`"auth-key-hmac":"7/AmPJvhwHNY/E1a3oEoqF5xjmt5FBr9YTppQvESUSY=",` +
			`"exp-version":2,` +
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
			`"time":4,` +
			`"memory":1024063,` +
			`"cpus":4},` +
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

	var kdf testutil.MockKDF
	_, _, err = keyData.RecoverKeysWithPassphrase("passphrase", &kdf)
	c.Check(err.Error(), Equals, data.errMsg)
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseNotSupportedKDF(c *C) {
	s.testRecoverKeysWithPassphraseErrorHandling(c, &testRecoverKeysWithPassphraseErrorHandlingData{
		kdfType: "other",
		errMsg:  "unexpected intermediate KDF type \"other\"",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseInvalidDerivedKeySize(c *C) {
	s.testRecoverKeysWithPassphraseErrorHandling(c, &testRecoverKeysWithPassphraseErrorHandlingData{
		derivedKeySize: -1,
		errMsg:         "invalid derived key size (-1 bytes)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseInvalidEncryptionKeySizeSmall(c *C) {
	s.testRecoverKeysWithPassphraseErrorHandling(c, &testRecoverKeysWithPassphraseErrorHandlingData{
		encryptionKeySize: -1,
		errMsg:            "invalid encryption key size (-1 bytes)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseInvalidEncryptionKeySizeBig(c *C) {
	s.testRecoverKeysWithPassphraseErrorHandling(c, &testRecoverKeysWithPassphraseErrorHandlingData{
		encryptionKeySize: 33,
		errMsg:            "invalid encryption key size (33 bytes)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseInvalidAuthKeySize(c *C) {
	s.testRecoverKeysWithPassphraseErrorHandling(c, &testRecoverKeysWithPassphraseErrorHandlingData{
		authKeySize: -1,
		errMsg:      "invalid auth key size (-1 bytes)",
	})
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseUnavailableKDF(c *C) {
	restore := MockHashAlgAvailable()
	defer restore()
	s.testRecoverKeysWithPassphraseErrorHandling(c, &testRecoverKeysWithPassphraseErrorHandlingData{
		errMsg: fmt.Sprintf("unavailable leaf KDF digest algorithm %d", crypto.SHA256),
	})
}

func (s *keyDataSuite) TestNewKeyDataWithPassphraseNotSupported(c *C) {
	// Test that creation of a new key data with passphrase fails when the
	// platform handler doesn't have passphrase support.
	primaryKey := s.newPrimaryKey(c, 32)
	passphraseParams, _ := s.mockProtectKeysWithPassphrase(c, primaryKey, nil, 32, crypto.SHA256, crypto.SHA256)

	var kdf testutil.MockKDF
	_, err := NewKeyDataWithPassphrase(passphraseParams, "passphrase", &kdf)
	c.Check(err, ErrorMatches, "cannot set passphrase: not supported")
}

func (s *keyDataSuite) TestChangePassphraseNotSupported(c *C) {
	// Test that changing passphrase of a key data with a passphrase set
	// fails when the platform handler doesn't have passphrase support.
	j := []byte(
		`{` +
			`"version":2,` +
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

	c.Check(keyData.ChangePassphrase("passphrase", "", new(testutil.MockKDF)), ErrorMatches, "cannot perform action because of an unexpected error: not supported")
}

func (s *keyDataSuite) TestChangePassphraseWithoutInitial(c *C) {
	// Test that changing passphrase on a key data without a passphrase set fails.
	j := []byte(
		`{` +
			`"version":2,` +
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

	c.Check(keyData.ChangePassphrase("passphrase", "", new(testutil.MockKDF)), ErrorMatches, "cannot change passphrase without setting an initial passphrase")
}

type testChangePassphraseData struct {
	passphrase1 string
	passphrase2 string
	kdfOptions  *KDFOptions
}

func (s *keyDataSuite) testChangePassphrase(c *C, data *testChangePassphraseData) {
	s.handler.passphraseSupport = true

	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeysWithPassphrase(c, primaryKey, data.kdfOptions, 32, crypto.SHA256, crypto.SHA256)

	var kdf testutil.MockKDF
	keyData, err := NewKeyDataWithPassphrase(protected, data.passphrase1, &kdf)
	c.Check(err, IsNil)

	c.Check(keyData.ChangePassphrase(data.passphrase1, data.passphrase2, &kdf), IsNil)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, 0, data.passphrase2, data.kdfOptions)
}

func (s *keyDataSuite) TestChangePassphrase(c *C) {
	s.testChangePassphrase(c, &testChangePassphraseData{
		passphrase1: "12345678",
		passphrase2: "87654321",
		kdfOptions:  &KDFOptions{}})
}

func (s *keyDataSuite) TestChangePassphraseDifferentPassphrase(c *C) {
	s.testChangePassphrase(c, &testChangePassphraseData{
		passphrase1: "87654321",
		passphrase2: "12345678",
		kdfOptions:  &KDFOptions{}})
}

func (s *keyDataSuite) TestChangePassphraseNilOptions(c *C) {
	s.testChangePassphrase(c, &testChangePassphraseData{
		passphrase1: "12345678",
		passphrase2: "87654321"})
}

func (s *keyDataSuite) TestChangePassphraseCustomDuration(c *C) {
	s.testChangePassphrase(c, &testChangePassphraseData{
		passphrase1: "12345678",
		passphrase2: "87654321",
		kdfOptions:  &KDFOptions{TargetDuration: 100 * time.Millisecond}})
}

func (s *keyDataSuite) TestChangePassphraseForceIterations(c *C) {
	s.testChangePassphrase(c, &testChangePassphraseData{
		passphrase1: "12345678",
		passphrase2: "87654321",
		kdfOptions:  &KDFOptions{ForceIterations: 3, MemoryKiB: 32 * 1024}})
}

func (s *keyDataSuite) TestChangePassphraseWrongPassphrase(c *C) {
	s.handler.passphraseSupport = true

	primaryKey := s.newPrimaryKey(c, 32)

	kdfOptions := &KDFOptions{
		TargetDuration: 100 * time.Millisecond,
	}
	protected, _ := s.mockProtectKeysWithPassphrase(c, primaryKey, kdfOptions, 32, crypto.SHA256, crypto.SHA256)

	var kdf testutil.MockKDF
	keyData, err := NewKeyDataWithPassphrase(protected, "12345678", &kdf)
	c.Check(err, IsNil)

	c.Check(keyData.ChangePassphrase("passphrase", "12345678", &kdf), Equals, ErrInvalidPassphrase)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, 0, "12345678", kdfOptions)
}

type testSnapModelAuthData struct {
	alg        crypto.Hash
	authModels []SnapModel
	model      SnapModel
	authorized bool
}

func (s *keyDataSuite) testSnapModelAuth(c *C, data *testSnapModelAuthData) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	c.Check(keyData.SetAuthorizedSnapModels(primaryKey, data.authModels...), IsNil)

	authorized, err := keyData.IsSnapModelAuthorized(primaryKey, data.model)
	c.Check(err, IsNil)
	c.Check(authorized, Equals, data.authorized)
}

func (s *keyDataSuite) TestSnapModelAuth1(c *C) {
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	s.testSnapModelAuth(c, &testSnapModelAuthData{
		alg:        crypto.SHA256,
		authModels: models,
		model:      models[0],
		authorized: true})
}

func (s *keyDataSuite) TestSnapModelAuth2(c *C) {
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
	s.testSnapModelAuth(c, &testSnapModelAuthData{
		alg:        crypto.SHA256,
		authModels: models,
		model:      models[1],
		authorized: true})
}

func (s *keyDataSuite) TestSnapModelAuth3(c *C) {
	s.testSnapModelAuth(c, &testSnapModelAuthData{
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

func (s *keyDataSuite) TestSnapModelAuth4(c *C) {
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	s.testSnapModelAuth(c, &testSnapModelAuthData{
		alg:        crypto.SHA512,
		authModels: models,
		model:      models[0],
		authorized: true})
}
func (s *keyDataSuite) TestSnapModelAuth5(c *C) {
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
	s.testSnapModelAuth(c, &testSnapModelAuthData{
		alg:        crypto.SHA256,
		authModels: models,
		model:      models[1],
		authorized: true})
}

func (s *keyDataSuite) TestSnapModelAuth6(c *C) {
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
	s.testSnapModelAuth(c, &testSnapModelAuthData{
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

func (s *keyDataSuite) TestSetAuthorizedSnapModelsWithWrongKey(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

	keyData, err := NewKeyData(protected)
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

type testWriteAtomicData struct {
	keyData *KeyData
	params  *KeyParams
	nmodels int
}

func (s *keyDataSuite) testWriteAtomic(c *C, data *testWriteAtomicData) {
	s.checkKeyDataJSONAuthModeNone(c, data.keyData, data.params, data.nmodels)
}

func (s *keyDataSuite) TestWriteAtomic1(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	s.testWriteAtomic(c, &testWriteAtomicData{
		keyData: keyData,
		params:  protected})
}

type testReadKeyDataData struct {
	key        DiskUnlockKey
	auxKey     PrimaryKey
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

	key, auxKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.key)
	c.Check(auxKey, DeepEquals, data.auxKey)

	authorized, err := keyData.IsSnapModelAuthorized(auxKey, data.model)
	c.Check(err, IsNil)
	c.Check(authorized, Equals, data.authorized)

	c.Check(keyData.SetAuthorizedSnapModels(auxKey), IsNil)
}

func (s *keyDataSuite) TestReadKeyData1(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	c.Check(keyData.SetAuthorizedSnapModels(primaryKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	s.testReadKeyData(c, &testReadKeyDataData{
		key:        unlockKey,
		auxKey:     primaryKey,
		id:         id,
		r:          &mockKeyDataReader{"foo", w.Reader()},
		model:      models[0],
		authorized: true})
}

func (s *keyDataSuite) TestReadKeyData2(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	c.Check(keyData.SetAuthorizedSnapModels(primaryKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	s.testReadKeyData(c, &testReadKeyDataData{
		key:        unlockKey,
		auxKey:     primaryKey,
		id:         id,
		r:          &mockKeyDataReader{"bar", w.Reader()},
		model:      models[0],
		authorized: true})
}

func (s *keyDataSuite) TestReadKeyData3(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

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

	c.Check(keyData.SetAuthorizedSnapModels(primaryKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	s.testReadKeyData(c, &testReadKeyDataData{
		key:        unlockKey,
		auxKey:     primaryKey,
		id:         id,
		r:          &mockKeyDataReader{"foo", w.Reader()},
		model:      models[1],
		authorized: true})
}

func (s *keyDataSuite) TestReadKeyData4(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeys(c, primaryKey, crypto.SHA256, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	c.Check(keyData.SetAuthorizedSnapModels(primaryKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	s.testReadKeyData(c, &testReadKeyDataData{
		key:    unlockKey,
		auxKey: primaryKey,
		id:     id,
		r:      &mockKeyDataReader{"foo", w.Reader()},
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		authorized: false})
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
			`"exp-version":1,` +
			`"exp-kdf_alg":0,` +
			`"exp-auth-mode":0},` +
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
			`"exp-version":1,`+
			`"exp-kdf_alg":0,`+
			`"exp-auth-mode":0},`+
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
