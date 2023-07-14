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
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"io/ioutil"
	"math/rand"
	"time"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	"golang.org/x/xerrors"

	. "gopkg.in/check.v1"
)

const mockPlatformName = "mock"

type mockPlatformKeyDataHandle struct {
	Key         []byte `json:"key"`
	IV          []byte `json:"iv"`
	AuthKeyHMAC []byte `json:"auth-key-hmac"`
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

func (h *mockPlatformKeyDataHandler) unmarshalHandle(data []byte) (*mockPlatformKeyDataHandle, error) {
	var handle mockPlatformKeyDataHandle
	if err := json.Unmarshal(data, &handle); err != nil {
		return nil, &PlatformHandlerError{Type: PlatformHandlerErrorInvalidData, Err: xerrors.Errorf("JSON decode error: %w", err)}
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

func (h *mockPlatformKeyDataHandler) recoverKeys(handle *mockPlatformKeyDataHandle, payload []byte) (KeyPayload, error) {
	b, err := aes.NewCipher(handle.Key)
	if err != nil {
		return nil, xerrors.Errorf("cannot create cipher: %w", err)
	}

	s := cipher.NewCFBDecrypter(b, handle.IV)
	out := make(KeyPayload, len(payload))
	s.XORKeyStream(out, payload)
	return out, nil
}

func (h *mockPlatformKeyDataHandler) RecoverKeys(data *PlatformKeyData) (KeyPayload, error) {
	if err := h.checkState(); err != nil {
		return nil, err
	}

	handle, err := h.unmarshalHandle(data.EncodedHandle)
	if err != nil {
		return nil, err
	}

	return h.recoverKeys(handle, data.EncryptedPayload)
}

func (h *mockPlatformKeyDataHandler) RecoverKeysWithAuthKey(data *PlatformKeyData, key []byte) (KeyPayload, error) {
	if !h.passphraseSupport {
		return nil, errors.New("not supported")
	}

	if err := h.checkState(); err != nil {
		return nil, err
	}

	handle, err := h.unmarshalHandle(data.EncodedHandle)
	if err != nil {
		return nil, err
	}

	if err := h.checkKey(handle, key); err != nil {
		return nil, err
	}

	return h.recoverKeys(handle, data.EncryptedPayload)
}

func (h *mockPlatformKeyDataHandler) ChangeAuthKey(data, old, new []byte) ([]byte, error) {
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
	handler *mockPlatformKeyDataHandler
}

func (s *keyDataTestBase) SetUpSuite(c *C) {
	s.handler = &mockPlatformKeyDataHandler{}
	RegisterPlatformKeyDataHandler(mockPlatformName, s.handler)
}

func (s *keyDataTestBase) SetUpTest(c *C) {
	s.handler.state = mockPlatformDeviceStateOK
	s.handler.passphraseSupport = false
}

func (s *keyDataTestBase) TearDownSuite(c *C) {
	RegisterPlatformKeyDataHandler(mockPlatformName, nil)
}

func (s *keyDataTestBase) newKeyDataKeys(c *C, sz1, sz2 int) (DiskUnlockKey, PrimaryKey) {
	key := make([]byte, sz1)
	auxKey := make([]byte, sz2)
	_, err := rand.Read(key)
	c.Assert(err, IsNil)
	_, err = rand.Read(auxKey)
	c.Assert(err, IsNil)
	return key, auxKey
}

func (s *keyDataTestBase) mockProtectKeys(c *C, key DiskUnlockKey, auxKey PrimaryKey, modelAuthHash crypto.Hash) (out *KeyParams) {
	payload := MarshalKeys(key, auxKey)

	k := make([]byte, 48)
	_, err := rand.Read(k)
	c.Assert(err, IsNil)

	handle := mockPlatformKeyDataHandle{
		Key: k[:32],
		IV:  k[32:]}

	h := hmac.New(func() hash.Hash { return crypto.SHA256.New() }, handle.Key)
	handle.AuthKeyHMAC = h.Sum(nil)

	b, err := aes.NewCipher(handle.Key)
	c.Assert(err, IsNil)
	stream := cipher.NewCFBEncrypter(b, handle.IV)

	out = &KeyParams{
		PlatformName:      mockPlatformName,
		Handle:            &handle,
		EncryptedPayload:  make([]byte, len(payload)),
		PrimaryKey:        auxKey,
		SnapModelAuthHash: modelAuthHash}
	stream.XORKeyStream(out.EncryptedPayload, payload)
	return
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

	c.Check(j, Not(testutil.HasKey), "passphrase_protected_payload")
}

func (s *keyDataTestBase) checkKeyDataJSONFromReaderAuthModeNone(c *C, r io.Reader, creationParams *KeyParams, nmodels int) {
	var j map[string]interface{}

	d := json.NewDecoder(r)
	c.Check(d.Decode(&j), IsNil)

	s.checkKeyDataJSONDecodedAuthModeNone(c, j, creationParams, nmodels)
}

func (s *keyDataTestBase) checkKeyDataJSONDecodedAuthModePassphrase(c *C, j map[string]interface{}, creationParams *KeyParams, nmodels int, passphrase string, kdfOpts *KDFOptions) {
	if kdfOpts == nil {
		var def KDFOptions
		kdfOpts = &def
	}
	var kdf testutil.MockKDF

	costParams, err := kdfOpts.DeriveCostParams(0, &kdf)
	c.Assert(err, IsNil)

	s.checkKeyDataJSONCommon(c, j, creationParams, nmodels)

	c.Check(j, Not(testutil.HasKey), "encrypted_payload")

	p, ok := j["passphrase_protected_payload"].(map[string]interface{})
	c.Check(ok, testutil.IsTrue)

	encryption, ok := p["encryption"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(encryption, Equals, "aes-cfb")

	keySize, ok := p["key_size"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(keySize, Equals, float64(32))

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

	str, ok = p["encrypted_payload"].(string)
	c.Check(ok, testutil.IsTrue)
	encryptedPayload, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)

	key, _ := kdf.Derive(passphrase, salt, costParams, 48)

	b, err := aes.NewCipher(key[:32])
	c.Assert(err, IsNil)
	stream := cipher.NewCFBDecrypter(b, key[32:])
	payload := make([]byte, len(encryptedPayload))
	stream.XORKeyStream(payload, encryptedPayload)
	c.Check(payload, DeepEquals, creationParams.EncryptedPayload)
}

func (s *keyDataTestBase) checkKeyDataJSONFromReaderAuthModePassphrase(c *C, r io.Reader, creationParams *KeyParams, nmodels int, passphrase string, kdfOpts *KDFOptions) {
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

func (s *keyDataSuite) checkKeyDataJSONAuthModePassphrase(c *C, keyData *KeyData, creationParams *KeyParams, nmodels int, passphrase string, kdfOpts *KDFOptions) {
	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModePassphrase(c, w.Reader(), creationParams, nmodels, passphrase, kdfOpts)
}

type testKeyPayloadData struct {
	key    DiskUnlockKey
	auxKey PrimaryKey
}

func (s *keyDataSuite) testKeyPayload(c *C, data *testKeyPayloadData) {
	payload := MarshalKeys(data.key, data.auxKey)

	key, auxKey, err := payload.Unmarshal()
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.key)
	c.Check(auxKey, DeepEquals, data.auxKey)
}

func (s *keyDataSuite) TestKeyPayload1(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)

	s.testKeyPayload(c, &testKeyPayloadData{
		key:    key,
		auxKey: auxKey})
}

func (s *keyDataSuite) TestKeyPayload2(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 64, 32)

	s.testKeyPayload(c, &testKeyPayloadData{
		key:    key,
		auxKey: auxKey})
}

func (s *keyDataSuite) TestKeyPayload3(c *C) {
	key, _ := s.newKeyDataKeys(c, 32, 0)

	s.testKeyPayload(c, &testKeyPayloadData{
		key: key})
}

func (s *keyDataSuite) TestKeyPayloadUnmarshalInvalid1(c *C) {
	payload := make(KeyPayload, 66)
	for i := range payload {
		payload[i] = 0xff
	}

	key, auxKey, err := payload.Unmarshal()
	c.Check(err, ErrorMatches, "EOF")
	c.Check(key, IsNil)
	c.Check(auxKey, IsNil)
}

func (s *keyDataSuite) TestKeyPayloadUnmarshalInvalid2(c *C) {
	payload := MarshalKeys(make(DiskUnlockKey, 32), make(PrimaryKey, 32))
	payload = append(payload, 0xff)

	key, auxKey, err := payload.Unmarshal()
	c.Check(err, ErrorMatches, "1 excess byte\\(s\\)")
	c.Check(key, IsNil)
	c.Check(auxKey, IsNil)
}

type keyDataHasher struct {
	hash.Hash
}

func (h *keyDataHasher) Commit() error { return nil }

func (s *keyDataSuite) TestKeyDataID(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	h := &keyDataHasher{Hash: crypto.SHA256.New()}
	c.Check(keyData.WriteAtomic(h), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)
	c.Check(id, DeepEquals, KeyID(h.Sum(nil)))
}

func (s *keyDataSuite) TestNewKeyData(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Check(keyData, NotNil)
	c.Check(err, IsNil)
}

func (s *keyDataSuite) TestUnmarshalPlatformHandle(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var handle *mockPlatformKeyDataHandle
	c.Check(keyData.UnmarshalPlatformHandle(&handle), IsNil)

	c.Check(handle, DeepEquals, protected.Handle)
}

func (s *keyDataSuite) TestMarshalAndUpdatePlatformHandle(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)
	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	handle := protected.Handle.(*mockPlatformKeyDataHandle)
	rand.Read(handle.AuthKeyHMAC)

	c.Check(keyData.MarshalAndUpdatePlatformHandle(&handle), IsNil)

	protected.Handle = handle

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModeNone(c, w.Reader(), protected, 0)
}

func (s *keyDataSuite) TestRecoverKeys(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	c.Check(recoveredAuxKey, DeepEquals, auxKey)
}

func (s *keyDataSuite) TestRecoverKeysUnrecognizedPlatform(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	protected.PlatformName = "foo"

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "no appropriate platform handler is registered")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysInvalidData(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	protected.Handle = []byte("\"\"")

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: JSON decode error: json: cannot unmarshal string into Go value of type secboot_test.mockPlatformKeyDataHandle")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysAuthModePassphrase(c *C) {
	s.handler.passphraseSupport = true

	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(keyData.SetPassphrase("passphrase", nil, &kdf), IsNil)

	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "cannot recover key without authorization")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysWithPassphraseAuthModeNone(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeysWithPassphrase("", nil)
	c.Check(err, ErrorMatches, "no passphrase is set")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) testRecoverKeysWithPassphrase(c *C, passphrase string) {
	s.handler.passphraseSupport = true

	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(keyData.SetPassphrase(passphrase, nil, &kdf), IsNil)

	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeysWithPassphrase(passphrase, &kdf)
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	c.Check(recoveredAuxKey, DeepEquals, auxKey)
}

func (s *keyDataSuite) TestRecoverKeysWithPassphrase1(c *C) {
	s.testRecoverKeysWithPassphrase(c, "passphrase")
}

func (s *keyDataSuite) TestRecoverKeysWithPassphrase2(c *C) {
	s.testRecoverKeysWithPassphrase(c, "1234")
}

func (s *keyDataSuite) TestSetPassphraseNotSupported(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	c.Check(keyData.SetPassphrase("passphrase", nil, new(testutil.MockKDF)), ErrorMatches, "not supported")

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected, 0)
}

func (s *keyDataSuite) TestSetPassphraseAlreadySet(c *C) {
	s.handler.passphraseSupport = true

	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF

	c.Check(keyData.SetPassphrase("passphrase", nil, &kdf), IsNil)
	c.Check(keyData.SetPassphrase("passphrase", nil, &kdf), ErrorMatches, "cannot set passphrase without authorization")

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, 0, "passphrase", nil)
}

type testSetPassphraseData struct {
	passphrase string
	kdfOptions *KDFOptions
}

func (s *keyDataSuite) testSetPassphrase(c *C, data *testSetPassphraseData) {
	s.handler.passphraseSupport = true

	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(keyData.SetPassphrase(data.passphrase, data.kdfOptions, &kdf), IsNil)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, 0, data.passphrase, data.kdfOptions)
}

func (s *keyDataSuite) TestSetPassphrase(c *C) {
	s.testSetPassphrase(c, &testSetPassphraseData{
		passphrase: "12345678",
		kdfOptions: &KDFOptions{}})
}

func (s *keyDataSuite) TestSetPassphraseDifferentPassphrase(c *C) {
	s.testSetPassphrase(c, &testSetPassphraseData{
		passphrase: "abcdefgh",
		kdfOptions: &KDFOptions{}})
}

func (s *keyDataSuite) TestSetPassphraseNilOptions(c *C) {
	s.testSetPassphrase(c, &testSetPassphraseData{
		passphrase: "12345678"})
}

func (s *keyDataSuite) TestSetPassphraseCustomDuration(c *C) {
	s.testSetPassphrase(c, &testSetPassphraseData{
		passphrase: "12345678",
		kdfOptions: &KDFOptions{TargetDuration: 100 * time.Millisecond}})
}

func (s *keyDataSuite) TestSetPassphraseForceIterations(c *C) {
	s.testSetPassphrase(c, &testSetPassphraseData{
		passphrase: "12345678",
		kdfOptions: &KDFOptions{ForceIterations: 3, MemoryKiB: 32 * 1024}})
}

func (s *keyDataSuite) TestChangePassphraseAuthModeNone(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	err = keyData.ChangePassphrase("passphrase1", "passphrase2", &KDFOptions{}, new(testutil.MockKDF))
	c.Check(err, ErrorMatches, "cannot change passphrase without setting an initial passphrase")

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected, 0)
}

type testChangePassphraseData struct {
	passphrase1 string
	passphrase2 string
	kdfOptions  *KDFOptions
}

func (s *keyDataSuite) testChangePassphrase(c *C, data *testChangePassphraseData) {
	s.handler.passphraseSupport = true

	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(keyData.SetPassphrase(data.passphrase1, data.kdfOptions, &kdf), IsNil)
	c.Check(keyData.ChangePassphrase(data.passphrase1, data.passphrase2, data.kdfOptions, &kdf), IsNil)

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

	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(keyData.SetPassphrase("12345678", nil, &kdf), IsNil)
	c.Check(keyData.ChangePassphrase("passphrase", "12345678", &KDFOptions{TargetDuration: 100 * time.Millisecond}, &kdf), Equals, ErrInvalidPassphrase)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, 0, "12345678", nil)
}

func (s *keyDataSuite) TestClearPassphraseWithPassphraseAuthModeNone(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	err = keyData.ClearPassphraseWithPassphrase("passphrase", new(testutil.MockKDF))
	c.Check(err, ErrorMatches, "no passphrase is set")

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected, 0)
}

func (s *keyDataSuite) TestClearPassphraseWithPassphrase(c *C) {
	s.handler.passphraseSupport = true

	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(keyData.SetPassphrase("12345678", nil, &kdf), IsNil)
	c.Check(keyData.ClearPassphraseWithPassphrase("12345678", &kdf), IsNil)

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected, 0)
}

func (s *keyDataSuite) TestClearPassphraseWithPassphraseWrongPassphrase(c *C) {
	s.handler.passphraseSupport = true

	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(keyData.SetPassphrase("12345678", nil, &kdf), IsNil)
	c.Check(keyData.ClearPassphraseWithPassphrase("passphrase", &kdf), Equals, ErrInvalidPassphrase)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, 0, "12345678", nil)
}

type testSnapModelAuthData struct {
	alg        crypto.Hash
	authModels []SnapModel
	model      SnapModel
	authorized bool
}

func (s *keyDataSuite) testSnapModelAuth(c *C, data *testSnapModelAuthData) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, data.alg)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	c.Check(keyData.SetAuthorizedSnapModels(auxKey, data.authModels...), IsNil)

	authorized, err := keyData.IsSnapModelAuthorized(auxKey, data.model)
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
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

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
	w := makeMockKeyDataWriter()
	c.Check(data.keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModeNone(c, w.Reader(), data.params, data.nmodels)
}

func (s *keyDataSuite) TestWriteAtomic1(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	s.testWriteAtomic(c, &testWriteAtomicData{
		keyData: keyData,
		params:  protected})
}

func (s *keyDataSuite) TestWriteAtomic2(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA512)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	s.testWriteAtomic(c, &testWriteAtomicData{
		keyData: keyData,
		params:  protected})
}

func (s *keyDataSuite) TestWriteAtomic3(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

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

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	s.testWriteAtomic(c, &testWriteAtomicData{
		keyData: keyData,
		params:  protected,
		nmodels: len(models)})
}

func (s *keyDataSuite) TestWriteAtomic4(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

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

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	s.testWriteAtomic(c, &testWriteAtomicData{
		keyData: keyData,
		params:  protected,
		nmodels: len(models)})
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
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

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

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	s.testReadKeyData(c, &testReadKeyDataData{
		key:        key,
		auxKey:     auxKey,
		id:         id,
		r:          &mockKeyDataReader{"foo", w.Reader()},
		model:      models[0],
		authorized: true})
}

func (s *keyDataSuite) TestReadKeyData2(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA512)

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

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	s.testReadKeyData(c, &testReadKeyDataData{
		key:        key,
		auxKey:     auxKey,
		id:         id,
		r:          &mockKeyDataReader{"bar", w.Reader()},
		model:      models[0],
		authorized: true})
}

func (s *keyDataSuite) TestReadKeyData3(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

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

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	s.testReadKeyData(c, &testReadKeyDataData{
		key:        key,
		auxKey:     auxKey,
		id:         id,
		r:          &mockKeyDataReader{"foo", w.Reader()},
		model:      models[1],
		authorized: true})
}

func (s *keyDataSuite) TestReadKeyData4(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA512)

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

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)

	s.testReadKeyData(c, &testReadKeyDataData{
		key:    key,
		auxKey: auxKey,
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
