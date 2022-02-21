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

	handle, err := h.unmarshalHandle(data.Handle)
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

	handle, err := h.unmarshalHandle(data.Handle)
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

func (s *keyDataTestBase) newKeyDataKeys(c *C, sz1, sz2 int) (DiskUnlockKey, AuxiliaryKey) {
	key := make([]byte, sz1)
	auxKey := make([]byte, sz2)
	_, err := rand.Read(key)
	c.Assert(err, IsNil)
	_, err = rand.Read(auxKey)
	c.Assert(err, IsNil)
	return key, auxKey
}

func (s *keyDataTestBase) mockProtectKeys(c *C, key DiskUnlockKey, auxKey AuxiliaryKey, modelAuthHash crypto.Hash) (out *KeyCreationData) {
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

	handleBytes, err := json.Marshal(&handle)
	c.Check(err, IsNil)

	out = &KeyCreationData{
		PlatformName: mockPlatformName,
		PlatformKeyData: PlatformKeyData{
			Handle:           handleBytes,
			EncryptedPayload: make([]byte, len(payload))},
		AuxiliaryKey:      auxKey,
		SnapModelAuthHash: modelAuthHash}
	stream.XORKeyStream(out.EncryptedPayload, payload)
	return
}

func (s *keyDataTestBase) checkKeyDataJSONCommon(c *C, j map[string]interface{}, creationData *KeyCreationData, nmodels int) {
	c.Check(j["platform_name"], Equals, creationData.PlatformName)

	var creationHandle map[string]interface{}
	c.Check(json.Unmarshal(creationData.Handle, &creationHandle), IsNil)

	handle, ok := j["platform_handle"].(map[string]interface{})
	c.Check(ok, testutil.IsTrue)
	str, ok := handle["key"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(str, Equals, creationHandle["key"].(string))
	str, ok = handle["iv"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(str, Equals, creationHandle["iv"].(string))

	c.Check(j["platform_handle"], DeepEquals, handle)

	m, ok := j["authorized_snap_models"].(map[string]interface{})
	c.Check(ok, testutil.IsTrue)

	h := toHash(c, m["alg"])
	c.Check(h, Equals, creationData.SnapModelAuthHash)

	str, ok = m["key_digest"].(string)
	c.Check(ok, testutil.IsTrue)
	keyDigest, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)
	c.Check(keyDigest, HasLen, h.Size())

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
}

func (s *keyDataTestBase) checkKeyDataJSONFromReaderAuthModeNone(c *C, r io.Reader, creationData *KeyCreationData, nmodels int) {
	var j map[string]interface{}

	d := json.NewDecoder(r)
	c.Check(d.Decode(&j), IsNil)

	s.checkKeyDataJSONCommon(c, j, creationData, nmodels)

	var creationHandle map[string]interface{}
	c.Check(json.Unmarshal(creationData.Handle, &creationHandle), IsNil)

	handle, ok := j["platform_handle"].(map[string]interface{})
	c.Check(ok, testutil.IsTrue)
	str, ok := handle["auth-key-hmac"].(string)
	c.Check(ok, testutil.IsTrue)

	str, ok = j["encrypted_payload"].(string)
	c.Check(ok, testutil.IsTrue)
	encryptedPayload, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)
	c.Check(encryptedPayload, DeepEquals, creationData.EncryptedPayload)

	c.Check(j, Not(testutil.HasKey), "passphrase_protected_payload")
}

func (s *keyDataTestBase) checkKeyDataJSONFromReaderAuthModePassphrase(c *C, r io.Reader, creationData *KeyCreationData, nmodels int, passphrase string, kdfOpts *KDFOptions) {
	if kdfOpts == nil {
		var def KDFOptions
		kdfOpts = &def
	}
	var kdf mockKDF

	costParams, err := kdfOpts.DeriveCostParams(0, &kdf)
	c.Assert(err, IsNil)

	var j map[string]interface{}

	d := json.NewDecoder(r)
	c.Check(d.Decode(&j), IsNil)

	s.checkKeyDataJSONCommon(c, j, creationData, nmodels)

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
	c.Check(payload, DeepEquals, creationData.EncryptedPayload)
}

func (s *keyDataTestBase) checkKeyDataJSONAuthModeNone(c *C, keyData *KeyData, creationData *KeyCreationData, nmodels int) {
	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModeNone(c, w.Reader(), creationData, nmodels)
}

func (s *keyDataTestBase) checkKeyDataJSONAuthModePassphrase(c *C, keyData *KeyData, creationData *KeyCreationData, nmodels int, passphrase string, kdfOpts *KDFOptions) {
	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModePassphrase(c, w.Reader(), creationData, nmodels, passphrase, kdfOpts)
}

type keyDataSuite struct {
	keyDataTestBase
}

var _ = Suite(&keyDataSuite{})

type testKeyPayloadData struct {
	key    DiskUnlockKey
	auxKey AuxiliaryKey
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
	payload := MarshalKeys(make(DiskUnlockKey, 32), make(AuxiliaryKey, 32))
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

	var kdf mockKDF
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

	var kdf mockKDF
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
	c.Check(keyData.SetPassphrase("passphrase", nil, &mockKDF{}), ErrorMatches, "not supported")

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected, 0)
}

func (s *keyDataSuite) TestSetPassphraseAlreadySet(c *C) {
	s.handler.passphraseSupport = true

	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var kdf mockKDF

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

	var kdf mockKDF
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
	err = keyData.ChangePassphrase("passphrase1", "passphrase2", &KDFOptions{}, &mockKDF{})
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

	var kdf mockKDF
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

	var kdf mockKDF
	c.Check(keyData.SetPassphrase("12345678", nil, &kdf), IsNil)
	c.Check(keyData.ChangePassphrase("passphrase", "12345678", &KDFOptions{TargetDuration: 100 * time.Millisecond}, &kdf), Equals, ErrInvalidPassphrase)

	s.checkKeyDataJSONAuthModePassphrase(c, keyData, protected, 0, "12345678", nil)
}

func (s *keyDataSuite) TestClearPassphraseWithPassphraseAuthModeNone(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	err = keyData.ClearPassphraseWithPassphrase("passphrase", &mockKDF{})
	c.Check(err, ErrorMatches, "no passphrase is set")

	s.checkKeyDataJSONAuthModeNone(c, keyData, protected, 0)
}

func (s *keyDataSuite) TestClearPassphraseWithPassphrase(c *C) {
	s.handler.passphraseSupport = true

	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	var kdf mockKDF
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

	var kdf mockKDF
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

	c.Check(keyData.SetAuthorizedSnapModels(make(AuxiliaryKey, 32), models...), ErrorMatches, "incorrect key supplied")
}

type testWriteAtomicData struct {
	keyData      *KeyData
	creationData *KeyCreationData
	nmodels      int
}

func (s *keyDataSuite) testWriteAtomic(c *C, data *testWriteAtomicData) {
	w := makeMockKeyDataWriter()
	c.Check(data.keyData.WriteAtomic(w), IsNil)

	s.checkKeyDataJSONFromReaderAuthModeNone(c, w.Reader(), data.creationData, data.nmodels)
}

func (s *keyDataSuite) TestWriteAtomic1(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	s.testWriteAtomic(c, &testWriteAtomicData{
		keyData:      keyData,
		creationData: protected})
}

func (s *keyDataSuite) TestWriteAtomic2(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA512)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	s.testWriteAtomic(c, &testWriteAtomicData{
		keyData:      keyData,
		creationData: protected})
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
		keyData:      keyData,
		creationData: protected,
		nmodels:      len(models)})
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
		keyData:      keyData,
		creationData: protected,
		nmodels:      len(models)})
}

type testReadKeyDataData struct {
	key        DiskUnlockKey
	auxKey     AuxiliaryKey
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
