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
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/rand"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	"golang.org/x/xerrors"

	. "gopkg.in/check.v1"
)

const mockPlatformName = "mock"

const (
	mockPlatformDeviceStateOK = iota
	mockPlatformDeviceStateUnavailable
	mockPlatformDeviceStateUninitialized
)

type mockPlatformKeyDataHandler struct {
	state int
}

func (h *mockPlatformKeyDataHandler) RecoverKeys(data *PlatformKeyData) (KeyPayload, error) {
	switch h.state {
	case mockPlatformDeviceStateUnavailable:
		return nil, &PlatformKeyRecoveryError{Type: PlatformKeyRecoveryErrorUnavailable, Err: errors.New("the platform device is unavailable")}
	case mockPlatformDeviceStateUninitialized:
		return nil, &PlatformKeyRecoveryError{Type: PlatformKeyRecoveryErrorUninitialized, Err: errors.New("the platform device is uninitialized")}
	}

	var str string
	if err := json.Unmarshal(data.Handle, &str); err != nil {
		return nil, &PlatformKeyRecoveryError{Type: PlatformKeyRecoveryErrorInvalidData, Err: xerrors.Errorf("JSON decode error: %w", err)}
	}

	handle, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, &PlatformKeyRecoveryError{Type: PlatformKeyRecoveryErrorInvalidData, Err: xerrors.Errorf("base64 decode error: %w", err)}
	}

	if len(handle) != 48 {
		return nil, &PlatformKeyRecoveryError{Type: PlatformKeyRecoveryErrorInvalidData, Err: errors.New("invalid handle length")}
	}

	b, err := aes.NewCipher(handle[:32])
	if err != nil {
		return nil, xerrors.Errorf("cannot create cipher: %w", err)
	}

	s := cipher.NewCFBDecrypter(b, handle[32:])
	out := make(KeyPayload, len(data.EncryptedPayload))
	s.XORKeyStream(out, data.EncryptedPayload)
	return out, nil
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

func (w *mockKeyDataWriter) Read(data []byte) (int, error) {
	if w.final == nil {
		return 0, io.EOF
	}
	return w.final.Read(data)
}

func makeMockKeyDataWriter() *mockKeyDataWriter {
	return &mockKeyDataWriter{tmp: new(bytes.Buffer)}
}

type mockKeyDataReader struct {
	id KeyID
	io.Reader
}

func (r *mockKeyDataReader) ID() KeyID {
	return r.id
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
}

func (s *keyDataTestBase) TearDownSuite(c *C) {
	RegisterPlatformKeyDataHandler(mockPlatformName, nil)
}

func (s *keyDataTestBase) newKeys(c *C, sz1, sz2 int) (DiskUnlockKey, AuxiliaryKey) {
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

	handle, err := json.Marshal(base64.StdEncoding.EncodeToString(k))
	c.Check(err, IsNil)

	b, err := aes.NewCipher(k[:32])
	c.Assert(err, IsNil)
	stream := cipher.NewCFBEncrypter(b, k[32:])

	out = &KeyCreationData{
		PlatformName: mockPlatformName,
		PlatformKeyData: PlatformKeyData{
			Handle:           handle,
			EncryptedPayload: make([]byte, len(payload))},
		AuxiliaryKey:      auxKey,
		SnapModelAuthHash: modelAuthHash}
	stream.XORKeyStream(out.EncryptedPayload, payload)
	return
}

func (s *keyDataTestBase) checkKeyDataJSON(c *C, j map[string]interface{}, creationData *KeyCreationData, nmodels int) {
	c.Check(j["platform_name"], Equals, creationData.PlatformName)

	handle, err := json.Marshal(j["platform_handle"])
	c.Check(err, IsNil)
	c.Check(handle, DeepEquals, creationData.Handle)

	str, ok := j["encrypted_payload"].(string)
	c.Check(ok, testutil.IsTrue)
	encryptedPayload, err := base64.StdEncoding.DecodeString(str)
	c.Check(err, IsNil)
	c.Check(encryptedPayload, DeepEquals, creationData.EncryptedPayload)

	c.Check(j, Not(testutil.HasKey), "passphrase_protected_payload")

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

type keyDataSuite struct {
	snapModelTestBase
	keyDataTestBase
}

var _ = Suite(&keyDataSuite{})

func (s *keyDataSuite) checkKeyDataJSON(c *C, r io.Reader, creationData *KeyCreationData, nmodels int) {
	var j map[string]interface{}

	d := json.NewDecoder(r)
	c.Check(d.Decode(&j), IsNil)

	s.keyDataTestBase.checkKeyDataJSON(c, j, creationData, nmodels)
}

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
	key, auxKey := s.newKeys(c, 32, 32)

	s.testKeyPayload(c, &testKeyPayloadData{
		key:    key,
		auxKey: auxKey})
}

func (s *keyDataSuite) TestKeyPayload2(c *C) {
	key, auxKey := s.newKeys(c, 64, 32)

	s.testKeyPayload(c, &testKeyPayloadData{
		key:    key,
		auxKey: auxKey})
}

func (s *keyDataSuite) TestKeyPayload3(c *C) {
	key, _ := s.newKeys(c, 32, 0)

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

type testKeyIDStringData struct {
	id       KeyID
	expected string
}

func (s *keyDataSuite) testKeyIDString(c *C, data *testKeyIDStringData) {
	c.Check(data.id.String(), Equals, data.expected)
}

func (s *keyDataSuite) TestKeyIDString1(c *C) {
	s.testKeyIDString(c, &testKeyIDStringData{
		id:       KeyID{Name: "foobar"},
		expected: "foobar@0"})
}

func (s *keyDataSuite) TestKeyIDStringLUKS(c *C) {
	s.testKeyIDString(c, &testKeyIDStringData{
		id: KeyID{
			Name:     "barfoo",
			Revision: 15},
		expected: "barfoo@15"})
}

func (s *keyDataSuite) TestRecoverKeys(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	c.Check(recoveredAuxKey, DeepEquals, auxKey)
}

func (s *keyDataSuite) TestRecoverKeysUnrecognizedPlatform(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	protected.PlatformName = "foo"

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "cannot recover key because there isn't a platform handler registered for it")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataSuite) TestRecoverKeysInvalidData(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	protected.Handle = []byte("\"\"")

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: invalid handle length")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

type testSnapModelAuthData struct {
	alg        crypto.Hash
	authModels []SnapModel
	model      SnapModel
	authorized bool
}

func (s *keyDataSuite) testSnapModelAuth(c *C, data *testSnapModelAuthData) {
	key, auxKey := s.newKeys(c, 32, 32)
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
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
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
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
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
			s.makeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")},
		model: s.makeMockCore20ModelAssertion(c, map[string]interface{}{
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
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
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
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
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

	s.checkKeyDataJSON(c, w, data.creationData, data.nmodels)
}

func (s *keyDataSuite) TestWriteAtomic1(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	s.testWriteAtomic(c, &testWriteAtomicData{
		keyData:      keyData,
		creationData: protected})
}

func (s *keyDataSuite) TestWriteAtomic2(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA512)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	s.testWriteAtomic(c, &testWriteAtomicData{
		keyData:      keyData,
		creationData: protected})
}

func (s *keyDataSuite) TestWriteAtomic3(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
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
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
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
	r          KeyDataReader
	model      SnapModel
	authorized bool
}

func (s *keyDataSuite) testReadKeyData(c *C, data *testReadKeyDataData) {
	keyData, err := ReadKeyData(data.r)
	c.Check(err, IsNil)

	c.Check(keyData.ID(), Equals, data.r.ID())

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
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	r := &mockKeyDataReader{KeyID{Name: "foo", Revision: 1}, w.final}

	s.testReadKeyData(c, &testReadKeyDataData{
		key:        key,
		auxKey:     auxKey,
		r:          r,
		model:      models[0],
		authorized: true})
}

func (s *keyDataSuite) TestReadKeyData2(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA512)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	r := &mockKeyDataReader{KeyID{Name: "bar", Revision: 3}, w.final}

	s.testReadKeyData(c, &testReadKeyDataData{
		key:        key,
		auxKey:     auxKey,
		r:          r,
		model:      models[0],
		authorized: true})
}

func (s *keyDataSuite) TestReadKeyData3(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	r := &mockKeyDataReader{KeyID{Name: "foo", Revision: 0}, w.final}

	s.testReadKeyData(c, &testReadKeyDataData{
		key:        key,
		auxKey:     auxKey,
		r:          r,
		model:      models[1],
		authorized: true})
}

func (s *keyDataSuite) TestReadKeyData4(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA512)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	w := makeMockKeyDataWriter()
	c.Check(keyData.WriteAtomic(w), IsNil)

	r := &mockKeyDataReader{KeyID{Name: "foo", Revision: 0}, w.final}

	s.testReadKeyData(c, &testReadKeyDataData{
		key:    key,
		auxKey: auxKey,
		r:      r,
		model: s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		authorized: false})
}
