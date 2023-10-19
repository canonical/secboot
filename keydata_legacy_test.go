package secboot

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"hash"
	"math/rand"

	"golang.org/x/xerrors"
	. "gopkg.in/check.v1"
)

const mockPlatformName = "mock-legacy"

const (
	mockPlatformDeviceStateOK = iota
	mockPlatformDeviceStateUnavailable
	mockPlatformDeviceStateUninitialized
)

type mockPlatformKeyDataHandle struct {
	Key         []byte `json:"key"`
	IV          []byte `json:"iv"`
	AuthKeyHMAC []byte `json:"auth-key-hmac"`
}

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

type keyDataLegacySuite struct {
	keyDataTestBase
}

var _ = Suite(&keyDataLegacySuite{})

type testLegacyKeyPayloadData struct {
	key    DiskUnlockKey
	auxKey PrimaryKey
}

func (s *keyDataLegacySuite) testKeyPayload(c *C, data *testLegacyKeyPayloadData) {
	payload := MarshalKeys(data.key, data.auxKey)

	key, auxKey, err := UnmarshalV1KeyPayload(payload)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.key)
	c.Check(auxKey, DeepEquals, data.auxKey)
}

func (s *keyDataLegacySuite) TestLegacyKeyPayload1(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)

	s.testKeyPayload(c, &testLegacyKeyPayloadData{
		key:    key,
		auxKey: auxKey})
}

func (s *keyDataLegacySuite) TestLegacyKeyPayload2(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 64, 32)

	s.testKeyPayload(c, &testLegacyKeyPayloadData{
		key:    key,
		auxKey: auxKey})
}

func (s *keyDataLegacySuite) TestLegacyKeyPayload3(c *C) {
	key, _ := s.newKeyDataKeys(c, 32, 0)

	s.testKeyPayload(c, &testLegacyKeyPayloadData{
		key: key})
}

func (s *keyDataLegacySuite) TestLegacyKeyPayloadUnmarshalInvalid1(c *C) {
	payload := make([]byte, 66)
	for i := range payload {
		payload[i] = 0xff
	}

	key, auxKey, err := UnmarshalV1KeyPayload(payload)
	c.Check(err, ErrorMatches, "EOF")
	c.Check(key, IsNil)
	c.Check(auxKey, IsNil)
}

func (s *keyDataLegacySuite) TestLegacyKeyPayloadUnmarshalInvalid2(c *C) {
	payload := MarshalKeys(make(DiskUnlockKey, 32), make(PrimaryKey, 32))
	payload = append(payload, 0xff)

	key, auxKey, err := UnmarshalV1KeyPayload(payload)
	c.Check(err, ErrorMatches, "1 excess byte\\(s\\)")
	c.Check(key, IsNil)
	c.Check(auxKey, IsNil)
}

func (s *keyDataLegacySuite) TestRecoverKeys(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	keyData.data.Version = 1

	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	c.Check(recoveredAuxKey, DeepEquals, auxKey)
}

func (s *keyDataLegacySuite) TestRecoverKeysUnrecognizedPlatform(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	protected.PlatformName = "foo"

	keyData, err := NewKeyData(protected)
	keyData.data.Version = 1

	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "no appropriate platform handler is registered")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataLegacySuite) TestRecoverKeysInvalidData(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	protected.Handle = []byte("\"\"")

	keyData, err := NewKeyData(protected)
	keyData.data.Version = 1

	c.Assert(err, IsNil)
	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: JSON decode error: json: cannot unmarshal string into Go value of type secboot.mockPlatformKeyDataHandle")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}
