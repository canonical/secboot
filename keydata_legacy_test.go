package secboot_test

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"hash"
	"math/rand"

	. "github.com/snapcore/secboot"
	"golang.org/x/crypto/cryptobyte"
	. "gopkg.in/check.v1"
)

type keyDataLegacySuite struct {
	keyDataTestBase
}

var _ = Suite(&keyDataLegacySuite{})

func (s *keyDataLegacySuite) SetUpSuite(c *C) {
	s.handler = &mockPlatformKeyDataHandler{}
	s.mockPlatformName = "mock-legacy"
	RegisterPlatformKeyDataHandler(s.mockPlatformName, s.handler)
}

func (s *keyDataLegacySuite) SetUpTest(c *C) {
	s.handler.state = mockPlatformDeviceStateOK
	s.handler.passphraseSupport = false
}

func (s *keyDataLegacySuite) TearDownSuite(c *C) {
	RegisterPlatformKeyDataHandler(s.mockPlatformName, nil)
}

func (s *keyDataLegacySuite) newKeyDataKeys(c *C, sz1, sz2 int) (DiskUnlockKey, PrimaryKey) {
	key := make([]byte, sz1)
	auxKey := make([]byte, sz2)
	_, err := rand.Read(key)
	c.Assert(err, IsNil)
	_, err = rand.Read(auxKey)
	c.Assert(err, IsNil)
	return key, auxKey
}

func (s *keyDataLegacySuite) mockProtectKeys(c *C, key DiskUnlockKey, auxKey PrimaryKey, kdfAlg crypto.Hash, modelAuthHash crypto.Hash) (out *KeyParams) {
	payload := MarshalKeys(key, auxKey)

	k := make([]byte, 44)
	_, err := rand.Read(k)
	c.Assert(err, IsNil)

	handle := mockPlatformKeyDataHandle{
		Key:   k[:32],
		Nonce: k[32:],
	}

	aad := mockPlatformAdditionalData{
		ExpectedGeneration: 1,
		ExpectedAuthMode:   AuthModeNone,
	}
	builder := cryptobyte.NewBuilder(nil)
	aad.MarshalASN1(builder)
	aadBytes, err := builder.Bytes()
	c.Assert(err, IsNil)

	h := hmac.New(func() hash.Hash { return kdfAlg.New() }, handle.Key)
	handle.AuthKeyHMAC = h.Sum(nil)

	b, err := aes.NewCipher(handle.Key)
	c.Assert(err, IsNil)
	aead, err := cipher.NewGCM(b)
	c.Assert(err, IsNil)
	ciphertext := aead.Seal(nil, handle.Nonce, payload, aadBytes)

	out = &KeyParams{
		PlatformName:      s.mockPlatformName,
		Handle:            &handle,
		EncryptedPayload:  ciphertext,
		PrimaryKey:        auxKey,
		SnapModelAuthHash: modelAuthHash}
	return
}

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
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256, crypto.SHA256)

	restore := MockKeyDataGeneration(0)
	defer restore()

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Assert(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	c.Check(recoveredAuxKey, DeepEquals, auxKey)
}

func (s *keyDataLegacySuite) TestRecoverKeysUnrecognizedPlatform(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256, crypto.SHA256)

	protected.PlatformName = "foo"

	restore := MockKeyDataGeneration(0)
	defer restore()

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "no appropriate platform handler is registered")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataLegacySuite) TestRecoverKeysInvalidData(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256, crypto.SHA256)

	protected.Handle = []byte("\"\"")

	restore := MockKeyDataGeneration(0)
	defer restore()

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: JSON decode error: json: cannot unmarshal string into Go value of type secboot_test.mockPlatformKeyDataHandle")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}

func (s *keyDataLegacySuite) TestRecoverKeysWithPassphraseAuthModeNone(c *C) {
	key, auxKey := s.newKeyDataKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeysWithPassphrase("", nil)
	c.Check(err, ErrorMatches, "cannot recover key with passphrase")
	c.Check(recoveredKey, IsNil)
	c.Check(recoveredAuxKey, IsNil)
}
