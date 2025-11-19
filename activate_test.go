// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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
	"context"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strings"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/bootscope"
	internal_bootscope "github.com/snapcore/secboot/internal/bootscope"
	"github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"
)

type mockActivateContextOption1 struct {
	k mockActivateConfigKey1
	v any
}

func (o *mockActivateContextOption1) ApplyOptionToConfig(config ActivateConfig) {
	config.Set(o.k, o.v)
}

func (o *mockActivateContextOption1) ApplyContextOptionToConfig(config ActivateConfig) {
	config.Set(o.k, o.v)
}

func withMockActivateContextOption1(k mockActivateConfigKey1, v any) ActivateContextOption {
	return &mockActivateContextOption1{k: k, v: v}
}

func makeRecoveryKey(c *C, key []byte) RecoveryKey {
	c.Assert(key, HasLen, 16)

	var out RecoveryKey
	copy(out[:], key)
	return out
}

type activateSuite struct {
	snapd_testutil.BaseTest
	keyDataTestBase
	keyringTestMixin
}

func (s *activateSuite) SetUpSuite(c *C) {
	s.keyDataTestBase.SetUpSuite(c)
	s.keyringTestMixin.SetUpSuite(c)
}

func (s *activateSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.keyDataTestBase.SetUpTest(c)
	s.keyringTestMixin.SetUpTest(c)

	s.handler.userAuthSupport = true
	internal_bootscope.UnsafeClearModelForTesting()
}

func (s *activateSuite) TearDownTest(c *C) {
	s.keyringTestMixin.TearDownTest(c)
	s.keyDataTestBase.TearDownTest(c)
	s.BaseTest.TearDownTest(c)
}

func (s *activateSuite) TearDownSuite(c *C) {
	s.keyringTestMixin.TearDownSuite(c)
	s.keyDataTestBase.TearDownSuite(c)
}

func (s *activateSuite) makeKeyDataBlobFromParams(c *C, params *KeyParams) []byte {
	kd, err := NewKeyData(params)
	c.Assert(err, IsNil)

	w := makeMockKeyDataWriter()
	c.Check(kd.WriteAtomic(w), IsNil)

	return w.Bytes()
}

func (s *activateSuite) makeKeyDataBlob(c *C, primaryKey PrimaryKey, uniqueKey []byte, role string) (blob []byte, unlockKey DiskUnlockKey) {
	var params *KeyParams
	params, unlockKey = s.mockProtectKeys(c, primaryKey, uniqueKey, role, crypto.SHA256)

	return s.makeKeyDataBlobFromParams(c, params), unlockKey
}

func (s *activateSuite) makeKeyDataBlobWithPassphrase(c *C, primaryKey PrimaryKey, uniqueKey []byte, role, passphrase string) (blob []byte, unlockKey DiskUnlockKey) {
	var params *KeyWithPassphraseParams
	params, unlockKey = s.mockProtectKeysWithPassphrase(c, primaryKey, uniqueKey, role, nil, 32, crypto.SHA256)

	kd, err := NewKeyDataWithPassphrase(params, passphrase)
	c.Assert(err, IsNil)

	w := makeMockKeyDataWriter()
	c.Check(kd.WriteAtomic(w), IsNil)

	return w.Bytes(), unlockKey
}

var _ = Suite(&activateSuite{})

func (s *activateSuite) TestNewActivateContext(c *C) {
	ctx, err := NewActivateContext(context.Background(), nil)
	c.Assert(err, IsNil)
	c.Assert(ctx, NotNil)

	c.Check(ctx.State(), DeepEquals, &ActivateState{
		Activations: make(map[string]*ContainerActivateState),
	})
	c.Check(ctx.Config().(interface{ Len() int }).Len(), Equals, 0)
	c.Check(ctx.PrimaryKey(), HasLen, 0)
}

func (*activateSuite) TestNewActivateContextWithProvidedState(c *C) {
	state := &ActivateState{
		Activations: map[string]*ContainerActivateState{
			"sda1": {Status: ActivationSucceededWithRecoveryKey},
		},
	}
	stateCopy := state.Copy()

	ctx, err := NewActivateContext(context.Background(), state)
	c.Assert(err, IsNil)
	c.Assert(ctx, NotNil)

	c.Check(ctx.State(), Equals, state)
	c.Check(ctx.State(), DeepEquals, stateCopy)
	c.Check(ctx.Config().(interface{ Len() int }).Len(), Equals, 0)
	c.Check(ctx.PrimaryKey(), HasLen, 0)
}

func (*activateSuite) TestNewActivateContextWithProvidedStateAndPrimaryKey1(c *C) {
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	state := &ActivateState{
		PrimaryKeyID: int32(id),
		Activations: map[string]*ContainerActivateState{
			"sda1": {Status: ActivationSucceededWithPlatformKey},
		},
	}
	stateCopy := state.Copy()

	ctx, err := NewActivateContext(context.Background(), state)
	c.Assert(err, IsNil)
	c.Assert(ctx, NotNil)

	c.Check(ctx.State(), Equals, state)
	c.Check(ctx.State(), DeepEquals, stateCopy)
	c.Check(ctx.Config().(interface{ Len() int }).Len(), Equals, 0)
	c.Check(ctx.PrimaryKey(), DeepEquals, PrimaryKey(primaryKey))
}

func (*activateSuite) TestNewActivateContextWithProvidedStateAndPrimaryKey2(c *C) {
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	state := &ActivateState{
		PrimaryKeyID: int32(id),
		Activations: map[string]*ContainerActivateState{
			"sda1": {Status: ActivationSucceededWithPlatformKey},
			"sda2": {Status: ActivationSucceededWithRecoveryKey},
		},
	}
	stateCopy := state.Copy()

	ctx, err := NewActivateContext(context.Background(), state)
	c.Assert(err, IsNil)
	c.Assert(ctx, NotNil)

	c.Check(ctx.State(), Equals, state)
	c.Check(ctx.State(), DeepEquals, stateCopy)
	c.Check(ctx.Config().(interface{ Len() int }).Len(), Equals, 0)
	c.Check(ctx.PrimaryKey(), DeepEquals, PrimaryKey(primaryKey))
}

func (*activateSuite) TestNewActivateContextWithProvidedStateAndNoPrimaryKey(c *C) {
	state := &ActivateState{
		Activations: map[string]*ContainerActivateState{
			"sda1": {Status: ActivationSucceededWithPlatformKey},
		},
	}
	stateCopy := state.Copy()

	ctx, err := NewActivateContext(context.Background(), state)
	c.Assert(err, IsNil)
	c.Assert(ctx, NotNil)

	c.Check(ctx.State(), Equals, state)
	c.Check(ctx.State(), DeepEquals, stateCopy)
	c.Check(ctx.Config().(interface{ Len() int }).Len(), Equals, 0)
	c.Check(ctx.PrimaryKey(), HasLen, 0)
}

func (*activateSuite) TestNewActivateContextWithOptions(c *C) {
	authRequestor := new(mockAuthRequestor)

	ctx, err := NewActivateContext(
		context.Background(),
		nil, // state
		WithAuthRequestor(authRequestor),
		WithKeyringDescriptionPrefix("ubuntu-fde"),
		WithDiscardStderrLogger(),
		WithRecoveryKeyTries(3),
	)
	c.Assert(err, IsNil)
	c.Assert(ctx, NotNil)

	c.Check(ctx.State(), DeepEquals, &ActivateState{
		Activations: make(map[string]*ContainerActivateState),
	})

	c.Check(ctx.Config().(interface{ Len() int }).Len(), Equals, 4)
	{
		v, exists := ActivateConfigGet[AuthRequestor](ctx.Config(), AuthRequestorKey)
		c.Check(exists, testutil.IsTrue)
		c.Check(v, Equals, authRequestor)
	}
	{
		v, exists := ActivateConfigGet[string](ctx.Config(), KeyringDescPrefixKey)
		c.Check(exists, testutil.IsTrue)
		c.Check(v, Equals, "ubuntu-fde")
	}
	{
		v, exists := ActivateConfigGet[io.Writer](ctx.Config(), StderrLoggerKey)
		c.Check(exists, testutil.IsTrue)
		c.Check(v, Equals, io.Discard)
	}
	{
		v, exists := ActivateConfigGet[uint](ctx.Config(), RecoveryKeyTriesKey)
		c.Check(exists, testutil.IsTrue)
		c.Check(v, Equals, uint(3))
	}

	c.Check(ctx.PrimaryKey(), HasLen, 0)
}

func (*activateSuite) TestNewActivateContextWithProvidedStateAndOptions(c *C) {
	state := &ActivateState{
		Activations: map[string]*ContainerActivateState{
			"sda1": {Status: ActivationSucceededWithRecoveryKey},
		},
	}
	stateCopy := state.Copy()

	stderr := new(os.File)

	ctx, err := NewActivateContext(
		context.Background(),
		state,
		WithKeyringDescriptionPrefix("foo"),
		WithStderrLogger(stderr),
		WithRecoveryKeyTries(5),
	)
	c.Assert(err, IsNil)
	c.Assert(ctx, NotNil)

	c.Check(ctx.State(), NotNil)
	c.Check(ctx.State(), DeepEquals, stateCopy)

	c.Check(ctx.Config().(interface{ Len() int }).Len(), Equals, 3)
	{
		v, exists := ActivateConfigGet[string](ctx.Config(), KeyringDescPrefixKey)
		c.Check(exists, testutil.IsTrue)
		c.Check(v, Equals, "foo")
	}
	{
		v, exists := ActivateConfigGet[io.Writer](ctx.Config(), StderrLoggerKey)
		c.Check(exists, testutil.IsTrue)
		c.Check(v, Equals, stderr)
	}
	{
		v, exists := ActivateConfigGet[uint](ctx.Config(), RecoveryKeyTriesKey)
		c.Check(exists, testutil.IsTrue)
		c.Check(v, Equals, uint(5))
	}

	c.Check(ctx.PrimaryKey(), HasLen, 0)
}

func (*activateSuite) TestNewActivateContextWithInvalidState1(c *C) {
	// Provide a state with a non-zero primary key ID when there are no activated containers.
	state := &ActivateState{
		PrimaryKeyID: 10,
	}

	_, err := NewActivateContext(context.Background(), state)
	c.Check(err, ErrorMatches, `invalid state: "primary-key-id" set with no activated containers`)
}

func (*activateSuite) TestNewActivateContextWithInvalidState2(c *C) {
	// Provide a state with a non-zero primary key ID when there are no containers activated
	// with a platform key.
	state := &ActivateState{
		PrimaryKeyID: 10,
		Activations: map[string]*ContainerActivateState{
			"sda1": {Status: ActivationSucceededWithRecoveryKey},
		},
	}

	_, err := NewActivateContext(context.Background(), state)
	c.Check(err, ErrorMatches, `invalid state: "primary-key-id" set with no containers activated with a platform keyslot`)
}

func (*activateSuite) TestNewActivateContextWithCanceledContext(c *C) {
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	state := &ActivateState{
		PrimaryKeyID: int32(id),
		Activations: map[string]*ContainerActivateState{
			"sda1": {Status: ActivationSucceededWithPlatformKey},
		},
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	cancelFunc()

	_, err = NewActivateContext(ctx, state)
	c.Check(err, ErrorMatches, `cannot obtain primary key from keyring: context canceled`)
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
}

func (*activateSuite) TestNewActivateContextWithInvalidPrimaryKeyID(c *C) {
	// Obtain a key ID that doesn't exist.
	var b [4]byte
	_, err := rand.Read(b[:])
	c.Assert(err, IsNil)
	invalidId := binary.BigEndian.Uint32(b[:])
	invalidId &= math.MaxInt32 // Only special IDs can be negative
	for {
		if invalidId&0x80000000 != 0 || invalidId == 0 {
			invalidId = 1
		}
		if _, err := keyring.GetKeyringID(keyring.KeyID(invalidId)); err == keyring.ErrKeyNotExist {
			break
		}
		invalidId += 1
	}

	state := &ActivateState{
		PrimaryKeyID: int32(invalidId),
		Activations: map[string]*ContainerActivateState{
			"sda1": {Status: ActivationSucceededWithPlatformKey},
		},
	}

	_, err = NewActivateContext(context.Background(), state)
	c.Check(err, ErrorMatches, `cannot obtain primary key from keyring: cannot complete operation because a specified key does not exist`)
	c.Check(errors.Is(err, keyring.ErrKeyNotExist), testutil.IsTrue)
}

type testActivateContextActivateContainerParams struct {
	initialState *ActivateState
	contextOpts  []ActivateContextOption

	authRequestor *mockAuthRequestor

	ctx       context.Context
	container *mockStorageContainer
	opts      []ActivateOption

	legacyV1KeyUnlock bool

	expectedStderr           string
	expectedTryKeys          [][]byte
	expectedAuthRequestName  string
	expectedAuthRequestPath  string
	expectedAuthRequestTypes []UserAuthType
	expectedActivateConfig   map[any]any
	expectedKeyringKeyPrefix string
	expectedPrimaryKey       PrimaryKey
	expectedUnlockKey        DiskUnlockKey
	expectedState            *ContainerActivateState
}

func (s *activateSuite) testActivateContextActivateContainer(c *C, params *testActivateContextActivateContainerParams) error {
	var primaryKeyId keyring.KeyID
	restore := MockAddKeyToUserKeyring(func(key []byte, container StorageContainer, purpose KeyringKeyPurpose, prefix string) (keyring.KeyID, error) {
		id, err := AddKeyToUserKeyring(key, container, purpose, prefix)
		if purpose == KeyringKeyPurposePrimary {
			primaryKeyId = id
		}
		return id, err
	})
	defer restore()

	stderr := new(strings.Builder)
	restore = MockStderr(stderr)
	defer restore()

	initialState := params.initialState
	if initialState == nil {
		initialState = &ActivateState{
			Activations: make(map[string]*ContainerActivateState),
		}
	}
	expectedState := initialState.Copy()
	if params.expectedState != nil {
		cs := params.expectedState.Copy()
		if cs.KeyslotErrors == nil {
			cs.KeyslotErrors = make(map[string]KeyslotErrorType)
		}
		expectedState.Activations[params.container.CredentialName()] = cs
	}

	activateCtx, err := NewActivateContext(context.Background(), params.initialState, params.contextOpts...)
	c.Assert(err, IsNil)

	ctx := params.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	err = activateCtx.ActivateContainer(ctx, params.container, params.opts...)
	c.Check(stderr.String(), Equals, params.expectedStderr)
	if err != nil {
		c.Check(params.container.isActivated(), testutil.IsFalse)
		c.Check(params.container.activateTryKeys(), DeepEquals, params.expectedTryKeys)

		_, keyringErr := GetKeyFromKernel(context.Background(), params.container, KeyringKeyPurposeUnlock, params.expectedKeyringKeyPrefix)
		c.Check(keyringErr, Equals, ErrKernelKeyNotFound)
		_, keyringErr = GetKeyFromKernel(context.Background(), params.container, KeyringKeyPurposePrimary, params.expectedKeyringKeyPrefix)
		c.Check(keyringErr, Equals, ErrKernelKeyNotFound)

		if params.expectedState == nil {
			expectedState.Activations[params.container.CredentialName()] = &ContainerActivateState{
				Status:        ActivationFailed,
				KeyslotErrors: make(map[string]KeyslotErrorType),
			}
		}
		c.Check(activateCtx.State(), DeepEquals, expectedState)

		return err
	}

	if params.authRequestor != nil {
		c.Assert(params.authRequestor.requests, HasLen, len(params.expectedAuthRequestTypes))
		for i, req := range params.authRequestor.requests {
			c.Check(req.name, Equals, params.expectedAuthRequestName)
			c.Check(req.path, Equals, params.expectedAuthRequestPath)
			c.Check(req.authTypes, Equals, params.expectedAuthRequestTypes[i])
		}
	}

	expectedCfg := params.expectedActivateConfig
	if expectedCfg == nil {
		expectedCfg = make(map[any]any)
	}

	key, cfg := params.container.activationParams(c)
	c.Check(key, DeepEquals, params.expectedUnlockKey)
	var tmpl interface{ Len() int }
	c.Assert(cfg, Implements, &tmpl)
	c.Check(cfg.(interface{ Len() int }).Len(), Equals, len(expectedCfg))
	for k, expectedVal := range expectedCfg {
		val, exists := cfg.Get(k)
		c.Check(exists, testutil.IsTrue, Commentf("key: %v", k))
		c.Check(val, DeepEquals, expectedVal, Commentf("key: %v", k))
	}

	expectedTryKeys := params.expectedTryKeys
	if len(expectedTryKeys) == 0 {
		expectedTryKeys = [][]byte{params.expectedUnlockKey}
	}
	c.Check(params.container.activateTryKeys(), DeepEquals, expectedTryKeys)

	k, err := GetKeyFromKernel(context.Background(), params.container, KeyringKeyPurposeUnlock, params.expectedKeyringKeyPrefix)
	c.Check(err, IsNil)
	c.Check(k, DeepEquals, []byte(params.expectedUnlockKey))

	k, err = GetKeyFromKernel(context.Background(), params.container, KeyringKeyPurposePrimary, params.expectedKeyringKeyPrefix)
	switch {
	case len(params.expectedPrimaryKey) == 0:
		c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
	default:
		c.Check(err, IsNil)
		c.Check(k, DeepEquals, []byte(params.expectedPrimaryKey))
	}

	if params.expectedState.Status == ActivationSucceededWithPlatformKey && expectedState.PrimaryKeyID == 0 && !params.legacyV1KeyUnlock {
		expectedState.PrimaryKeyID = int32(primaryKeyId)
	}
	c.Check(activateCtx.State(), DeepEquals, expectedState)

	return nil
}

func (s *activateSuite) TestActivateContainerAuthModeNone(c *C) {
	// Test a simple case with 2 keyslots with no user auth. The have
	// the same priority, so "default" will be ordered first.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithReadKeyslotError(c *C) {
	// Test the case where there are 2 keyslots but the 1 keyslot cannot be read.
	// The keyslot should be skipped and unlocking succeeds with the other keyslot.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
			withStorageContainerReaderOptions(
				withStorageContainerReaderReadKeyslotErr("default", errors.New("some error")),
			),
		),
		expectedStderr: `Error with keyslot "default": invalid key data: cannot read keyslot: some error
`,
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default-fallback",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithInvalidKeyData(c *C) {
	// Test the case where there are 2 keyslots but the 1 keyslot cannot be decoded.
	// The keyslot should be skipped and unlocking succeeds with the other keyslot.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	_, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, []byte("invalid key data")),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedStderr: `Error with keyslot "default": invalid key data: cannot decode keyslot metadata: cannot decode key data: invalid character 'i' looking for beginning of value
`,
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default-fallback",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModeNoneIgnoresRecoveryKey(c *C) {
	// Test a simple case with 2 keyslots with no user auth and 1 recovery key.
	// The unlocking path for keys with no user auth should run first and ignore
	// recovery keys.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
			withStorageContainerKeyslot("a-recovery-key", testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18"), KeyslotTypeRecovery, 0, nil),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModeNoneWithRecoverKeysErrorAndFallback(c *C) {
	// Test a case with 2 keyslots where the key for the 1st attempted keyslot cannot
	// be recovered. The 2 keyslots have the same priority, and so "default" is ordered
	// before "default-recover".
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "8517c4e1f9798772b7b68500e822cc211d7be1178a75c22bd5b9af5d711610cf"), "run")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	s.handler.permittedRoles = []string{"recover"}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedStderr: `Error with keyslot "default": cannot recover keys from keyslot: incompatible key data role params: permission denied
`,
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default-fallback",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorIncompatibleRoleParams,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModeNoneWithUnlockErrorAndFallback(c *C) {
	// Test a case with 2 keyslots where the key for the 1st attempted keyslot cannot
	// be used to unlock the storage container. The 2 keyslots have the same priority,
	// and so "default" is ordered before "default-recovery".
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "8517c4e1f9798772b7b68500e822cc211d7be1178a75c22bd5b9af5d711610cf"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", testutil.DecodeHexString(c, "1722a0532afcccae49eaf40e3e88b3978637de6218307a091ea33c4cb1c9f0f4"), KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedStderr: `Error with keyslot "default": invalid key data: cannot activate container with key recovered from keyslot metadata: invalid key
`,
		expectedTryKeys:    [][]byte{unlockKey1, unlockKey2},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default-fallback",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModeNoneWithContextOptions(c *C) {
	// Test a simple case with 2 keyslots with no user auth, making sure that
	// options supplied to NewActivateContext are passed through to
	// StorageContainer.Activate.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			withMockActivateContextOption1("foo", "value1"),
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 1, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedActivateConfig: map[any]any{
			mockActivateConfigKey1("foo"): "value1",
		},
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModeNoneWithOptions(c *C) {
	// Test a simple case with 2 keyslots with no user auth, making sure that
	// options supplied to ActivateContext.ActivateContainer are passed through to
	// StorageContainer.Activate, overriding any passed to NewActivateContext.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			withMockActivateContextOption1("foo", "value1"),
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 1, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			withMockActivateContextOption1("foo", "value2"),
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedActivateConfig: map[any]any{
			mockActivateConfigKey1("foo"): "value2",
		},
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModeNonePriority(c *C) {
	// Test that keyslots with no user auth honour the priority.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 1, kd2),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default-fallback",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerDifferentPrimaryKey(c *C) {
	// Test that a different primary key is reflected in what is added to the
	// keyring.
	primaryKey := testutil.DecodeHexString(c, "990e0742eaa152b5c2bcc3aaf94c9dae58df62a46c13ab569a3e7b4afebb7e1d")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerDifferentCredentialName(c *C) {
	// Test that a storage container with a different credential name is reflected in
	// what is added to the keyring.
	primaryKey := testutil.DecodeHexString(c, "990e0742eaa152b5c2bcc3aaf94c9dae58df62a46c13ab569a3e7b4afebb7e1d")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/nvme0n1p2"),
			withStorageContainerCredentialName("nvme0n1p2"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithKeyringDescriptionPrefix(c *C) {
	// Test that WithKeyringDescriptionPrefix is properly integrated.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithKeyringDescriptionPrefix("foo"),
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedActivateConfig: map[any]any{
			KeyringDescPrefixKey: "foo",
		},
		expectedKeyringKeyPrefix: "foo",
		expectedPrimaryKey:       primaryKey,
		expectedUnlockKey:        unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithLegacyKeyringKeyDescriptionPaths(c *C) {
	// Test that WithLegacyKeyringKeyDescriptionPaths is properly integrated.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	legacyPaths := []string{
		"/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32",
		"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340",
	}

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	for _, path := range legacyPaths {
		s.addFileInfo(path, &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithLegacyKeyringKeyDescriptionPaths(legacyPaths...),
		},
		expectedActivateConfig: map[any]any{
			LegacyKeyringKeyDescPathsKey: legacyPaths,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)

	for _, path := range legacyPaths {
		unlockKey, err := GetDiskUnlockKeyFromKernel("", path, false)
		c.Check(err, IsNil, Commentf("path: %s", path))
		c.Check(unlockKey, DeepEquals, DiskUnlockKey(unlockKey1), Commentf("path: %s", path))

		key, err := GetPrimaryKeyFromKernel("", path, false)
		c.Check(err, IsNil, Commentf("path: %s", path))
		c.Check(key, DeepEquals, PrimaryKey(primaryKey), Commentf("path: %s", path))
	}
}

func (s *activateSuite) TestActivateContainerWithLegacyKeyringKeyDescriptionPathsDifferentPath(c *C) {
	// Test the WithLegacyKeyringKeyDescriptionPaths integration with
	// a different storage container path.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	legacyPaths := []string{
		"/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32",
		"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340",
	}

	s.addFileInfo("/dev/nvme0n1p2", &unix.Stat_t{Rdev: unix.Mkdev(259, 2), Mode: unix.S_IFBLK})
	for _, path := range legacyPaths {
		s.addFileInfo(path, &unix.Stat_t{Rdev: unix.Mkdev(259, 2), Mode: unix.S_IFBLK})
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/nvme0n1p2"),
			withStorageContainerCredentialName("nvme0n1p2"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithLegacyKeyringKeyDescriptionPaths(legacyPaths...),
		},
		expectedActivateConfig: map[any]any{
			LegacyKeyringKeyDescPathsKey: legacyPaths,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)

	for _, path := range legacyPaths {
		unlockKey, err := GetDiskUnlockKeyFromKernel("", path, false)
		c.Check(err, IsNil, Commentf("path: %s", path))
		c.Check(unlockKey, DeepEquals, DiskUnlockKey(unlockKey1), Commentf("path: %s", path))

		key, err := GetPrimaryKeyFromKernel("", path, false)
		c.Check(err, IsNil, Commentf("path: %s", path))
		c.Check(key, DeepEquals, PrimaryKey(primaryKey), Commentf("path: %s", path))
	}
}

func (s *activateSuite) TestActivateContainerWithLegacyKeyringKeyDescriptionPathsWithDifferentPrimaryKey(c *C) {
	// Test that a different primary key is reflected in what is added to the
	// keyring with WithLegacyKeyringKeyDescriptionPaths.
	primaryKey := testutil.DecodeHexString(c, "990e0742eaa152b5c2bcc3aaf94c9dae58df62a46c13ab569a3e7b4afebb7e1d")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	legacyPaths := []string{
		"/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32",
		"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340",
	}

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	for _, path := range legacyPaths {
		s.addFileInfo(path, &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithLegacyKeyringKeyDescriptionPaths(legacyPaths...),
		},
		expectedActivateConfig: map[any]any{
			LegacyKeyringKeyDescPathsKey: legacyPaths,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)

	for _, path := range legacyPaths {
		unlockKey, err := GetDiskUnlockKeyFromKernel("", path, false)
		c.Check(err, IsNil, Commentf("path: %s", path))
		c.Check(unlockKey, DeepEquals, DiskUnlockKey(unlockKey1), Commentf("path: %s", path))

		key, err := GetPrimaryKeyFromKernel("", path, false)
		c.Check(err, IsNil, Commentf("path: %s", path))
		c.Check(key, DeepEquals, PrimaryKey(primaryKey), Commentf("path: %s", path))
	}
}

func (s *activateSuite) TestActivateContainerWithLegacyKeyringKeyDescriptionPathsAndWithKeyringDescriptionPrefix(c *C) {
	// Test that WithLegacyKeyringKeyDescriptionPaths is properly integrated
	// with WithKeyringDescriptionPrefix.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	legacyPaths := []string{
		"/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32",
		"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340",
	}

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	for _, path := range legacyPaths {
		s.addFileInfo(path, &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithKeyringDescriptionPrefix("foo"),
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithLegacyKeyringKeyDescriptionPaths(legacyPaths...),
		},
		expectedActivateConfig: map[any]any{
			KeyringDescPrefixKey:         "foo",
			LegacyKeyringKeyDescPathsKey: legacyPaths,
		},
		expectedKeyringKeyPrefix: "foo",
		expectedPrimaryKey:       primaryKey,
		expectedUnlockKey:        unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)

	for _, path := range legacyPaths {
		unlockKey, err := GetDiskUnlockKeyFromKernel("foo", path, false)
		c.Check(err, IsNil, Commentf("path: %s", path))
		c.Check(unlockKey, DeepEquals, DiskUnlockKey(unlockKey1), Commentf("path: %s", path))

		key, err := GetPrimaryKeyFromKernel("foo", path, false)
		c.Check(err, IsNil, Commentf("path: %s", path))
		c.Check(key, DeepEquals, PrimaryKey(primaryKey), Commentf("path: %s", path))
	}
}

func (s *activateSuite) TestActivateContainerWithLegacyKeyringKeyDescriptionPathsIgnoredNotExist(c *C) {
	// Test that WithLegacyKeyringKeyDescriptionPaths is ignored if the storage
	// container path does not exist.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	legacyPaths := []string{
		"/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32",
		"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340",
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithLegacyKeyringKeyDescriptionPaths(legacyPaths...),
		},
		expectedActivateConfig: map[any]any{
			LegacyKeyringKeyDescPathsKey: legacyPaths,
		},
		expectedStderr: `Ignoring WithLegacyKeyringDescriptionPaths because the container path does not refer to a filesystem object
`,
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)

	for _, path := range legacyPaths {
		_, err := GetDiskUnlockKeyFromKernel("", path, false)
		c.Check(err, Equals, ErrKernelKeyNotFound, Commentf("path: %s", path))
		_, err = GetPrimaryKeyFromKernel("", path, false)
		c.Check(err, Equals, ErrKernelKeyNotFound, Commentf("path: %s", path))
	}
}

func (s *activateSuite) TestActivateContainerWithLegacyKeyringKeyDescriptionPathsIgnoredNotBlockDevice(c *C) {
	// Test that WithLegacyKeyringKeyDescriptionPaths is ignored if the storage
	// container path does not point to a block device.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	legacyPaths := []string{
		"/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32",
		"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340",
	}

	s.addFileInfo("/data", &unix.Stat_t{})

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/data"),
			withStorageContainerCredentialName("data"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithLegacyKeyringKeyDescriptionPaths(legacyPaths...),
		},
		expectedStderr: `Ignoring WithLegacyKeyringDescriptionPaths because the container is not a block device
`,
		expectedActivateConfig: map[any]any{
			LegacyKeyringKeyDescPathsKey: legacyPaths,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)

	for _, path := range legacyPaths {
		_, err := GetDiskUnlockKeyFromKernel("", path, false)
		c.Check(err, Equals, ErrKernelKeyNotFound, Commentf("path: %s", path))
		_, err = GetPrimaryKeyFromKernel("", path, false)
		c.Check(err, Equals, ErrKernelKeyNotFound, Commentf("path: %s", path))
	}
}

func (s *activateSuite) TestActivateContainerWithLegacyKeyringKeyDescriptionPathsIgnoredPathNotExist(c *C) {
	// Test that WithLegacyKeyringKeyDescriptionPaths ignores paths that
	// do not exist.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	legacyPaths := []string{
		"/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32",
		"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340",
	}

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	s.addFileInfo("/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithLegacyKeyringKeyDescriptionPaths(legacyPaths...),
		},
		expectedStderr: `Ignoring WithLegacyKeyringDescriptionPaths path "/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340" which does not exist
`,
		expectedActivateConfig: map[any]any{
			LegacyKeyringKeyDescPathsKey: legacyPaths,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)

	unlockKey, err := GetDiskUnlockKeyFromKernel("", "/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32", false)
	c.Check(err, IsNil)
	c.Check(unlockKey, DeepEquals, DiskUnlockKey(unlockKey1))

	key, err := GetPrimaryKeyFromKernel("", "/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32", false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, PrimaryKey(primaryKey))

	_, err = GetDiskUnlockKeyFromKernel("", "/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340", false)
	c.Check(err, Equals, ErrKernelKeyNotFound)
	_, err = GetPrimaryKeyFromKernel("", "/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340", false)
	c.Check(err, Equals, ErrKernelKeyNotFound)
}

func (s *activateSuite) TestActivateContainerWithLegacyKeyringKeyDescriptionPathsIgnoredPathNotBlockDevice(c *C) {
	// Test that WithLegacyKeyringKeyDescriptionPaths ignores paths that
	// do not point to a block device.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	legacyPaths := []string{
		"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340",
		"/",
	}

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	s.addFileInfo("/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	s.addFileInfo("/", &unix.Stat_t{})

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithLegacyKeyringKeyDescriptionPaths(legacyPaths...),
		},
		expectedStderr: `Ignoring WithLegacyKeyringDescriptionPaths path "/" because it is not a block device
`,
		expectedActivateConfig: map[any]any{
			LegacyKeyringKeyDescPathsKey: legacyPaths,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)

	unlockKey, err := GetDiskUnlockKeyFromKernel("", "/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340", false)
	c.Check(err, IsNil)
	c.Check(unlockKey, DeepEquals, DiskUnlockKey(unlockKey1))

	key, err := GetPrimaryKeyFromKernel("", "/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340", false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, PrimaryKey(primaryKey))

	_, err = GetDiskUnlockKeyFromKernel("", "/", false)
	c.Check(err, Equals, ErrKernelKeyNotFound)
	_, err = GetPrimaryKeyFromKernel("", "/", false)
	c.Check(err, Equals, ErrKernelKeyNotFound)
}

func (s *activateSuite) TestActivateContainerWithLegacyKeyringKeyDescriptionPathsIgnoredPathDifferentBlockDevice(c *C) {
	// Test that WithLegacyKeyringKeyDescriptionPaths ignores paths that
	// point to a different block device.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	legacyPaths := []string{
		"/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32",
		"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340",
	}

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	s.addFileInfo("/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32", &unix.Stat_t{Rdev: unix.Mkdev(259, 2), Mode: unix.S_IFBLK})
	s.addFileInfo("/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithLegacyKeyringKeyDescriptionPaths(legacyPaths...),
		},
		expectedStderr: `Ignoring WithLegacyKeyringDescriptionPaths path "/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32" because it does not refer to the container block device
`,
		expectedActivateConfig: map[any]any{
			LegacyKeyringKeyDescPathsKey: legacyPaths,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)

	unlockKey, err := GetDiskUnlockKeyFromKernel("", "/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340", false)
	c.Check(err, IsNil)
	c.Check(unlockKey, DeepEquals, DiskUnlockKey(unlockKey1))

	key, err := GetPrimaryKeyFromKernel("", "/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340", false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, PrimaryKey(primaryKey))

	_, err = GetDiskUnlockKeyFromKernel("", "/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32", false)
	c.Check(err, Equals, ErrKernelKeyNotFound)
	_, err = GetPrimaryKeyFromKernel("", "/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32", false)
	c.Check(err, Equals, ErrKernelKeyNotFound)
}

func (s *activateSuite) TestActivateContainerRecoveryKeyFallback(c *C) {
	// Test a simple case with 2 platform keyslots with no user auth and a
	// recovery keyslot. Neither platform keyslot works, so unlocking
	// happens with the recovery key.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "8517c4e1f9798772b7b68500e822cc211d7be1178a75c22bd5b9af5d711610cf"), "run")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "c2a1d329cc15cd8b06c11c4ca57acf7448567a2e27241bd82ddfe6d7e8846cfa"), "run")

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	s.handler.permittedRoles = []string{"recover"}

	authRequestor := &mockAuthRequestor{
		responses: []any{makeRecoveryKey(c, recoveryKey)},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedStderr: `Error with keyslot "default": cannot recover keys from keyslot: incompatible key data role params: permission denied
Error with keyslot "default-fallback": cannot recover keys from keyslot: incompatible key data role params: permission denied
`,
		expectedAuthRequestName:  "data",
		expectedAuthRequestPath:  "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
			RecoveryKeyTriesKey:             uint(3),
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorIncompatibleRoleParams,
				"default-fallback": KeyslotErrorIncompatibleRoleParams,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerRecoveryKeyRetryAfterInvalidRecoveryKey(c *C) {
	// Test that unlocking with a recovery key works after first providing
	// an invalid recovery key.
	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			"foo",
			makeRecoveryKey(c, recoveryKey),
		},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedStderr: `Cannot parse recovery key: incorrectly formatted: insufficient characters
`,
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypeRecoveryKey,
			UserAuthTypeRecoveryKey,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
			RecoveryKeyTriesKey:             uint(3),
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerRecoveryKeyRetryAfterIncorrectRecoveryKey(c *C) {
	// Test that unlocking with a recovery key works after first providing
	// an incorrect recovery key.
	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")
	incorrectRecoveryKey := testutil.DecodeHexString(c, "c9654970edbf1c8005f4f0c38ab6b300")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			makeRecoveryKey(c, incorrectRecoveryKey),
			makeRecoveryKey(c, recoveryKey),
		},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedTryKeys:         [][]byte{incorrectRecoveryKey, recoveryKey},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypeRecoveryKey,
			UserAuthTypeRecoveryKey,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
			RecoveryKeyTriesKey:             uint(3),
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerRecoveryKeyWithRecoveryKeyTries(c *C) {
	// Test that WithRecoveryKeyTries is integrated properly.
	incorrectRecoveryKey := testutil.DecodeHexString(c, "c9654970edbf1c8005f4f0c38ab6b300")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			makeRecoveryKey(c, incorrectRecoveryKey),
			makeRecoveryKey(c, incorrectRecoveryKey),
			makeRecoveryKey(c, incorrectRecoveryKey),
		},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default-recovery", testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18"), KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedTryKeys:         [][]byte{incorrectRecoveryKey, incorrectRecoveryKey, incorrectRecoveryKey},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypeRecoveryKey,
			UserAuthTypeRecoveryKey,
			UserAuthTypeRecoveryKey,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
			RecoveryKeyTriesKey:             uint(3),
		},
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default-recovery": KeyslotErrorIncorrectUserAuth,
			},
			KeyslotErrorsOrder: []string{"default-recovery"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerRecoveryKeyWithDifferentRecoveryKeyTries(c *C) {
	// Test that WithRecoveryKeyTries is integrated properly.
	incorrectRecoveryKey := testutil.DecodeHexString(c, "c9654970edbf1c8005f4f0c38ab6b300")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			makeRecoveryKey(c, incorrectRecoveryKey),
			makeRecoveryKey(c, incorrectRecoveryKey),
		},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(2),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default-recovery", testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18"), KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedTryKeys:         [][]byte{incorrectRecoveryKey, incorrectRecoveryKey},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypeRecoveryKey,
			UserAuthTypeRecoveryKey,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
			RecoveryKeyTriesKey:             uint(2),
		},
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default-recovery": KeyslotErrorIncorrectUserAuth,
			},
			KeyslotErrorsOrder: []string{"default-recovery"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerRecoveryKeyWithNoRecoveryKeyTries(c *C) {
	// Test that we can't unlock with a recovery key if WithRecoveryKeyTries
	// is not supplied.
	authRequestor := &mockAuthRequestor{}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default-recovery", testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18"), KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypeRecoveryKey,
			UserAuthTypeRecoveryKey,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerRecoveryKeyFallbackWithWillCheckStorageContainerBinding(c *C) {
	// Test that the integration of WillCheckStorageContainerBinding doesn't
	// disable the recovery key fallback, as it does modify the state machine flags.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "8517c4e1f9798772b7b68500e822cc211d7be1178a75c22bd5b9af5d711610cf"), "run")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "c2a1d329cc15cd8b06c11c4ca57acf7448567a2e27241bd82ddfe6d7e8846cfa"), "run")

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	s.handler.permittedRoles = []string{"recover"}

	authRequestor := &mockAuthRequestor{
		responses: []any{makeRecoveryKey(c, recoveryKey)},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
			WillCheckStorageContainerBinding(),
		},
		expectedStderr: `Error with keyslot "default": cannot recover keys from keyslot: incompatible key data role params: permission denied
Error with keyslot "default-fallback": cannot recover keys from keyslot: incompatible key data role params: permission denied
`,
		expectedAuthRequestName:  "data",
		expectedAuthRequestPath:  "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                         authRequestor,
			AuthRequestorUserVisibleNameKey:          "data",
			RecoveryKeyTriesKey:                      uint(3),
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorIncompatibleRoleParams,
				"default-fallback": KeyslotErrorIncompatibleRoleParams,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, IsNil)
}
func (s *activateSuite) TestActivateContainerWithDifferentAuthRequestorUserVisibleName(c *C) {
	// Test that WithAuthRequestorUserVisibleName is integrated by supplying
	// it with a different name compared with other tests.
	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{
		responses: []any{makeRecoveryKey(c, recoveryKey)},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("foo"),
		},
		expectedAuthRequestName:  "foo",
		expectedAuthRequestPath:  "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "foo",
			RecoveryKeyTriesKey:             uint(3),
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithNoAuthRequestor(c *C) {
	// Test that we can't unlock with any method that requires user auth
	// if WithAuthRequestor is not supplied.
	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default-recovery", testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18"), KeyslotTypeRecovery, 0, nil),
		),
		expectedStderr: `Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerWithRequestUserCredentialError(c *C) {
	// Test that we get an appropriate error if AuthRequestor.RequestUserCredential
	// returns an error.
	authRequestor := &mockAuthRequestor{
		responses: []any{errors.New("some error")},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default-recovery", testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18"), KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("foo"),
		},
	})
	c.Check(err, ErrorMatches, `cannot complete state "try-with-user-auth-keyslots": cannot request user credential: some error`)
}

func (s *activateSuite) TestActivateContainerWithOpenReadError(c *C) {
	// Test that we get an appropriate error if StorageContainer.OpenRead
	// returns an error.
	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerOpenReadErr(errors.New("some error")),
		),
	})
	c.Check(err, ErrorMatches, `cannot complete state "init-keyslots-attemps": cannot open storage container for reading: some error`)
}

func (s *activateSuite) TestActivateContainerWithListKeyslotNamesError(c *C) {
	// Test that we get an appropriate error if StorageContainerReader.ListKeyslotNames
	// returns an error.
	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerReaderOptions(
				withStorageContainerReaderListKeyslotNamesErr(errors.New("some error")),
			),
		),
	})
	c.Check(err, ErrorMatches, `cannot complete state "init-keyslots-attemps": cannot list keyslot names from StorageContainer: some error`)
}

func (s *activateSuite) TestActivateContainerContext(c *C) {
	// Verify that the supplied context is used everywhere.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd, unlockKey := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")

	ctx := context.WithValue(context.Background(), "foo", "bar")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		ctx: ctx,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
			withStorageContainerExpectedContext(ctx),
			withStorageContainerReaderOptions(
				withStorageContainerReaderExpectedContext(ctx),
			),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithCanceledContext(c *C) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		ctx: ctx,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
		),
	})
	c.Check(err, ErrorMatches, `context canceled`)
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
}

func (s *activateSuite) TestActivateContainerWithExternalKeyData(c *C) {
	// Test that WithExternalKeyData is integrated properly.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd, unlockKey := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")

	external := []*ExternalKeyData{
		NewExternalKeyData("default", newMockKeyDataReader("", kd)),
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, nil),
		),
		opts: []ActivateOption{
			WithExternalKeyData(external...),
		},
		expectedStderr: `Error with keyslot "default": invalid key data: cannot decode keyslot metadata: cannot decode key data: EOF
`,
		expectedActivateConfig: map[any]any{
			ExternalKeyDataKey: external,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "external:default",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithExternalKeyDataMultiple(c *C) {
	// Test WithExternalKeyData with more than 1 key. The 2 external keys
	// have the same priority, and so "default" is ordered before
	// "default-recovery"
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	s.handler.permittedRoles = []string{"recover"}

	external := []*ExternalKeyData{
		NewExternalKeyData("default-fallback", newMockKeyDataReader("", kd2)),
		NewExternalKeyData("default", newMockKeyDataReader("", kd1)),
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, nil),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, nil),
		),
		opts: []ActivateOption{
			WithExternalKeyData(external...),
		},
		expectedStderr: `Error with keyslot "default": invalid key data: cannot decode keyslot metadata: cannot decode key data: EOF
Error with keyslot "default-fallback": invalid key data: cannot decode keyslot metadata: cannot decode key data: EOF
Error with keyslot "external:default": cannot recover keys from keyslot: incompatible key data role params: permission denied
`,
		expectedActivateConfig: map[any]any{
			ExternalKeyDataKey: external,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "external:default-fallback",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorInvalidKeyData,
				"default-fallback": KeyslotErrorInvalidKeyData,
				"external:default": KeyslotErrorIncompatibleRoleParams,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback", "external:default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithExternalKeyDataPriority1(c *C) {
	// Test that keys provided via WithExternalKeyData have a higher priority
	// than 0.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	external := []*ExternalKeyData{
		NewExternalKeyData("default-fallback", newMockKeyDataReader("", kd2)),
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, nil),
		),
		opts: []ActivateOption{
			WithExternalKeyData(external...),
		},
		expectedStderr: `Error with keyslot "default-fallback": invalid key data: cannot decode keyslot metadata: cannot decode key data: EOF
`,
		expectedActivateConfig: map[any]any{
			ExternalKeyDataKey: external,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "external:default-fallback",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default-fallback": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"default-fallback"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithExternalKeyDataPriority2(c *C) {
	// Test that native keys can be prioritised ahead of keys added with
	// WithExternalKeyData.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	external := []*ExternalKeyData{
		NewExternalKeyData("default", newMockKeyDataReader("", kd1)),
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, nil),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 101, kd2),
		),
		opts: []ActivateOption{
			WithExternalKeyData(external...),
		},
		expectedStderr: `Error with keyslot "default": invalid key data: cannot decode keyslot metadata: cannot decode key data: EOF
`,
		expectedActivateConfig: map[any]any{
			ExternalKeyDataKey: external,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default-fallback",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithInvalidExternalKeyData(c *C) {
	// Test that supplying invalid key data to WithExternalKeyData is
	// handled correctly.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd, unlockKey := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")

	external := []*ExternalKeyData{
		NewExternalKeyData("default", newMockKeyDataReader("", []byte("invalid key data"))),
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		opts: []ActivateOption{
			WithExternalKeyData(external...),
		},
		expectedStderr: `Error with keyslot "external:default": invalid key data: cannot decode key data: invalid character 'i' looking for beginning of value
`,
		expectedActivateConfig: map[any]any{
			ExternalKeyDataKey: external,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
			KeyslotErrors: map[string]KeyslotErrorType{
				"external:default": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"external:default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithV1KeyData(c *C) {
	// Test that it's possible to unlock the first storage container with
	// a legacy v1 key.
	primaryKey := testutil.DecodeHexString(c, "b410288b4d466cbeb08b490e5a1728dad0282b27c15f1f4828cac62e88fb7ff5")
	unlockKey := testutil.DecodeHexString(c, "d765126a3f3ff1cde33445d9eb178ac6302deb813d023020e3a56abf60398dd1")

	kd := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"0GCaTfIgLy9dCqqcfOTjMs9CXm4rPQUnvJNmPKhnIes=",` +
			`"iv":"jRuLy2H7lDV2tyMd8t5L6g==",` +
			`"auth-key-hmac":"6b9WLMjXPvtVSyUZ2/Cwu8ksvZla1nyqtBPK3jL4q7I=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"DqgmsMD4d2NMqQ9ugLBTLRZW+ZCOkjgR6rRyIAXOb2Rdd0wA21SN09N9Nmkt5fzNou34P6OVTEu8wQd+nToGzQk8Tlc=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"qX+OkuhbLRAmB3BvgSQR7U0qUMJguOQqPG/V8aMarqk=",` +
			`"digest":"PrtdZnxX2aE0rCxgn/vmHSUKWS4Cr2P+B7Hj70W1D7w="},` +
			`"hmacs":["6PbEHuaRXkghoQlYYRZbj4PWcq2XfL/qXuPzTfxKjDE=",` +
			`"JVhzcAvNFHYQYgPM82TVVtIsuTBbxjBs8wCb1yDY5mA="]}}
	`)

	bootscope.SetModel(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"))

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		legacyV1KeyUnlock:  true,
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithV1KeyDataWrongModel(c *C) {
	// Test that unlocking with a v1 key fails if it is not authorized
	// for the current boot model.
	unlockKey := testutil.DecodeHexString(c, "f7fa464710317654f14f22ab6eff4c88f13a77d78045f2a882e47c62286093b2")

	kd := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"fGSmc6pljAph4q00AKuniTSl19yZSHOO5ClFBnm3mEg=",` +
			`"iv":"GanDRGxWSx4stoOC8ueRaQ==",` +
			`"auth-key-hmac":"NPjHH7EG+guHv7ZUl5tetrD7268e6+kx4TIiOUzC2ks=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"kDm5zMabUoz83oLJMhmjWMmFexRSPJi0+yYgyGlp6l9hr20e4NZCzyiIchrHRXjS/ipVLy42H2pPm0fdTF3YXnYuKnk=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"7G4XkozL+sVJ2+vcp0zof6m3M6XRNSooHdV07GFmG74=",` +
			`"digest":"bCda3tRyxm9yobtWLPflFzdpXOWoSyBkLjAI4Ni/+pE="},` +
			`"hmacs":null}}
`)

	bootscope.SetModel(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"))

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		expectedStderr: `Error with keyslot "default": incompatible key data role params: snap model is not authorized
Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorIncompatibleRoleParams,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerWithV1KeyDataNoBootModelSet(c *C) {
	// Test that unlocking with a v1 key fails if the boot model is not set.
	unlockKey := testutil.DecodeHexString(c, "d765126a3f3ff1cde33445d9eb178ac6302deb813d023020e3a56abf60398dd1")

	kd := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"0GCaTfIgLy9dCqqcfOTjMs9CXm4rPQUnvJNmPKhnIes=",` +
			`"iv":"jRuLy2H7lDV2tyMd8t5L6g==",` +
			`"auth-key-hmac":"6b9WLMjXPvtVSyUZ2/Cwu8ksvZla1nyqtBPK3jL4q7I=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"DqgmsMD4d2NMqQ9ugLBTLRZW+ZCOkjgR6rRyIAXOb2Rdd0wA21SN09N9Nmkt5fzNou34P6OVTEu8wQd+nToGzQk8Tlc=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"qX+OkuhbLRAmB3BvgSQR7U0qUMJguOQqPG/V8aMarqk=",` +
			`"digest":"PrtdZnxX2aE0rCxgn/vmHSUKWS4Cr2P+B7Hj70W1D7w="},` +
			`"hmacs":["6PbEHuaRXkghoQlYYRZbj4PWcq2XfL/qXuPzTfxKjDE=",` +
			`"JVhzcAvNFHYQYgPM82TVVtIsuTBbxjBs8wCb1yDY5mA="]}}
	`)

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		expectedStderr: `Error with keyslot "default": encountered generation 1 key but bootscope.SetModel has not been called
Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorUnknown,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyProtectedByStorageContainerAfterOneRecoveryKey(c *C) {
	// Test the case where we attempt to unlock a container after the first
	// one was unlocked using a recovery key. In this case, we don't permit
	// platform keyslots protected by platforms that aren't registered with
	// the PlatformProtectedByStorageContainer flag.
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock2", handler2, PlatformProtectedByStorageContainer)
	defer RegisterPlatformKeyDataHandler("mock2", nil, 0)

	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "50ad62d4630bd3ca269e1a566b75b0f4929ef236c2534209d027a2f7d67fb58e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "2cb73011100e11a939141760898b5cda790678fb1cc4e6bad47035c3d1917246"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 1, kd2), // Higher priority so that it would be used if not rejected
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithRecoveryKeyAfterOneRecoveryKey(c *C) {
	// Test the case where we attempt to unlock a container after the first
	// one was unlocked using a recovery key. In this case, we don't permit
	// platform keyslots protected by platforms that aren't registered with
	// the PlatformProtectedByStorageContainer flag, so this should fall back
	// to requiring a recovery key.
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock2", handler2, PlatformProtectedByStorageContainer)
	defer RegisterPlatformKeyDataHandler("mock2", nil, 0)

	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "50ad62d4630bd3ca269e1a566b75b0f4929ef236c2534209d027a2f7d67fb58e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "2cb73011100e11a939141760898b5cda790678fb1cc4e6bad47035c3d1917246"), "recover")

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{
		responses: []any{makeRecoveryKey(c, recoveryKey)},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
			},
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", nil, KeyslotTypePlatform, 0, kd1), // Configured to fail unlocking
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("save"),
		},
		expectedStderr: `Error with keyslot "default": invalid key data: cannot activate container with key recovered from keyslot metadata: invalid key
`,
		expectedTryKeys:          [][]byte{unlockKey1, recoveryKey},
		expectedAuthRequestName:  "save",
		expectedAuthRequestPath:  "/dev/sda2",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			RecoveryKeyTriesKey:             uint(3),
			AuthRequestorUserVisibleNameKey: "save",
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerNoSuitableKeyslotsAfterOneRecoveryKey(c *C) {
	// Test the case where we attempt to unlock a container after the first
	// one was unlocked using a recovery key. In this case, we don't permit
	// platform keyslots protected by platforms that aren't registered with
	// the PlatformProtectedByStorageContainer flag, so this should fail
	// because there are no suitable keyslots.
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock2", handler2, PlatformProtectedByStorageContainer)
	defer RegisterPlatformKeyDataHandler("mock2", nil, 0)

	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "50ad62d4630bd3ca269e1a566b75b0f4929ef236c2534209d027a2f7d67fb58e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "2cb73011100e11a939141760898b5cda790678fb1cc4e6bad47035c3d1917246"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", nil, KeyslotTypePlatform, 0, kd1), // Configured to fail unlocking
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedStderr: `Error with keyslot "default": invalid key data: cannot activate container with key recovered from keyslot metadata: invalid key
Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
		expectedTryKeys: [][]byte{unlockKey1},
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerNoSuitableKeyslotsBecauseNoSuitablePlatformRegisteredAfterOneRecoveryKey(c *C) {
	// Test the case where we attempt to unlock a container after the first
	// one was unlocked using a recovery key. In this case, we don't permit
	// platform keyslots protected by platforms that aren't registered with
	// the PlatformProtectedByStorageContainer flag, so this should fail
	// because there are no suitable keyslots.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "50ad62d4630bd3ca269e1a566b75b0f4929ef236c2534209d027a2f7d67fb58e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "2cb73011100e11a939141760898b5cda790678fb1cc4e6bad47035c3d1917246"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedStderr: `Error with keyslot "default": no appropriate platform handler is registered
Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorUnknown,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerWithRecoveryKeyAfterOneRecoveryKeyWithWillCheckStorageContainerBinding(c *C) {
	// Test that the integration of WillCheckStorageContainerBinding doesn't
	// disable the recovery key fallback, as it does modify the state machine
	// flags.
	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{
		responses: []any{makeRecoveryKey(c, recoveryKey)},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
			},
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("save"),
			WillCheckStorageContainerBinding(),
		},
		expectedAuthRequestName:  "save",
		expectedAuthRequestPath:  "/dev/sda2",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                         authRequestor,
			RecoveryKeyTriesKey:                      uint(3),
			AuthRequestorUserVisibleNameKey:          "save",
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithV1PlatformKeyAfterOneRecoveryKeyUsedWillCheckStorageContainerBinding(c *C) {
	// Test the integration of WillCheckStorageContainerBinding. Unlocking with
	// a v1 key should succeed even if the previous container was unlocked with a
	// recovery key. In this case, the caller must verify that the storage
	// containers are properly bound.
	primaryKey := testutil.DecodeHexString(c, "b410288b4d466cbeb08b490e5a1728dad0282b27c15f1f4828cac62e88fb7ff5")
	unlockKey := testutil.DecodeHexString(c, "d765126a3f3ff1cde33445d9eb178ac6302deb813d023020e3a56abf60398dd1")
	kd := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"0GCaTfIgLy9dCqqcfOTjMs9CXm4rPQUnvJNmPKhnIes=",` +
			`"iv":"jRuLy2H7lDV2tyMd8t5L6g==",` +
			`"auth-key-hmac":"6b9WLMjXPvtVSyUZ2/Cwu8ksvZla1nyqtBPK3jL4q7I=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"DqgmsMD4d2NMqQ9ugLBTLRZW+ZCOkjgR6rRyIAXOb2Rdd0wA21SN09N9Nmkt5fzNou34P6OVTEu8wQd+nToGzQk8Tlc=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"qX+OkuhbLRAmB3BvgSQR7U0qUMJguOQqPG/V8aMarqk=",` +
			`"digest":"PrtdZnxX2aE0rCxgn/vmHSUKWS4Cr2P+B7Hj70W1D7w="},` +
			`"hmacs":["6PbEHuaRXkghoQlYYRZbj4PWcq2XfL/qXuPzTfxKjDE=",` +
			`"JVhzcAvNFHYQYgPM82TVVtIsuTBbxjBs8wCb1yDY5mA="]}}
	`)

	bootscope.SetModel(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"))

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		opts: []ActivateOption{
			WillCheckStorageContainerBinding(),
		},
		legacyV1KeyUnlock: true,
		expectedActivateConfig: map[any]any{
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyProtectedByStorageContainerAfterPlatformKeyUsed(c *C) {
	// Test the case where we attempt to unlock a container after the first one
	// was unlocked with a platform key. In this case, unlocking with a platform
	// key protected with a platform registered with the PlatformProtectedByStorageContainer
	// flag works fine.
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock2", handler2, PlatformProtectedByStorageContainer)
	defer RegisterPlatformKeyDataHandler("mock2", nil, 0)

	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyAfterPlatformKeyUsed(c *C) {
	// Test the case where we attempt to unlock a container after the first one
	// was unlocked with a platform key. In this case, unlocking with a platform
	// key protected with a platform that is not registered with the
	// PlatformProtectedByStorageContainer flag works fine.
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock2", handler2, PlatformProtectedByStorageContainer)
	defer RegisterPlatformKeyDataHandler("mock2", nil, 0)

	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 1, kd2),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default-fallback",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithNoSuitableKeyslotsAfterPlatformKeyUsed(c *C) {
	// Test the case where we attempt to unlock a container after the first one
	// was unlocked with a platform key. In this case, both platform keys fail
	// and we can't fall back to using the recover key because it is not permitted.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{}

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),   // Configured to fail
			withStorageContainerKeyslot("default-fallback", nil, KeyslotTypePlatform, 0, kd2), // Configured to fail
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("save"),
		},
		expectedStderr: `Error with keyslot "default": no appropriate platform handler is registered
Error with keyslot "default-fallback": invalid key data: cannot activate container with key recovered from keyslot metadata: invalid key
`,
		expectedTryKeys: [][]byte{unlockKey2},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			RecoveryKeyTriesKey:             uint(3),
			AuthRequestorUserVisibleNameKey: "save",
		},
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorUnknown,
				"default-fallback": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerPrimaryKeyCrosscheckFailAuthModeNoneAfterPlatformKeyUsed(c *C) {
	// Test the case where we attempt to unlock a container after the first one
	// was unlocked with a platform key. Unlocking fails because the keyslot
	// has a different primary key compared with the first container.
	primaryKey1 := testutil.DecodeHexString(c, "990e0742eaa152b5c2bcc3aaf94c9dae58df62a46c13ab569a3e7b4afebb7e1d")

	id, err := AddKeyToUserKeyring(primaryKey1, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	primaryKey2 := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey2, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey2, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1), // Configured to fail.
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedStderr: `Error with keyslot "default": no appropriate platform handler is registered
Error with keyslot "default-fallback": invalid key data: invalid primary key
Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorUnknown,
				"default-fallback": KeyslotErrorInvalidPrimaryKey,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerPrimaryKeyProtectedByStorageContainerNoPrimaryKeyCrosscheckAfterPlatformKeyUsed(c *C) {
	// Test the case where we attempt to unlock a container after the first one
	// was unlocked with a platform key. Unlocking succeeds with a key protected by
	// a platform registered with the PlatformProtectedByStorageContainer despite the
	// primary key being different, because the primary key does not need to be
	// checked in this case.
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock2", handler2, PlatformProtectedByStorageContainer)
	defer RegisterPlatformKeyDataHandler("mock2", nil, 0)

	primaryKey1 := testutil.DecodeHexString(c, "990e0742eaa152b5c2bcc3aaf94c9dae58df62a46c13ab569a3e7b4afebb7e1d")

	id, err := AddKeyToUserKeyring(primaryKey1, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	primaryKey2 := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey2, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey1, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedPrimaryKey: primaryKey2,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyProtectedByStorageContainerAfterV1PlatformKeyUsed(c *C) {
	// Test that it's possible to unlock a container with a platform key protected by
	// a platform that's registered with the PlatformProtectedByStorageContainer flag
	// after the previous container was unlocked with a v1 platform key.
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock2", handler2, PlatformProtectedByStorageContainer)
	defer RegisterPlatformKeyDataHandler("mock2", nil, 0)

	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd := s.makeKeyDataBlobFromParams(c, params)

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyAfterV1PlatformKeyUsedWillCheckStorageContainerBinding(c *C) {
	// Test the integration of WillCheckStorageContainerBinding. Unlocking with
	// a new platform key should succeed even if the previous container was unlocked
	// with a v1 platform key. In this case, no primary key cross-check is performed
	// and the caller must verify that the storage containers are properly bound.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd, unlockKey := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		opts: []ActivateOption{
			WillCheckStorageContainerBinding(),
		},
		expectedActivateConfig: map[any]any{
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyFailsAfterV1PlatformKeyUsed(c *C) {
	// Test that unlocking with a new platform key fails if the previous storage container
	// was unlocked with a v1 platform key. This is because it's not possible to cross-check
	// the primary keys, as they have different properties.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	kd, unlockKey := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		expectedStderr: `Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerWithV1PlatformKeyAfterPlatformKeyUsedWillCheckStorageContainerBinding(c *C) {
	// Test the integration of WillCheckStorageContainerBinding. Unlocking with
	// a v1 key should succeed even if the previous container was unlocked with a
	// new key. In this case, no primary key cross-check is performed and the caller
	// must verify that the storage containers are properly bound.
	primaryKey1 := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey1, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	primaryKey2 := testutil.DecodeHexString(c, "b410288b4d466cbeb08b490e5a1728dad0282b27c15f1f4828cac62e88fb7ff5")
	unlockKey := testutil.DecodeHexString(c, "d765126a3f3ff1cde33445d9eb178ac6302deb813d023020e3a56abf60398dd1")
	kd := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"0GCaTfIgLy9dCqqcfOTjMs9CXm4rPQUnvJNmPKhnIes=",` +
			`"iv":"jRuLy2H7lDV2tyMd8t5L6g==",` +
			`"auth-key-hmac":"6b9WLMjXPvtVSyUZ2/Cwu8ksvZla1nyqtBPK3jL4q7I=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"DqgmsMD4d2NMqQ9ugLBTLRZW+ZCOkjgR6rRyIAXOb2Rdd0wA21SN09N9Nmkt5fzNou34P6OVTEu8wQd+nToGzQk8Tlc=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"qX+OkuhbLRAmB3BvgSQR7U0qUMJguOQqPG/V8aMarqk=",` +
			`"digest":"PrtdZnxX2aE0rCxgn/vmHSUKWS4Cr2P+B7Hj70W1D7w="},` +
			`"hmacs":["6PbEHuaRXkghoQlYYRZbj4PWcq2XfL/qXuPzTfxKjDE=",` +
			`"JVhzcAvNFHYQYgPM82TVVtIsuTBbxjBs8wCb1yDY5mA="]}}
	`)

	bootscope.SetModel(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"))

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		opts: []ActivateOption{
			WillCheckStorageContainerBinding(),
		},
		legacyV1KeyUnlock: true,
		expectedActivateConfig: map[any]any{
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedPrimaryKey: primaryKey2,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithV1PlatformKeyAfterV1PlatformKeyUsedWillCheckStorageContainerBinding(c *C) {
	// Test the integration of WillCheckStorageContainerBinding. Unlocking with
	// a v1 key should succeed if the previous container was also unlocked with a
	// v1 key. In this case, no primary key cross-check is performed and the caller
	// must verify that the storage containers are properly bound.
	primaryKey := testutil.DecodeHexString(c, "b410288b4d466cbeb08b490e5a1728dad0282b27c15f1f4828cac62e88fb7ff5")
	unlockKey := testutil.DecodeHexString(c, "d765126a3f3ff1cde33445d9eb178ac6302deb813d023020e3a56abf60398dd1")
	kd := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"0GCaTfIgLy9dCqqcfOTjMs9CXm4rPQUnvJNmPKhnIes=",` +
			`"iv":"jRuLy2H7lDV2tyMd8t5L6g==",` +
			`"auth-key-hmac":"6b9WLMjXPvtVSyUZ2/Cwu8ksvZla1nyqtBPK3jL4q7I=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"DqgmsMD4d2NMqQ9ugLBTLRZW+ZCOkjgR6rRyIAXOb2Rdd0wA21SN09N9Nmkt5fzNou34P6OVTEu8wQd+nToGzQk8Tlc=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"qX+OkuhbLRAmB3BvgSQR7U0qUMJguOQqPG/V8aMarqk=",` +
			`"digest":"PrtdZnxX2aE0rCxgn/vmHSUKWS4Cr2P+B7Hj70W1D7w="},` +
			`"hmacs":["6PbEHuaRXkghoQlYYRZbj4PWcq2XfL/qXuPzTfxKjDE=",` +
			`"JVhzcAvNFHYQYgPM82TVVtIsuTBbxjBs8wCb1yDY5mA="]}}
	`)

	bootscope.SetModel(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"))

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		opts: []ActivateOption{
			WillCheckStorageContainerBinding(),
		},
		legacyV1KeyUnlock: true,
		expectedActivateConfig: map[any]any{
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithV1PlatformKeyFailsAfterPlatformKeyUsed(c *C) {
	// Test that unlocking with a v1 key fails after the previous storage container
	// was unlocked with a new key. This is because it's not possible to cross-check
	// the primary keys, as they have different properties.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	unlockKey := testutil.DecodeHexString(c, "d765126a3f3ff1cde33445d9eb178ac6302deb813d023020e3a56abf60398dd1")
	kd := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"0GCaTfIgLy9dCqqcfOTjMs9CXm4rPQUnvJNmPKhnIes=",` +
			`"iv":"jRuLy2H7lDV2tyMd8t5L6g==",` +
			`"auth-key-hmac":"6b9WLMjXPvtVSyUZ2/Cwu8ksvZla1nyqtBPK3jL4q7I=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"DqgmsMD4d2NMqQ9ugLBTLRZW+ZCOkjgR6rRyIAXOb2Rdd0wA21SN09N9Nmkt5fzNou34P6OVTEu8wQd+nToGzQk8Tlc=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"qX+OkuhbLRAmB3BvgSQR7U0qUMJguOQqPG/V8aMarqk=",` +
			`"digest":"PrtdZnxX2aE0rCxgn/vmHSUKWS4Cr2P+B7Hj70W1D7w="},` +
			`"hmacs":["6PbEHuaRXkghoQlYYRZbj4PWcq2XfL/qXuPzTfxKjDE=",` +
			`"JVhzcAvNFHYQYgPM82TVVtIsuTBbxjBs8wCb1yDY5mA="]}}
	`)

	bootscope.SetModel(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"))

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		expectedStderr: `Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerWithNoSuitableKeyslotsAfterPlatformKeyUsedWithWillCheckStorageContainerBinding(c *C) {
	// Test that the integration of WillCheckStorageContainerBinding doesn't
	// enable the recovery key fallback, as it does modify the state machine
	// flags.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{}

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("save"),
			WillCheckStorageContainerBinding(),
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                         authRequestor,
			RecoveryKeyTriesKey:                      uint(3),
			AuthRequestorUserVisibleNameKey:          "save",
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyAfterPlatformAndRecoveryKeyUsed(c *C) {
	// Test the case where we attempt to unlock a container after the first containers
	// were unlocked with a mix of platform and recovery keys. In this case, unlocking
	// with a normal platform key should work fine.
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock2", handler2, PlatformProtectedByStorageContainer)
	defer RegisterPlatformKeyDataHandler("mock2", nil, 0)

	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 1, kd2),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default-fallback",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyProtectedByStorageContainerAfterPlatformAndRecoveryKeyUsed(c *C) {
	// Test the case where we attempt to unlock a container after the first containers
	// were unlocked with a mix of platform and recovery keys. In this case, unlocking
	// with a platform key protected by a platform that's registered with the
	// PlatformProtectedByStorageContainer flag should work fine.
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock2", handler2, PlatformProtectedByStorageContainer)
	defer RegisterPlatformKeyDataHandler("mock2", nil, 0)

	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithRecoveryKeyAfterPlatformAndRecoveryKeyUsed(c *C) {
	// Test the case where we attempt to unlock a container after the first containers
	// were unlocked with a mix of platform and recovery keys. In this case, unlocking
	// with a recovery key should work fine.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{
		responses: []any{makeRecoveryKey(c, recoveryKey)},
	}

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),   // Configured to fail.
			withStorageContainerKeyslot("default-fallback", nil, KeyslotTypePlatform, 0, kd2), // Configured to fail.
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("foo"),
		},
		expectedStderr: `Error with keyslot "default": no appropriate platform handler is registered
Error with keyslot "default-fallback": invalid key data: cannot activate container with key recovered from keyslot metadata: invalid key
`,
		expectedTryKeys:          [][]byte{unlockKey2, recoveryKey},
		expectedAuthRequestName:  "foo",
		expectedAuthRequestPath:  "/dev/sda3",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			RecoveryKeyTriesKey:             uint(3),
			AuthRequestorUserVisibleNameKey: "foo",
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorUnknown,
				"default-fallback": KeyslotErrorInvalidKeyData,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerPrimaryKeyCrosscheckFailAfterPlatformKeyAndRecoveryKeyUsed(c *C) {
	// Test the case where we attempt to unlock a container after the first containers
	// were unlocked with a mix of platform and recovery keys. In this case, unlocking
	// fails because the keyslot has a different primary key compared with one
	// used previously.
	primaryKey1 := testutil.DecodeHexString(c, "990e0742eaa152b5c2bcc3aaf94c9dae58df62a46c13ab569a3e7b4afebb7e1d")

	id, err := AddKeyToUserKeyring(primaryKey1, newMockStorageContainer(withStorageContainerCredentialName("sda2")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	primaryKey2 := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey1 := s.mockProtectKeys(c, primaryKey2, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd1 := s.makeKeyDataBlobFromParams(c, params)

	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey2, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1), // Configured to fail.
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		expectedStderr: `Error with keyslot "default": no appropriate platform handler is registered
Error with keyslot "default-fallback": invalid key data: invalid primary key
Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorUnknown,
				"default-fallback": KeyslotErrorInvalidPrimaryKey,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyProtectedByStorageContainerAfterV1PlatformKeyAndRecoveryKeyUsed(c *C) {
	// Test that it's possible to unlock a container with a platform key protected by
	// a platform that's registered with the PlatformProtectedByStorageContainer flag
	// after the previous containers were unlocked with a mix of v1 platform keys
	// and recovery keys.
	handler2 := new(mockPlatformKeyDataHandler)
	RegisterPlatformKeyDataHandler("mock2", handler2, PlatformProtectedByStorageContainer)
	defer RegisterPlatformKeyDataHandler("mock2", nil, 0)

	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	// XXX: This is a bit of a hack for now. I think that keyDataTestBase and
	// mockPlatformKeyDataHandler need a bit of a rethink.
	params, unlockKey := s.mockProtectKeys(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "", crypto.SHA256)
	params.PlatformName = "mock2"
	kd := s.makeKeyDataBlobFromParams(c, params)

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyAfterV1PlatformKeyAndRecoveryKeyUsedWillCheckStorageContainerBinding(c *C) {
	// Test the integration of WillCheckStorageContainerBinding. Unlocking with
	// a new platform key should succeed even if the previous containers were unlocked
	// with a mix of v1 platform keys and recovery keys. In this case, no primary key
	// cross-check is performed and the caller must verify that the storage containers
	// are properly bound.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd, unlockKey := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		opts: []ActivateOption{
			WillCheckStorageContainerBinding(),
		},
		expectedActivateConfig: map[any]any{
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithPlatformKeyFailsAfterV1PlatformKeyAndRecoveryKeyUsed(c *C) {
	// Test that unlocking with a new platform key fails if the previous storage containers
	// were unlocked with a mix of v1 platform keys and recovery keys. This is because it's
	// not possible to cross-check the primary keys, as they have different properties.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	kd, unlockKey := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		expectedStderr: `Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerWithV1PlatformKeyAfterPlatformKeyAndRecoveryKeyUsedWillCheckStorageContainerBinding(c *C) {
	// Test the integration of WillCheckStorageContainerBinding. Unlocking with
	// a v1 key should succeed even if the previous containers were unlocked with a
	// mix of new platform keys and recovery keys. In this case, no primary key
	// cross-check is performed and the caller must verify that the storage
	// containers are properly bound.
	primaryKey1 := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey1, newMockStorageContainer(withStorageContainerCredentialName("sda2")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	primaryKey2 := testutil.DecodeHexString(c, "b410288b4d466cbeb08b490e5a1728dad0282b27c15f1f4828cac62e88fb7ff5")
	unlockKey := testutil.DecodeHexString(c, "d765126a3f3ff1cde33445d9eb178ac6302deb813d023020e3a56abf60398dd1")
	kd := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"0GCaTfIgLy9dCqqcfOTjMs9CXm4rPQUnvJNmPKhnIes=",` +
			`"iv":"jRuLy2H7lDV2tyMd8t5L6g==",` +
			`"auth-key-hmac":"6b9WLMjXPvtVSyUZ2/Cwu8ksvZla1nyqtBPK3jL4q7I=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"DqgmsMD4d2NMqQ9ugLBTLRZW+ZCOkjgR6rRyIAXOb2Rdd0wA21SN09N9Nmkt5fzNou34P6OVTEu8wQd+nToGzQk8Tlc=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"qX+OkuhbLRAmB3BvgSQR7U0qUMJguOQqPG/V8aMarqk=",` +
			`"digest":"PrtdZnxX2aE0rCxgn/vmHSUKWS4Cr2P+B7Hj70W1D7w="},` +
			`"hmacs":["6PbEHuaRXkghoQlYYRZbj4PWcq2XfL/qXuPzTfxKjDE=",` +
			`"JVhzcAvNFHYQYgPM82TVVtIsuTBbxjBs8wCb1yDY5mA="]}}
	`)

	bootscope.SetModel(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"))

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		opts: []ActivateOption{
			WillCheckStorageContainerBinding(),
		},
		legacyV1KeyUnlock: true,
		expectedActivateConfig: map[any]any{
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedPrimaryKey: primaryKey2,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithV1PlatformKeyAfterV1PlatformKeyAndRecoveryKeyUsedWillCheckStorageContainerBinding(c *C) {
	// Test the integration of WillCheckStorageContainerBinding. Unlocking with
	// a v1 key should succeed if the previous containers were unlocked with a mix
	// of v1 platform keys and recovery keys. In this case, no primary key cross-check
	// is performed and the caller must verify that the storage containers are properly
	// bound.
	primaryKey := testutil.DecodeHexString(c, "b410288b4d466cbeb08b490e5a1728dad0282b27c15f1f4828cac62e88fb7ff5")
	unlockKey := testutil.DecodeHexString(c, "d765126a3f3ff1cde33445d9eb178ac6302deb813d023020e3a56abf60398dd1")
	kd := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"0GCaTfIgLy9dCqqcfOTjMs9CXm4rPQUnvJNmPKhnIes=",` +
			`"iv":"jRuLy2H7lDV2tyMd8t5L6g==",` +
			`"auth-key-hmac":"6b9WLMjXPvtVSyUZ2/Cwu8ksvZla1nyqtBPK3jL4q7I=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"DqgmsMD4d2NMqQ9ugLBTLRZW+ZCOkjgR6rRyIAXOb2Rdd0wA21SN09N9Nmkt5fzNou34P6OVTEu8wQd+nToGzQk8Tlc=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"qX+OkuhbLRAmB3BvgSQR7U0qUMJguOQqPG/V8aMarqk=",` +
			`"digest":"PrtdZnxX2aE0rCxgn/vmHSUKWS4Cr2P+B7Hj70W1D7w="},` +
			`"hmacs":["6PbEHuaRXkghoQlYYRZbj4PWcq2XfL/qXuPzTfxKjDE=",` +
			`"JVhzcAvNFHYQYgPM82TVVtIsuTBbxjBs8wCb1yDY5mA="]}}
	`)

	bootscope.SetModel(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"))

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		opts: []ActivateOption{
			WillCheckStorageContainerBinding(),
		},
		legacyV1KeyUnlock: true,
		expectedActivateConfig: map[any]any{
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithV1PlatformKeyFailsAfterPlatformKeyAndRecoveryKeyUsed(c *C) {
	// Test that unlocking with a v1 key fails after the previous storage containers
	// were unlocked with a mix of new platform keys and recovery keys. This is because
	// it's not possible to cross-check the primary keys, as they have different properties.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda2")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	unlockKey := testutil.DecodeHexString(c, "d765126a3f3ff1cde33445d9eb178ac6302deb813d023020e3a56abf60398dd1")
	kd := []byte(
		`{` +
			`"generation":1,` +
			`"platform_name":"mock",` +
			`"platform_handle":` +
			`{` +
			`"key":"0GCaTfIgLy9dCqqcfOTjMs9CXm4rPQUnvJNmPKhnIes=",` +
			`"iv":"jRuLy2H7lDV2tyMd8t5L6g==",` +
			`"auth-key-hmac":"6b9WLMjXPvtVSyUZ2/Cwu8ksvZla1nyqtBPK3jL4q7I=",` +
			`"exp-generation":1,` +
			`"exp-kdf_alg":5,` +
			`"exp-auth-mode":0},` +
			`"role":"",` +
			`"kdf_alg":"sha256",` +
			`"encrypted_payload":"DqgmsMD4d2NMqQ9ugLBTLRZW+ZCOkjgR6rRyIAXOb2Rdd0wA21SN09N9Nmkt5fzNou34P6OVTEu8wQd+nToGzQk8Tlc=",` +
			`"authorized_snap_models":` +
			`{` +
			`"alg":"sha256",` +
			`"kdf_alg":"sha256",` +
			`"key_digest":` +
			`{` +
			`"alg":"sha256",` +
			`"salt":"qX+OkuhbLRAmB3BvgSQR7U0qUMJguOQqPG/V8aMarqk=",` +
			`"digest":"PrtdZnxX2aE0rCxgn/vmHSUKWS4Cr2P+B7Hj70W1D7w="},` +
			`"hmacs":["6PbEHuaRXkghoQlYYRZbj4PWcq2XfL/qXuPzTfxKjDE=",` +
			`"JVhzcAvNFHYQYgPM82TVVtIsuTBbxjBs8wCb1yDY5mA="]}}
	`)

	bootscope.SetModel(testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"))

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default", unlockKey, KeyslotTypePlatform, 0, kd),
		),
		expectedStderr: `Cannot try keyslots that require a user credential because WithAuthRequestor wasn't supplied
`,
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerWithRecoveryKeyAfterPlatformKeyAndRecoveryKeyUsedWithWillCheckStorageContainerBinding(c *C) {
	// Test that the integration of WillCheckStorageContainerBinding doesn't
	// disable the recovery key fallback, as it does modify the state machine
	// flags.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")

	id, err := AddKeyToUserKeyring(primaryKey, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{
		responses: []any{makeRecoveryKey(c, recoveryKey)},
	}

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithRecoveryKeyTries(3),
		},
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithRecoveryKey},
				"sda2": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda3"),
			withStorageContainerCredentialName("sda3"),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("foo"),
			WillCheckStorageContainerBinding(),
		},
		expectedAuthRequestName:  "foo",
		expectedAuthRequestPath:  "/dev/sda3",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                         authRequestor,
			RecoveryKeyTriesKey:                      uint(3),
			AuthRequestorUserVisibleNameKey:          "foo",
			WillCheckStorageContainerBindingOption(): struct{}{},
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithActivateStateCustomData(c *C) {
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")
	kd2, unlockKey2 := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover")

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithActivateStateCustomData(json.RawMessage(`"foo"`)),
		},
		expectedActivateConfig: map[any]any{
			ActivateStateCustomDataKey: json.RawMessage(`"foo"`),
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:     ActivationSucceededWithPlatformKey,
			Keyslot:    "default",
			CustomData: json.RawMessage(`"foo"`),
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModePassphrase(c *C) {
	// Test a simple case with 2 keyslots with passphrase auth.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover", "secret")
	kd2, unlockKey2 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover", "foo")

	authRequestor := &mockAuthRequestor{
		responses: []any{"secret"},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithPassphraseTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedAuthRequestName:  "data",
		expectedAuthRequestPath:  "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypePassphrase},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			PassphraseTriesKey:              uint(3),
			AuthRequestorUserVisibleNameKey: "data",
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModePassphraseRetryAfterIncorrectPassphrase(c *C) {
	// Test a simple case with 2 keyslots with passphrase auth. The first
	// passphrase is incorrect for both keyslots, but we should get another
	// attempt.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover", "secret")
	kd2, unlockKey2 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover", "foo")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			"incorrect",
			"secret",
		},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithPassphraseTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypePassphrase,
			UserAuthTypePassphrase,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			PassphraseTriesKey:              uint(3),
			AuthRequestorUserVisibleNameKey: "data",
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey1,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default-fallback": KeyslotErrorIncorrectUserAuth,
			},
			KeyslotErrorsOrder: []string{"default-fallback"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModePassphraseSecondKey(c *C) {
	// Test a simple case with 2 keyslots with passphrase auth. Unlocking happens
	// with the second tested keyslot.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover", "secret")
	kd2, unlockKey2 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover", "foo")

	authRequestor := &mockAuthRequestor{
		responses: []any{"foo"},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithPassphraseTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedAuthRequestName:  "data",
		expectedAuthRequestPath:  "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypePassphrase},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			PassphraseTriesKey:              uint(3),
			AuthRequestorUserVisibleNameKey: "data",
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default-fallback",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default": KeyslotErrorIncorrectUserAuth,
			},
			KeyslotErrorsOrder: []string{"default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModePassphraseWithPassphraseTries(c *C) {
	// Test the integration of WithPassphraseTries.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover", "secret")
	kd2, unlockKey2 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover", "foo")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			"incorrect",
			"incorrect",
			"incorrect",
		},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithPassphraseTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypePassphrase,
			UserAuthTypePassphrase,
			UserAuthTypePassphrase,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			PassphraseTriesKey:              uint(3),
			AuthRequestorUserVisibleNameKey: "data",
		},
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorIncorrectUserAuth,
				"default-fallback": KeyslotErrorIncorrectUserAuth,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerAuthModePassphraseWithDifferentPassphraseTries(c *C) {
	// Test the integration of WithPassphraseTries.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover", "secret")
	kd2, unlockKey2 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover", "foo")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			"incorrect",
			"incorrect",
		},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithPassphraseTries(2),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypePassphrase,
			UserAuthTypePassphrase,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			PassphraseTriesKey:              uint(2),
			AuthRequestorUserVisibleNameKey: "data",
		},
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorIncorrectUserAuth,
				"default-fallback": KeyslotErrorIncorrectUserAuth,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestActivateContainerAuthModePassphraseWithRecoveryKeyFallback(c *C) {
	// Test a simple case with 2 keyslots with passphrase auth and
	// a recovery keyslot. Unlocking happens with a recovery keyslot
	// after entering an incorrect passphrase.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover", "secret")
	kd2, unlockKey2 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover", "foo")

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			"incorrect",
			makeRecoveryKey(c, recoveryKey),
		},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithPassphraseTries(3),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
			UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			PassphraseTriesKey:              uint(3),
			RecoveryKeyTriesKey:             uint(3),
			AuthRequestorUserVisibleNameKey: "data",
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorIncorrectUserAuth,
				"default-fallback": KeyslotErrorIncorrectUserAuth,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModePassphraseBecomesUnavailableWithRecoveryKeyFallback(c *C) {
	// Test a simple case with 2 keyslots with passphrase auth and
	// a recovery keyslot. Unlocking happens with a recovery keyslot
	// after the 2 platform keyslots fail with errors. The last
	// credential request should only be for a recovery key.
	// This also test unlocking errors with passphrase keyslots, as
	// well as passphrase keyslots becoming unusable.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover", "secret")
	kd2, unlockKey2 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover", "foo")

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			"secret",
			"foo",
			makeRecoveryKey(c, recoveryKey),
		},
	}

	s.handler.permittedRoles = []string{"run+recover"}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithPassphraseTries(3),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", nil, KeyslotTypePlatform, 0, kd1),                 // Configured to fail.
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2), // Not permitted.
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedStderr: `Error with keyslot "default": invalid key data: cannot activate container with key recovered from keyslot metadata: invalid key
Error with keyslot "default-fallback": cannot recover keys from keyslot: incompatible key data role params: permission denied
`,
		expectedTryKeys: [][]byte{
			unlockKey1,
			recoveryKey,
		},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
			UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
			UserAuthTypeRecoveryKey,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			PassphraseTriesKey:              uint(3),
			RecoveryKeyTriesKey:             uint(3),
			AuthRequestorUserVisibleNameKey: "data",
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorInvalidKeyData,
				"default-fallback": KeyslotErrorIncompatibleRoleParams,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModePassphraseWithRecoveryKeyFallbackAfterPassphraseTriesExhausted(c *C) {
	// Test a simple case with 2 keyslots with passphrase auth and
	// a recovery keyslot. Unlocking happens with a recovery keyslot
	// after all passphrase tries are exhausted.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover", "secret")
	kd2, unlockKey2 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover", "foo")

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			"incorrect",
			"incorrect",
			"incorrect",
			makeRecoveryKey(c, recoveryKey),
		},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithPassphraseTries(3),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
			UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
			UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
			UserAuthTypeRecoveryKey,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			PassphraseTriesKey:              uint(3),
			RecoveryKeyTriesKey:             uint(3),
			AuthRequestorUserVisibleNameKey: "data",
		},
		expectedUnlockKey: recoveryKey,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithRecoveryKey,
			Keyslot: "default-recovery",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorIncorrectUserAuth,
				"default-fallback": KeyslotErrorIncorrectUserAuth,
			},
			KeyslotErrorsOrder: []string{"default", "default-fallback"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerAuthModePassphraseAfterRecoveryKeyFallbackTriesExhausted(c *C) {
	// Test a simple case with 2 keyslots with passphrase auth and
	// a recovery keyslot. Unlocking happens with a passphrase keyslot
	// after all recovery key tries are exhausted.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover", "secret")
	kd2, unlockKey2 := s.makeKeyDataBlobWithPassphrase(c, primaryKey, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover", "foo")

	recoveryKey := testutil.DecodeHexString(c, "9124e9a56e40c65424c5f652127f8d18")
	incorrectRecoveryKey := testutil.DecodeHexString(c, "c9654970edbf1c8005f4f0c38ab6b300")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			makeRecoveryKey(c, incorrectRecoveryKey),
			makeRecoveryKey(c, incorrectRecoveryKey),
			makeRecoveryKey(c, incorrectRecoveryKey),
			"foo",
		},
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithPassphraseTries(5),
			WithRecoveryKeyTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
			withStorageContainerKeyslot("default-recovery", recoveryKey, KeyslotTypeRecovery, 0, nil),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("data"),
		},
		expectedTryKeys: [][]byte{
			incorrectRecoveryKey,
			incorrectRecoveryKey,
			incorrectRecoveryKey,
			unlockKey2,
		},
		expectedAuthRequestName: "data",
		expectedAuthRequestPath: "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
			UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
			UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
			UserAuthTypePassphrase,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			PassphraseTriesKey:              uint(5),
			RecoveryKeyTriesKey:             uint(3),
			AuthRequestorUserVisibleNameKey: "data",
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
		expectedState: &ContainerActivateState{
			Status:  ActivationSucceededWithPlatformKey,
			Keyslot: "default-fallback",
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorIncorrectUserAuth,
				"default-recovery": KeyslotErrorIncorrectUserAuth,
			},
			KeyslotErrorsOrder: []string{"default-recovery", "default"},
		},
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerPrimaryKeyCrosscheckFailAuthModePassphraseAfterPlatformKeyUsed(c *C) {
	primaryKey1 := testutil.DecodeHexString(c, "990e0742eaa152b5c2bcc3aaf94c9dae58df62a46c13ab569a3e7b4afebb7e1d")

	id, err := AddKeyToUserKeyring(primaryKey1, newMockStorageContainer(withStorageContainerCredentialName("sda1")), KeyringKeyPurposePrimary, "ubuntu-fde")
	c.Check(err, IsNil)

	primaryKey2 := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd1, unlockKey1 := s.makeKeyDataBlobWithPassphrase(c, primaryKey2, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover", "secret")
	kd2, unlockKey2 := s.makeKeyDataBlobWithPassphrase(c, primaryKey2, testutil.DecodeHexString(c, "d72501b0b558c3119e036d5585629a026e82c05b6a4f19511daa3f12cc37902f"), "recover", "foo")

	authRequestor := &mockAuthRequestor{
		responses: []any{
			"foo",
			"secret",
		},
	}

	err = s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		initialState: &ActivateState{
			PrimaryKeyID: int32(id),
			Activations: map[string]*ContainerActivateState{
				"sda1": &ContainerActivateState{Status: ActivationSucceededWithPlatformKey},
			},
		},
		contextOpts: []ActivateContextOption{
			WithAuthRequestor(authRequestor),
			WithPassphraseTries(3),
		},
		authRequestor: authRequestor,
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda2"),
			withStorageContainerCredentialName("sda2"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-fallback", unlockKey2, KeyslotTypePlatform, 0, kd2),
		),
		opts: []ActivateOption{
			WithAuthRequestorUserVisibleName("save"),
		},
		expectedStderr: `Error with keyslot "default-fallback": invalid key data: invalid primary key
Error with keyslot "default": invalid key data: invalid primary key
`,
		expectedAuthRequestName: "save",
		expectedAuthRequestPath: "/dev/sda2",
		expectedAuthRequestTypes: []UserAuthType{
			UserAuthTypePassphrase,
			UserAuthTypePassphrase,
		},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			PassphraseTriesKey:              uint(3),
			AuthRequestorUserVisibleNameKey: "save",
		},
		expectedState: &ContainerActivateState{
			Status: ActivationFailed,
			KeyslotErrors: map[string]KeyslotErrorType{
				"default":          KeyslotErrorInvalidPrimaryKey,
				"default-fallback": KeyslotErrorInvalidPrimaryKey,
			},
			KeyslotErrorsOrder: []string{"default-fallback", "default"},
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
}

func (s *activateSuite) TestDeactivateContainer(c *C) {
	state := &ActivateState{
		Activations: map[string]*ContainerActivateState{
			"sda1": {
				Status:  ActivationSucceededWithRecoveryKey,
				Keyslot: "default-recovery",
				KeyslotErrors: map[string]KeyslotErrorType{
					"default": KeyslotErrorInvalidKeyData,
				},
			},
		},
	}
	expectedState := state.Copy()
	expectedState.Activations["sda1"].Status = ActivationDeactivated
	expectedState.Activations["sda1"].Keyslot = ""
	expectedContainerState := state.Activations["sda1"]

	ctx, err := NewActivateContext(context.Background(), state)
	c.Assert(err, IsNil)

	container := newMockStorageContainer(
		withStorageContainerPath("/dev/sda1"),
		withStorageContainerCredentialName("sda1"),
		withStorageContainerActivated(),
	)

	c.Check(ctx.DeactivateContainer(context.Background(), container, ""), IsNil)
	c.Check(container.isActivated(), testutil.IsFalse)
	c.Check(ctx.State(), DeepEquals, expectedState)
	c.Check(ctx.State().Activations["sda1"], Equals, expectedContainerState)
}

func (s *activateSuite) TestDeactivateContainerError(c *C) {
	state := &ActivateState{
		Activations: map[string]*ContainerActivateState{
			"sda1": {
				Status:  ActivationSucceededWithRecoveryKey,
				Keyslot: "default-recovery",
				KeyslotErrors: map[string]KeyslotErrorType{
					"default": KeyslotErrorInvalidKeyData,
				},
			},
		},
	}
	expectedState := state.Copy()

	ctx, err := NewActivateContext(context.Background(), state)
	c.Assert(err, IsNil)

	container := newMockStorageContainer(
		withStorageContainerPath("/dev/sda1"),
		withStorageContainerCredentialName("sda1"),
	)

	c.Check(ctx.DeactivateContainer(context.Background(), container, ""), Equals, ErrStorageContainerNotActive)
	c.Check(ctx.State(), DeepEquals, expectedState)
}

func (s *activateSuite) TestDeactivateContainerContext(c *C) {
	state := &ActivateState{
		Activations: map[string]*ContainerActivateState{
			"sda1": {
				Status:  ActivationSucceededWithRecoveryKey,
				Keyslot: "default-recovery",
				KeyslotErrors: map[string]KeyslotErrorType{
					"default": KeyslotErrorInvalidKeyData,
				},
			},
		},
	}
	expectedState := state.Copy()
	expectedState.Activations["sda1"].Status = ActivationDeactivated
	expectedState.Activations["sda1"].Keyslot = ""
	expectedContainerState := state.Activations["sda1"]

	ctx, err := NewActivateContext(context.Background(), state)
	c.Assert(err, IsNil)

	expectedCtx := context.WithValue(context.Background(), "foo", "bar")

	container := newMockStorageContainer(
		withStorageContainerPath("/dev/sda1"),
		withStorageContainerCredentialName("sda1"),
		withStorageContainerActivated(),
		withStorageContainerExpectedContext(expectedCtx),
	)

	c.Check(ctx.DeactivateContainer(expectedCtx, container, ""), IsNil)
	c.Check(container.isActivated(), testutil.IsFalse)
	c.Check(ctx.State(), DeepEquals, expectedState)
	c.Check(ctx.State().Activations["sda1"], Equals, expectedContainerState)
}

func (s *activateSuite) TestDeactivateContainerNoProvidedState(c *C) {
	expectedState := &ActivateState{
		Activations: map[string]*ContainerActivateState{
			"sda1": {Status: ActivationDeactivated},
		},
	}

	ctx, err := NewActivateContext(context.Background(), nil)
	c.Assert(err, IsNil)

	container := newMockStorageContainer(
		withStorageContainerPath("/dev/sda1"),
		withStorageContainerCredentialName("sda1"),
		withStorageContainerActivated(),
	)

	c.Check(ctx.DeactivateContainer(context.Background(), container, ""), IsNil)
	c.Check(container.isActivated(), testutil.IsFalse)
	c.Check(ctx.State(), DeepEquals, expectedState)
}

func (s *activateSuite) TestActivateOneContainerStateMachinePrimaryKeyInfoWithMoreWork(c *C) {
	m := NewActivateOneContainerStateMachine(nil, make(mockActivateConfig), nil, 0)
	_, _, err := m.PrimaryKeyInfo()
	c.Check(err, ErrorMatches, `state machine has not finished`)
}

func (s *activateSuite) TestActivateOneContainerStateMachineActivationStateWithMoreWork(c *C) {
	m := NewActivateOneContainerStateMachine(nil, make(mockActivateConfig), nil, 0)
	_, err := m.ActivationState()
	c.Check(err, ErrorMatches, `state machine has not finished`)
}
