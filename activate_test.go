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
	"errors"
	"io"
	"os"
	"strings"

	. "github.com/snapcore/secboot"
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

func (s *activateSuite) makeKeyDataBlob(c *C, primaryKey PrimaryKey, uniqueKey []byte, role string) (blob []byte, unlockKey DiskUnlockKey) {
	var params *KeyParams
	params, unlockKey = s.mockProtectKeys(c, primaryKey, uniqueKey, role, crypto.SHA256)

	kd, err := NewKeyData(params)
	c.Assert(err, IsNil)

	w := makeMockKeyDataWriter()
	c.Check(kd.WriteAtomic(w), IsNil)

	return w.Bytes(), unlockKey
}

var _ = Suite(&activateSuite{})

func (s *activateSuite) TestNewActivateContext(c *C) {
	ctx := NewActivateContext(nil)
	c.Assert(ctx, NotNil)

	c.Check(ctx.State(), NotNil)
	c.Check(ctx.Config().(interface{ Len() int }).Len(), Equals, 0)
}

func (*activateSuite) TestNewActivateContextWithProvidedState(c *C) {
	// TODO: Populate some state when it has some members.
	state := new(ActivateState)
	stateCopy := &(*state)

	ctx := NewActivateContext(state)
	c.Assert(ctx, NotNil)

	c.Check(ctx.State(), Equals, state)
	c.Check(ctx.State(), DeepEquals, stateCopy)
	c.Check(ctx.Config().(interface{ Len() int }).Len(), Equals, 0)
}

func (*activateSuite) TestNewActivateContextWithOptions(c *C) {
	authRequestor := new(mockAuthRequestor)

	ctx := NewActivateContext(
		nil, // state
		WithAuthRequestor(authRequestor),
		WithKeyringDescriptionPrefix("ubuntu-fde"),
		WithDiscardStderrLogger(),
		WithRecoveryKeyTries(3),
	)
	c.Assert(ctx, NotNil)

	c.Check(ctx.State(), NotNil)

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
}

func (*activateSuite) TestNewActivateContextWithProvidedStateAndOptions(c *C) {
	// TODO: Populate some state when it has some members.
	state := new(ActivateState)
	stateCopy := &(*state)

	stderr := new(os.File)

	ctx := NewActivateContext(
		state,
		WithKeyringDescriptionPrefix("foo"),
		WithStderrLogger(stderr),
		WithRecoveryKeyTries(5),
	)
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
}

type testActivateContextActivateContainerParams struct {
	initialState *ActivateState
	contextOpts  []ActivateContextOption

	authRequestor *mockAuthRequestor

	ctx       context.Context
	container *mockStorageContainer
	opts      []ActivateOption

	expectedStderr           string
	expectedTryKeys          [][]byte
	expectedAuthRequestName  string
	expectedAuthRequestPath  string
	expectedAuthRequestTypes []UserAuthType
	expectedActivateConfig   map[any]any
	expectedKeyringKeyPrefix string
	expectedKeyringKeyName   string
	expectedPrimaryKey       PrimaryKey
	expectedUnlockKey        DiskUnlockKey
}

func (s *activateSuite) testActivateContextActivateContainer(c *C, params *testActivateContextActivateContainerParams) error {
	stderr := new(strings.Builder)
	restore := MockStderr(stderr)
	defer restore()

	activateCtx := NewActivateContext(params.initialState, params.contextOpts...)

	ctx := params.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	err := activateCtx.ActivateContainer(ctx, params.container, params.opts...)
	c.Check(stderr.String(), Equals, params.expectedStderr)
	if err != nil {
		c.Check(params.container.isActivated(), testutil.IsFalse)
		c.Check(params.container.activateTryKeys(), DeepEquals, params.expectedTryKeys)

		_, keyringErr := GetKeyFromKernel(context.Background(), params.container, KeyringKeyPurposeUnlock, params.expectedKeyringKeyPrefix)
		c.Check(keyringErr, Equals, ErrKernelKeyNotFound)
		_, keyringErr = GetKeyFromKernel(context.Background(), params.container, KeyringKeyPurposePrimary, params.expectedKeyringKeyPrefix)
		c.Check(keyringErr, Equals, ErrKernelKeyNotFound)

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
		expectedStderr: `Error with keyslot "default": cannot recover keys from keyslot: invalid key data: permission denied
`,
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
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
		expectedStderr: `Error with keyslot "default": cannot recover keys from keyslot: invalid key data: permission denied
Error with keyslot "default-fallback": cannot recover keys from keyslot: invalid key data: permission denied
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
		expectedAuthRequestName:  "data",
		expectedAuthRequestPath:  "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey, UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
			RecoveryKeyTriesKey:             uint(3),
		},
		expectedUnlockKey: recoveryKey,
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
		expectedTryKeys:          [][]byte{incorrectRecoveryKey, recoveryKey},
		expectedAuthRequestName:  "data",
		expectedAuthRequestPath:  "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey, UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
			RecoveryKeyTriesKey:             uint(3),
		},
		expectedUnlockKey: recoveryKey,
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
		expectedTryKeys:          [][]byte{incorrectRecoveryKey, incorrectRecoveryKey, incorrectRecoveryKey},
		expectedAuthRequestName:  "data",
		expectedAuthRequestPath:  "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey, UserAuthTypeRecoveryKey, UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
			RecoveryKeyTriesKey:             uint(3),
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
		expectedTryKeys:          [][]byte{incorrectRecoveryKey, incorrectRecoveryKey},
		expectedAuthRequestName:  "data",
		expectedAuthRequestPath:  "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey, UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
			RecoveryKeyTriesKey:             uint(2),
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
		expectedAuthRequestName:  "data",
		expectedAuthRequestPath:  "/dev/sda1",
		expectedAuthRequestTypes: []UserAuthType{UserAuthTypeRecoveryKey, UserAuthTypeRecoveryKey},
		expectedActivateConfig: map[any]any{
			AuthRequestorKey:                authRequestor,
			AuthRequestorUserVisibleNameKey: "data",
		},
	})
	c.Check(err, Equals, ErrCannotActivate)
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
		NewExternalKeyData("default-recover", newMockKeyDataReader("", kd2)),
		NewExternalKeyData("default", newMockKeyDataReader("", kd1)),
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, nil),
			withStorageContainerKeyslot("default-recover", unlockKey2, KeyslotTypePlatform, 0, nil),
		),
		opts: []ActivateOption{
			WithExternalKeyData(external...),
		},
		expectedStderr: `Error with keyslot "default": invalid key data: cannot decode keyslot metadata: cannot decode key data: EOF
Error with keyslot "default-recover": invalid key data: cannot decode keyslot metadata: cannot decode key data: EOF
Error with keyslot "external:default": cannot recover keys from keyslot: invalid key data: permission denied
`,
		expectedActivateConfig: map[any]any{
			ExternalKeyDataKey: external,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
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
		NewExternalKeyData("default-recover", newMockKeyDataReader("", kd2)),
	}

	err := s.testActivateContextActivateContainer(c, &testActivateContextActivateContainerParams{
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("sda1"),
			withStorageContainerKeyslot("default", unlockKey1, KeyslotTypePlatform, 0, kd1),
			withStorageContainerKeyslot("default-recover", unlockKey2, KeyslotTypePlatform, 0, nil),
		),
		opts: []ActivateOption{
			WithExternalKeyData(external...),
		},
		expectedStderr: `Error with keyslot "default-recover": invalid key data: cannot decode keyslot metadata: cannot decode key data: EOF
`,
		expectedActivateConfig: map[any]any{
			ExternalKeyDataKey: external,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey2,
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
			withStorageContainerKeyslot("default-recover", unlockKey2, KeyslotTypePlatform, 101, kd2),
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
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestActivateContainerWithInvalidExternalKeyData(c *C) {
	// Test that supplying invalid key data to WithExternalKeyData is
	// handled correctly.
	primaryKey := testutil.DecodeHexString(c, "ed988fada3dbf68e13862cfc52b6d6205c862dd0941e643a81dcab106a79ce6a")
	kd, unlockKey := s.makeKeyDataBlob(c, primaryKey, testutil.DecodeHexString(c, "4d8b57f05f0e70a73768c1d9f1078b8e9b0e9c399f555342e1ac4e675fea122e"), "run+recover")

	external := []*ExternalKeyData{
		NewExternalKeyData("default-fallback", newMockKeyDataReader("", []byte("invalid key data"))),
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
		expectedStderr: `Error with external key metadata "external:default-fallback": invalid key data: cannot decode key data: invalid character 'i' looking for beginning of value
`,
		expectedActivateConfig: map[any]any{
			ExternalKeyDataKey: external,
		},
		expectedPrimaryKey: primaryKey,
		expectedUnlockKey:  unlockKey,
	})
	c.Check(err, IsNil)
}

func (s *activateSuite) TestDeactivateContainer(c *C) {
	ctx := NewActivateContext(nil)

	container := newMockStorageContainer(
		withStorageContainerPath("/dev/sda1"),
		withStorageContainerActivated(),
	)

	c.Check(ctx.DeactivateContainer(context.Background(), container, ""), IsNil)
	c.Check(container.isActivated(), testutil.IsFalse)
}

func (s *activateSuite) TestDeactivateContainerError(c *C) {
	ctx := NewActivateContext(nil)

	container := newMockStorageContainer(
		withStorageContainerPath("/dev/sda1"),
	)

	c.Check(ctx.DeactivateContainer(context.Background(), container, ""), Equals, ErrStorageContainerNotActive)
}

func (s *activateSuite) TestDeactivateContainerContext(c *C) {
	ctx := NewActivateContext(nil)

	expectedCtx := context.WithValue(context.Background(), "foo", "bar")

	container := newMockStorageContainer(
		withStorageContainerPath("/dev/sda1"),
		withStorageContainerActivated(),
		withStorageContainerExpectedContext(expectedCtx),
	)

	c.Check(ctx.DeactivateContainer(expectedCtx, container, ""), IsNil)
	c.Check(container.isActivated(), testutil.IsFalse)
}
