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
	"bytes"
	"crypto"
	"encoding/json"
	"io"
	"os"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type mockActivateConfig map[any]any

func (c mockActivateConfig) Get(key any) (val any, exists bool) {
	val, exists = c[key]
	return val, exists
}

func (c mockActivateConfig) Set(key, val any) {
	if val == nil {
		delete(c, key)
		return
	}
	c[key] = val
}

type mockActivateConfigKey1 string
type mockActivateConfigKey2 struct{}

type activateOptionsSuite struct{}

var _ = Suite(&activateOptionsSuite{})

func (*activateOptionsSuite) TestActivateConfigImpl(c *C) {
	cfg := make(ActivateConfigImpl)

	k1 := mockActivateConfigKey1("foo")
	cfg.Set(k1, int(10))
	k2 := mockActivateConfigKey2{}
	cfg.Set(k2, "bar")

	v, exists := cfg.Get(k1)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, int(10))

	v, exists = cfg.Get(k2)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, "bar")

	cfg.Set(k1, nil)
	_, exists = cfg.Get(k1)
	c.Check(exists, testutil.IsFalse)
}

func (*activateOptionsSuite) TestActivateConfigGet(c *C) {
	k := mockActivateConfigKey1("foo")

	cfg := make(mockActivateConfig)
	cfg[k] = int(10)

	v, exists := ActivateConfigGet[int](cfg, k)
	c.Check(exists, testutil.IsTrue)
	c.Assert(v, FitsTypeOf, int(0))
	c.Check(v, Equals, 10)
}

func (*activateOptionsSuite) TestActivateConfigGetDifferentValue(c *C) {
	k := mockActivateConfigKey1("foo")

	cfg := make(mockActivateConfig)
	cfg[k] = int(-5)

	v, exists := ActivateConfigGet[int](cfg, k)
	c.Check(exists, testutil.IsTrue)
	c.Assert(v, FitsTypeOf, int(0))
	c.Check(v, Equals, -5)
}

func (*activateOptionsSuite) TestActivateConfigGetDifferentKeyValue(c *C) {
	k := mockActivateConfigKey1("bar")

	cfg := make(mockActivateConfig)
	cfg[k] = int(10)

	v, exists := ActivateConfigGet[int](cfg, k)
	c.Check(exists, testutil.IsTrue)
	c.Assert(v, FitsTypeOf, int(0))
	c.Check(v, Equals, 10)
}

func (*activateOptionsSuite) TestActivateConfigGetDifferentKeyType(c *C) {
	k := mockActivateConfigKey2{}

	cfg := make(mockActivateConfig)
	cfg[k] = int(10)

	v, exists := ActivateConfigGet[int](cfg, k)
	c.Check(exists, testutil.IsTrue)
	c.Assert(v, FitsTypeOf, int(0))
	c.Check(v, Equals, 10)
}

func (*activateOptionsSuite) TestActivateConfigGetDifferentValueType(c *C) {
	k := mockActivateConfigKey1("foo")

	cfg := make(mockActivateConfig)
	cfg[k] = "bar"

	v, exists := ActivateConfigGet[string](cfg, k)
	c.Check(exists, testutil.IsTrue)
	c.Assert(v, FitsTypeOf, "")
	c.Check(v, Equals, "bar")
}

func (*activateOptionsSuite) TestActivateConfigGetMissing(c *C) {
	cfg := make(mockActivateConfig)

	v, exists := ActivateConfigGet[int](cfg, mockActivateConfigKey1("foo"))
	c.Check(exists, testutil.IsFalse)
	c.Assert(v, FitsTypeOf, int(0))
	c.Check(v, Equals, 0)
}

func (*activateOptionsSuite) TestWillCheckStorageContainerBinding(c *C) {
	cfg := make(mockActivateConfig)

	opt := WillCheckStorageContainerBinding()
	opt.ApplyOptionToConfig(cfg)

	_, exists := ActivateConfigGet[struct{}](cfg, WillCheckStorageContainerBindingOption())
	c.Check(exists, testutil.IsTrue)
}

func (*activateOptionsSuite) TestWithAuthRequestor(c *C) {
	cfg := make(mockActivateConfig)

	req := new(mockAuthRequestor)
	opt := WithAuthRequestor(req)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[AuthRequestor](cfg, AuthRequestorKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, req)
}

func (*activateOptionsSuite) TestWithAuthRequestorContext(c *C) {
	cfg := make(mockActivateConfig)

	req := new(mockAuthRequestor)
	opt := WithAuthRequestor(req)
	opt.ApplyContextOptionToConfig(cfg)

	v, exists := ActivateConfigGet[AuthRequestor](cfg, AuthRequestorKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, req)
}

func (*activateOptionsSuite) TestWithAuthRequestorUserVisibleName1(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithAuthRequestorUserVisibleName("data")
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[string](cfg, AuthRequestorUserVisibleNameKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, "data")
}

func (*activateOptionsSuite) TestWithAuthRequestorUserVisibleName2(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithAuthRequestorUserVisibleName("save")
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[string](cfg, AuthRequestorUserVisibleNameKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, "save")
}

func (*activateOptionsSuite) TestWithExternalKeyDataFromReader1(c *C) {
	cfg := make(mockActivateConfig)

	r := new(mockKeyDataReader)
	opt := WithExternalKeyDataFromReader("foo", r)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]*ExternalKeyData](cfg, ExternalKeyDataKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, []*ExternalKeyData{NewExternalKeyData("foo", r, nil)})
}

func (*activateOptionsSuite) TestWithExternalKeyDataFromReader2(c *C) {
	cfg := make(mockActivateConfig)

	r1 := &mockKeyDataReader{Reader: bytes.NewReader([]byte("key data 1"))}
	opt := WithExternalKeyDataFromReader("foo", r1)
	opt.ApplyOptionToConfig(cfg)

	r2 := &mockKeyDataReader{Reader: bytes.NewReader([]byte("key data 2"))}
	opt = WithExternalKeyDataFromReader("bar", r2)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]*ExternalKeyData](cfg, ExternalKeyDataKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, []*ExternalKeyData{
		NewExternalKeyData("foo", r1, nil),
		NewExternalKeyData("bar", r2, nil),
	})
}

func (*activateOptionsSuite) TestWithExternalKeyData1(c *C) {
	cfg := make(mockActivateConfig)

	data := new(KeyData)
	opt := WithExternalKeyData("foo", data)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]*ExternalKeyData](cfg, ExternalKeyDataKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, []*ExternalKeyData{NewExternalKeyData("foo", nil, data)})
}

func (*activateOptionsSuite) TestWithExternalKeyData2(c *C) {
	cfg := make(mockActivateConfig)

	data1, err := NewKeyData(&KeyParams{
		Handle:           []byte("\"handle1\""),
		EncryptedPayload: []byte("payload 1"),
		PlatformName:     "mock",
		KDFAlg:           crypto.SHA256,
	})
	c.Assert(err, IsNil)
	opt := WithExternalKeyData("foo", data1)
	opt.ApplyOptionToConfig(cfg)

	data2, err := NewKeyData(&KeyParams{
		Handle:           []byte("\"handle2\""),
		EncryptedPayload: []byte("payload 2"),
		PlatformName:     "mock",
		KDFAlg:           crypto.SHA256,
	})
	c.Assert(err, IsNil)
	opt = WithExternalKeyData("bar", data2)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]*ExternalKeyData](cfg, ExternalKeyDataKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, []*ExternalKeyData{
		NewExternalKeyData("foo", nil, data1),
		NewExternalKeyData("bar", nil, data2),
	})
}

func (*activateOptionsSuite) TestWithExternalKeyDataAndWithExternalKeyDataFromReader(c *C) {
	cfg := make(mockActivateConfig)

	data := new(KeyData)
	opt := WithExternalKeyData("foo", data)
	opt.ApplyOptionToConfig(cfg)

	r := new(mockKeyDataReader)
	opt = WithExternalKeyDataFromReader("bar", r)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]*ExternalKeyData](cfg, ExternalKeyDataKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, []*ExternalKeyData{
		NewExternalKeyData("foo", nil, data),
		NewExternalKeyData("bar", r, nil),
	})
}

func (*activateOptionsSuite) TestWithExternalUnlockKey1(c *C) {
	cfg := make(mockActivateConfig)

	key := testutil.DecodeHexString(c, "442232215cf79f2fbc6d5c4de44f1b1c48a0d68c6edc7639b28777d7b2a3c243")
	opt := WithExternalUnlockKey("foo", key, ExternalUnlockKeyFromPlatformDevice)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]*ExternalUnlockKey](cfg, ExternalUnlockKeyKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, []*ExternalUnlockKey{NewExternalUnlockKey("foo", key, ExternalUnlockKeyFromPlatformDevice)})
}

func (*activateOptionsSuite) TestWithExternalUnlockKey2(c *C) {
	cfg := make(mockActivateConfig)

	key1 := testutil.DecodeHexString(c, "442232215cf79f2fbc6d5c4de44f1b1c48a0d68c6edc7639b28777d7b2a3c243")
	opt := WithExternalUnlockKey("foo", key1, ExternalUnlockKeyFromStorageContainer)
	opt.ApplyOptionToConfig(cfg)

	key2 := testutil.DecodeHexString(c, "1f11ea11681129341720cfc1fe475df5fa7873bcd5a020cb7eb0eef5399ba096")
	opt = WithExternalUnlockKey("bar", key2, ExternalUnlockKeyFromStorageContainer)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]*ExternalUnlockKey](cfg, ExternalUnlockKeyKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, []*ExternalUnlockKey{
		NewExternalUnlockKey("foo", key1, ExternalUnlockKeyFromStorageContainer),
		NewExternalUnlockKey("bar", key2, ExternalUnlockKeyFromStorageContainer),
	})
}

func (*activateOptionsSuite) TestWithKeyringDescriptionPrefix1(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithKeyringDescriptionPrefix("ubuntu-fde")
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[string](cfg, KeyringDescPrefixKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, "ubuntu-fde")
}

func (*activateOptionsSuite) TestWithKeyringDescriptionPrefix2(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithKeyringDescriptionPrefix("foo")
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[string](cfg, KeyringDescPrefixKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, "foo")
}

func (*activateOptionsSuite) TestWithKeyringDescriptionPrefixContext(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithKeyringDescriptionPrefix("ubuntu-fde")
	opt.ApplyContextOptionToConfig(cfg)

	v, exists := ActivateConfigGet[string](cfg, KeyringDescPrefixKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, "ubuntu-fde")
}

func (*activateOptionsSuite) TestWithLegacyKeyringKeyDescriptionPaths1(c *C) {
	cfg := make(mockActivateConfig)

	paths := []string{"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340"}
	opt := WithLegacyKeyringKeyDescriptionPaths(paths...)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]string](cfg, LegacyKeyringKeyDescPathsKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, paths)
}

func (*activateOptionsSuite) TestWithLegacyKeyringKeyDescriptionPaths2(c *C) {
	cfg := make(mockActivateConfig)

	paths := []string{
		"/dev/disk/by-partuuid/2f8c0406-d21a-42d1-9b59-9d22da8c9d32",
		"/dev/disk/by-uuid/de4b30b6-708d-4c9e-bb16-052b8cd57340",
	}
	opt := WithLegacyKeyringKeyDescriptionPaths(paths...)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]string](cfg, LegacyKeyringKeyDescPathsKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, paths)
}

func (*activateOptionsSuite) TestWithStderrLogger(c *C) {
	cfg := make(mockActivateConfig)

	stderr := new(os.File)
	opt := WithStderrLogger(stderr)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[io.Writer](cfg, StderrLoggerKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, stderr)
}

func (*activateOptionsSuite) TestWithStderrLoggerContext(c *C) {
	cfg := make(mockActivateConfig)

	stderr := new(os.File)
	opt := WithStderrLogger(stderr)
	opt.ApplyContextOptionToConfig(cfg)

	v, exists := ActivateConfigGet[io.Writer](cfg, StderrLoggerKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, stderr)
}

func (*activateOptionsSuite) TestWithDiscardStderrLogger(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithDiscardStderrLogger()
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[io.Writer](cfg, StderrLoggerKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, io.Discard)
}

func (*activateOptionsSuite) TestWithDiscardStderrLoggerContext(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithDiscardStderrLogger()
	opt.ApplyContextOptionToConfig(cfg)

	v, exists := ActivateConfigGet[io.Writer](cfg, StderrLoggerKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, io.Discard)
}

func (*activateOptionsSuite) TestWithPassphraseTries1(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithPassphraseTries(3)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[uint](cfg, PassphraseTriesKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, uint(3))
}

func (*activateOptionsSuite) TestWithPassphraseTries2(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithPassphraseTries(5)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[uint](cfg, PassphraseTriesKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, uint(5))
}

func (*activateOptionsSuite) TestWithPassphraseTriesContext(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithPassphraseTries(3)
	opt.ApplyContextOptionToConfig(cfg)

	v, exists := ActivateConfigGet[uint](cfg, PassphraseTriesKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, uint(3))
}

func (*activateOptionsSuite) TestWithPINTries1(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithPINTries(3)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[uint](cfg, PinTriesKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, uint(3))
}

func (*activateOptionsSuite) TestWithPINTries2(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithPINTries(5)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[uint](cfg, PinTriesKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, uint(5))
}

func (*activateOptionsSuite) TestWithPINTriesContext(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithPINTries(3)
	opt.ApplyContextOptionToConfig(cfg)

	v, exists := ActivateConfigGet[uint](cfg, PinTriesKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, uint(3))
}

func (*activateOptionsSuite) TestWithRecoveryKeyTries1(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithRecoveryKeyTries(3)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[uint](cfg, RecoveryKeyTriesKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, uint(3))
}

func (*activateOptionsSuite) TestWithRecoveryKeyTries2(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithRecoveryKeyTries(5)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[uint](cfg, RecoveryKeyTriesKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, uint(5))
}

func (*activateOptionsSuite) TestWithRecoveryKeyTriesContext(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithRecoveryKeyTries(3)
	opt.ApplyContextOptionToConfig(cfg)

	v, exists := ActivateConfigGet[uint](cfg, RecoveryKeyTriesKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, Equals, uint(3))
}

func (*activateOptionsSuite) TestWithActivateStateCustomData1(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithActivateStateCustomData(json.RawMessage(`{"foo":"bar"}`))
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[json.RawMessage](cfg, ActivateStateCustomDataKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, json.RawMessage(`{"foo":"bar"}`))
}

func (*activateOptionsSuite) TestWithActivateStateCustomData2(c *C) {
	cfg := make(mockActivateConfig)

	opt := WithActivateStateCustomData(json.RawMessage(`[5, 7]`))
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[json.RawMessage](cfg, ActivateStateCustomDataKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, json.RawMessage(`[5, 7]`))
}
