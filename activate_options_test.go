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

func (*activateOptionsSuite) TestWithExternalKeyData1(c *C) {
	cfg := make(mockActivateConfig)

	external := []*ExternalKeyData{NewExternalKeyData("foo", nil)}
	opt := WithExternalKeyData(external...)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]*ExternalKeyData](cfg, ExternalKeyDataKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, external)
}

func (*activateOptionsSuite) TestWithExternalKeyData2(c *C) {
	cfg := make(mockActivateConfig)

	external := []*ExternalKeyData{NewExternalKeyData("bar", nil), NewExternalKeyData("foo", nil)}
	opt := WithExternalKeyData(external...)
	opt.ApplyOptionToConfig(cfg)

	v, exists := ActivateConfigGet[[]*ExternalKeyData](cfg, ExternalKeyDataKey)
	c.Check(exists, testutil.IsTrue)
	c.Check(v, DeepEquals, external)
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
