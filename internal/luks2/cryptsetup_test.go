// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package luks2_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luks2/luks2test"
	"github.com/snapcore/secboot/internal/paths/pathstest"
)

type cryptsetupSuite struct {
	snapd_testutil.BaseTest
}

func (s *cryptsetupSuite) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_EXPENSIVE_CRYPTSETUP_TESTS"); exists {
		c.Skip("skipping expensive cryptsetup tests")
	}
}

func (s *cryptsetupSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.AddCleanup(pathstest.MockRunDir(c.MkDir()))

	s.AddCleanup(luks2test.WrapCryptsetup(c))
}

func (s *cryptsetupSuite) checkLUKS2Passphrase(c *C, path string, key []byte) {
	cmd := exec.Command("cryptsetup", "open", "--test-passphrase", "--key-file", "-", path)
	cmd.Stdin = bytes.NewReader(key)
	c.Check(cmd.Run(), IsNil)
}

func (s *cryptsetupSuite) mockCryptsetupFeatures(c *C, features Features) (cmd *snapd_testutil.MockCmd, reset func()) {
	luks2test.ResetCryptsetupFeatures()

	responsesFile := filepath.Join(c.MkDir(), "responses")

	responses := []string{"0"}
	var version string
	switch {
	case features&(FeatureHeaderSizeSetting|FeatureTokenImport) == (FeatureHeaderSizeSetting | FeatureTokenImport):
		version = "2.1.0"
	case features&FeatureTokenImport > 0:
		version = "2.0.3"
	case features&FeatureHeaderSizeSetting > 0:
		c.Fatal("invalid features")
	default:
		version = "2.0.2"
	}

	if features&FeatureTokenReplace > 0 {
		responses = append(responses, "0")
	} else {
		responses = append(responses, "1")
	}

	c.Check(ioutil.WriteFile(responsesFile, []byte(strings.Join(responses, "\n")), 0644), IsNil)

	cryptsetupBottom := `
r=$(head -1 %[1]s)
sed -i -e '1,1d' %[1]s
echo "cryptsetup %[2]s"
exit "$r"
`
	cmd = snapd_testutil.MockCommand(c, "cryptsetup", fmt.Sprintf(cryptsetupBottom, responsesFile, version))
	return cmd, func() {
		luks2test.ResetCryptsetupFeatures()
		cmd.Restore()
	}
}

var _ = Suite(&cryptsetupSuite{})

func (s *cryptsetupSuite) testDetectCryptsetupFeatures(c *C, expected Features) {
	mockCryptsetup, reset := s.mockCryptsetupFeatures(c, expected)
	defer reset()

	features := DetectCryptsetupFeatures()
	c.Check(features, Equals, expected)

	c.Check(mockCryptsetup.Calls(), DeepEquals, [][]string{
		{"cryptsetup", "--version"},
		{"cryptsetup", "--test-args", "token", "import", "--token-id", "0", "--token-replace", "/dev/null"}})
	mockCryptsetup.ForgetCalls()

	features = DetectCryptsetupFeatures()
	c.Check(features, Equals, expected)
	c.Check(mockCryptsetup.Calls(), HasLen, 0)
}

func (s *cryptsetupSuite) TestDetectCryptsetupFeaturesAll(c *C) {
	s.testDetectCryptsetupFeatures(c, FeatureHeaderSizeSetting|FeatureTokenImport|FeatureTokenReplace)
}

func (s *cryptsetupSuite) TestDetectCryptsetupFeaturesNone(c *C) {
	s.testDetectCryptsetupFeatures(c, 0)
}

func (s *cryptsetupSuite) TestDetectCryptsetupFeaturesNoTokenReplace(c *C) {
	s.testDetectCryptsetupFeatures(c, FeatureHeaderSizeSetting|FeatureTokenImport)
}

type testFormatData struct {
	label   string
	key     []byte
	options *FormatOptions
}

func (s *cryptsetupSuite) testFormat(c *C, data *testFormatData) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	c.Check(Format(devicePath, data.label, data.key, data.options), IsNil)

	options := data.options
	if options == nil {
		options = new(FormatOptions)
	}

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)

	c.Check(info.Label, Equals, data.label)

	c.Check(info.Metadata.Keyslots, HasLen, 1)
	keyslot, ok := info.Metadata.Keyslots[0]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.KeySize, Equals, 64)
	c.Check(keyslot.Priority, Equals, SlotPriorityNormal)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, KDFTypeArgon2i)

	c.Check(info.Metadata.Segments, HasLen, 1)
	segment, ok := info.Metadata.Segments[0]
	c.Assert(ok, Equals, true)
	c.Check(segment.Encryption, Equals, "aes-xts-plain64")

	c.Check(info.Metadata.Tokens, HasLen, 0)

	expectedMetadataSize := uint64(16 * 1024)
	if options.MetadataKiBSize > 0 {
		expectedMetadataSize = uint64(options.MetadataKiBSize * 1024)
	}
	expectedKeyslotsSize := uint64(16*1024*1024) - (2 * expectedMetadataSize)
	if options.KeyslotsAreaKiBSize > 0 {
		expectedKeyslotsSize = uint64(options.KeyslotsAreaKiBSize * 1024)
	}

	c.Check(info.Metadata.Config.JSONSize, Equals, expectedMetadataSize-uint64(4*1024))
	c.Check(info.Metadata.Config.KeyslotsSize, Equals, expectedKeyslotsSize)

	expectedMemoryKiB := 1 * 1024 * 1024
	if options.KDFOptions.MemoryKiB > 0 {
		expectedMemoryKiB = options.KDFOptions.MemoryKiB
	}

	if options.KDFOptions.ForceIterations > 0 {
		c.Check(keyslot.KDF.Time, Equals, options.KDFOptions.ForceIterations)
		c.Check(keyslot.KDF.Memory, Equals, expectedMemoryKiB)
	} else {
		expectedKDFTime := 2000 * time.Millisecond
		if options.KDFOptions.TargetDuration > 0 {
			expectedKDFTime = options.KDFOptions.TargetDuration
		}

		c.Check(keyslot.KDF.Memory, snapd_testutil.IntLessEqual, expectedMemoryKiB)

		start := time.Now()
		luks2test.CheckLUKS2Passphrase(c, devicePath, data.key)
		elapsed := time.Now().Sub(start)
		// Check KDF time here with +/-20% tolerance and additional 500ms for cryptsetup exec and other activities
		c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntGreaterThan, int(float64(expectedKDFTime/time.Millisecond)*0.8))
		c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntLessThan, int(float64(expectedKDFTime/time.Millisecond)*1.2)+500)
	}
}

func (s *cryptsetupSuite) TestFormatDefaults(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:   "test",
		key:     key,
		options: &FormatOptions{}})
}

func (s *cryptsetupSuite) TestFormatNilOptions(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label: "test",
		key:   key})
}

func (s *cryptsetupSuite) TestFormatWithCustomKDFTime(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:   "test",
		key:     key,
		options: &FormatOptions{KDFOptions: KDFOptions{TargetDuration: 100 * time.Millisecond}}})
}

func (s *cryptsetupSuite) TestFormatWithCustomKDFMemory(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:   "data",
		key:     key,
		options: &FormatOptions{KDFOptions: KDFOptions{TargetDuration: 100 * time.Millisecond, MemoryKiB: 32 * 1024}}})
}

func (s *cryptsetupSuite) TestFormatWithForceIterations(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:   "data",
		key:     key,
		options: &FormatOptions{KDFOptions: KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}}})
}

func (s *cryptsetupSuite) TestFormatWithDifferentLabel(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:   "data",
		key:     key,
		options: &FormatOptions{KDFOptions: KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}}})
}

func (s *cryptsetupSuite) TestFormatWithCustomMetadataSize(c *C) {
	if DetectCryptsetupFeatures()&FeatureHeaderSizeSetting == 0 {
		c.Skip("cryptsetup doesn't support --luks2-metadata-size")
	}

	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label: "test",
		key:   key,
		options: &FormatOptions{
			KDFOptions:      KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4},
			MetadataKiBSize: 2 * 1024}})
}

func (s *cryptsetupSuite) TestFormatWithCustomKeyslotsAreaSize(c *C) {
	if DetectCryptsetupFeatures()&FeatureHeaderSizeSetting == 0 {
		c.Skip("cryptsetup doesn't support --luks2-keyslots-size")
	}

	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label: "test",
		key:   key,
		options: &FormatOptions{
			KDFOptions:          KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4},
			KeyslotsAreaKiBSize: 2 * 1024}})
}

func (s *cryptsetupSuite) TestFormatWithCustomMetadataSizeUnsupported(c *C) {
	_, reset := s.mockCryptsetupFeatures(c, 0)
	defer reset()

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{MetadataKiBSize: 2 * 1024}), Equals, ErrMissingCryptsetupFeature)
}

func (s *cryptsetupSuite) TestFormatWithCustomKeyslotsAreaSizeUnsupported(c *C) {
	_, reset := s.mockCryptsetupFeatures(c, 0)
	defer reset()

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KeyslotsAreaKiBSize: 2 * 1024}), Equals, ErrMissingCryptsetupFeature)
}

type testAddKeyData struct {
	key     []byte
	options *AddKeyOptions
	time    time.Duration
}

func (s *cryptsetupSuite) testAddKey(c *C, data *testAddKeyData) {
	primaryKey := make([]byte, 32)
	rand.Read(primaryKey)

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)
	fmtOpts := FormatOptions{KDFOptions: KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}}
	c.Assert(Format(devicePath, "", primaryKey, &fmtOpts), IsNil)

	startInfo, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)

	c.Check(AddKey(devicePath, primaryKey, data.key, data.options), IsNil)

	endInfo, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)

	newSlotId := -1
	for s := range endInfo.Metadata.Keyslots {
		if _, ok := startInfo.Metadata.Keyslots[s]; !ok {
			newSlotId = int(s)
			break
		}
	}

	options := data.options
	if options == nil {
		options = &AddKeyOptions{Slot: AnySlot}
	}

	c.Assert(newSlotId, snapd_testutil.IntGreaterThan, -1)
	if options.Slot != AnySlot {
		c.Check(newSlotId, Equals, options.Slot)
	}

	c.Check(endInfo.Metadata.Keyslots, HasLen, 2)
	keyslot, ok := endInfo.Metadata.Keyslots[newSlotId]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.KeySize, Equals, 64)
	c.Check(keyslot.Priority, Equals, SlotPriorityNormal)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, KDFTypeArgon2i)

	expectedMemoryKiB := 1 * 1024 * 1024
	if options.KDFOptions.MemoryKiB > 0 {
		expectedMemoryKiB = options.KDFOptions.MemoryKiB
	}

	if options.KDFOptions.ForceIterations > 0 {
		c.Check(keyslot.KDF.Time, Equals, options.KDFOptions.ForceIterations)
		c.Check(keyslot.KDF.Memory, Equals, expectedMemoryKiB)
	} else {
		expectedKDFTime := 2000 * time.Millisecond
		if options.KDFOptions.TargetDuration > 0 {
			expectedKDFTime = options.KDFOptions.TargetDuration
		}

		c.Check(keyslot.KDF.Memory, snapd_testutil.IntLessEqual, expectedMemoryKiB)

		start := time.Now()
		luks2test.CheckLUKS2Passphrase(c, devicePath, data.key)
		elapsed := time.Now().Sub(start)
		// Check KDF time here with +/-20% tolerance and additional 500ms for cryptsetup exec and other activities
		c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntGreaterThan, int(float64(expectedKDFTime/time.Millisecond)*0.8))
		c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntLessThan, int(float64(expectedKDFTime/time.Millisecond)*1.2)+500)
	}
}

func (s *cryptsetupSuite) TestAddKeyDefaults(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key:     key,
		options: &AddKeyOptions{Slot: AnySlot}})
}

func (s *cryptsetupSuite) TestAddKeyNilOptions(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{key: key})
}

func (s *cryptsetupSuite) TestAddKeyWithCustomKDFTime(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		options: &AddKeyOptions{
			KDFOptions: KDFOptions{TargetDuration: 100 * time.Millisecond},
			Slot:       AnySlot}})
}

func (s *cryptsetupSuite) TestAddKeyWithCustomKDFMemory(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		options: &AddKeyOptions{
			KDFOptions: KDFOptions{TargetDuration: 100 * time.Millisecond, MemoryKiB: 32 * 1024},
			Slot:       AnySlot}})
}

func (s *cryptsetupSuite) TestAddKeyWithForceIterations(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		options: &AddKeyOptions{
			KDFOptions: KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4},
			Slot:       AnySlot}})
}

func (s *cryptsetupSuite) TestAddKeyWithSpecificKeyslot(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		options: &AddKeyOptions{
			KDFOptions: KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4},
			Slot:       8}})
}

func (s *cryptsetupSuite) TestAddKeyWithIncorrectExistingKey(c *C) {
	primaryKey := make([]byte, 32)
	rand.Read(primaryKey)

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	options := FormatOptions{KDFOptions: KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}}
	c.Assert(Format(devicePath, "", primaryKey, &options), IsNil)

	c.Check(AddKey(devicePath, make([]byte, 32), []byte("foo"), nil), ErrorMatches, "cryptsetup failed with: No key available with this passphrase.")

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 1)
	_, ok := info.Metadata.Keyslots[0]
	c.Check(ok, Equals, true)

	luks2test.CheckLUKS2Passphrase(c, devicePath, primaryKey)
}

type testImportTokenData struct {
	token            Token
	options          *ImportTokenOptions
	expectedKeyslots []int
	expectedParams   map[string]interface{}
}

func (s *cryptsetupSuite) testImportToken(c *C, data *testImportTokenData) {
	if DetectCryptsetupFeatures()&FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: kdfOptions}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 32), make([]byte, 32), &AddKeyOptions{KDFOptions: kdfOptions, Slot: AnySlot}), IsNil)

	c.Check(ImportToken(devicePath, data.token, data.options), IsNil)

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)

	id := 0
	if data.options != nil && data.options.Id != AnyId {
		id = data.options.Id
	}

	c.Assert(info.Metadata.Tokens, HasLen, 1)
	token, ok := info.Metadata.Tokens[id].(*GenericToken)
	c.Assert(ok, Equals, true)
	c.Check(token.TokenType, Equals, data.token.Type())
	c.Check(token.TokenKeyslots, DeepEquals, data.token.Keyslots())
	c.Check(token.Params, DeepEquals, data.expectedParams)
}

func (s *cryptsetupSuite) TestImportToken1(c *C) {
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &GenericToken{
			TokenType:     "secboot-test",
			TokenKeyslots: []int{0},
			Params: map[string]interface{}{
				"secboot-a": 50,
				"secboot-b": data}},
		expectedKeyslots: []int{0},
		expectedParams: map[string]interface{}{
			"secboot-a": float64(50),
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *cryptsetupSuite) TestImportToken2(c *C) {
	// Test with a different type, keyslot and data types.
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &GenericToken{
			TokenType:     "secboot-test-2",
			TokenKeyslots: []int{1},
			Params: map[string]interface{}{
				"secboot-a": true,
				"secboot-b": data}},
		expectedKeyslots: []int{1},
		expectedParams: map[string]interface{}{
			"secboot-a": true,
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *cryptsetupSuite) TestImportToken3(c *C) {
	// Test with multiple keyslots.
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &GenericToken{
			TokenType:     "secboot-test",
			TokenKeyslots: []int{0, 1},
			Params: map[string]interface{}{
				"secboot-a": 50,
				"secboot-b": data}},
		expectedKeyslots: []int{0, 1},
		expectedParams: map[string]interface{}{
			"secboot-a": float64(50),
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *cryptsetupSuite) TestImportToken4(c *C) {
	// Test with options
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &GenericToken{
			TokenType:     "secboot-test",
			TokenKeyslots: []int{0},
			Params: map[string]interface{}{
				"secboot-a": 50,
				"secboot-b": data}},
		options:          &ImportTokenOptions{Id: AnyId},
		expectedKeyslots: []int{0},
		expectedParams: map[string]interface{}{
			"secboot-a": float64(50),
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *cryptsetupSuite) TestImportToken5(c *C) {
	// Test with specific ID
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &GenericToken{
			TokenType:     "secboot-test",
			TokenKeyslots: []int{0},
			Params: map[string]interface{}{
				"secboot-a": 50,
				"secboot-b": data}},
		options:          &ImportTokenOptions{Id: 8},
		expectedKeyslots: []int{0},
		expectedParams: map[string]interface{}{
			"secboot-a": float64(50),
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *cryptsetupSuite) TestImportTokenUnsupported(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: kdfOptions}), IsNil)

	_, reset := s.mockCryptsetupFeatures(c, 0)
	defer reset()

	token := &GenericToken{
		TokenType:     "secboot-test",
		TokenKeyslots: []int{0}}
	c.Check(ImportToken(devicePath, token, nil), Equals, ErrMissingCryptsetupFeature)
}

func (s *cryptsetupSuite) TestReplaceToken(c *C) {
	if DetectCryptsetupFeatures()&(FeatureTokenImport|FeatureTokenReplace) != FeatureTokenImport|FeatureTokenReplace {
		c.Skip("cryptsetup doesn't support token import and replace")
	}

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: kdfOptions}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 32), make([]byte, 32), &AddKeyOptions{KDFOptions: kdfOptions, Slot: AnySlot}), IsNil)

	token1 := &GenericToken{
		TokenType:     "secboot-test",
		TokenKeyslots: []int{0},
		Params:        map[string]interface{}{"secboot-a": float64(50)}}
	c.Check(ImportToken(devicePath, token1, nil), IsNil)

	token2 := &GenericToken{
		TokenType:     "secboot-test",
		TokenKeyslots: []int{0},
		Params:        map[string]interface{}{"secboot-a": float64(60)}}
	c.Check(ImportToken(devicePath, token2, &ImportTokenOptions{Id: 8}), IsNil)

	token2 = &GenericToken{
		TokenType:     "secboot-test",
		TokenKeyslots: []int{0},
		Params:        map[string]interface{}{"secboot-a": float64(70)}}
	c.Check(ImportToken(devicePath, token2, &ImportTokenOptions{Id: 8, Replace: true}), IsNil)

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)

	c.Assert(info.Metadata.Tokens, HasLen, 2)

	token, ok := info.Metadata.Tokens[0].(*GenericToken)
	c.Assert(ok, Equals, true)
	c.Check(token.TokenType, Equals, token1.TokenType)
	c.Check(token.TokenKeyslots, DeepEquals, token1.TokenKeyslots)
	c.Check(token.Params, DeepEquals, token1.Params)

	token, ok = info.Metadata.Tokens[8].(*GenericToken)
	c.Assert(ok, Equals, true)
	c.Check(token.TokenType, Equals, token2.TokenType)
	c.Check(token.TokenKeyslots, DeepEquals, token2.TokenKeyslots)
	c.Check(token.Params, DeepEquals, token2.Params)
}

type mockToken struct {
	TokenType     TokenType    `json:"type"`
	TokenKeyslots []JsonNumber `json:"keyslots"`
	A             string       `json:"secboot-a"`
	B             int          `json:"secboot-b"`
}

func (t *mockToken) Type() TokenType { return t.TokenType }

func (t *mockToken) Keyslots() []int {
	var slots []int
	for _, v := range t.TokenKeyslots {
		slot, _ := v.Int()
		slots = append(slots, slot)
	}
	return slots
}

func (s *cryptsetupSuite) TestImportExternalToken(c *C) {
	s.testImportToken(c, &testImportTokenData{
		token: &mockToken{
			TokenType:     "secboot-test",
			TokenKeyslots: []JsonNumber{"0"},
			A:             "bar",
			B:             30},
		expectedKeyslots: []int{0},
		expectedParams: map[string]interface{}{
			"secboot-a": "bar",
			"secboot-b": float64(30)}})
}

func (s *cryptsetupSuite) testRemoveToken(c *C, tokenId int) {
	if DetectCryptsetupFeatures()&FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: kdfOptions}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 32), make([]byte, 32), &AddKeyOptions{KDFOptions: kdfOptions, Slot: AnySlot}), IsNil)
	c.Assert(ImportToken(devicePath, &GenericToken{TokenType: "secboot-foo", TokenKeyslots: []int{0}}, nil), IsNil)
	c.Assert(ImportToken(devicePath, &GenericToken{TokenType: "secboot-bar", TokenKeyslots: []int{1}}, nil), IsNil)

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Tokens, HasLen, 2)
	_, ok := info.Metadata.Tokens[tokenId]
	c.Check(ok, Equals, true)

	c.Check(RemoveToken(devicePath, tokenId), IsNil)

	info, err = ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Tokens, HasLen, 1)
	_, ok = info.Metadata.Tokens[tokenId]
	c.Check(ok, Equals, false)
}

func (s *cryptsetupSuite) TestRemoveToken1(c *C) {
	s.testRemoveToken(c, 0)
}

func (s *cryptsetupSuite) TestRemoveToken2(c *C) {
	s.testRemoveToken(c, 1)
}

func (s *cryptsetupSuite) TestRemoveNonExistantToken(c *C) {
	if DetectCryptsetupFeatures()&FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	options := FormatOptions{KDFOptions: KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}}
	c.Assert(Format(devicePath, "", make([]byte, 32), &options), IsNil)
	c.Assert(ImportToken(devicePath, &GenericToken{TokenType: "secboot-foo", TokenKeyslots: []int{0}}, nil), IsNil)

	c.Check(RemoveToken(devicePath, 10), ErrorMatches, "cryptsetup failed with: Token 10 is not in use.")

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Tokens, HasLen, 1)
	_, ok := info.Metadata.Tokens[0]
	c.Check(ok, Equals, true)
}

type testKillSlotData struct {
	key1    []byte
	key2    []byte
	key     []byte
	slotId  int
	testKey []byte
}

func (s *cryptsetupSuite) testKillSlot(c *C, data *testKillSlotData) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}
	c.Assert(Format(devicePath, "", data.key1, &FormatOptions{KDFOptions: kdfOptions}), IsNil)
	c.Assert(AddKey(devicePath, data.key1, data.key2, &AddKeyOptions{KDFOptions: kdfOptions, Slot: AnySlot}), IsNil)

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 2)
	_, ok := info.Metadata.Keyslots[data.slotId]
	c.Check(ok, Equals, true)

	c.Check(KillSlot(devicePath, data.slotId, data.key), IsNil)

	info, err = ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 1)
	_, ok = info.Metadata.Keyslots[data.slotId]
	c.Check(ok, Equals, false)

	luks2test.CheckLUKS2Passphrase(c, devicePath, data.testKey)
}

func (s *cryptsetupSuite) TestKillSlot1(c *C) {
	key1 := make([]byte, 32)
	rand.Read(key1)
	key2 := make([]byte, 32)
	rand.Read(key2)

	s.testKillSlot(c, &testKillSlotData{
		key1:    key1,
		key2:    key2,
		key:     key1,
		slotId:  1,
		testKey: key1})
}

func (s *cryptsetupSuite) TestKillSlot2(c *C) {
	key1 := make([]byte, 32)
	rand.Read(key1)
	key2 := make([]byte, 32)
	rand.Read(key2)

	s.testKillSlot(c, &testKillSlotData{
		key1:    key1,
		key2:    key2,
		key:     key2,
		slotId:  0,
		testKey: key2})
}

func (s *cryptsetupSuite) TestKillSlotWithWrongPassphrase(c *C) {
	key1 := make([]byte, 32)
	rand.Read(key1)
	key2 := make([]byte, 32)
	rand.Read(key2)

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}
	c.Assert(Format(devicePath, "", key1, &FormatOptions{KDFOptions: kdfOptions}), IsNil)
	c.Assert(AddKey(devicePath, key1, key2, &AddKeyOptions{KDFOptions: kdfOptions, Slot: AnySlot}), IsNil)

	c.Check(KillSlot(devicePath, 1, key2), ErrorMatches, "cryptsetup failed with: No key available with this passphrase.")

	luks2test.CheckLUKS2Passphrase(c, devicePath, key1)
	luks2test.CheckLUKS2Passphrase(c, devicePath, key2)
}

func (s *cryptsetupSuite) TestKillNonExistantSlot(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)
	options := FormatOptions{KDFOptions: KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}}
	c.Assert(Format(devicePath, "", key, &options), IsNil)

	c.Check(KillSlot(devicePath, 8, key), ErrorMatches, "cryptsetup failed with: Keyslot 8 is not active.")

	luks2test.CheckLUKS2Passphrase(c, devicePath, key)
}

type testSetSlotPriorityData struct {
	slotId   int
	priority SlotPriority
}

func (s *cryptsetupSuite) testSetSlotPriority(c *C, data *testSetSlotPriorityData) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{MemoryKiB: 32 * 1024, ForceIterations: 4}
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: kdfOptions}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 32), make([]byte, 32), &AddKeyOptions{KDFOptions: kdfOptions, Slot: AnySlot}), IsNil)

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	keyslot, ok := info.Metadata.Keyslots[data.slotId]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.Priority, Equals, SlotPriorityNormal)

	c.Check(SetSlotPriority(devicePath, data.slotId, data.priority), IsNil)

	info, err = ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	keyslot, ok = info.Metadata.Keyslots[data.slotId]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.Priority, Equals, data.priority)
}

func (s *cryptsetupSuite) TestSetSlotPriority1(c *C) {
	s.testSetSlotPriority(c, &testSetSlotPriorityData{
		slotId:   0,
		priority: SlotPriorityHigh})
}

func (s *cryptsetupSuite) TestSetSlotPriority2(c *C) {
	s.testSetSlotPriority(c, &testSetSlotPriorityData{
		slotId:   1,
		priority: SlotPriorityHigh})
}

func (s *cryptsetupSuite) TestSetSlotPriority3(c *C) {
	s.testSetSlotPriority(c, &testSetSlotPriorityData{
		slotId:   1,
		priority: SlotPriorityIgnore})
}
