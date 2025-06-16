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
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luks2/luks2test"
	"github.com/snapcore/secboot/internal/paths/pathstest"
	"github.com/snapcore/secboot/internal/testutil"
)

type cryptsetupSuiteBase struct {
	snapd_testutil.BaseTest

	cryptsetup *snapd_testutil.MockCmd
}

func (s *cryptsetupSuiteBase) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.AddCleanup(pathstest.MockRunDir(c.MkDir()))
	s.AddCleanup(luks2test.WrapCryptsetup(c))

	cryptsetupWrapperTpl := `exec %[1]s "$@" </dev/stdin`

	cryptsetup, err := exec.LookPath("cryptsetup")
	c.Assert(err, IsNil)

	s.cryptsetup = snapd_testutil.MockCommand(c, "cryptsetup", fmt.Sprintf(cryptsetupWrapperTpl, cryptsetup))
	s.AddCleanup(s.cryptsetup.Restore)

	// cryptsetup parameters are arch specific
	s.AddCleanup(MockRuntimeGOARCH("amd64"))
}

type cryptsetupSuite struct {
	cryptsetupSuiteBase
}

type cryptsetupSuiteExpensive struct {
	cryptsetupSuiteBase
}

func (s *cryptsetupSuiteExpensive) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_EXPENSIVE_CRYPTSETUP_TESTS"); exists {
		c.Skip("skipping expensive cryptsetup tests")
	}
}

func (s *cryptsetupSuiteBase) mockCryptsetupFeatures(c *C, features Features) (cmd *snapd_testutil.MockCmd, reset func()) {
	ResetCryptsetupFeatures()

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
		ResetCryptsetupFeatures()
		cmd.Restore()
	}
}

var _ = Suite(&cryptsetupSuite{})
var _ = Suite(&cryptsetupSuiteExpensive{})

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

func (s *cryptsetupSuite) TestFormatOptionsValidateGood(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	for _, opts := range []FormatOptions{
		{MetadataKiBSize: 16},
		{MetadataKiBSize: 32},
		{MetadataKiBSize: 64},
		{MetadataKiBSize: 128},
		{MetadataKiBSize: 256},
		{MetadataKiBSize: 512},
		{MetadataKiBSize: 1024},
		{MetadataKiBSize: 2048},
		{MetadataKiBSize: 4096},
		{KeyslotsAreaKiBSize: 2040},
		{KeyslotsAreaKiBSize: 4096},
		{KeyslotsAreaKiBSize: 128 * 1024},
	} {
		opts.KDFOptions = KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}
		c.Check(Format(devicePath, "", make([]byte, 32), &opts), IsNil, Commentf("opts: %#v", opts))
	}
}

func (s *cryptsetupSuite) TestFormatOptionsValidateBadMetadataSize(c *C) {
	for _, opts := range []FormatOptions{
		{MetadataKiBSize: 1},
		{MetadataKiBSize: 19},
		{MetadataKiBSize: 8192},
	} {
		c.Check(Format("/dev/null", "", make([]byte, 32), &opts), ErrorMatches,
			fmt.Sprintf("cannot set metadata size to %v KiB", opts.MetadataKiBSize))
	}
}

func (s *cryptsetupSuite) TestFormatOptionsValidateBadKeyslotsAreaSize(c *C) {
	var minSize uint32
	switch KeySize(SelectCipher()) {
	case 32:
		minSize = 124
	case 64:
		minSize = 248
	default:
		c.Fatalf("unknown keysize")
	}

	for _, opts := range []FormatOptions{
		// minimum size
		{KeyslotsAreaKiBSize: minSize},
		// must be multiply of 4KiB
		{KeyslotsAreaKiBSize: (4 * 1024) + 1},
		// can't be more than 128MiB
		{KeyslotsAreaKiBSize: 128*1024 + 1},
		{KeyslotsAreaKiBSize: 256 * 1024},
	} {
		c.Check(Format("/dev/null", "", make([]byte, 32), &opts), ErrorMatches,
			fmt.Sprintf("cannot set keyslots area size to %v KiB", opts.KeyslotsAreaKiBSize), Commentf("%v", opts))
	}
}

func (s *cryptsetupSuite) TestFormatKDFOptionsValidateGood(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	for _, opts := range []KDFOptions{
		{Type: KDFTypePBKDF2, ForceIterations: 2000},
		{Type: KDFTypePBKDF2, ForceIterations: 2000, Hash: HashSHA512},
		{Type: KDFTypeArgon2i, ForceIterations: 4, MemoryKiB: 32 * 1024},
	} {
		c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: opts}), IsNil, Commentf("opts: %#v", opts))
	}
}

func (s *cryptsetupSuite) TestFormatKDFOptionsValidateBadForcedIterWithBenchmark(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)
	c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: KDFOptions{Type: KDFTypeArgon2i, TargetDuration: 100 * time.Millisecond, ForceIterations: 4}}),
		ErrorMatches, `cannot use both ForceIterations and TargetDuration`)
}

func (s *cryptsetupSuite) TestFormatKDFOptionsValidateBadPBKDF2Options(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	for _, opts := range []KDFOptions{
		{Type: KDFTypePBKDF2, MemoryKiB: 64 * 1024},
		{Type: KDFTypePBKDF2, Parallel: 1},
	} {
		c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: opts}),
			ErrorMatches, `cannot use argon2 options with pbkdf2`, Commentf("opts: %#v", opts))
	}
}

func (s *cryptsetupSuite) TestFormatKDFOptionsValidateBadPBKDF2ForceIterations(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	for _, opts := range []KDFOptions{
		{Type: KDFTypePBKDF2, ForceIterations: 999},
		{Type: KDFTypePBKDF2, ForceIterations: 500},
	} {
		c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: opts}),
			ErrorMatches, fmt.Sprintf("cannot set pbkdf2 ForceIterations to %d", opts.ForceIterations), Commentf("opts: %#v", opts))
	}
}

func (s *cryptsetupSuite) TestFormatKDFOptionsValidateBadArgon2ForceIterations(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	for _, opts := range []KDFOptions{
		{Type: KDFTypeArgon2i, ForceIterations: 3},
		{Type: KDFTypeArgon2i, ForceIterations: 1},
	} {
		c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: opts}),
			ErrorMatches, fmt.Sprintf("cannot set argon2 ForceIterations to %d", opts.ForceIterations), Commentf("opts: %#v", opts))
	}
}

func (s *cryptsetupSuite) TestFormatKDFOptionsValidateBadArgon2Parallel(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	for _, opts := range []KDFOptions{
		{Type: KDFTypeArgon2i, Parallel: 5},
		{Type: KDFTypeArgon2i, Parallel: 8},
	} {
		c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: opts}),
			ErrorMatches, fmt.Sprintf("cannot set argon2 Parallel to %d", opts.Parallel), Commentf("opts: %#v", opts))
	}
}

func (s *cryptsetupSuite) TestFormatKDFOptionsValidateBadOptionsWithNoType(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	for _, opts := range []KDFOptions{
		{MemoryKiB: 32 * 1024},
		{ForceIterations: 1000},
		{Parallel: 4},
		{Hash: HashSHA256},
	} {
		c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: opts}),
			ErrorMatches, `cannot set options without selecting a type`, Commentf("opts: %#v", opts))
	}
}

func (s *cryptsetupSuite) TestFormatKDFOptionsValidateBadArgon2Memory(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	for _, opts := range []KDFOptions{
		{Type: KDFTypeArgon2i, MemoryKiB: 31},
		{Type: KDFTypeArgon2i, MemoryKiB: 5 * 1024 * 1024},
	} {
		c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: opts}),
			ErrorMatches, fmt.Sprintf("cannot set argon2 MemoryKiB to %d", opts.MemoryKiB), Commentf("opts: %#v", opts))
	}
}

func (s *cryptsetupSuiteExpensive) TestFormatKDFOptionsValidateGood(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	for _, opts := range []KDFOptions{
		{},
		{TargetDuration: 100 * time.Millisecond},
		{Type: KDFTypePBKDF2},
		{Type: KDFTypePBKDF2, TargetDuration: 100 * time.Millisecond},
		{Type: KDFTypePBKDF2, Hash: HashSHA512},
		{Type: KDFTypePBKDF2, TargetDuration: 100 * time.Millisecond, Hash: HashSHA512},
		{Type: KDFTypeArgon2i},
		{Type: KDFTypeArgon2i, TargetDuration: 100 * time.Millisecond},
		{Type: KDFTypeArgon2i, MemoryKiB: 64 * 1024},
		{Type: KDFTypeArgon2i, ForceIterations: 4},
		{Type: KDFTypeArgon2i, Parallel: 1},
		{Type: KDFTypeArgon2i, TargetDuration: 100 * time.Millisecond, MemoryKiB: 64 * 1024},
	} {
		c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: opts}), IsNil, Commentf("opts: %#v", opts))
	}
}

type testFormatData struct {
	label   string
	key     []byte
	options *FormatOptions

	extraArgs []string
}

func (s *cryptsetupSuiteBase) testFormat(c *C, data *testFormatData) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	c.Check(Format(devicePath, data.label, data.key, data.options), IsNil)

	cipher := SelectCipher()
	keysize := KeySize(cipher)
	cmd := []string{"cryptsetup", "--batch-mode", "luksFormat", "--type", "luks2",
		"--key-file", "-", "--cipher", cipher, "--key-size", strconv.Itoa(keysize * 8),
		"--label", data.label}
	cmd = append(cmd, data.extraArgs...)
	cmd = append(cmd, devicePath)
	c.Check(s.cryptsetup.Calls(), DeepEquals, [][]string{cmd})

	options := data.options
	if options == nil {
		options = new(FormatOptions)
	}

	info, err := ReadHeader(context.Background(), devicePath)
	c.Assert(err, IsNil)

	c.Check(info.Label, Equals, data.label)

	c.Check(info.Metadata.Keyslots, HasLen, 1)
	keyslot, ok := info.Metadata.Keyslots[0]
	c.Assert(ok, Equals, true)

	// Handle any default in cryptsetup - we only test keyslot.KDF.Type
	// when the test is explicit about the value.
	expectedKDFType := keyslot.KDF.Type
	if options.KDFOptions.Type != "" {
		expectedKDFType = options.KDFOptions.Type
	}

	c.Check(keyslot.KeySize, Equals, keysize)
	c.Check(keyslot.Priority, Equals, SlotPriorityNormal)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, expectedKDFType)

	switch expectedKDFType {
	case KDFTypeArgon2i, KDFTypeArgon2id:
		expectedMemoryKiB := 1 * 1024 * 1024
		if options.KDFOptions.MemoryKiB > 0 {
			expectedMemoryKiB = int(options.KDFOptions.MemoryKiB)
		}

		if options.KDFOptions.ForceIterations > 0 {
			c.Check(keyslot.KDF.Time, Equals, int(options.KDFOptions.ForceIterations))
			c.Check(keyslot.KDF.Memory, Equals, expectedMemoryKiB)
		} else {
			c.Check(keyslot.KDF.Memory, snapd_testutil.IntLessEqual, expectedMemoryKiB)
		}
		c.Check(keyslot.KDF.Iterations, Equals, 0)
	case KDFTypePBKDF2:
		if options.KDFOptions.ForceIterations > 0 {
			c.Check(keyslot.KDF.Iterations, Equals, int(options.KDFOptions.ForceIterations))
		}
		if options.KDFOptions.Hash != "" {
			c.Check(keyslot.KDF.Hash, Equals, options.KDFOptions.Hash)
		}
		c.Check(keyslot.KDF.Time, Equals, 0)
	}

	c.Check(info.Metadata.Segments, HasLen, 1)
	segment, ok := info.Metadata.Segments[0]
	c.Assert(ok, Equals, true)
	c.Check(segment.Encryption, Equals, cipher)

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

	// We used to time this to make sure we are supplying the correct parameters to
	// cryptsetup, but that was unreliable. For now, we rely on the command line
	// parameters that were tested earlier, and trust that those are correct.
	c.Check(TestContainerKey(devicePath, data.key), testutil.IsTrue)
}

func (s *cryptsetupSuiteExpensive) TestFormatDefaults(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:   "test",
		key:     key,
		options: &FormatOptions{},
	})
}

func (s *cryptsetupSuiteExpensive) TestFormatNilOptions(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label: "test",
		key:   key})
}

func (s *cryptsetupSuiteExpensive) TestFormatWithArgon2i(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:     "test",
		key:       key,
		options:   &FormatOptions{KDFOptions: KDFOptions{Type: KDFTypeArgon2i}},
		extraArgs: []string{"--pbkdf", "argon2i"},
	})
}

func (s *cryptsetupSuiteExpensive) TestFormatWithArgon2id(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:     "test",
		key:       key,
		options:   &FormatOptions{KDFOptions: KDFOptions{Type: KDFTypeArgon2id}},
		extraArgs: []string{"--pbkdf", "argon2id"},
	})
}

func (s *cryptsetupSuiteExpensive) TestFormatWithCustomKDFTime(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:     "test",
		key:       key,
		options:   &FormatOptions{KDFOptions: KDFOptions{TargetDuration: 100 * time.Millisecond}},
		extraArgs: []string{"--iter-time", "100"},
	})
}

func (s *cryptsetupSuiteExpensive) TestFormatWithCustomKDFMemory(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:     "data",
		key:       key,
		options:   &FormatOptions{KDFOptions: KDFOptions{Type: KDFTypeArgon2id, TargetDuration: 100 * time.Millisecond, MemoryKiB: 32 * 1024}},
		extraArgs: []string{"--pbkdf", "argon2id", "--iter-time", "100", "--pbkdf-memory", "32768"},
	})
}

func (s *cryptsetupSuite) TestFormatWithForceIterations(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:     "data",
		key:       key,
		options:   &FormatOptions{KDFOptions: KDFOptions{Type: KDFTypeArgon2id, MemoryKiB: 32 * 1024, ForceIterations: 4}},
		extraArgs: []string{"--pbkdf", "argon2id", "--pbkdf-memory", "32768", "--pbkdf-force-iterations", "4"},
	})
}

func (s *cryptsetupSuiteExpensive) TestFormatWithPBKDF2(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:     "test",
		key:       key,
		options:   &FormatOptions{KDFOptions: KDFOptions{Type: KDFTypePBKDF2}},
		extraArgs: []string{"--pbkdf", "pbkdf2"},
	})
}

func (s *cryptsetupSuite) TestFormatWithPBKDF2ForceIterations(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:     "test",
		key:       key,
		options:   &FormatOptions{KDFOptions: KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}},
		extraArgs: []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"},
	})
}

func (s *cryptsetupSuite) TestFormatWithPBKDF2CustomHash(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:     "test",
		key:       key,
		options:   &FormatOptions{KDFOptions: KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000, Hash: HashSHA512}},
		extraArgs: []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--hash", "sha512"},
	})
}

func (s *cryptsetupSuite) TestFormatWithDifferentLabel(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:     "data",
		key:       key,
		options:   &FormatOptions{KDFOptions: KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}},
		extraArgs: []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"},
	})
}

func (s *cryptsetupSuite) TestFormatWithCustomMetadataSize(c *C) {
	if DetectCryptsetupFeatures()&FeatureHeaderSizeSetting == 0 {
		c.Skip("cryptsetup doesn't support --luks2-metadata-size")
	}
	s.cryptsetup.ForgetCalls()

	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label: "test",
		key:   key,
		options: &FormatOptions{
			KDFOptions:      KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000},
			MetadataKiBSize: 2 * 1024},
		extraArgs: []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--luks2-metadata-size", "2048k"},
	})
}

func (s *cryptsetupSuite) TestFormatWithCustomKeyslotsAreaSize(c *C) {
	if DetectCryptsetupFeatures()&FeatureHeaderSizeSetting == 0 {
		c.Skip("cryptsetup doesn't support --luks2-keyslots-size")
	}
	s.cryptsetup.ForgetCalls()

	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label: "test",
		key:   key,
		options: &FormatOptions{
			KDFOptions:          KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000},
			KeyslotsAreaKiBSize: 2 * 1024},
		extraArgs: []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--luks2-keyslots-size", "2048k"},
	})
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

func (s *cryptsetupSuite) TestFormatWithInvalidMetadataSize(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)
	c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{MetadataKiBSize: 20}), ErrorMatches, "cannot set metadata size to 20 KiB")
}

func (s *cryptsetupSuite) TestFormatWithInvalidKeyslotsAreaSize(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)
	c.Check(Format(devicePath, "", make([]byte, 32), &FormatOptions{KeyslotsAreaKiBSize: 41}), ErrorMatches, "cannot set keyslots area size to 41 KiB")
}

func (s *cryptsetupSuite) TestFormatWithInlineCryptoEngine(c *C) {
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", "echo cryptsetup 2.6.1")
	defer mockCryptsetup.Restore()

	key := make([]byte, 32)
	rand.Read(key)
	options := &FormatOptions{
		KDFOptions: KDFOptions{
			Type: KDFTypePBKDF2, ForceIterations: 1000},
		KeyslotsAreaKiBSize: 2 * 1024,
		InlineCryptoEngine:  true}
	err := Format("some-path", "test", key, options)
	c.Assert(err, IsNil)
	// feature detection
	c.Assert(mockCryptsetup.Calls(), HasLen, 3)
	c.Check(mockCryptsetup.Calls()[2], snapd_testutil.Contains, "--inline-crypto-engine")
}

type testAddKeyData struct {
	key     []byte
	options *AddKeyOptions
	time    time.Duration

	extraArgs []string
}

func (s *cryptsetupSuiteBase) testAddKey(c *C, data *testAddKeyData) {
	primaryKey := make([]byte, 32)
	rand.Read(primaryKey)

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)
	fmtOpts := FormatOptions{KDFOptions: KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}}
	c.Assert(Format(devicePath, "", primaryKey, &fmtOpts), IsNil)

	s.cryptsetup.ForgetCalls()

	startInfo, err := ReadHeader(context.Background(), devicePath)
	c.Assert(err, IsNil)

	c.Check(AddKey(devicePath, primaryKey, data.key, data.options), IsNil)

	c.Assert(s.cryptsetup.Calls(), HasLen, 1)
	c.Assert(s.cryptsetup.Calls()[0], HasLen, 11+len(data.extraArgs))
	c.Check(s.cryptsetup.Calls()[0][0:9], DeepEquals, []string{"cryptsetup", "luksAddKey", "--type", "luks2", "--key-file", "-", "--keyfile-size", strconv.Itoa(len(primaryKey)), "--batch-mode"})
	if len(data.extraArgs) > 0 {
		c.Check(s.cryptsetup.Calls()[0][9:9+len(data.extraArgs)], DeepEquals, data.extraArgs)
	}
	c.Check(s.cryptsetup.Calls()[0][9+len(data.extraArgs):], DeepEquals, []string{devicePath, "-"})

	endInfo, err := ReadHeader(context.Background(), devicePath)
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

	// Handle any default in cryptsetup - we only test keyslot.KDF.Type
	// when the test is explicit about the value.
	expectedKDFType := keyslot.KDF.Type
	if options.KDFOptions.Type != "" {
		expectedKDFType = options.KDFOptions.Type
	}

	cipher := SelectCipher()
	c.Check(keyslot.KeySize, Equals, KeySize(cipher))
	c.Check(keyslot.Priority, Equals, SlotPriorityNormal)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, expectedKDFType)

	switch expectedKDFType {
	case KDFTypeArgon2i, KDFTypeArgon2id:
		expectedMemoryKiB := 1 * 1024 * 1024
		if options.KDFOptions.MemoryKiB > 0 {
			expectedMemoryKiB = int(options.KDFOptions.MemoryKiB)
		}

		if options.KDFOptions.ForceIterations > 0 {
			c.Check(keyslot.KDF.Time, Equals, int(options.KDFOptions.ForceIterations))
			c.Check(keyslot.KDF.Memory, Equals, expectedMemoryKiB)
		} else {
			c.Check(keyslot.KDF.Memory, snapd_testutil.IntLessEqual, expectedMemoryKiB)
		}
		c.Check(keyslot.KDF.Iterations, Equals, 0)
	case KDFTypePBKDF2:
		if options.KDFOptions.ForceIterations > 0 {
			c.Check(keyslot.KDF.Iterations, Equals, int(options.KDFOptions.ForceIterations))
		}
		if options.KDFOptions.Hash != "" {
			c.Check(keyslot.KDF.Hash, Equals, options.KDFOptions.Hash)
		}
		c.Check(keyslot.KDF.Time, Equals, 0)
	}

	// We used to time this to make sure we are supplying the correct parameters to
	// cryptsetup, but that was unreliable. For now, we rely on the command line
	// parameters that were tested earlier, and trust that those are correct.
	c.Check(TestContainerKey(devicePath, data.key), testutil.IsTrue)
}

func (s *cryptsetupSuiteExpensive) TestAddKeyDefaults(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key:     key,
		options: &AddKeyOptions{Slot: AnySlot}})
}

func (s *cryptsetupSuiteExpensive) TestAddKeyNilOptions(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{key: key})
}

func (s *cryptsetupSuiteExpensive) TestAddKeyWithArgon2(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key:       key,
		options:   &AddKeyOptions{Slot: AnySlot, KDFOptions: KDFOptions{Type: KDFTypeArgon2i}},
		extraArgs: []string{"--pbkdf", "argon2i"},
	})
}

func (s *cryptsetupSuiteExpensive) TestAddKeyWithArgon2id(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key:       key,
		options:   &AddKeyOptions{Slot: AnySlot, KDFOptions: KDFOptions{Type: KDFTypeArgon2id}},
		extraArgs: []string{"--pbkdf", "argon2id"},
	})
}

func (s *cryptsetupSuiteExpensive) TestAddKeyWithCustomKDFTime(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		options: &AddKeyOptions{
			KDFOptions: KDFOptions{TargetDuration: 100 * time.Millisecond},
			Slot:       AnySlot},
		extraArgs: []string{"--iter-time", "100"}})
}

func (s *cryptsetupSuiteExpensive) TestAddKeyWithCustomKDFMemory(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		options: &AddKeyOptions{
			KDFOptions: KDFOptions{Type: KDFTypeArgon2id, TargetDuration: 100 * time.Millisecond, MemoryKiB: 32 * 1024},
			Slot:       AnySlot},
		extraArgs: []string{"--pbkdf", "argon2id", "--iter-time", "100", "--pbkdf-memory", "32768"}})
}

func (s *cryptsetupSuite) TestAddKeyWithForceIterations(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		options: &AddKeyOptions{
			KDFOptions: KDFOptions{Type: KDFTypeArgon2id, MemoryKiB: 32 * 1024, ForceIterations: 4},
			Slot:       AnySlot},
		extraArgs: []string{"--pbkdf", "argon2id", "--pbkdf-memory", "32768", "--pbkdf-force-iterations", "4"}})
}

func (s *cryptsetupSuiteExpensive) TestAddKeyWithPBKDF2(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key:       key,
		options:   &AddKeyOptions{Slot: AnySlot, KDFOptions: KDFOptions{Type: KDFTypePBKDF2}},
		extraArgs: []string{"--pbkdf", "pbkdf2"},
	})
}

func (s *cryptsetupSuite) TestAddKeyWithPBKDF2ForceIterations(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		options: &AddKeyOptions{
			KDFOptions: KDFOptions{
				Type:            KDFTypePBKDF2,
				ForceIterations: 1000,
			},
			Slot: AnySlot},
		extraArgs: []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"},
	})
}

func (s *cryptsetupSuite) TestAddKeyWithPBKDF2CustomHash(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		options: &AddKeyOptions{
			KDFOptions: KDFOptions{
				Type:            KDFTypePBKDF2,
				ForceIterations: 1000,
				Hash:            HashSHA512,
			},
			Slot: AnySlot},
		extraArgs: []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--hash", "sha512"},
	})
}

func (s *cryptsetupSuite) TestAddKeyWithSpecificKeyslot(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		options: &AddKeyOptions{
			KDFOptions: KDFOptions{
				Type:            KDFTypePBKDF2,
				ForceIterations: 1000,
			},
			Slot: 8},
		extraArgs: []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-slot", "8"}})
}

func (s *cryptsetupSuite) TestAddKeyWithIncorrectExistingKey(c *C) {
	primaryKey := make([]byte, 32)
	rand.Read(primaryKey)

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	options := FormatOptions{KDFOptions: KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}}
	c.Assert(Format(devicePath, "", primaryKey, &options), IsNil)

	c.Check(AddKey(devicePath, make([]byte, 32), []byte("foo"), nil), ErrorMatches, "cryptsetup failed with: No key available with this passphrase.")

	info, err := ReadHeader(context.Background(), devicePath)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 1)
	_, ok := info.Metadata.Keyslots[0]
	c.Check(ok, Equals, true)

	c.Check(TestContainerKey(devicePath, primaryKey), testutil.IsTrue)
}

type testImportTokenData struct {
	token   Token
	options *ImportTokenOptions

	extraArgs []string

	expectedKeyslots []int
	expectedParams   map[string]interface{}
}

func (s *cryptsetupSuite) testImportToken(c *C, data *testImportTokenData) {
	if DetectCryptsetupFeatures()&FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: kdfOptions}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 32), make([]byte, 32), &AddKeyOptions{KDFOptions: kdfOptions, Slot: AnySlot}), IsNil)

	s.cryptsetup.ForgetCalls()

	c.Check(ImportToken(devicePath, data.token, data.options), IsNil)

	c.Assert(s.cryptsetup.Calls(), HasLen, 1)
	c.Assert(s.cryptsetup.Calls()[0], HasLen, 4+len(data.extraArgs))
	c.Check(s.cryptsetup.Calls()[0][0:3], DeepEquals, []string{"cryptsetup", "token", "import"})
	if data.extraArgs != nil {
		c.Check(s.cryptsetup.Calls()[0][3:3+len(data.extraArgs)], DeepEquals, data.extraArgs)
	}
	c.Check(s.cryptsetup.Calls()[0][3+len(data.extraArgs)], Equals, devicePath)

	info, err := ReadHeader(context.Background(), devicePath)
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
		extraArgs:        []string{"--token-id", "8"},
		expectedKeyslots: []int{0},
		expectedParams: map[string]interface{}{
			"secboot-a": float64(50),
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *cryptsetupSuite) TestImportTokenUnsupported(c *C) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}
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

	kdfOptions := KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}
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

	s.cryptsetup.ForgetCalls()

	token2 = &GenericToken{
		TokenType:     "secboot-test",
		TokenKeyslots: []int{0},
		Params:        map[string]interface{}{"secboot-a": float64(70)}}
	c.Check(ImportToken(devicePath, token2, &ImportTokenOptions{Id: 8, Replace: true}), IsNil)

	c.Check(s.cryptsetup.Calls(), DeepEquals, [][]string{{"cryptsetup", "token", "import", "--token-id", "8", "--token-replace", devicePath}})

	info, err := ReadHeader(context.Background(), devicePath)
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

	kdfOptions := KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: kdfOptions}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 32), make([]byte, 32), &AddKeyOptions{KDFOptions: kdfOptions, Slot: AnySlot}), IsNil)
	c.Assert(ImportToken(devicePath, &GenericToken{TokenType: "secboot-foo", TokenKeyslots: []int{0}}, nil), IsNil)
	c.Assert(ImportToken(devicePath, &GenericToken{TokenType: "secboot-bar", TokenKeyslots: []int{1}}, nil), IsNil)

	info, err := ReadHeader(context.Background(), devicePath)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Tokens, HasLen, 2)
	_, ok := info.Metadata.Tokens[tokenId]
	c.Check(ok, Equals, true)

	s.cryptsetup.ForgetCalls()

	c.Check(RemoveToken(devicePath, tokenId), IsNil)

	c.Check(s.cryptsetup.Calls(), DeepEquals, [][]string{
		{"cryptsetup", "token", "remove", "--token-id", strconv.Itoa(tokenId), devicePath},
	})

	info, err = ReadHeader(context.Background(), devicePath)
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

	options := FormatOptions{KDFOptions: KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}}
	c.Assert(Format(devicePath, "", make([]byte, 32), &options), IsNil)
	c.Assert(ImportToken(devicePath, &GenericToken{TokenType: "secboot-foo", TokenKeyslots: []int{0}}, nil), IsNil)

	c.Check(RemoveToken(devicePath, 10), ErrorMatches, "cryptsetup failed with: Token 10 is not in use.")

	info, err := ReadHeader(context.Background(), devicePath)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Tokens, HasLen, 1)
	_, ok := info.Metadata.Tokens[0]
	c.Check(ok, Equals, true)
}

type testKillSlotData struct {
	key1    []byte
	key2    []byte
	slotId  int
	testKey []byte
}

func (s *cryptsetupSuite) testKillSlot(c *C, data *testKillSlotData) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}
	c.Assert(Format(devicePath, "", data.key1, &FormatOptions{KDFOptions: kdfOptions}), IsNil)
	c.Assert(AddKey(devicePath, data.key1, data.key2, &AddKeyOptions{KDFOptions: kdfOptions, Slot: AnySlot}), IsNil)

	info, err := ReadHeader(context.Background(), devicePath)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 2)
	_, ok := info.Metadata.Keyslots[data.slotId]
	c.Check(ok, Equals, true)

	s.cryptsetup.ForgetCalls()

	c.Check(KillSlot(devicePath, data.slotId), IsNil)

	c.Check(s.cryptsetup.Calls(), DeepEquals, [][]string{
		{"cryptsetup", "luksKillSlot", "--batch-mode", "--type", "luks2", devicePath, strconv.Itoa(data.slotId)},
	})

	info, err = ReadHeader(context.Background(), devicePath)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 1)
	_, ok = info.Metadata.Keyslots[data.slotId]
	c.Check(ok, Equals, false)

	c.Check(TestContainerKey(devicePath, data.testKey), testutil.IsTrue)
}

func (s *cryptsetupSuite) TestKillSlot1(c *C) {
	key1 := make([]byte, 32)
	rand.Read(key1)
	key2 := make([]byte, 32)
	rand.Read(key2)

	s.testKillSlot(c, &testKillSlotData{
		key1:    key1,
		key2:    key2,
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
		slotId:  0,
		testKey: key2})
}

func (s *cryptsetupSuite) TestKillNonExistantSlot(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	devicePath := luks2test.CreateEmptyDiskImage(c, 20)
	options := FormatOptions{KDFOptions: KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}}
	c.Assert(Format(devicePath, "", key, &options), IsNil)

	c.Check(KillSlot(devicePath, 8), ErrorMatches, "cryptsetup failed with: Keyslot 8 is not active.")

	c.Check(TestContainerKey(devicePath, key), testutil.IsTrue)
}

type testSetSlotPriorityData struct {
	slotId   int
	priority SlotPriority
}

func (s *cryptsetupSuite) testSetSlotPriority(c *C, data *testSetSlotPriorityData) {
	devicePath := luks2test.CreateEmptyDiskImage(c, 20)

	kdfOptions := KDFOptions{Type: KDFTypePBKDF2, ForceIterations: 1000}
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFOptions: kdfOptions}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 32), make([]byte, 32), &AddKeyOptions{KDFOptions: kdfOptions, Slot: AnySlot}), IsNil)

	info, err := ReadHeader(context.Background(), devicePath)
	c.Assert(err, IsNil)
	keyslot, ok := info.Metadata.Keyslots[data.slotId]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.Priority, Equals, SlotPriorityNormal)

	s.cryptsetup.ForgetCalls()

	c.Check(SetSlotPriority(devicePath, data.slotId, data.priority), IsNil)

	c.Check(s.cryptsetup.Calls(), DeepEquals, [][]string{
		{"cryptsetup", "config", "--priority", data.priority.String(), "--key-slot", strconv.Itoa(data.slotId), devicePath},
	})

	info, err = ReadHeader(context.Background(), devicePath)
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

var _ = Suite(&cryptsetupSuiteARM{})

type cryptsetupSuiteARM struct {
	cryptsetupSuite
}

func (s *cryptsetupSuiteARM) SetUpTest(c *C) {
	s.cryptsetupSuite.SetUpTest(c)
	s.AddCleanup(MockRuntimeGOARCH("arm"))
}

var _ = Suite(&cipherSuite{})

type cipherSuite struct {
	snapd_testutil.BaseTest
}

func (s *cipherSuite) TestSelectCipherAndKeysize(c *C) {
	for _, tc := range []struct {
		arch string

		expectedCipher  string
		expectedKeysize int
	}{
		{"386", "aes-xts-plain64", 64},
		{"amd64", "aes-xts-plain64", 64},
		{"arm64", "aes-xts-plain64", 64},
		{"ppc", "aes-xts-plain64", 64},
		{"ppc64", "aes-xts-plain64", 64},
		{"ppc64le", "aes-xts-plain64", 64},
		{"riscv64", "aes-xts-plain64", 64},
		{"s390x", "aes-xts-plain64", 64},
		{"", "aes-xts-plain64", 64},
		// only arm is using a different cipher
		{"arm", "aes-cbc-essiv:sha256", 32},
	} {
		s.AddCleanup(MockRuntimeGOARCH(tc.arch))
		cipher := SelectCipher()
		keysize := KeySize(cipher)
		c.Check(cipher, Equals, tc.expectedCipher)
		c.Check(keysize, Equals, tc.expectedKeysize)
	}
}
