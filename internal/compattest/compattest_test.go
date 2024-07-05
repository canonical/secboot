// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package compattest

import (
	"bufio"
	"encoding/hex"
	"flag"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tpm2test"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

func init() {
	tpm2_testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

type compatTestSuiteBase struct {
	tpm2test.TPMSimulatorTest
	dataPath string
	tmpDir   string
}

func (s *compatTestSuiteBase) setUpSuiteBase(c *C, dataPath string) {
	if tpm2_testutil.TPMBackend != tpm2_testutil.TPMBackendMssim {
		c.Skip("-use-mssim not supplied")
	}
	s.dataPath = dataPath
}

func (s *compatTestSuiteBase) SetUpTest(c *C) {
	s.tmpDir = c.MkDir()

	srcDir, err := os.Open(s.dataPath)
	c.Assert(err, IsNil)
	defer srcDir.Close()

	srcDirFiles, err := srcDir.Readdir(0)
	c.Assert(err, IsNil)

	for _, fi := range srcDirFiles {
		if fi.Name() == "NVChip" {
			continue
		}

		func() {
			src, err := os.Open(filepath.Join(s.dataPath, fi.Name()))
			c.Assert(err, IsNil)
			defer src.Close()

			dest, err := os.Create(filepath.Join(s.tmpDir, fi.Name()))
			c.Assert(err, IsNil)
			defer dest.Close()

			_, err = io.Copy(dest, src)
			c.Assert(err, IsNil)
		}()
	}

	simulatorShutdown, err := tpm2_testutil.LaunchTPMSimulator(&tpm2_testutil.TPMSimulatorOptions{SourcePath: s.dataPath + "/NVChip"})
	c.Assert(err, IsNil)

	s.InitCleanup(c)
	s.AddFixtureCleanup(func(_ *C) { simulatorShutdown() })

	s.TPMSimulatorTest.SetUpTest(c)
}

func (s *compatTestSuiteBase) absPath(name string) string {
	return filepath.Join(s.tmpDir, name)
}

func (s *compatTestSuiteBase) readFile(c *C, name string) []byte {
	b, err := ioutil.ReadFile(s.absPath(name))
	c.Assert(err, IsNil)
	return b
}

func (s *compatTestSuiteBase) replayPCRSequenceFromReader(c *C, r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		components := strings.Split(scanner.Text(), " ")
		c.Assert(len(components), Equals, 3)

		pcr, err := strconv.Atoi(components[0])
		c.Assert(err, IsNil)
		alg, err := strconv.ParseUint(components[1], 10, 16)
		c.Assert(err, IsNil)
		digest, err := hex.DecodeString(components[2])
		c.Assert(err, IsNil)

		c.Assert(s.TPM().PCRExtend(s.TPM().PCRHandleContext(pcr), tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmId(alg), digest)}, nil), IsNil)
	}
}

func (s *compatTestSuiteBase) replayPCRSequenceFromFile(c *C, path string) {
	f, err := os.Open(path)
	c.Assert(err, IsNil)
	defer f.Close()

	s.replayPCRSequenceFromReader(c, f)
}

func (s *compatTestSuiteBase) copyFile(c *C, path string) string {
	src, err := os.Open(path)
	c.Assert(err, IsNil)
	defer src.Close()

	dst, err := ioutil.TempFile(s.tmpDir, filepath.Base(path))
	c.Assert(err, IsNil)
	defer dst.Close()

	_, err = io.Copy(dst, src)
	c.Assert(err, IsNil)

	return dst.Name()
}

func (s *compatTestSuiteBase) testUnsealCommon(c *C) {
	k, err := secboot_tpm2.ReadSealedKeyObjectFromFile(s.absPath("key"))
	c.Assert(err, IsNil)

	key, authPrivateKey, err := k.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)

	expectedKey, err := ioutil.ReadFile(s.absPath("clearKey"))
	c.Assert(err, IsNil)
	c.Check(key, DeepEquals, secboot.DiskUnlockKey(expectedKey))

	var expectedAuthPrivateKey secboot.PrimaryKey
	authKeyPath := s.absPath("authKey")
	if _, err := os.Stat(authKeyPath); err == nil {
		expectedAuthPrivateKey, err = ioutil.ReadFile(authKeyPath)
		c.Assert(err, IsNil)
	}
	c.Check(authPrivateKey, DeepEquals, expectedAuthPrivateKey)
}

func (s *compatTestSuiteBase) testUnseal(c *C, pcrEventsFile string) {
	s.replayPCRSequenceFromFile(c, pcrEventsFile)
	s.testUnsealCommon(c)
}

func (s *compatTestSuiteBase) testUnsealErrorMatchesCommon(c *C, pattern string) {
	k, err := secboot_tpm2.ReadSealedKeyObjectFromFile(s.absPath("key"))
	c.Assert(err, IsNil)

	_, _, err = k.UnsealFromTPM(s.TPM())
	c.Check(err, ErrorMatches, pattern)
}

func TestMain(m *testing.M) {
	// Provide a way for run-tests to configure this in a way that
	// can be ignored by other suites
	if _, ok := os.LookupEnv("USE_MSSIM"); ok {
		tpm2_testutil.TPMBackend = tpm2_testutil.TPMBackendMssim
	}

	flag.Parse()
	os.Exit(m.Run())
}
