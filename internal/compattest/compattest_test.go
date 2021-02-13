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
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

var testPIN = "12345678"

func Test(t *testing.T) { TestingT(t) }

type compatTestSuiteBase struct {
	testutil.TPMSimulatorTestBase
	dataPath          string
	tmpDir            string
	simulatorShutdown func()
}

func (s *compatTestSuiteBase) setUpSuiteBase(c *C, dataPath string) {
	if !testutil.UseMssim {
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

	simulatorShutdown, err := testutil.LaunchTPMSimulator(&testutil.TPMSimulatorOptions{SourceDir: s.dataPath})
	c.Assert(err, IsNil)
	// We can't use AddCleanup here because the simulator cleanup needs to execute after the test's TPM connection
	// has been closed.
	s.simulatorShutdown = simulatorShutdown

	s.TPMSimulatorTestBase.SetUpTest(c)
}

func (s *compatTestSuiteBase) TearDownTest(c *C) {
	s.TPMSimulatorTestBase.TearDownTest(c)
	if s.simulatorShutdown == nil {
		return
	}
	s.simulatorShutdown()
}

func (s *compatTestSuiteBase) absPath(name string) string {
	return filepath.Join(s.tmpDir, name)
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

		c.Assert(s.TPM.PCRExtend(s.TPM.PCRHandleContext(pcr), tpm2.TaggedHashList{{HashAlg: tpm2.HashAlgorithmId(alg), Digest: digest}}, nil), IsNil)
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

func (s *compatTestSuiteBase) testUnsealCommon(c *C, pin string) {
	k, err := secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)

	key, authPrivateKey, err := k.UnsealFromTPM(s.TPM, pin)
	c.Check(err, IsNil)

	expectedKey, err := ioutil.ReadFile(s.absPath("clearKey"))
	c.Assert(err, IsNil)
	c.Check(key, DeepEquals, expectedKey)

	var expectedAuthPrivateKey secboot.TPMPolicyAuthKey
	authKeyPath := s.absPath("authKey")
	if _, err := os.Stat(authKeyPath); err == nil {
		expectedAuthPrivateKey, err = ioutil.ReadFile(authKeyPath)
		c.Assert(err, IsNil)
	}
	c.Check(authPrivateKey, DeepEquals, expectedAuthPrivateKey)
}

func (s *compatTestSuiteBase) testUnseal(c *C, pcrEventsFile string) {
	s.replayPCRSequenceFromFile(c, pcrEventsFile)
	s.testUnsealCommon(c, "")
}

func (s *compatTestSuiteBase) TestChangePIN(c *C) {
	k, err := secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.AuthMode2F(), Equals, secboot.AuthModeNone)

	c.Check(secboot.ChangePIN(s.TPM, s.absPath("key"), "", testPIN), IsNil)
	k, err = secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.AuthMode2F(), Equals, secboot.AuthModePassphrase)

	c.Check(secboot.ChangePIN(s.TPM, s.absPath("key"), testPIN, ""), IsNil)
	k, err = secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.AuthMode2F(), Equals, secboot.AuthModeNone)
}

func (s *compatTestSuiteBase) testUnsealWithPIN(c *C, pcrEventsFile string) {
	c.Check(secboot.ChangePIN(s.TPM, s.absPath("key"), "", testPIN), IsNil)
	s.replayPCRSequenceFromFile(c, pcrEventsFile)
	s.testUnsealCommon(c, testPIN)
}

func (s *compatTestSuiteBase) testUnsealErrorMatchesCommon(c *C, pattern string) {
	k, err := secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)

	_, _, err = k.UnsealFromTPM(s.TPM, "")
	c.Check(err, ErrorMatches, pattern)
}
