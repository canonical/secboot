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

func (s *compatTestSuiteBase) testUnseal(c *C, pcrEventsFile string) {
	s.replayPCRSequenceFromFile(c, pcrEventsFile)

	k, err := secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.AuthMode2F(), Equals, secboot.AuthModeNone)

	key, err := k.UnsealFromTPM(s.TPM, "")
	c.Check(err, IsNil)

	expectedKey, err := ioutil.ReadFile(s.absPath("clearKey"))
	c.Assert(err, IsNil)

	c.Check(key, DeepEquals, expectedKey)
}

func (s *compatTestSuiteBase) TestChangePIN(c *C) {
	k, err := secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.AuthMode2F(), Equals, secboot.AuthModeNone)

	c.Check(secboot.ChangePIN(s.TPM, s.absPath("key"), "", testPIN), IsNil)
	k, err = secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.AuthMode2F(), Equals, secboot.AuthModePIN)

	c.Check(secboot.ChangePIN(s.TPM, s.absPath("key"), testPIN, ""), IsNil)
	k, err = secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.AuthMode2F(), Equals, secboot.AuthModeNone)
}

func (s *compatTestSuiteBase) testUnsealWithPIN(c *C, pcrEventsFile string) {
	c.Check(secboot.ChangePIN(s.TPM, s.absPath("key"), "", testPIN), IsNil)

	s.replayPCRSequenceFromFile(c, pcrEventsFile)

	k, err := secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.AuthMode2F(), Equals, secboot.AuthModePIN)

	key, err := k.UnsealFromTPM(s.TPM, testPIN)
	c.Check(err, IsNil)

	expectedKey, err := ioutil.ReadFile(s.absPath("clearKey"))
	c.Assert(err, IsNil)

	c.Check(key, DeepEquals, expectedKey)
}

func (s *compatTestSuiteBase) testUpdateKeyPCRProtectionPolicy(c *C, pcrProfile *secboot.PCRProtectionProfile) {
	c.Check(secboot.UpdateKeyPCRProtectionPolicy(s.TPM, s.absPath("key"), s.absPath("pud"), pcrProfile), IsNil)
}

func (s *compatTestSuiteBase) testUpdateKeyPCRProtectionPolicyRevokes(c *C, pcrProfile *secboot.PCRProtectionProfile, pcrEventsFile string) {
	tmpDir := c.MkDir()
	keyFile, err := os.Open(s.absPath("key"))
	c.Assert(err, IsNil)
	defer keyFile.Close()

	keyFileBackup, err := os.Create(filepath.Join(tmpDir, "key"))
	c.Assert(err, IsNil)
	defer keyFileBackup.Close()

	_, err = io.Copy(keyFileBackup, keyFile)
	c.Assert(err, IsNil)

	c.Check(secboot.UpdateKeyPCRProtectionPolicy(s.TPM, s.absPath("key"), s.absPath("pud"), pcrProfile), IsNil)

	s.replayPCRSequenceFromFile(c, pcrEventsFile)

	k, err := secboot.ReadSealedKeyObject(filepath.Join(tmpDir, "key"))
	c.Assert(err, IsNil)

	_, err = k.UnsealFromTPM(s.TPM, "")
	c.Check(err, ErrorMatches, "invalid key data file: cannot complete authorization policy assertions: the PCR policy has been revoked")
}

func (s *compatTestSuiteBase) testUpdateKeyPCRProtectionPolicyAndUnseal(c *C, pcrProfile *secboot.PCRProtectionProfile, pcrEvents io.Reader) {
	c.Check(secboot.UpdateKeyPCRProtectionPolicy(s.TPM, s.absPath("key"), s.absPath("pud"), pcrProfile), IsNil)

	s.replayPCRSequenceFromReader(c, pcrEvents)

	k, err := secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)

	key, err := k.UnsealFromTPM(s.TPM, "")
	c.Check(err, IsNil)

	expectedKey, err := ioutil.ReadFile(s.absPath("clearKey"))
	c.Assert(err, IsNil)

	c.Check(key, DeepEquals, expectedKey)
}

func (s *compatTestSuiteBase) testUnsealAfterLock(c *C, pcrEventsFile string) {
	c.Assert(secboot.LockAccessToSealedKeys(s.TPM), IsNil)

	s.replayPCRSequenceFromFile(c, pcrEventsFile)

	k, err := secboot.ReadSealedKeyObject(s.absPath("key"))
	c.Assert(err, IsNil)

	_, err = k.UnsealFromTPM(s.TPM, "")
	c.Check(err, ErrorMatches, "cannot access the sealed key object until the next TPM reset or restart")
}
