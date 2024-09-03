// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/argon2"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type argon2RemoteSupportSuite struct{}

func (s *argon2RemoteSupportSuite) TearDownTest(c *C) {
	ClearIsArgon2RemoteProcess()
}

var _ = Suite(&argon2RemoteSupportSuite{})

func (s *argon2RemoteSupportSuite) TestInProcessKDFDeriveNotSupported(c *C) {
	_, err := InProcessArgon2KDF().Derive("foo", nil, Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32, Threads: 1}, 32)
	c.Check(err, ErrorMatches, `no argon2 KDF: please call secboot.SetIsArgon2RemoteProcess if the intention is to run Argon2 directly in this process`)
}

func (s *argon2RemoteSupportSuite) TestInProcessKDFDeriveNoParams(c *C) {
	SetIsArgon2RemoteProcess()
	_, err := InProcessArgon2KDF().Derive("foo", nil, Argon2id, nil, 32)
	c.Check(err, ErrorMatches, `nil params`)
}

func (s *argon2RemoteSupportSuite) TestInProcessKDFDeriveInvalidMode(c *C) {
	SetIsArgon2RemoteProcess()
	_, err := InProcessArgon2KDF().Derive("foo", nil, Argon2Default, &Argon2CostParams{Time: 4, MemoryKiB: 32, Threads: 1}, 32)
	c.Check(err, ErrorMatches, `invalid mode`)
}

func (s *argon2RemoteSupportSuite) TestInProcessKDFDeriveInvalidTime(c *C) {
	SetIsArgon2RemoteProcess()
	_, err := InProcessArgon2KDF().Derive("foo", nil, Argon2id, &Argon2CostParams{Time: 0, MemoryKiB: 32, Threads: 1}, 32)
	c.Check(err, ErrorMatches, `invalid time cost`)
}

func (s *argon2RemoteSupportSuite) TestInProcessKDFDeriveInvalidThreads(c *C) {
	SetIsArgon2RemoteProcess()
	_, err := InProcessArgon2KDF().Derive("foo", nil, Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32, Threads: 0}, 32)
	c.Check(err, ErrorMatches, `invalid number of threads`)
}

func (s *argon2RemoteSupportSuite) TestInProcessKDFTimeNotSupported(c *C) {
	_, err := InProcessArgon2KDF().Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32, Threads: 1})
	c.Check(err, ErrorMatches, `no argon2 KDF: please call secboot.SetIsArgon2RemoteProcess if the intention is to run Argon2 directly in this process`)
}

func (s *argon2RemoteSupportSuite) TestInProcessKDFTimeNoParams(c *C) {
	SetIsArgon2RemoteProcess()
	_, err := InProcessArgon2KDF().Time(Argon2id, nil)
	c.Check(err, ErrorMatches, `nil params`)
}

func (s *argon2RemoteSupportSuite) TestInProcessKDFTimeInvalidMode(c *C) {
	SetIsArgon2RemoteProcess()
	_, err := InProcessArgon2KDF().Time(Argon2Default, &Argon2CostParams{Time: 4, MemoryKiB: 32, Threads: 1})
	c.Check(err, ErrorMatches, `invalid mode`)
}

func (s *argon2RemoteSupportSuite) TestInProcessKDFTimeInvalidTime(c *C) {
	SetIsArgon2RemoteProcess()
	_, err := InProcessArgon2KDF().Time(Argon2id, &Argon2CostParams{Time: 0, MemoryKiB: 32, Threads: 1})
	c.Check(err, ErrorMatches, `invalid time cost`)
}

func (s *argon2RemoteSupportSuite) TestInProcessKDFTimeInvalidThreads(c *C) {
	SetIsArgon2RemoteProcess()
	_, err := InProcessArgon2KDF().Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32, Threads: 0})
	c.Check(err, ErrorMatches, `invalid number of threads`)
}

func (s *argon2RemoteSupportSuite) TestRunArgon2RequestInRemoteProcessInvalidProcess(c *C) {
	out := RunArgon2RequestInRemoteProcess(&Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2RemoteOutput{
		Command:     Argon2RemoteCommandDerive,
		ErrorType:   Argon2RemoteErrorProcessNotConfigured,
		ErrorString: "cannot run in a process that isn't configured as an Argon2 remote process",
	})
}

func (s *argon2RemoteSupportSuite) TestRunArgon2RequestInRemoteProcessInvalidMode(c *C) {
	SetIsArgon2RemoteProcess()
	out := RunArgon2RequestInRemoteProcess(&Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2Mode("foo"),
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2RemoteOutput{
		Command:     Argon2RemoteCommandDerive,
		ErrorType:   Argon2RemoteErrorInvalidMode,
		ErrorString: "invalid mode: \"foo\"",
	})
}

func (s *argon2RemoteSupportSuite) TestRunArgon2RequestInRemoteProcessInvalidTime(c *C) {
	SetIsArgon2RemoteProcess()
	out := RunArgon2RequestInRemoteProcess(&Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       0,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2RemoteOutput{
		Command:     Argon2RemoteCommandDerive,
		ErrorType:   Argon2RemoteErrorInvalidTimeCost,
		ErrorString: "invalid time cost: cannot be zero",
	})
}

func (s *argon2RemoteSupportSuite) TestRunArgon2RequestInRemoteProcessInvalidThreads(c *C) {
	SetIsArgon2RemoteProcess()
	out := RunArgon2RequestInRemoteProcess(&Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    0,
	})
	c.Check(out, DeepEquals, &Argon2RemoteOutput{
		Command:     Argon2RemoteCommandDerive,
		ErrorType:   Argon2RemoteErrorInvalidThreads,
		ErrorString: "invalid threads: cannot be zero",
	})
}

func (s *argon2RemoteSupportSuite) TestArgon2RemoteOutputErr(c *C) {
	out := &Argon2RemoteOutput{
		Command:     Argon2RemoteCommandDerive,
		ErrorType:   Argon2RemoteErrorProcessNotConfigured,
		ErrorString: "cannot run in a process that isn't configured as an Argon2 remote process",
	}
	err := out.Err()
	c.Check(err, ErrorMatches, `cannot process KDF request: process-not-configured \(cannot run in a process that isn't configured as an Argon2 remote process\)`)
	var e *Argon2RemoteError
	c.Check(errors.As(err, &e), testutil.IsTrue)
}

type argon2RemoteSupportSuiteExpensive struct {
	runArgon2RemoteDir string
}

func (s *argon2RemoteSupportSuiteExpensive) runArgon2RemotePath() string {
	return filepath.Join(s.runArgon2RemoteDir, "run_argon2")
}

func (s *argon2RemoteSupportSuiteExpensive) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_ARGON2_TESTS"); exists {
		c.Skip("skipping expensive argon2 tests")
	}
	s.runArgon2RemoteDir = c.MkDir()
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", s.runArgon2RemoteDir, "./cmd/run_argon2")
	c.Assert(cmd.Run(), IsNil)
}

func (s *argon2RemoteSupportSuiteExpensive) SetUpTest(c *C) {
	SetIsArgon2RemoteProcess()
}

func (s *argon2RemoteSupportSuiteExpensive) TearDownTest(c *C) {
	ClearIsArgon2RemoteProcess()
}

var _ = Suite(&argon2RemoteSupportSuiteExpensive{})

type testInProcessArgon2KDFDeriveData struct {
	passphrase string
	salt       []byte
	mode       Argon2Mode
	params     *Argon2CostParams
	keyLen     uint32

	expectedKey []byte
}

func (s *argon2RemoteSupportSuiteExpensive) testInProcessKDFDerive(c *C, data *testInProcessArgon2KDFDeriveData) {
	key, err := InProcessArgon2KDF().Derive(data.passphrase, data.salt, data.mode, data.params, data.keyLen)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.expectedKey)
}

func (s *argon2RemoteSupportSuiteExpensive) TestInProcessKDFDerive(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "cbd85bef66eae997ed1f8f7f3b1d5bec09425f72789f5113d0215bb8bdc6891f"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestInProcessKDFDeriveDifferentPassphrase(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "bar",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "19b17adfb811233811b9e5872165803d01e81d3951e73b996a40c49b15c6e532"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestInProcessKDFiDeriveDifferentSalt(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "foo",
		salt:       []byte("zyxwtsrqponmlkjihgfedcba987654"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "b5cf92c57c00f2a1d0de9d46ba0acef0e37ad1d4807b45b2dad1a50e797cc96d"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestInProcessKDFDeriveDifferentMode(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2i,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "60b6d0ab8d4c39b4f17a7c05486c714097d2bf1f1d85c6d5fad4fe24171003fe"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestInProcessKDFDeriveDifferentParams(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      48,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "f83001f90fbbc24823773e56f65eeace261285ab7e1394efeb8348d2184c240c"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestInProcessKDFDeriveDifferentKeyLen(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen:      64,
		expectedKey: testutil.DecodeHexString(c, "dc8b7ed604470a49d983f86b1574b8619631ccd0282f591b227c153ce200f395615e7ddb5b01026edbf9bf7105ca2de294d67f69d9678e65417d59e51566e746"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestInProcessKDFTime(c *C) {
	time1, err := InProcessArgon2KDF().Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32 * 1024, Threads: 4})
	c.Check(err, IsNil)

	runtime.GC()
	time2, err := InProcessArgon2KDF().Time(Argon2id, &Argon2CostParams{Time: 16, MemoryKiB: 32 * 1024, Threads: 4})
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)

	runtime.GC()
	time2, err = InProcessArgon2KDF().Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 128 * 1024, Threads: 4})
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)

	runtime.GC()
	time2, err = InProcessArgon2KDF().Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32 * 1024, Threads: 1})
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)
}

func (s *argon2RemoteSupportSuiteExpensive) testRunArgon2RequestInRemoteProcessDerive(c *C, input *Argon2RemoteInput) {
	res := RunArgon2RequestInRemoteProcess(input)
	c.Check(res.Command, Equals, Argon2RemoteCommandDerive)
	c.Check(res.Err(), IsNil)

	runtime.GC()

	expected := argon2.Key(input.Passphrase, input.Salt, argon2.Mode(input.Mode), &argon2.CostParams{
		Time:      input.Time,
		MemoryKiB: input.MemoryKiB,
		Threads:   input.Threads}, input.Keylen)
	c.Check(expected, DeepEquals, res.Key)
}

func (s *argon2RemoteSupportSuiteExpensive) TestRunArgon2RequestInRemoteProcessDerive(c *C) {
	s.testRunArgon2RequestInRemoteProcessDerive(c, &Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
		Keylen:     32,
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRunArgon2RequestInRemoteProcessDeriveDifferentPassphrase(c *C) {
	s.testRunArgon2RequestInRemoteProcessDerive(c, &Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "bar",
		Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
		Keylen:     32,
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRunArgon2RequestInRemoteProcessDeriveDifferentSalt(c *C) {
	s.testRunArgon2RequestInRemoteProcessDerive(c, &Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       []byte("zyxwtsrqponmlkjihgfedcba987654"),
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
		Keylen:     32,
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRunArgon2RequestInRemoteProcessDeriveDifferentMode(c *C) {
	s.testRunArgon2RequestInRemoteProcessDerive(c, &Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		Mode:       Argon2i,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
		Keylen:     32,
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRunArgon2RequestInRemoteProcessDeriveDifferentParams(c *C) {
	s.testRunArgon2RequestInRemoteProcessDerive(c, &Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		Mode:       Argon2id,
		Time:       48,
		MemoryKiB:  32 * 1024,
		Threads:    4,
		Keylen:     32,
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRunArgon2RequestInRemoteProcessDeriveDifferentKeylen(c *C) {
	s.testRunArgon2RequestInRemoteProcessDerive(c, &Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
		Keylen:     64,
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRunArgon2RequestInRemoteProcessTime(c *C) {
	res := RunArgon2RequestInRemoteProcess(&Argon2RemoteInput{
		Command:   Argon2RemoteCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32 * 1024,
		Threads:   4,
	})
	c.Check(res.Err(), IsNil)

	ClearIsArgon2RemoteProcess()
	SetIsArgon2RemoteProcess()
	res2 := RunArgon2RequestInRemoteProcess(&Argon2RemoteInput{
		Command:   Argon2RemoteCommandTime,
		Mode:      Argon2id,
		Time:      16,
		MemoryKiB: 32 * 1024,
		Threads:   4,
	})
	c.Check(res2.Err(), IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(res2.Duration > res.Duration, testutil.IsTrue)

	ClearIsArgon2RemoteProcess()
	SetIsArgon2RemoteProcess()
	res2 = RunArgon2RequestInRemoteProcess(&Argon2RemoteInput{
		Command:   Argon2RemoteCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 128 * 1024,
		Threads:   4,
	})
	c.Check(res2.Err(), IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(res2.Duration > res.Duration, testutil.IsTrue)

	ClearIsArgon2RemoteProcess()
	SetIsArgon2RemoteProcess()
	res2 = RunArgon2RequestInRemoteProcess(&Argon2RemoteInput{
		Command:   Argon2RemoteCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32 * 1024,
		Threads:   1,
	})
	c.Check(res2.Err(), IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(res2.Duration > res.Duration, testutil.IsTrue)
}

func (s *argon2RemoteSupportSuiteExpensive) TestRunArgon2RequestInRemoteProcessConsumedProcess(c *C) {
	out := RunArgon2RequestInRemoteProcess(&Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, NotNil)

	out = RunArgon2RequestInRemoteProcess(&Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2RemoteOutput{
		Command:     Argon2RemoteCommandDerive,
		ErrorType:   Argon2RemoteErrorConsumedProcess,
		ErrorString: "cannot run more than once in the same process",
	})
}

type testRemoteArgon2DeriveParams struct {
	passphrase  string
	salt        []byte
	mode        Argon2Mode
	params      *Argon2CostParams
	keyLen      uint32
	expectedKey []byte
}

func (s *argon2RemoteSupportSuiteExpensive) testRemoteArgon2Derive(c *C, params *testRemoteArgon2DeriveParams) {
	kdf := NewRemoteArgon2KDF(func() (*exec.Cmd, error) {
		return exec.Command(s.runArgon2RemotePath()), nil
	})
	key, err := kdf.Derive(params.passphrase, params.salt, params.mode, params.params, params.keyLen)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, params.expectedKey)
}

func (s *argon2RemoteSupportSuiteExpensive) TestRemoteArgon2Derive(c *C) {
	s.testRemoteArgon2Derive(c, &testRemoteArgon2DeriveParams{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "cbd85bef66eae997ed1f8f7f3b1d5bec09425f72789f5113d0215bb8bdc6891f"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRemoteArgon2DeriveDifferentPassphrase(c *C) {
	s.testRemoteArgon2Derive(c, &testRemoteArgon2DeriveParams{
		passphrase: "bar",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "19b17adfb811233811b9e5872165803d01e81d3951e73b996a40c49b15c6e532"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRemoteArgon2DeriveDifferentSalt(c *C) {
	s.testRemoteArgon2Derive(c, &testRemoteArgon2DeriveParams{
		passphrase: "foo",
		salt:       []byte("zyxwtsrqponmlkjihgfedcba987654"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "b5cf92c57c00f2a1d0de9d46ba0acef0e37ad1d4807b45b2dad1a50e797cc96d"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRemoteArgon2DeriveDifferentMode(c *C) {
	s.testRemoteArgon2Derive(c, &testRemoteArgon2DeriveParams{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2i,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "60b6d0ab8d4c39b4f17a7c05486c714097d2bf1f1d85c6d5fad4fe24171003fe"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRemoteArgon2DeriveDifferentParams(c *C) {
	s.testRemoteArgon2Derive(c, &testRemoteArgon2DeriveParams{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      48,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "f83001f90fbbc24823773e56f65eeace261285ab7e1394efeb8348d2184c240c"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRemoteArgon2DeriveDifferentKeyLen(c *C) {
	s.testRemoteArgon2Derive(c, &testRemoteArgon2DeriveParams{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen:      64,
		expectedKey: testutil.DecodeHexString(c, "dc8b7ed604470a49d983f86b1574b8619631ccd0282f591b227c153ce200f395615e7ddb5b01026edbf9bf7105ca2de294d67f69d9678e65417d59e51566e746"),
	})
}

func (s *argon2RemoteSupportSuiteExpensive) TestRemoteArgon2Time(c *C) {
	kdf := NewRemoteArgon2KDF(func() (*exec.Cmd, error) {
		return exec.Command(s.runArgon2RemotePath()), nil
	})

	time1, err := kdf.Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32 * 1024, Threads: 4})
	c.Check(err, IsNil)

	time2, err := kdf.Time(Argon2id, &Argon2CostParams{Time: 16, MemoryKiB: 32 * 1024, Threads: 4})
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)

	time2, err = kdf.Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 128 * 1024, Threads: 4})
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)

	time2, err = kdf.Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32 * 1024, Threads: 1})
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)
}
