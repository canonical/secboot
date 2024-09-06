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
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type argon2OutOfProcessSupportSuite struct{}

func (s *argon2OutOfProcessSupportSuite) TearDownTest(c *C) {
	ClearIsArgon2HandlerProcess()
}

var _ = Suite(&argon2OutOfProcessSupportSuite{})

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessDeriveRequestInvalidProcess(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandDerive,
		ErrorType:   Argon2OutOfProcessErrorProcessNotConfigured,
		ErrorString: "cannot handle out-of-process request in a process that isn't configured as an Argon2 handler process",
	})
}

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessDeriveRequestInvalidMode(c *C) {
	SetIsArgon2HandlerProcess()
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2Mode("foo"),
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandDerive,
		ErrorType:   Argon2OutOfProcessErrorInvalidMode,
		ErrorString: "invalid mode: \"foo\"",
	})
}

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessDeriveRequestInvalidTime(c *C) {
	SetIsArgon2HandlerProcess()
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       0,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandDerive,
		ErrorType:   Argon2OutOfProcessErrorInvalidTimeCost,
		ErrorString: "invalid time cost: cannot be zero",
	})
}

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessDeriveRequestInvalidThreads(c *C) {
	SetIsArgon2HandlerProcess()
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    0,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandDerive,
		ErrorType:   Argon2OutOfProcessErrorInvalidThreads,
		ErrorString: "invalid threads: cannot be zero",
	})
}

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessTimeRequestInvalidPassphrase(c *C) {
	SetIsArgon2HandlerProcess()
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandTime,
		Passphrase: "foo",
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandTime,
		ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
		ErrorString: "cannot supply passphrase for \"time\" command",
	})
}

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessTimeRequestInvalidSalt(c *C) {
	SetIsArgon2HandlerProcess()
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Salt:      []byte("0123456789abcdefghijklmnopqrstuv"),
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandTime,
		ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
		ErrorString: "cannot supply salt for \"time\" command",
	})
}

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessTimeRequestInvalidKeylen(c *C) {
	SetIsArgon2HandlerProcess()
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Keylen:    32,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandTime,
		ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
		ErrorString: "cannot supply keylen for \"time\" command",
	})
}

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessInvalidCommand(c *C) {
	SetIsArgon2HandlerProcess()
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommand("foo"),
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommand("foo"),
		ErrorType:   Argon2OutOfProcessErrorInvalidCommand,
		ErrorString: "invalid command: \"foo\"",
	})
}

func (s *argon2OutOfProcessSupportSuite) TestArgon2OutOfProcessResponseErr(c *C) {
	out := &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandDerive,
		ErrorType:   Argon2OutOfProcessErrorProcessNotConfigured,
		ErrorString: "cannot run in a process that isn't configured as an Argon2 remote process",
	}
	err := out.Err()
	c.Check(err, ErrorMatches, `cannot process KDF request: process-not-configured \(cannot run in a process that isn't configured as an Argon2 remote process\)`)
	var e *Argon2OutOfProcessError
	c.Check(errors.As(err, &e), testutil.IsTrue)
}

func (s *argon2OutOfProcessSupportSuite) TestCallingSetIsArgon2HandlerSucceeds(c *C) {
	SetIsArgon2HandlerProcess()
	c.Assert(GlobalArgon2KDF(), testutil.ConvertibleTo, &Argon2OutOfProcessHandler{})
	c.Check(GlobalArgon2KDF().(*Argon2OutOfProcessHandler).KDF, Equals, InProcessArgon2KDF)
	c.Check(GlobalArgon2KDF().(*Argon2OutOfProcessHandler).Status, Equals, uint32(0))
}

func (s *argon2OutOfProcessSupportSuite) TestCallingSetIsArgon2HandlerMoreThanOncePanics(c *C) {
	SetIsArgon2HandlerProcess()
	c.Check(func() { SetIsArgon2HandlerProcess() }, PanicMatches, `cannot call SetIsArgon2HandlerProcess more than once`)
}

func (s *argon2OutOfProcessSupportSuite) TestCallingSetIsArgon2HandlerAfterSetArgon2KDFSucceeds(c *C) {
	SetArgon2KDF(InProcessArgon2KDF)
	SetIsArgon2HandlerProcess()
	c.Assert(GlobalArgon2KDF(), testutil.ConvertibleTo, &Argon2OutOfProcessHandler{})
	c.Check(GlobalArgon2KDF().(*Argon2OutOfProcessHandler).KDF, Equals, InProcessArgon2KDF)
	c.Check(GlobalArgon2KDF().(*Argon2OutOfProcessHandler).Status, Equals, uint32(0))
}

type argon2OutOfProcessSupportSuiteExpensive struct {
	runArgon2OutputDir string
}

func (s *argon2OutOfProcessSupportSuiteExpensive) runArgon2HandlerPath() string {
	return filepath.Join(s.runArgon2OutputDir, "run_argon2")
}

func (s *argon2OutOfProcessSupportSuiteExpensive) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_ARGON2_TESTS"); exists {
		c.Skip("skipping expensive argon2 tests")
	}
	s.runArgon2OutputDir = c.MkDir()
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", s.runArgon2OutputDir, "./cmd/run_argon2")
	c.Assert(cmd.Run(), IsNil)
}

func (s *argon2OutOfProcessSupportSuiteExpensive) SetUpTest(c *C) {
	SetIsArgon2HandlerProcess()
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TearDownTest(c *C) {
	ClearIsArgon2HandlerProcess()
}

var _ = Suite(&argon2OutOfProcessSupportSuiteExpensive{})

type testRunArgon2OutOfProcessRequestDeriveParams struct {
	req         *Argon2OutOfProcessRequest
	expectedKey []byte
}

func (s *argon2OutOfProcessSupportSuiteExpensive) testRunArgon2OutOfProcessRequestDerive(c *C, params *testRunArgon2OutOfProcessRequestDeriveParams) {
	rsp := RunArgon2OutOfProcessRequest(params.req)
	c.Assert(rsp, NotNil)
	c.Check(rsp.Command, Equals, Argon2OutOfProcessCommandDerive)
	c.Check(rsp.Err(), IsNil)
	c.Check(rsp.Key, DeepEquals, params.expectedKey)
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestDerive(c *C) {
	s.testRunArgon2OutOfProcessRequestDerive(c, &testRunArgon2OutOfProcessRequestDeriveParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  32,
			Threads:    4,
			Keylen:     32,
		},
		expectedKey: testutil.DecodeHexString(c, "cbd85bef66eae997ed1f8f7f3b1d5bec09425f72789f5113d0215bb8bdc6891f"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestDeriveDifferentPassphrase(c *C) {
	s.testRunArgon2OutOfProcessRequestDerive(c, &testRunArgon2OutOfProcessRequestDeriveParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "bar",
			Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  32,
			Threads:    4,
			Keylen:     32,
		},
		expectedKey: testutil.DecodeHexString(c, "19b17adfb811233811b9e5872165803d01e81d3951e73b996a40c49b15c6e532"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestDeriveDifferentSalt(c *C) {
	s.testRunArgon2OutOfProcessRequestDerive(c, &testRunArgon2OutOfProcessRequestDeriveParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       []byte("zyxwtsrqponmlkjihgfedcba987654"),
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  32,
			Threads:    4,
			Keylen:     32,
		},
		expectedKey: testutil.DecodeHexString(c, "b5cf92c57c00f2a1d0de9d46ba0acef0e37ad1d4807b45b2dad1a50e797cc96d"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestDeriveDifferentMode(c *C) {
	s.testRunArgon2OutOfProcessRequestDerive(c, &testRunArgon2OutOfProcessRequestDeriveParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
			Mode:       Argon2i,
			Time:       4,
			MemoryKiB:  32,
			Threads:    4,
			Keylen:     32,
		},
		expectedKey: testutil.DecodeHexString(c, "60b6d0ab8d4c39b4f17a7c05486c714097d2bf1f1d85c6d5fad4fe24171003fe"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestDeriveDifferentParams(c *C) {
	s.testRunArgon2OutOfProcessRequestDerive(c, &testRunArgon2OutOfProcessRequestDeriveParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
			Mode:       Argon2id,
			Time:       48,
			MemoryKiB:  32 * 1024,
			Threads:    4,
			Keylen:     32,
		},
		expectedKey: testutil.DecodeHexString(c, "f83001f90fbbc24823773e56f65eeace261285ab7e1394efeb8348d2184c240c"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestDeriveDifferentKeylen(c *C) {
	s.testRunArgon2OutOfProcessRequestDerive(c, &testRunArgon2OutOfProcessRequestDeriveParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  32,
			Threads:    4,
			Keylen:     64,
		},
		expectedKey: testutil.DecodeHexString(c, "dc8b7ed604470a49d983f86b1574b8619631ccd0282f591b227c153ce200f395615e7ddb5b01026edbf9bf7105ca2de294d67f69d9678e65417d59e51566e746"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestTime(c *C) {
	res := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32 * 1024,
		Threads:   4,
	})
	c.Check(res.Err(), IsNil)

	ClearIsArgon2HandlerProcess()
	SetIsArgon2HandlerProcess()
	res2 := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      Argon2id,
		Time:      16,
		MemoryKiB: 32 * 1024,
		Threads:   4,
	})
	c.Check(res2.Err(), IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(res2.Duration > res.Duration, testutil.IsTrue)

	ClearIsArgon2HandlerProcess()
	SetIsArgon2HandlerProcess()
	res2 = RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 128 * 1024,
		Threads:   4,
	})
	c.Check(res2.Err(), IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(res2.Duration > res.Duration, testutil.IsTrue)

	ClearIsArgon2HandlerProcess()
	SetIsArgon2HandlerProcess()
	res2 = RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
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

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestDeriveConsumedProcess(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, NotNil)

	out = RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandDerive,
		ErrorType:   Argon2OutOfProcessErrorConsumedProcess,
		ErrorString: "cannot run derive command: argon2 out-of-process handler has alreay been used - a new process should be started to handle a new request",
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestTimeConsumedProcess(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	})
	c.Check(out, NotNil)

	out = RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandTime,
		ErrorType:   Argon2OutOfProcessErrorConsumedProcess,
		ErrorString: "cannot run time command: argon2 out-of-process handler has alreay been used - a new process should be started to handle a new request",
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestWaitForAndRunOutOfProcessArgon2Request(c *C) {
	var wg sync.WaitGroup
	wg.Add(1)

	reqR, reqW := io.Pipe()
	rspR, rspW := io.Pipe()

	go func() {
		c.Check(WaitForAndRunArgon2OutOfProcessRequest(reqR, rspW), IsNil)
		wg.Done()
	}()

	enc := json.NewEncoder(reqW)
	c.Check(enc.Encode(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
		Keylen:     32,
	}), IsNil)

	dec := json.NewDecoder(rspR)
	var rsp *Argon2OutOfProcessResponse
	c.Check(dec.Decode(&rsp), IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "cbd85bef66eae997ed1f8f7f3b1d5bec09425f72789f5113d0215bb8bdc6891f"),
	})

	wg.Wait()
}

type testOutOfProcessArgon2DeriveParams struct {
	passphrase  string
	salt        []byte
	mode        Argon2Mode
	params      *Argon2CostParams
	keyLen      uint32
	expectedKey []byte
}

func (s *argon2OutOfProcessSupportSuiteExpensive) testOutOfProcessArgon2Derive(c *C, params *testOutOfProcessArgon2DeriveParams) {
	kdf := NewOutOfProcessArgon2KDF(func() (*exec.Cmd, error) {
		return exec.Command(s.runArgon2HandlerPath()), nil
	})
	key, err := kdf.Derive(params.passphrase, params.salt, params.mode, params.params, params.keyLen)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, params.expectedKey)
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2Derive(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
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

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveDifferentPassphrase(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
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

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveDifferentSalt(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
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

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveDifferentMode(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
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

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveDifferentParams(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
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

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveDifferentKeyLen(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
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

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2Time(c *C) {
	kdf := NewOutOfProcessArgon2KDF(func() (*exec.Cmd, error) {
		return exec.Command(s.runArgon2HandlerPath()), nil
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
