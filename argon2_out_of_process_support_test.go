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
	"time"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
	"gopkg.in/tomb.v2"
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
		MemoryKiB:  32 * 1024,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandDerive,
		ErrorType:   Argon2OutOfProcessErrorUnexpected,
		ErrorString: "cannot handle request in a process that isn't configured as an Argon2 handler process, try calling SetIsArgon2HandlerProcess",
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
		MemoryKiB:  32 * 10224,
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
		MemoryKiB:  32 * 1024,
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
		MemoryKiB:  32 * 1024,
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
		MemoryKiB:  32 * 1024,
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
		MemoryKiB: 32 * 1024,
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
		MemoryKiB: 32 * 1024,
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
		MemoryKiB: 32 * 1024,
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
		ErrorType:   Argon2OutOfProcessErrorUnexpected,
		ErrorString: "cannot run in a process that isn't configured as an Argon2 remote process",
	}
	err := out.Err()
	c.Check(err, ErrorMatches, `cannot process KDF request: unexpected-error \(cannot run in a process that isn't configured as an Argon2 remote process\)`)
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

func (s *argon2OutOfProcessSupportSuite) TestCallingSetArgon2KDFAfterSetIsArgon2HandlerPanics(c *C) {
	SetIsArgon2HandlerProcess()
	c.Check(func() { SetArgon2KDF(InProcessArgon2KDF) }, PanicMatches, `cannot call SetArgon2KDF in a process where SetIsArgon2HandlerProcess has already been called`)
}

func (s *argon2OutOfProcessSupportSuite) TestNoArgon2OutOfProcessWatchdogHandler(c *C) {
	req := &Argon2OutOfProcessRequest{
		Command:           Argon2OutOfProcessCommandWatchdog,
		WatchdogChallenge: []byte{1, 2, 3, 4},
	}
	rsp, err := NoArgon2OutOfProcessWatchdogHandler(req)
	c.Check(rsp, IsNil)
	c.Check(err, ErrorMatches, `unexpected watchdog request: no handler service for it`)
}

func (s *argon2OutOfProcessSupportSuite) TestArgon2OutOfProcessWatchdogHandlerHMACSHA256InvalidCommand(c *C) {
	handler := Argon2OutOfProcessWatchdogHandlerHMACSHA256()

	req := &Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	}
	rsp, err := handler(req)
	c.Check(rsp, IsNil)
	c.Check(err, ErrorMatches, `unexpected command "time"`)
}

func (s *argon2OutOfProcessSupportSuite) TestArgon2OutOfProcessWatchdogHandlerHMACSHA256(c *C) {
	handler := Argon2OutOfProcessWatchdogHandlerHMACSHA256()

	req := &Argon2OutOfProcessRequest{
		Command:           Argon2OutOfProcessCommandWatchdog,
		WatchdogChallenge: testutil.DecodeHexString(c, "79e7d47fed15d6eef1e7e5f54cbb69d37169378527d65d2ba809a364930e94e3"),
	}
	rsp, err := handler(req)
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command:          Argon2OutOfProcessCommandWatchdog,
		WatchdogResponse: testutil.DecodeHexString(c, "1fed49cb3f22b3ddc895a7837833d84b181bda9a1a6f098a297d163729a33c58"),
	})

	req = &Argon2OutOfProcessRequest{
		Command:           Argon2OutOfProcessCommandWatchdog,
		WatchdogChallenge: testutil.DecodeHexString(c, "3c1de58760e53cac4facc2d5409b362fcf9b81f9b611479f5956abdb0227e567"),
	}
	rsp, err = handler(req)
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command:          Argon2OutOfProcessCommandWatchdog,
		WatchdogResponse: testutil.DecodeHexString(c, "cb487ce254d115cf91f282c8c82a6c5d01b16db99f71175242d060f455fc4624"),
	})
}

func (s *argon2OutOfProcessSupportSuite) TestNoArgon2OutOfProcessWatchdogMonitorUnexpectedResponse(c *C) {
	reqChan := make(chan *Argon2OutOfProcessRequest)
	rspChan := make(chan *Argon2OutOfProcessResponse)

	tmb := new(tomb.Tomb)
	tmb.Go(func() error {
		// Run a routine for running NoArgon2OutOfProcessWatchdogMonitor.
		tmb.Go(func() error {
			return NoArgon2OutOfProcessWatchdogMonitor(tmb, reqChan, rspChan)
		})

		rspChan <- new(Argon2OutOfProcessResponse)
		return nil
	})
	c.Check(tmb.Wait(), ErrorMatches, `unexpected watchdog response: no monitor sending requests`)
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

func (s *argon2OutOfProcessSupportSuiteExpensive) TestNoArgon2OutOfProcessWatchdogMonitor(c *C) {
	reqChan := make(chan *Argon2OutOfProcessRequest)
	rspChan := make(chan *Argon2OutOfProcessResponse)

	doneEarlyChan := make(chan struct{})

	tmb := new(tomb.Tomb)
	tmb.Go(func() error {
		// Run a routine for running NoArgon2OutOfProcessWatchdogMonitor.
		tmb.Go(func() error {
			defer func() {
				// What we want to do here is ensure NoArgon2OutOfProcessWatchdogMonitor
				// doesn't return until the provided tomb enters a dying state. This check
				// is a bit racy because there's a small window where NoArgon2OutOfProcessWatchdogMonitor
				// returns and then the tomb enters a dying state before this defer runs.
				// I think that this is ok for now.
				select {
				case <-tmb.Dying():
					// do nothing
				default:
					// Tomb is still alive
					close(doneEarlyChan)
				}
			}()
			return NoArgon2OutOfProcessWatchdogMonitor(tmb, reqChan, rspChan)
		})

		// Run another routine to make sure we get no watchdog requests and to detect whether
		// NoArgon2OutOfProcessWatchdogMonitor returns early.
		tmb.Go(func() error {
			for tmb.Alive() {
				select {
				case <-reqChan:
					return errors.New("unexpected watchdog request")
				case <-doneEarlyChan:
					return errors.New("watchdog monitor returned whilst tomb is still alive")
				case <-tmb.Dying():
				}
			}
			return nil
		})

		// Run the test for 1 second.
		select {
		case <-time.After(1 * time.Second):
			// Kill the tomb to finish the test
			tmb.Kill(nil)
		case <-tmb.Dying():
			// Something else already failed - there's no point in waiting for the timeout here
			return nil
		}
		return nil
	})
	c.Check(tmb.Wait(), IsNil)
}

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
			MemoryKiB:  32 * 1024,
			Threads:    4,
			Keylen:     32,
		},
		expectedKey: testutil.DecodeHexString(c, "b47ad96075d64cb92cdc7678e6bbb85f496da6e84d7ea05fbc0092dfb0ac3e13"),
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
			MemoryKiB:  32 * 1024,
			Threads:    4,
			Keylen:     32,
		},
		expectedKey: testutil.DecodeHexString(c, "e5081bdbb5dc709ecd789ad6da76ce6c49d2bc3b958dda4a93c6b4140def877e"),
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
			MemoryKiB:  32 * 1024,
			Threads:    4,
			Keylen:     32,
		},
		expectedKey: testutil.DecodeHexString(c, "bd962af1e81debad7966d3c0ca1dd9398dc231a3c25c96de54a1df97233d1a49"),
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
			MemoryKiB:  32 * 1024,
			Threads:    4,
			Keylen:     32,
		},
		expectedKey: testutil.DecodeHexString(c, "0d781d62896d7bb71830251af01be0323f2006770beb917e62a2ea3330693625"),
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
			MemoryKiB:  64 * 1024,
			Threads:    4,
			Keylen:     32,
		},
		expectedKey: testutil.DecodeHexString(c, "ba935d605f3f021c6cad26c8e2c0316fcc23814b2aa580e33e0ddb040692fb77"),
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
			MemoryKiB:  32 * 1024,
			Threads:    4,
			Keylen:     64,
		},
		expectedKey: testutil.DecodeHexString(c, "385251574d5dfa3c25eb5fa2ad99f74cba39c284a16999b2d8e6908ad2304225e1f706dc860867179759ca058c9e0b961f6a4ec88f0eb38ba825d655bf892116"),
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

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestDeriveRestartProcess(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       nil,
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32 * 1024,
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
		MemoryKiB:  32 * 1024,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandDerive,
		ErrorType:   Argon2OutOfProcessErrorRestartProcess,
		ErrorString: "cannot run \"derive\" command: argon2 out-of-process handler has already been used to process a request - a new process should be started to handle another request",
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcessRequestTimeRestartProcess(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32 * 1024,
		Threads:   4,
	})
	c.Check(out, NotNil)

	out = RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32 * 1024,
		Threads:   4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandTime,
		ErrorType:   Argon2OutOfProcessErrorRestartProcess,
		ErrorString: "cannot run \"time\" command: argon2 out-of-process handler has already been used to process a request - a new process should be started to handle another request",
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestWaitForAndRunOutOfProcessArgon2Request(c *C) {
	var wg sync.WaitGroup
	wg.Add(1)

	reqR, reqW := io.Pipe()
	rspR, rspW := io.Pipe()

	go func() {
		c.Check(WaitForAndRunArgon2OutOfProcessRequest(reqR, rspW, nil), IsNil)
		wg.Done()
	}()

	enc := json.NewEncoder(reqW)
	c.Check(enc.Encode(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32 * 1024,
		Threads:    4,
		Keylen:     32,
	}), IsNil)

	dec := json.NewDecoder(rspR)
	var rsp *Argon2OutOfProcessResponse
	c.Check(dec.Decode(&rsp), IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "b47ad96075d64cb92cdc7678e6bbb85f496da6e84d7ea05fbc0092dfb0ac3e13"),
	})

	c.Check(reqW.Close(), IsNil)
	wg.Wait()
}

type testOutOfProcessArgon2DeriveParams struct {
	watchdogMonitor Argon2OutOfProcessWatchdogMonitor
	watchdogHandler string
	passphrase      string
	salt            []byte
	mode            Argon2Mode
	params          *Argon2CostParams
	keyLen          uint32
	expectedKey     []byte
}

func (s *argon2OutOfProcessSupportSuiteExpensive) testOutOfProcessArgon2Derive(c *C, params *testOutOfProcessArgon2DeriveParams) {
	kdf := NewOutOfProcessArgon2KDF(func() (*exec.Cmd, error) {
		return exec.Command(s.runArgon2HandlerPath(), params.watchdogHandler), nil
	}, params.watchdogMonitor)
	key, err := kdf.Derive(params.passphrase, params.salt, params.mode, params.params, params.keyLen)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, params.expectedKey)
	c.Logf("%x", key)
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2Derive(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
		watchdogMonitor: Argon2OutOfProcessWatchdogMonitorHMACSHA256(50*time.Millisecond, 50*time.Millisecond),
		watchdogHandler: "hmac-sha256",
		passphrase:      "foo",
		salt:            []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:            Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "b47ad96075d64cb92cdc7678e6bbb85f496da6e84d7ea05fbc0092dfb0ac3e13"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveDifferentPassphrase(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
		watchdogMonitor: Argon2OutOfProcessWatchdogMonitorHMACSHA256(50*time.Millisecond, 50*time.Millisecond),
		watchdogHandler: "hmac-sha256",
		passphrase:      "bar",
		salt:            []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:            Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "e5081bdbb5dc709ecd789ad6da76ce6c49d2bc3b958dda4a93c6b4140def877e"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveDifferentSalt(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
		watchdogMonitor: Argon2OutOfProcessWatchdogMonitorHMACSHA256(50*time.Millisecond, 50*time.Millisecond),
		watchdogHandler: "hmac-sha256",
		passphrase:      "foo",
		salt:            []byte("zyxwtsrqponmlkjihgfedcba987654"),
		mode:            Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "bd962af1e81debad7966d3c0ca1dd9398dc231a3c25c96de54a1df97233d1a49"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveDifferentMode(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
		watchdogMonitor: Argon2OutOfProcessWatchdogMonitorHMACSHA256(50*time.Millisecond, 50*time.Millisecond),
		watchdogHandler: "hmac-sha256",
		passphrase:      "foo",
		salt:            []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:            Argon2i,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "0d781d62896d7bb71830251af01be0323f2006770beb917e62a2ea3330693625"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveDifferentParams(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
		watchdogMonitor: Argon2OutOfProcessWatchdogMonitorHMACSHA256(50*time.Millisecond, 50*time.Millisecond),
		watchdogHandler: "hmac-sha256",
		passphrase:      "foo",
		salt:            []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:            Argon2id,
		params: &Argon2CostParams{
			Time:      48,
			MemoryKiB: 64 * 1024,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "ba935d605f3f021c6cad26c8e2c0316fcc23814b2aa580e33e0ddb040692fb77"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveLongDuration(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
		watchdogMonitor: Argon2OutOfProcessWatchdogMonitorHMACSHA256(50*time.Millisecond, 50*time.Millisecond),
		watchdogHandler: "hmac-sha256",
		passphrase:      "foo",
		salt:            []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:            Argon2id,
		params: &Argon2CostParams{
			Time:      100,
			MemoryKiB: 512 * 1024,
			Threads:   4},
		keyLen:      32,
		expectedKey: testutil.DecodeHexString(c, "f3dc0bc830b9530adc647b136765b4266a41a62d90b9ce6b7a784b91b1566ab5"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2DeriveDifferentKeylen(c *C) {
	s.testOutOfProcessArgon2Derive(c, &testOutOfProcessArgon2DeriveParams{
		watchdogMonitor: Argon2OutOfProcessWatchdogMonitorHMACSHA256(50*time.Millisecond, 50*time.Millisecond),
		watchdogHandler: "hmac-sha256",
		passphrase:      "foo",
		salt:            []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:            Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen:      64,
		expectedKey: testutil.DecodeHexString(c, "385251574d5dfa3c25eb5fa2ad99f74cba39c284a16999b2d8e6908ad2304225e1f706dc860867179759ca058c9e0b961f6a4ec88f0eb38ba825d655bf892116"),
	})
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestOutOfProcessArgon2Time(c *C) {
	kdf := NewOutOfProcessArgon2KDF(func() (*exec.Cmd, error) {
		return exec.Command(s.runArgon2HandlerPath(), "hmac-sha256"), nil
	}, Argon2OutOfProcessWatchdogMonitorHMACSHA256(50*time.Millisecond, 50*time.Millisecond))

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
