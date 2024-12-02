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
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/paths"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
	"gopkg.in/tomb.v2"
)

// argon2OutOfProcessHandlerSupportMixin provides capabilities shared
// between suites that test the remote side of out-of-process Argon2 components.
type argon2OutOfProcessHandlerSupportMixin struct {
	restoreLockPath func()
}

func (s *argon2OutOfProcessHandlerSupportMixin) SetUpTest(c *C) {
	s.restoreLockPath = MockArgon2OutOfProcessHandlerSystemLockPath(filepath.Join(c.MkDir(), "argon2.lock"))
}

func (s *argon2OutOfProcessHandlerSupportMixin) TearDownTest(c *C) {
	if s.restoreLockPath != nil {
		s.restoreLockPath()
	}
	ResetArgon2OutOfProcessHandlerStatus()
}

type testWaitForAndRunArgon2OutOfProcessRequestParams struct {
	req       *Argon2OutOfProcessRequest
	wdHandler Argon2OutOfProcessWatchdogHandler
	wdMonitor Argon2OutOfProcessWatchdogMonitor
}

func (s *argon2OutOfProcessHandlerSupportMixin) testWaitForAndRunArgon2OutOfProcessRequest(c *C, params *testWaitForAndRunArgon2OutOfProcessRequestParams) (*Argon2OutOfProcessResponse, error) {
	// Create 2 pipes to communicate with WaitForAndRunArgon2OutOfProcessRequest
	reqR, reqW := io.Pipe()
	rspR, rspW := io.Pipe()

	var actualRsp *Argon2OutOfProcessResponse // The response from the test function
	tmb := new(tomb.Tomb)                     // The tomb for tracking goroutines

	// Spin up a goroutine to bootstrap the test setup and then process responses from the
	// test function. I'm not sure how thread safe the test library is, so we avoid doing
	// asserts in any goroutines we create.
	tmb.Go(func() error {
		// Spin up a dedicated routine for running the test function
		// (WaitForAndRunArgon2OutOfProcessRequest), passing it one end
		// of each pipe and the supplied watchdog handler. Assuming
		// nothing else in the test exits a routine with an error, errors
		// returned from the test function will propagate out of the tomb
		// and will be checked on the main test goroutine.
		tmb.Go(func() (err error) {
			return WaitForAndRunArgon2OutOfProcessRequest(reqR, rspW, params.wdHandler)
		})

		// reqChan receives requests and then serializes them to the test function on a
		// dedicated goroutine.
		reqChan := make(chan *Argon2OutOfProcessRequest)

		// wdRspChan is used by the response processing loop to send watchdog
		// responses to the watchdog handler.
		wdRspChan := make(chan *Argon2OutOfProcessResponse)

		// Spin up a routine to send requests to the test function.
		tmb.Go(func() error {
			for tmb.Alive() {
				select {
				case req := <-reqChan:
					enc := json.NewEncoder(reqW)
					if err := enc.Encode(req); err != nil {
						return fmt.Errorf("cannot encode request: %w", err)
					}
				case <-tmb.Dying():
				}
			}
			return tomb.ErrDying
		})

		// Spin up a routine to run the watchdog monitor
		tmb.Go(func() error {
			watchdog := params.wdMonitor
			if watchdog == nil {
				// Copy the default behaviour for WaitForAndRunArgon2OutOfProcessRequest
				watchdog = NoArgon2OutOfProcessWatchdogMonitor()
			}
			err := watchdog(tmb, reqChan, wdRspChan)
			if err == nil && tmb.Alive() {
				// The watchdog is not meant to return a nil error whilst the tomb
				// is alive.
				return errors.New("watchdog monitor terminated unexpectedly")
			}
			return err
		})

		// Send the main request
		select {
		case reqChan <- params.req:
		case <-tmb.Dying():
			return tomb.ErrDying
		}

		// Process responses
		for tmb.Alive() {
			dec := json.NewDecoder(rspR)
			dec.DisallowUnknownFields()
			var rsp *Argon2OutOfProcessResponse
			if err := dec.Decode(&rsp); err != nil {
				return fmt.Errorf("cannot decode response: %w", err)
			}

			if rsp.Err() != nil {
				// Just return an error response.
				return rsp.Err()
			}

			switch rsp.Command {
			case Argon2OutOfProcessCommandWatchdog:
				// Direct watchdog responses to wdRspChan so they can be picked up by
				// the watchdog handler.
				select {
				case wdRspChan <- rsp:
				case <-tmb.Dying():
					// This loop will no longer iterate
				}
			default:
				actualRsp = rsp
				tmb.Kill(nil)
				// This loop will no longer iterate
			}
		}
		return tomb.ErrDying
	})

	// Wait for the tomb to begin dying
	<-tmb.Dying()

	// Close our end of the pipes supplied to the test function, as
	// a real parent process would.
	c.Check(reqW.Close(), IsNil)
	c.Check(rspR.Close(), IsNil)

	// Wait for everything to die, hopefully successfully
	if err := tmb.Wait(); err != nil {
		return nil, err
	}
	return actualRsp, nil
}

// argon2OutOfProcessParentSupportMixin provides capabilities shared
// between suites that test the parent side of out-of-process Argon2 components.
type argon2OutOfProcessParentSupportMixin struct {
	restoreLockPath    func()
	runArgon2OutputDir string
}

func (s *argon2OutOfProcessParentSupportMixin) SetUpSuite(c *C) {
	s.runArgon2OutputDir = c.MkDir()
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", s.runArgon2OutputDir, "./cmd/run_argon2")
	c.Assert(cmd.Run(), IsNil)
}

func (s *argon2OutOfProcessParentSupportMixin) SetUpTest(c *C) {
	s.restoreLockPath = MockArgon2OutOfProcessHandlerSystemLockPath(filepath.Join(c.MkDir(), "argon2.lock"))
}

func (s *argon2OutOfProcessParentSupportMixin) TearDownTest(c *C) {
	if s.restoreLockPath != nil {
		s.restoreLockPath()
	}
}

func (s *argon2OutOfProcessParentSupportMixin) newHandlerCmd(args ...string) func() (*exec.Cmd, error) {
	return func() (*exec.Cmd, error) {
		return exec.Command(filepath.Join(s.runArgon2OutputDir, "run_argon2"), append([]string{paths.Argon2OutOfProcessHandlerSystemLockPath}, args...)...), nil
	}
}

type testHMACArgon2OutOfProcessWatchdogMonitorParams struct {
	monitorAlg crypto.Hash
	period     time.Duration
	timeout    time.Duration
	handlerAlg crypto.Hash

	minDelay time.Duration
	maxDelay time.Duration
}

func (s *argon2OutOfProcessParentSupportMixin) testHMACArgon2OutOfProcessWatchdogMonitor(c *C, params *testHMACArgon2OutOfProcessWatchdogMonitorParams) error {
	c.Assert(params.maxDelay >= params.minDelay, testutil.IsTrue)

	monitor := HMACArgon2OutOfProcessWatchdogMonitor(params.monitorAlg, params.period, params.timeout)
	handler := HMACArgon2OutOfProcessWatchdogHandler(params.handlerAlg)

	tmb := new(tomb.Tomb)
	reqChan := make(chan *Argon2OutOfProcessRequest)
	rspChan := make(chan *Argon2OutOfProcessResponse)

	// Spin up a routine to handle watchdog requests and setup the test
	tmb.Go(func() error {
		// Spin up a routine to run the monitor
		tmb.Go(func() error {
			return monitor(tmb, reqChan, rspChan)
		})

		// Spin up a routine that will terminate the test after 2 seconds
		tmb.Go(func() error {
			<-time.After(2 * time.Second)
			tmb.Kill(nil)
			return tomb.ErrDying
		})

		// Run a loop whilst the tomb is alive to handle wachdog requests
		for tmb.Alive() {
			start := time.Now() // Record the start time
			select {
			case req := <-reqChan:
				period := time.Now().Sub(start)

				// Ensure the monitor period is accurate within +/- 10%
				min := time.Duration(float64(period) * 0.9)
				max := time.Duration(float64(period) * 1.1)
				if period < min || period > max {
					return fmt.Errorf("unexpected period %v", period)
				}

				// Ensure the monitor send the correct command
				if req.Command != Argon2OutOfProcessCommandWatchdog {
					return fmt.Errorf("unexpected request command %q", req.Command)
				}

				// Run the handler
				rsp, err := handler(req.WatchdogChallenge)
				if err != nil {
					return fmt.Errorf("cannot handle challenge: %w", err)
				}

				// Insert a delay
				delay := params.minDelay + time.Duration((float64(rand.Intn(100))/100)*float64(params.maxDelay-params.minDelay))
				select {
				case <-time.After(delay):
				case <-tmb.Dying():
					return tomb.ErrDying
				}

				// Send the response back to the monmitor
				select {
				case rspChan <- &Argon2OutOfProcessResponse{Command: Argon2OutOfProcessCommandWatchdog, WatchdogResponse: rsp}:
				case <-tmb.Dying():
				}
			case <-tmb.Dying():
			}
		}
		return tomb.ErrDying
	})

	return tmb.Wait()
}

type argon2OutOfProcessHandlerSupportSuite struct {
	argon2OutOfProcessHandlerSupportMixin
}

type argon2OutOfProcessHandlerSupportSuiteExpensive struct {
	argon2OutOfProcessHandlerSupportMixin
}

func (s *argon2OutOfProcessHandlerSupportSuiteExpensive) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_ARGON2_TESTS"); exists {
		c.Skip("skipping expensive argon2 tests")
	}
}

type argon2OutOfProcessParentSupportSuite struct {
	argon2OutOfProcessParentSupportMixin
}

type argon2OutOfProcessParentSupportSuiteExpensive struct {
	argon2OutOfProcessParentSupportMixin
}

func (s *argon2OutOfProcessParentSupportSuiteExpensive) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_ARGON2_TESTS"); exists {
		c.Skip("skipping expensive argon2 tests")
	}
	s.argon2OutOfProcessParentSupportMixin.SetUpSuite(c)
}

var _ = Suite(&argon2OutOfProcessHandlerSupportSuite{})
var _ = Suite(&argon2OutOfProcessHandlerSupportSuiteExpensive{})
var _ = Suite(&argon2OutOfProcessParentSupportSuite{})
var _ = Suite(&argon2OutOfProcessParentSupportSuiteExpensive{})

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveRequestInvalidMode(c *C) {
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
		ErrorString: "mode cannot be \"foo\"",
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveRequestInvalidTime(c *C) {
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
		ErrorString: "time cannot be zero",
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveRequestInvalidThreads(c *C) {
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
		ErrorString: "threads cannot be zero",
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveRequestInvalidWatchdogChallenge(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:           Argon2OutOfProcessCommandDerive,
		Passphrase:        "foo",
		Salt:              nil,
		Keylen:            32,
		Mode:              Argon2id,
		Time:              4,
		MemoryKiB:         32 * 1024,
		Threads:           1,
		WatchdogChallenge: []byte{1, 2, 3, 4},
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandDerive,
		ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
		ErrorString: "invalid watchdog challenge: cannot service a watchdog",
	})
}
func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessTimeRequestInvalidPassphrase(c *C) {
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

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessTimeRequestInvalidSalt(c *C) {
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

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessTimeRequestInvalidKeylen(c *C) {
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

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessInvalidCommand(c *C) {
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
		ErrorString: "command cannot be \"foo\"",
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveMoreThanOnce(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "7306196ab24ea3ac9daab7f14345a9dc228dccef07075dbd2e047deac96689ea"),
	})

	out = RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command: Argon2OutOfProcessCommandDerive,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command:     Argon2OutOfProcessCommandDerive,
		ErrorType:   Argon2OutOfProcessErrorRestartProcess,
		ErrorString: "this process cannot handle any more KDF requests",
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveMinimum(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "7306196ab24ea3ac9daab7f14345a9dc228dccef07075dbd2e047deac96689ea"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveDifferentThreads(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    1,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "5699b81ee10e189505874d0cbd93d61186b90554c716d309037907b7238113e1"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveDifferentTime(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
		Keylen:     32,
		Mode:       Argon2id,
		Time:       5,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "2f2d7dd170cf43aff82737bc1c2fbe685b34190fc8b62378693c3b0685b96912"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveDifferentMemory(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  64,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "6f49db1f7336329c0d5fd652642b144b204d7976c5fcb4c72b6e1d9ea345fa32"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveDifferentPassphrase(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "bar",
		Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "43cb7f6d24bb2da9ae04735c7193c7523fe057243f09c1241a99cd4ccd7d17f5"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveDifferentSalt(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       testutil.DecodeHexString(c, "97226ac63a73c7dafef57066ee645abe"),
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "720ff1ce2beecf00c4586d659bd7fa9f018cc4f115f398975eff50b35f3393ff"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveDifferentKeyLen(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
		Keylen:     64,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "21ab785e199d43575ca11e85e0a1281b4426c973cfad0a899b24bc4b8057355912a20b5f4132d8132ce3aa5bffe0d9a6a7fd05d3ab67898c196d584c98d47e44"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessDeriveDifferentMode(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "foo",
		Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
		Keylen:     32,
		Mode:       Argon2i,
		Time:       4,
		MemoryKiB:  32,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "a02a0203ea0e5e9abe4006fc80d1aca26b0adc1f898214c4c61d31f90bd4d129"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuiteExpensive) TestRunArgon2OutOfProcess2GB(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "bar",
		Salt:       testutil.DecodeHexString(c, "5d53157092d5f97034c0d3fd078b8f5c"),
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  2 * 1024 * 1024,
		Threads:    4,
	})
	c.Check(out, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "9b5add3d66b041c49c63ba1244bb1cd8cbc7dcf1e4b0918dc13b4fd6131ae5fd"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestRunArgon2OutOfProcessTime(c *C) {
	out := RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      Argon2id,
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	})
	c.Check(out, NotNil)
	c.Check(out.Command, Equals, Argon2OutOfProcessCommandTime)
	c.Check(out.Duration, Not(Equals), time.Duration(0))

	origDuration := out.Duration

	// Permit calling the function again
	ResetArgon2OutOfProcessHandlerStatus()

	out = RunArgon2OutOfProcessRequest(&Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      Argon2id,
		Time:      8,
		MemoryKiB: 512,
		Threads:   4,
	})
	c.Check(out, NotNil)
	c.Check(out.Command, Equals, Argon2OutOfProcessCommandTime)
	c.Check(out.Duration > origDuration, testutil.IsTrue)
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestHMACArgon2OutOfProcessWatchdogHandlerSHA256(c *C) {
	handler := HMACArgon2OutOfProcessWatchdogHandler(crypto.SHA256)

	rsp, err := handler(testutil.DecodeHexString(c, "3674f5b88f2e6b36ae94aa01f1ee16eaf9ab90df0979ae966837bcd37f0fa1fc"))
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, testutil.DecodeHexString(c, "9086bd5b0208ac012a345839d7dd5e442db9597a882e2d328ebf35a2f27ce919"))

	rsp, err = handler(testutil.DecodeHexString(c, "3c1de58760e53cac4facc2d5409b362fcf9b81f9b611479f5956abdb0227e567"))
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, testutil.DecodeHexString(c, "3d746bc1f5c471ea9983596512ac846910facf966b611dc2c62e08203afc86f0"))
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestHMACArgon2OutOfProcessWatchdogHandlerSHA384(c *C) {
	handler := HMACArgon2OutOfProcessWatchdogHandler(crypto.SHA384)

	rsp, err := handler(testutil.DecodeHexString(c, "7b70dfe03ac13bf595061f0d454d10a3595b494277306fe3ed6cdc1c711199cf943bed96023dbd07699f1b6fcbe96574"))
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, testutil.DecodeHexString(c, "5e1c3249bcf2e8c93dad1368ef2204fc0d497336ac0e4f260f8c39fa300dc9b9c7f9e19156b4f87c08c1b34537d7d2e1"))

	rsp, err = handler(testutil.DecodeHexString(c, "dada0215efc0e034f431fce916caf73af7fd84ad24f9215d08959699745957c7e29190d214e8c1cda78c45a2f0bd4059"))
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, testutil.DecodeHexString(c, "a36e2bda200e88620d53d32196bb6c49efa24c152009a7aac7fcb36e1b97ae2fb62ffc359c2247a8c2bb8f2e89f4b8a9"))
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestNoArgon2OutOfProcessWatchdogHandler(c *C) {
	handler := NoArgon2OutOfProcessWatchdogHandler()
	_, err := handler([]byte{1, 2, 3, 4})
	c.Check(err, ErrorMatches, `unexpected watchdog request: no handler`)
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestWaitForAndRunArgon2OutOfProcessRequestMinimum(c *C) {
	rsp, err := s.testWaitForAndRunArgon2OutOfProcessRequest(c, &testWaitForAndRunArgon2OutOfProcessRequestParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
			Keylen:     32,
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  32,
			Threads:    4,
		},
		wdHandler: NoArgon2OutOfProcessWatchdogHandler(),
		wdMonitor: NoArgon2OutOfProcessWatchdogMonitor(),
	})
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "7306196ab24ea3ac9daab7f14345a9dc228dccef07075dbd2e047deac96689ea"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestWaitForAndRunArgon2OutOfProcessRequestDifferentThreads(c *C) {
	rsp, err := s.testWaitForAndRunArgon2OutOfProcessRequest(c, &testWaitForAndRunArgon2OutOfProcessRequestParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
			Keylen:     32,
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  32,
			Threads:    1,
		},
		wdHandler: NoArgon2OutOfProcessWatchdogHandler(),
		wdMonitor: NoArgon2OutOfProcessWatchdogMonitor(),
	})
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "5699b81ee10e189505874d0cbd93d61186b90554c716d309037907b7238113e1"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestWaitForAndRunArgon2OutOfProcessRequestDifferentTime(c *C) {
	rsp, err := s.testWaitForAndRunArgon2OutOfProcessRequest(c, &testWaitForAndRunArgon2OutOfProcessRequestParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
			Keylen:     32,
			Mode:       Argon2id,
			Time:       5,
			MemoryKiB:  32,
			Threads:    4,
		},
		wdHandler: NoArgon2OutOfProcessWatchdogHandler(),
		wdMonitor: NoArgon2OutOfProcessWatchdogMonitor(),
	})
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "2f2d7dd170cf43aff82737bc1c2fbe685b34190fc8b62378693c3b0685b96912"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestWaitForAndRunArgon2OutOfProcessRequestDifferentMemory(c *C) {
	rsp, err := s.testWaitForAndRunArgon2OutOfProcessRequest(c, &testWaitForAndRunArgon2OutOfProcessRequestParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
			Keylen:     32,
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  64,
			Threads:    4,
		},
		wdHandler: NoArgon2OutOfProcessWatchdogHandler(),
		wdMonitor: NoArgon2OutOfProcessWatchdogMonitor(),
	})
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "6f49db1f7336329c0d5fd652642b144b204d7976c5fcb4c72b6e1d9ea345fa32"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestWaitForAndRunArgon2OutOfProcessRequestPassphrase(c *C) {
	rsp, err := s.testWaitForAndRunArgon2OutOfProcessRequest(c, &testWaitForAndRunArgon2OutOfProcessRequestParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "bar",
			Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
			Keylen:     32,
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  32,
			Threads:    4,
		},
		wdHandler: NoArgon2OutOfProcessWatchdogHandler(),
		wdMonitor: NoArgon2OutOfProcessWatchdogMonitor(),
	})
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "43cb7f6d24bb2da9ae04735c7193c7523fe057243f09c1241a99cd4ccd7d17f5"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestWaitForAndRunArgon2OutOfProcessRequestDifferentSalt(c *C) {
	rsp, err := s.testWaitForAndRunArgon2OutOfProcessRequest(c, &testWaitForAndRunArgon2OutOfProcessRequestParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       testutil.DecodeHexString(c, "97226ac63a73c7dafef57066ee645abe"),
			Keylen:     32,
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  32,
			Threads:    4,
		},
		wdHandler: NoArgon2OutOfProcessWatchdogHandler(),
		wdMonitor: NoArgon2OutOfProcessWatchdogMonitor(),
	})
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "720ff1ce2beecf00c4586d659bd7fa9f018cc4f115f398975eff50b35f3393ff"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestWaitForAndRunArgon2OutOfProcessRequestDifferentKeyLen(c *C) {
	rsp, err := s.testWaitForAndRunArgon2OutOfProcessRequest(c, &testWaitForAndRunArgon2OutOfProcessRequestParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
			Keylen:     64,
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  32,
			Threads:    4,
		},
		wdHandler: NoArgon2OutOfProcessWatchdogHandler(),
		wdMonitor: NoArgon2OutOfProcessWatchdogMonitor(),
	})
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "21ab785e199d43575ca11e85e0a1281b4426c973cfad0a899b24bc4b8057355912a20b5f4132d8132ce3aa5bffe0d9a6a7fd05d3ab67898c196d584c98d47e44"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuite) TestWaitForAndRunArgon2OutOfProcessRequestDifferentMode(c *C) {
	rsp, err := s.testWaitForAndRunArgon2OutOfProcessRequest(c, &testWaitForAndRunArgon2OutOfProcessRequestParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "foo",
			Salt:       testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"),
			Keylen:     32,
			Mode:       Argon2i,
			Time:       4,
			MemoryKiB:  32,
			Threads:    4,
		},
		wdHandler: NoArgon2OutOfProcessWatchdogHandler(),
		wdMonitor: NoArgon2OutOfProcessWatchdogMonitor(),
	})
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "a02a0203ea0e5e9abe4006fc80d1aca26b0adc1f898214c4c61d31f90bd4d129"),
	})
}

func (s *argon2OutOfProcessHandlerSupportSuiteExpensive) TestWaitForAndRunArgon2OutOfProcessRequest2GB(c *C) {
	rsp, err := s.testWaitForAndRunArgon2OutOfProcessRequest(c, &testWaitForAndRunArgon2OutOfProcessRequestParams{
		req: &Argon2OutOfProcessRequest{
			Command:    Argon2OutOfProcessCommandDerive,
			Passphrase: "bar",
			Salt:       testutil.DecodeHexString(c, "5d53157092d5f97034c0d3fd078b8f5c"),
			Keylen:     32,
			Mode:       Argon2id,
			Time:       4,
			MemoryKiB:  2 * 1024 * 1024,
			Threads:    4,
		},
		wdHandler: HMACArgon2OutOfProcessWatchdogHandler(crypto.SHA256),
		wdMonitor: HMACArgon2OutOfProcessWatchdogMonitor(crypto.SHA256, 100*time.Millisecond, 50*time.Millisecond),
	})
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, &Argon2OutOfProcessResponse{
		Command: Argon2OutOfProcessCommandDerive,
		Key:     testutil.DecodeHexString(c, "9b5add3d66b041c49c63ba1244bb1cd8cbc7dcf1e4b0918dc13b4fd6131ae5fd"),
	})
}

func (s *argon2OutOfProcessParentSupportSuite) TestNoArgon2OutOfProcessWatchdogMonitorUnexpectedResponse(c *C) {
	monitor := NoArgon2OutOfProcessWatchdogMonitor()

	tmb := new(tomb.Tomb)
	reqChan := make(chan *Argon2OutOfProcessRequest)
	rspChan := make(chan *Argon2OutOfProcessResponse)

	tmb.Go(func() error {
		return monitor(tmb, reqChan, rspChan)
	})

	select {
	case rspChan <- new(Argon2OutOfProcessResponse):
	case <-time.After(2 * time.Second): // Give the test 2 seconds to complete
	}

	c.Check(tmb.Wait(), ErrorMatches, `unexpected watchdog response`)
}

func (s *argon2OutOfProcessParentSupportSuiteExpensive) TestNoArgon2OutOfProcessWatchdogMonitor(c *C) {
	monitor := NoArgon2OutOfProcessWatchdogMonitor()

	tmb := new(tomb.Tomb)
	reqChan := make(chan *Argon2OutOfProcessRequest)
	rspChan := make(chan *Argon2OutOfProcessResponse)

	tmb.Go(func() error {
		tmb.Go(func() error {
			return monitor(tmb, reqChan, rspChan)
		})

		// Run the monitor for 2 seconds to make sure we don't see any requests.
		select {
		case <-time.After(2 * time.Second):
		case <-reqChan:
			return errors.New("unexpected watchdog request")
		}

		tmb.Kill(nil)
		return tomb.ErrDying
	})
	c.Check(tmb.Wait(), IsNil)
}

func (s *argon2OutOfProcessParentSupportSuiteExpensive) TestHMACArgon2OutOfProcessWatchdogMonitor(c *C) {
	err := s.testHMACArgon2OutOfProcessWatchdogMonitor(c, &testHMACArgon2OutOfProcessWatchdogMonitorParams{
		monitorAlg: crypto.SHA256,
		period:     100 * time.Millisecond,
		timeout:    20 * time.Millisecond,
		handlerAlg: crypto.SHA256,
		minDelay:   5 * time.Millisecond,
		maxDelay:   15 * time.Millisecond,
	})
	c.Check(err, IsNil)
}

func (s *argon2OutOfProcessParentSupportSuiteExpensive) TestHMACArgon2OutOfProcessWatchdogMonitorDifferentAlg(c *C) {
	err := s.testHMACArgon2OutOfProcessWatchdogMonitor(c, &testHMACArgon2OutOfProcessWatchdogMonitorParams{
		monitorAlg: crypto.SHA384,
		period:     100 * time.Millisecond,
		timeout:    20 * time.Millisecond,
		handlerAlg: crypto.SHA384,
		minDelay:   5 * time.Millisecond,
		maxDelay:   15 * time.Millisecond,
	})
	c.Check(err, IsNil)
}

func (s *argon2OutOfProcessParentSupportSuiteExpensive) TestHMACArgon2OutOfProcessWatchdogMonitorDifferentPeriod(c *C) {
	err := s.testHMACArgon2OutOfProcessWatchdogMonitor(c, &testHMACArgon2OutOfProcessWatchdogMonitorParams{
		monitorAlg: crypto.SHA256,
		period:     200 * time.Millisecond,
		timeout:    20 * time.Millisecond,
		handlerAlg: crypto.SHA256,
		minDelay:   5 * time.Millisecond,
		maxDelay:   15 * time.Millisecond,
	})
	c.Check(err, IsNil)
}

func (s *argon2OutOfProcessParentSupportSuiteExpensive) TestHMACArgon2OutOfProcessWatchdogMonitorDifferentTimeout(c *C) {
	err := s.testHMACArgon2OutOfProcessWatchdogMonitor(c, &testHMACArgon2OutOfProcessWatchdogMonitorParams{
		monitorAlg: crypto.SHA256,
		period:     100 * time.Millisecond,
		timeout:    50 * time.Millisecond,
		handlerAlg: crypto.SHA256,
		minDelay:   35 * time.Millisecond,
		maxDelay:   45 * time.Millisecond,
	})
	c.Check(err, IsNil)
}

func (s *argon2OutOfProcessParentSupportSuite) TestHMACArgon2OutOfProcessWatchdogMonitorResponseTimeout(c *C) {
	err := s.testHMACArgon2OutOfProcessWatchdogMonitor(c, &testHMACArgon2OutOfProcessWatchdogMonitorParams{
		monitorAlg: crypto.SHA256,
		period:     100 * time.Millisecond,
		timeout:    20 * time.Millisecond,
		handlerAlg: crypto.SHA256,
		minDelay:   25 * time.Millisecond,
		maxDelay:   25 * time.Millisecond,
	})
	c.Check(err, ErrorMatches, `timeout waiting for watchdog response from remote process`)
}

func (s *argon2OutOfProcessParentSupportSuite) TestHMACArgon2OutOfProcessWatchdogMonitorInvalidResponse(c *C) {
	err := s.testHMACArgon2OutOfProcessWatchdogMonitor(c, &testHMACArgon2OutOfProcessWatchdogMonitorParams{
		monitorAlg: crypto.SHA384,
		period:     100 * time.Millisecond,
		timeout:    20 * time.Millisecond,
		handlerAlg: crypto.SHA256,
		minDelay:   5 * time.Millisecond,
		maxDelay:   15 * time.Millisecond,
	})
	c.Check(err, ErrorMatches, `unexpected watchdog response value from remote process`)
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveMinimum(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("none"), 0, nil)
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	}
	key, err := kdf.Derive("foo", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2id, params, 32)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, testutil.DecodeHexString(c, "7306196ab24ea3ac9daab7f14345a9dc228dccef07075dbd2e047deac96689ea"))
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveDifferentThreads(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("none"), 0, nil)
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 32,
		Threads:   1,
	}
	key, err := kdf.Derive("foo", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2id, params, 32)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, testutil.DecodeHexString(c, "5699b81ee10e189505874d0cbd93d61186b90554c716d309037907b7238113e1"))
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveDifferentTime(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("none"), 0, nil)
	params := &Argon2CostParams{
		Time:      5,
		MemoryKiB: 32,
		Threads:   4,
	}
	key, err := kdf.Derive("foo", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2id, params, 32)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, testutil.DecodeHexString(c, "2f2d7dd170cf43aff82737bc1c2fbe685b34190fc8b62378693c3b0685b96912"))
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveDifferentMemory(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("none"), 0, nil)
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 64,
		Threads:   4,
	}
	key, err := kdf.Derive("foo", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2id, params, 32)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, testutil.DecodeHexString(c, "6f49db1f7336329c0d5fd652642b144b204d7976c5fcb4c72b6e1d9ea345fa32"))
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveDifferentPassphrase(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("none"), 0, nil)
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	}
	key, err := kdf.Derive("bar", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2id, params, 32)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, testutil.DecodeHexString(c, "43cb7f6d24bb2da9ae04735c7193c7523fe057243f09c1241a99cd4ccd7d17f5"))
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveDifferentSalt(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("none"), 0, nil)
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	}
	key, err := kdf.Derive("foo", testutil.DecodeHexString(c, "97226ac63a73c7dafef57066ee645abe"), Argon2id, params, 32)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, testutil.DecodeHexString(c, "720ff1ce2beecf00c4586d659bd7fa9f018cc4f115f398975eff50b35f3393ff"))
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveKeyLen(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("none"), 0, nil)
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	}
	key, err := kdf.Derive("foo", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2id, params, 64)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, testutil.DecodeHexString(c, "21ab785e199d43575ca11e85e0a1281b4426c973cfad0a899b24bc4b8057355912a20b5f4132d8132ce3aa5bffe0d9a6a7fd05d3ab67898c196d584c98d47e44"))
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveDifferentMode(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("none"), 0, nil)
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	}
	key, err := kdf.Derive("foo", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2i, params, 32)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, testutil.DecodeHexString(c, "a02a0203ea0e5e9abe4006fc80d1aca26b0adc1f898214c4c61d31f90bd4d129"))
}

func (s *argon2OutOfProcessParentSupportSuiteExpensive) TestArgon2KDFDerive2GB(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("hmac", "sha256"), 0, HMACArgon2OutOfProcessWatchdogMonitor(crypto.SHA256, 100*time.Millisecond, 50*time.Millisecond))
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 2 * 1024 * 1024,
		Threads:   4,
	}
	key, err := kdf.Derive("bar", testutil.DecodeHexString(c, "5d53157092d5f97034c0d3fd078b8f5c"), Argon2id, params, 32)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, testutil.DecodeHexString(c, "9b5add3d66b041c49c63ba1244bb1cd8cbc7dcf1e4b0918dc13b4fd6131ae5fd"))
}

func (s *argon2OutOfProcessParentSupportSuiteExpensive) TestArgon2KDFDerive2GBDifferentWatchdogHMAC(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("hmac", "sha384"), 0, HMACArgon2OutOfProcessWatchdogMonitor(crypto.SHA384, 100*time.Millisecond, 50*time.Millisecond))
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 2 * 1024 * 1024,
		Threads:   4,
	}
	key, err := kdf.Derive("bar", testutil.DecodeHexString(c, "5d53157092d5f97034c0d3fd078b8f5c"), Argon2id, params, 32)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, testutil.DecodeHexString(c, "9b5add3d66b041c49c63ba1244bb1cd8cbc7dcf1e4b0918dc13b4fd6131ae5fd"))
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveErr(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("none"), 0, nil)
	params := &Argon2CostParams{
		Time:      0,
		MemoryKiB: 32,
		Threads:   4,
	}
	_, err := kdf.Derive("bar", testutil.DecodeHexString(c, "5d53157092d5f97034c0d3fd078b8f5c"), Argon2id, params, 32)
	c.Check(err, ErrorMatches, `cannot process request: invalid-time-cost \(time cannot be zero\)`)
	c.Check(err, testutil.ConvertibleTo, new(Argon2OutOfProcessError))
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFTime(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("none"), 0, nil)
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 32,
		Threads:   4,
	}
	origDuration, err := kdf.Time(Argon2id, params)
	c.Check(err, IsNil)

	params = &Argon2CostParams{
		Time:      8,
		MemoryKiB: 512,
		Threads:   4,
	}
	duration, err := kdf.Time(Argon2id, params)
	c.Check(err, IsNil)
	c.Check(duration > origDuration, testutil.IsTrue)
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveParallelSerialized(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("hmac", "sha256"), 10*time.Minute, HMACArgon2OutOfProcessWatchdogMonitor(crypto.SHA256, 100*time.Millisecond, 50*time.Millisecond))
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 2 * 1024 * 1024,
		Threads:   4,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		key, err := kdf.Derive("foo", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2id, params, 32)
		c.Check(err, IsNil)
		c.Check(key, DeepEquals, testutil.DecodeHexString(c, "d38bda36abedb509c77cbc032d80f8ebc2c1742f12a4dbedfe42a20c77db51f3"))
		wg.Done()
	}()
	go func() {
		key, err := kdf.Derive("bar", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2id, params, 32)
		c.Check(err, IsNil)
		c.Check(key, DeepEquals, testutil.DecodeHexString(c, "4f98f746990ccc53520a3096ce201e2935aac92649896c65fb5f947824f0032e"))
		wg.Done()
	}()
	wg.Wait()
}

func (s *argon2OutOfProcessParentSupportSuite) TestArgon2KDFDeriveParallelTimeout(c *C) {
	kdf := NewOutOfProcessArgon2KDF(s.newHandlerCmd("hmac", "sha256"), 100*time.Millisecond, HMACArgon2OutOfProcessWatchdogMonitor(crypto.SHA256, 100*time.Millisecond, 50*time.Millisecond))
	params := &Argon2CostParams{
		Time:      4,
		MemoryKiB: 2 * 1024 * 1024,
		Threads:   4,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		key, err := kdf.Derive("foo", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2id, params, 32)
		c.Check(err, IsNil)
		c.Check(key, DeepEquals, testutil.DecodeHexString(c, "d38bda36abedb509c77cbc032d80f8ebc2c1742f12a4dbedfe42a20c77db51f3"))
		wg.Done()
	}()
	go func() {
		<-time.NewTimer(20 * time.Millisecond).C
		_, err := kdf.Derive("bar", testutil.DecodeHexString(c, "7ed928d8153e3084393d73f938ad3e03"), Argon2id, params, 32)
		c.Check(err, ErrorMatches, `cannot process request: timeout-error \(cannot acquire argon2 system lock: request timeout\)`)
		c.Check(err, testutil.ConvertibleTo, &Argon2OutOfProcessError{})
		wg.Done()
	}()
	wg.Wait()
}
