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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

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

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessMinimum(c *C) {
	SetIsArgon2HandlerProcess()
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

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessThreads1(c *C) {
	SetIsArgon2HandlerProcess()
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

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessTime5(c *C) {
	SetIsArgon2HandlerProcess()
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

func (s *argon2OutOfProcessSupportSuite) TestRunArgon2OutOfProcessMemory64(c *C) {
	SetIsArgon2HandlerProcess()
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

func (s *argon2OutOfProcessSupportSuite) TestHMACArgon2OutOfProcessWatchdogHandlerSHA256(c *C) {
	handler := HMACArgon2OutOfProcessWatchdogHandler(crypto.SHA256)

	rsp, err := handler(testutil.DecodeHexString(c, "3674f5b88f2e6b36ae94aa01f1ee16eaf9ab90df0979ae966837bcd37f0fa1fc"))
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, testutil.DecodeHexString(c, "9086bd5b0208ac012a345839d7dd5e442db9597a882e2d328ebf35a2f27ce919"))

	rsp, err = handler(testutil.DecodeHexString(c, "3c1de58760e53cac4facc2d5409b362fcf9b81f9b611479f5956abdb0227e567"))
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, testutil.DecodeHexString(c, "d9938d01b2e93073d4b1524371bd3f7b646d5f06335861c54030ba6a1164f6d0"))
}

func (s *argon2OutOfProcessSupportSuite) TestHMACArgon2OutOfProcessWatchdogHandlerSHA384(c *C) {
	handler := HMACArgon2OutOfProcessWatchdogHandler(crypto.SHA384)

	rsp, err := handler(testutil.DecodeHexString(c, "7b70dfe03ac13bf595061f0d454d10a3595b494277306fe3ed6cdc1c711199cf943bed96023dbd07699f1b6fcbe96574"))
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, testutil.DecodeHexString(c, "5e1c3249bcf2e8c93dad1368ef2204fc0d497336ac0e4f260f8c39fa300dc9b9c7f9e19156b4f87c08c1b34537d7d2e1"))

	rsp, err = handler(testutil.DecodeHexString(c, "dada0215efc0e034f431fce916caf73af7fd84ad24f9215d08959699745957c7e29190d214e8c1cda78c45a2f0bd4059"))
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, testutil.DecodeHexString(c, "41c4b9e86cf1c43bb53439a105f7a769b0bbd7669e11d4761ebb4e7b8ec0de8169d427c63443b772655c66846fd2c8dd"))
}

func (s *argon2OutOfProcessSupportSuite) TestNoArgon2OutOfProcessWatchdogHandler(c *C) {
	handler := NoArgon2OutOfProcessWatchdogHandler()
	_, err := handler([]byte{1, 2, 3, 4})
	c.Check(err, ErrorMatches, `unexpected request: no handler for watchdog`)
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

func (s *argon2OutOfProcessSupportSuiteExpensive) TestRunArgon2OutOfProcess2GB(c *C) {
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

func (s *argon2OutOfProcessSupportSuiteExpensive) testWaitForAndRunArgon2OutOfProcessRequest(c *C, req *Argon2OutOfProcessRequest, expectedRsp *Argon2OutOfProcessResponse, wdMonitor Argon2OutOfProcessWatchdogMonitor, wdHandler Argon2OutOfProcessWatchdogHandler) {
	reqR, reqW := io.Pipe()
	rspR, rspW := io.Pipe()

	tmb := new(tomb.Tomb)

	var wg sync.WaitGroup
	wg.Add(1)

	tmb.Go(func() error {
		// Spin up a dedicated routine for running the test function
		// (WaitForAndRunArgon2OutOfProcessRequest).
		tmb.Go(func() (err error) {
			defer wg.Done()
			return WaitForAndRunArgon2OutOfProcessRequest(reqR, rspW, wdHandler)
		})

		// wdReqChan is sent requests from the watchdog monitor which are then
		// received by another goroutine, which serializes them and sends them to
		// the remote process via its stdin.
		wdReqChan := make(chan *Argon2OutOfProcessRequest)

		// wdRspChan is sent watchdog responses received from the remote process
		// via stdout, and they are subsequently received by the watchdog monitor
		// for processing.
		wdRspChan := make(chan *Argon2OutOfProcessResponse)

		// Spin up the watchdog monitor
		tmb.Go(func() error {
			err := wdMonitor(tmb, wdReqChan, wdRspChan)
			if err == nil && tmb.Alive() {
				// The watchdog returning an error will terminate the tomb, but if
				// it returns no error whilst the tomb is still alive, then consider
				// this to be unexpected. In this case, begin the termination of the
				// tomb.
				return errors.New("watchdog monitor terminated unexpectedly")
			}
			return err
		})

		// Spin up a tomb for processing requests from the watchdog.
		tmb.Go(func() error {
			for tmb.Alive() {
				dec := json.NewDecoder(rspR)
				var rsp *Argon2OutOfProcessResponse
				c.Check(dec.Decode(&rsp), IsNil)

				switch rsp.Command {
				case Argon2OutOfProcessCommandWatchdog:
					wdRspChan <- rsp
				default:
					// Check the final reponse
					c.Check(rsp, DeepEquals, expectedRsp)

					// Trigger the termination of WaitForAndRunArgon2OutOfProcessRequest.
					c.Check(reqW.Close(), IsNil)

					// Wait for WaitForAndRunArgon2OutOfProcessRequest and the rest of the tomb to finish cleanly.
					wg.Wait()
				}
			}

			tmb.Go(func() error {
				if req != nil {
					enc := json.NewEncoder(reqW)
					if err := enc.Encode(req); err != nil {
						return fmt.Errorf("cannot encode initial request: %w", err)
					}
				}
				for {
					select {
					case <-tmb.Dying():
						return nil
					case req := <-wdReqChan:
						// Send the watchdog request to its io.Reader
						enc := json.NewEncoder(reqR)
						if err := enc.Encode(req); err != nil {
							return fmt.Errorf("cannot encode watchdog request: %w", err)
						}
					}
				}
			})
			return nil
		})
		return nil
	})

	c.Check(tmb.Wait(), IsNil)
}

func (s *argon2OutOfProcessSupportSuiteExpensive) TestWaitForAndRunArgon2OutOfProcessRequest(c *C) {
	s.testWaitForAndRunArgon2OutOfProcessRequest(c, &Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: "bar",
		Salt:       testutil.DecodeHexString(c, "5d53157092d5f97034c0d3fd078b8f5c"),
		Keylen:     32,
		Mode:       Argon2id,
		Time:       4,
		MemoryKiB:  128 * 1024,
		Threads:    4,
	}, &Argon2OutOfProcessResponse{}, NoArgon2OutOfProcessWatchdogMonitor(), NoArgon2OutOfProcessWatchdogHandler())
}
