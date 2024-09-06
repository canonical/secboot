// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2024 Canonical Ltd
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

package secboot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync/atomic"
	"time"
)

// Argon2OutOfProcessCommand represents an argon2 command to run out of process.
type Argon2OutOfProcessCommand string

const (
	// Argon2OutOfProcessCommandDerive requests to derive a key from a passphrase
	Argon2OutOfProcessCommandDerive Argon2OutOfProcessCommand = "derive"

	// Argon2OutOfProcessCommandTime requests the duration that the KDF took to
	// execute. This excludes additional costs such as process startup.
	Argon2OutOfProcessCommandTime Argon2OutOfProcessCommand = "time"
)

// Argon2OutOfProcessRequest is an input request for an argon2 operation in
// a remote process.
type Argon2OutOfProcessRequest struct {
	Command    Argon2OutOfProcessCommand `json:"command"`              // The command to run
	Passphrase string                    `json:"passphrase,omitempty"` // If the command is "derive, the passphrase
	Salt       []byte                    `json:"salt,omitempty"`       // If the command is "derive", the salt
	Keylen     uint32                    `json:"keylen,omitempty"`     // If the command is "derive", the key length in bytes
	Mode       Argon2Mode                `json:"mode"`                 // The Argon2 mode
	Time       uint32                    `json:"time"`                 // The time cost
	MemoryKiB  uint32                    `json:"memory"`               // The memory cost in KiB
	Threads    uint8                     `json:"threads"`              // The number of threads to use
}

// Argon2OutOfProcessErrorType describes the type of error produced by [RunArgon2OutOfProcessRequest]
// or [WaitForAndRunArgon2OutOfProcessRequest].
type Argon2OutOfProcessErrorType string

const (
	// Argon2OutOfProcessErrorInvalidCommand means that an invalid command was supplied.
	Argon2OutOfProcessErrorInvalidCommand Argon2OutOfProcessErrorType = "invalid-command"

	// Argon2OutOfProcessErrorInvalidMode means that an invalid mode was supplied.
	Argon2OutOfProcessErrorInvalidMode Argon2OutOfProcessErrorType = "invalid-mode"

	// Argon2OutOfProcessErrorInvalidTimeCost means that an invalid time cost was supplied.
	Argon2OutOfProcessErrorInvalidTimeCost Argon2OutOfProcessErrorType = "invalid-time-cost"

	// Argon2OutOfProcessErrorInvalidThreads means that an invalid number of threads was supplied.
	Argon2OutOfProcessErrorInvalidThreads Argon2OutOfProcessErrorType = "invalid-threads"

	// Argon2OutOfProcessErrorConsumedProcess means that this process has already performed one
	// execution of the KDF, and the process should exit and be replaced by a new one.
	Argon2OutOfProcessErrorConsumedProcess Argon2OutOfProcessErrorType = "consumed-process"

	// Argon2OutOfProcessErrorProcessNotConfigured means that nothing has called SetIsArgon2HandlerProcess
	// to configure the process for handling an Argon2 request.
	Argon2OutOfProcessErrorProcessNotConfigured Argon2OutOfProcessErrorType = "process-not-configured"

	// Argon2OutOfProcessErrorUnexpected means that an unexpected error occurred when
	// running the operation.
	Argon2OutOfProcessErrorUnexpected Argon2OutOfProcessErrorType = "unexpected-error"

	// Argon2OutOfProcessErrorUnexpectedInput means that there was an error with
	// the supplied request input not covered by one of the more specific error types.
	Argon2OutOfProcessErrorUnexpectedInput Argon2OutOfProcessErrorType = "unexpected-input"
)

// Argon2OutOfProcessResponse is the response to a request for an argon2
// operation in a remote process.
type Argon2OutOfProcessResponse struct {
	Command     Argon2OutOfProcessCommand   `json:"command"`                // The input command
	Key         []byte                      `json:"key,omitempty"`          // The derived key, if the input command was "derive"
	Duration    time.Duration               `json:"duration,omitempty"`     // The duration, if the input command was "duration"
	ErrorType   Argon2OutOfProcessErrorType `json:"error-type,omitempty"`   // The error type, if an error occurred
	ErrorString string                      `json:"error-string,omitempty"` // The error string, if an error occurred
}

// Argon2OutOfProcessError is returned from [Argon2OutOfProcessResponse.Err]
// if the response indicates an error, or directly from methods of the [Argon2KDF]
// implementation created by [NewOutOfProcessKDF] when the received response indicates
// that an error ocurred.
type Argon2OutOfProcessError struct {
	ErrorType   Argon2OutOfProcessErrorType
	ErrorString string
}

// Error implements the error interface.
func (e *Argon2OutOfProcessError) Error() string {
	str := new(bytes.Buffer)
	fmt.Fprintf(str, "cannot process KDF request: %v", e.ErrorType)
	if e.ErrorString != "" {
		fmt.Fprintf(str, " (%s)", e.ErrorString)
	}
	return str.String()
}

// Err returns an error associated with the response if one occurred, or nil if no
// error occurred. If the response indicates an error, the returned error will be a
// *[Argon2OutOfProcessError].
func (o *Argon2OutOfProcessResponse) Err() error {
	if o.ErrorType == "" {
		return nil
	}
	return &Argon2OutOfProcessError{
		ErrorType:   o.ErrorType,
		ErrorString: o.ErrorString,
	}
}

const (
	argon2Unused  uint32 = 0
	argon2Expired uint32 = 1
)

var errArgon2OutOfProcessHandlerExpired = errors.New("argon2 out-of-process handler has alreay been used - a new process should be started to handle a new request")

// argon2OutOfProcessHandler is an implementation of Argon2KDF that will
// only process a single call before returning an error on subsequent calls.
type argon2OutOfProcessHandler struct {
	Status uint32
	KDF    Argon2KDF
}

// consume uses up the single request that this KDF can process, and returns true
// if it can continue processing the request, or false if it should stop processing
// the reqest because it has already processed a request in the past and the process
// should be restarted.
func (k *argon2OutOfProcessHandler) consume() bool {
	return atomic.CompareAndSwapUint32(&k.Status, argon2Unused, argon2Expired)
}

func (k *argon2OutOfProcessHandler) Derive(passphrase string, salt []byte, mode Argon2Mode, params *Argon2CostParams, keyLen uint32) ([]byte, error) {
	if !k.consume() {
		return nil, errArgon2OutOfProcessHandlerExpired
	}
	return k.KDF.Derive(passphrase, salt, mode, params, keyLen)
}

func (k *argon2OutOfProcessHandler) Time(mode Argon2Mode, params *Argon2CostParams) (time.Duration, error) {
	if !k.consume() {
		return 0, errArgon2OutOfProcessHandlerExpired
	}
	return k.KDF.Time(mode, params)
}

const (
	notArgon2HandlerProcess      uint32 = 0
	becomingArgon2HandlerProcess uint32 = 1
	readyArgon2HandlerProcess    uint32 = 2
)

var (
	argon2OutOfProcessStatus uint32 = notArgon2HandlerProcess
)

// SetIsArgon2HandlerProcess marks this process as being a process capable of handling and
// processing an Argon2 request on behalf of another process, and executing it in this process
// before returning a response to the caller.
//
// Note that this can only be called once in a process lifetime. Calling it more than once
// results in a panic. It shouldn't be used alongside [SetArgon2KDF] - if this has already been
// called, a panic will occur as well. Applications should only use one of these functions in a
// process.
//
// Calling this sets the process-wide Argon2 implementation (the one normally set via
// [SetArgon2KDF]) to a variation of [InProcessArgon2KDF] that will only process a single
// request before responding with an error on subsequent requests.
//
// Calling this function is required in order to be able to use [RunArgon2OutOfProcessRequest]
// and [WaitForAndRunArgon2OutOfProcessRequest].
func SetIsArgon2HandlerProcess() {
	// Mark process as becoming an argon2 handler process. This will ensure that new calls
	// to SetArgon2KDF to panic.
	if !atomic.CompareAndSwapUint32(&argon2OutOfProcessStatus, notArgon2HandlerProcess, becomingArgon2HandlerProcess) {
		panic("cannot call SetIsArgon2HandlerProcess more than once")
	}

	// Take the lock that SetArgon2KDF uses to wait for existing calls to finish if there
	// are any pending.
	argon2Mu.Lock()
	defer argon2Mu.Unlock()

	// There currently aren't any callers inside SetArgon2KDF, and we have the lock. We
	// own the global KDF now - we're going to set the global implementation, overwriting
	// whatever was there previously. Any future calls to SetArgon2KDF will panic.
	argon2Impl = &argon2OutOfProcessHandler{
		Status: argon2Unused,
		KDF:    InProcessArgon2KDF,
	}

	// Mark this process as ready so that RunArgon2OutOfProcessRequest and
	// WaitForAndRunArgon2OutOfProcessRequest will work.
	atomic.StoreUint32(&argon2OutOfProcessStatus, readyArgon2HandlerProcess)
}

// RunArgon2OutOfProcessRequest runs the specified argon2 request, and returns a response. This
// function can only be called once in a process. Subsequent calls in the same process will result
// in an error response being returned.
//
// This function requires [SetIsArgon2HandlerProcess] to have already been called in this process,
// else an error response will be returned.
func RunArgon2OutOfProcessRequest(request *Argon2OutOfProcessRequest) *Argon2OutOfProcessResponse {
	if atomic.LoadUint32(&argon2OutOfProcessStatus) < readyArgon2HandlerProcess {
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorProcessNotConfigured,
			ErrorString: "cannot handle out-of-process request in a process that isn't configured as an Argon2 handler process",
		}
	}

	switch request.Mode {
	case Argon2id, Argon2i:
		// ok
	default:
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorInvalidMode,
			ErrorString: fmt.Sprintf("invalid mode: %q", string(request.Mode)),
		}
	}

	costParams := &Argon2CostParams{
		Time:      request.Time,
		MemoryKiB: request.MemoryKiB,
		Threads:   request.Threads,
	}
	if costParams.Time == 0 {
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorInvalidTimeCost,
			ErrorString: "invalid time cost: cannot be zero",
		}
	}
	if costParams.Threads == 0 {
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorInvalidThreads,
			ErrorString: "invalid threads: cannot be zero",
		}
	}

	switch request.Command {
	case Argon2OutOfProcessCommandDerive:
		key, err := argon2KDF().Derive(request.Passphrase, request.Salt, request.Mode, costParams, request.Keylen)
		if err != nil {
			errorType := Argon2OutOfProcessErrorUnexpected
			if errors.Is(err, errArgon2OutOfProcessHandlerExpired) {
				// This process has already processed a request, so it should be restarted.
				errorType = Argon2OutOfProcessErrorConsumedProcess
			}
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   errorType,
				ErrorString: fmt.Sprintf("cannot run derive command: %v", err),
			}
		}
		return &Argon2OutOfProcessResponse{
			Command: request.Command,
			Key:     key,
		}
	case Argon2OutOfProcessCommandTime:
		if len(request.Passphrase) > 0 {
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
				ErrorString: "cannot supply passphrase for \"time\" command",
			}
		}
		if len(request.Salt) > 0 {
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
				ErrorString: "cannot supply salt for \"time\" command",
			}
		}
		if request.Keylen > 0 {
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
				ErrorString: "cannot supply keylen for \"time\" command",
			}
		}

		duration, err := argon2KDF().Time(request.Mode, costParams)
		if err != nil {
			errorType := Argon2OutOfProcessErrorUnexpected
			if errors.Is(err, errArgon2OutOfProcessHandlerExpired) {
				// This process has already processed a request, so it should be restarted.
				errorType = Argon2OutOfProcessErrorConsumedProcess
			}
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   errorType,
				ErrorString: fmt.Sprintf("cannot run time command: %v", err),
			}
		}
		return &Argon2OutOfProcessResponse{
			Command:  request.Command,
			Duration: duration,
		}
	default:
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorInvalidCommand,
			ErrorString: fmt.Sprintf("invalid command: %q", string(request.Command)),
		}
	}
}

// WaitForAndRunArgon2OutOfProcessRequest waits for a [Argon2OutOfProcessRequest] request on the
// supplied io.Reader before running it and sending a [Argon2OutOfProcessResponse] response back via
// the supplied io.Writer. These will generally be connected to the process's os.Stdin and
// os.Stdout - at least they will need to be when using [NewOutOfProcessKDF] on the parent side.
//
// This function can only be called once in a process. Subsequent calls in the same process will
// result in an error response being returned via the io.Writer (after receiving a new request via
// the io.Reader).
//
// This function requires [SetIsArgon2HandlerProcess] to have already been called in this process,
// else an error response will be returned via the io.Writer.
func WaitForAndRunArgon2OutOfProcessRequest(in io.Reader, out io.Writer) error {
	var req *Argon2OutOfProcessRequest
	dec := json.NewDecoder(in)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return fmt.Errorf("cannot decode request: %w", err)
	}

	rsp := RunArgon2OutOfProcessRequest(req)

	enc := json.NewEncoder(out)
	if err := enc.Encode(rsp); err != nil {
		return fmt.Errorf("cannot encode response: %w", err)
	}

	return nil
}

// outOfProcessArgon2KDFImpl is an Argon2KDFImpl that runs the KDF in a short-lived
// helper process, using the remote JSON protocol defined in this package.
type outOfProcessArgon2KDFImpl struct {
	newHandlerCmd func() (*exec.Cmd, error)
}

func (k *outOfProcessArgon2KDFImpl) sendRequestAndWaitForResponse(req *Argon2OutOfProcessRequest) (rsp *Argon2OutOfProcessResponse, err error) {
	cmd, err := k.newHandlerCmd()
	if err != nil {
		return nil, fmt.Errorf("cannot create new command: %w", err)
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		// This doesn't fail once the OS pipe is created, so there's no
		// cleanup to do on failure paths.
		return nil, fmt.Errorf("cannot create stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		// This doesn't fail once the OS pipe is created, so there's no
		// cleanup to do on failure paths.
		return nil, fmt.Errorf("cannot create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cannot start handler process: %w", err)
	}
	defer func() {
		// Run Cmd.Wait in a defer so that we shut down on error paths too,
		// and we capture the Wait error if there was no other error.
		waitErr := cmd.Wait()
		if waitErr != nil && err == nil {
			rsp = nil
			err = fmt.Errorf("cannot wait for remote process to finish: %w", waitErr)
		}
	}()

	// Send the input params to the remote process.
	enc := json.NewEncoder(stdinPipe)
	if err := enc.Encode(req); err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	// Wait for thre result from the remote process.
	dec := json.NewDecoder(stdoutPipe)
	if err := dec.Decode(&rsp); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}

	return rsp, nil
}

func (k *outOfProcessArgon2KDFImpl) Derive(passphrase string, salt []byte, mode Argon2Mode, params *Argon2CostParams, keyLen uint32) (key []byte, err error) {
	req := &Argon2OutOfProcessRequest{
		Command:    Argon2OutOfProcessCommandDerive,
		Passphrase: passphrase,
		Salt:       salt,
		Keylen:     keyLen,
		Mode:       mode,
		Time:       params.Time,
		MemoryKiB:  params.MemoryKiB,
		Threads:    params.Threads,
	}
	rsp, err := k.sendRequestAndWaitForResponse(req)
	if err != nil {
		return nil, err
	}
	if rsp.Err() != nil {
		return nil, rsp.Err()
	}
	return rsp.Key, nil
}

func (k *outOfProcessArgon2KDFImpl) Time(mode Argon2Mode, params *Argon2CostParams) (duration time.Duration, err error) {
	req := &Argon2OutOfProcessRequest{
		Command:   Argon2OutOfProcessCommandTime,
		Mode:      mode,
		Time:      params.Time,
		MemoryKiB: params.MemoryKiB,
		Threads:   params.Threads,
	}
	rsp, err := k.sendRequestAndWaitForResponse(req)
	if err != nil {
		return 0, err
	}
	if rsp.Err() != nil {
		return 0, rsp.Err()
	}
	return rsp.Duration, nil
}

// NewOutOfProcessArgonKDF returns a new Argon2KDF that runs each KDF invocation in a
// short-lived handler process, using a *[exec.Cmd] created by the supplied function,
// and using a protocol compatibile with [WaitForAndRunArgon2OutOfProcessRequest]
// in the handler process.
//
// The supplied function must not start the process, nor should it set the Stdin or
// Stdout fields of the [exec.Cmd] structure, as 2 pipes will be created for sending
// the request to the process via its stdin and receiving the response from the process
// via its stdout.
func NewOutOfProcessArgon2KDF(newHandlerCmd func() (*exec.Cmd, error)) Argon2KDF {
	if newHandlerCmd == nil {
		panic("newHandlerCmd cannot be nil")
	}
	return &outOfProcessArgon2KDFImpl{
		newHandlerCmd: newHandlerCmd,
	}
}
