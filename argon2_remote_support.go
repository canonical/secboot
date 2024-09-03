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

	"github.com/snapcore/secboot/internal/argon2"
)

type nullInProcessArgon2KDFImpl struct{}

func (_ nullInProcessArgon2KDFImpl) Derive(passphrase string, salt []byte, mode Argon2Mode, params *Argon2CostParams, keyLen uint32) ([]byte, error) {
	return nil, errors.New("no argon2 KDF: please call secboot.SetIsArgon2RemoteProcess if the intention is to run Argon2 directly in this process")
}

func (_ nullInProcessArgon2KDFImpl) Time(mode Argon2Mode, params *Argon2CostParams) (time.Duration, error) {
	return 0, errors.New("no argon2 KDF: please call secboot.SetIsArgon2RemoteProcess if the intention is to run Argon2 directly in this process")
}

type inProcessArgon2KDFImpl struct{}

func (_ inProcessArgon2KDFImpl) Derive(passphrase string, salt []byte, mode Argon2Mode, params *Argon2CostParams, keyLen uint32) ([]byte, error) {
	switch {
	case mode != Argon2i && mode != Argon2id:
		return nil, errors.New("invalid mode")
	case params == nil:
		return nil, errors.New("nil params")
	case params.Time == 0:
		return nil, errors.New("invalid time cost")
	case params.Threads == 0:
		return nil, errors.New("invalid number of threads")
	}

	return argon2.Key(passphrase, salt, argon2.Mode(mode), params.internalParams(), keyLen), nil
}

func (_ inProcessArgon2KDFImpl) Time(mode Argon2Mode, params *Argon2CostParams) (time.Duration, error) {
	switch {
	case mode != Argon2i && mode != Argon2id:
		return 0, errors.New("invalid mode")
	case params == nil:
		return 0, errors.New("nil params")
	case params.Time == 0:
		return 0, errors.New("invalid time cost")
	case params.Threads == 0:
		return 0, errors.New("invalid number of threads")
	}

	return argon2.KeyDuration(argon2.Mode(mode), params.internalParams()), nil
}

// InProcessArgon2KDF returns the in-process implementation of the Argon2 KDF. This shouldn't
// be used in long-lived system processes - these processes should instead provide their own
// [Argon2KDF] implementation which proxies requests to a short-lived remote process which will
// use this in-process implementation once and then exit. This approach avoids memory exhaustion
// and the need to run a full GC mark and sweep ([runtime.GC]) between invocations, which has
// a significant time penalty. Argon2 isn't really compativle with garbage collected runtimes.
//
// There are plenty of helpers in this package to facilitate this, such as JSON serializable
// types ([Argon2RemoteInput] and [Argon2RemoteOutput]) and a function ([RunArgon2KDFInRemoteProcess])
// that can process these types to run the KDF in-process using a request from a parent process.
//
// There are higher-level helpers too, such as an [Argon2KDF] implementation that can be created
// in the parent process and which creates new remote processes to send each command to (see
// [NewRemoteArgon2KDF]). The remote process is then able to process an incoming request by passing
// [os.Stdin] and [os.Stdout] directly to [WaitAndRunArgon2RequestInRemoteProcess].
//
// It is indended that the remote process is a special mode of argv[0] (ie, snapd or snap-bootstrap)
// in order to avoid the bloat of adding additional go binaries.
//
// A process must call [SetIsArgon2RemoteProcess] before this returns anything other than a null
// implementation of the KDF.
//
// Note that whilst [WaitAndRunArgon2RequestInRemoteProcess] and [RunArgon2KDFInRemoteProcess]
// contain protections that only allow a single invocation of this KDF in the lifetime of a process,
// direct access via this API doesn't provde the same protections.
func InProcessArgon2KDF() Argon2KDF {
	if atomic.LoadUint32(&argon2RemoteProcessStatus) > notArgon2RemoteProcess {
		return inProcessArgon2KDFImpl{}
	}
	return nullInProcessArgon2KDFImpl{}
}

// Argon2RemoteCommand represents the command to run.
type Argon2RemoteCommand string

const (
	// Argon2RemoteCommandDerive requests to derive a key from a passphrase
	Argon2RemoteCommandDerive Argon2RemoteCommand = "derive"

	// Argon2RemoteCommandTime requests the duration that the KDF took to
	// execute. This excludes things like process startup.
	Argon2RemoteCommandTime Argon2RemoteCommand = "time"
)

// Argon2RemoteInput is an input request for an argon2 operation in
// a remote process.
type Argon2RemoteInput struct {
	Command    Argon2RemoteCommand `json:"command"`              // The command to run
	Passphrase string              `json:"passphrase,omitempty"` // If the command is "derive, the passphrase
	Salt       []byte              `json:"salt,omitempty"`       // If the command is "derive", the salt
	Keylen     uint32              `json:"keylen,omitempty"`     // If the command is "derive", the key length in bytes
	Mode       Argon2Mode          `json:"mode"`                 // The Argon2 mode
	Time       uint32              `json:"time"`                 // The time cost
	MemoryKiB  uint32              `json:"memory"`               // The memory cost in KiB
	Threads    uint8               `json:"threads"`              // The number of threads to use
}

// Argon2RemoteErrorType describes the type of error produced by [RunArgon2RequestInRemoteProcess].
type Argon2RemoteErrorType string

const (
	// Argon2RemoteErrorInvalidCommand means that an invalid command was supplied.
	Argon2RemoteErrorInvalidCommand Argon2RemoteErrorType = "invalid-command"

	// Argon2RemoteErrorInvalidMode means that an invalid mode was supplied.
	Argon2RemoteErrorInvalidMode Argon2RemoteErrorType = "invalid-mode"

	// Argon2RemoteErrorInvalidTimeCost means that an invalid time cost was supplied.
	Argon2RemoteErrorInvalidTimeCost Argon2RemoteErrorType = "invalid-time-cost"

	// Argon2RemoteErrorInvalidThreads means that an invalid number of threads was supplied.
	Argon2RemoteErrorInvalidThreads Argon2RemoteErrorType = "invalid-threads"

	// Argon2RemoteErrorConsumedProcess means that this process has already performed one
	// execution of the KDF, and a new process should replace it.
	Argon2RemoteErrorConsumedProcess Argon2RemoteErrorType = "consumed-process"

	// Argon2RemoteErrorProcessNotConfigured means that nothing has called SetIsArgon2RemoteProcess.
	Argon2RemoteErrorProcessNotConfigured Argon2RemoteErrorType = "process-not-configured"

	// Argon2RemoteErrorUnexpected means that an unexpected error occurred.
	Argon2RemoteErrorUnexpected Argon2RemoteErrorType = "unexpected-error"

	// Argon2RemoteErrorUnexpectedInput means that there was an error with
	// the supplied error not covered by one of the more specific error types..
	Argon2RemoteErrorUnexpectedInput Argon2RemoteErrorType = "unexpected-input"
)

// Argon2RemoteOutput is the response to a request for an argon2
// operation in a remote process.
type Argon2RemoteOutput struct {
	Command     Argon2RemoteCommand   `json:"command"`                // The input command
	Key         []byte                `json:"key,omitempty"`          // The derived key, if the input command was "derive"
	Duration    time.Duration         `json:"duration,omitempty"`     // The duration, if the input command was "duration"
	ErrorType   Argon2RemoteErrorType `json:"error-type,omitempty"`   // The error type, if an error occurred
	ErrorString string                `json:"error-string,omitempty"` // The error string, if an error occurred
}

// Argon2RemoteError is returned from the [Argon2] implentation created be
// [NewRemoteArgon2KDF] when the received response indicates that an error
// ocurred.
type Argon2RemoteError struct {
	ErrorType   Argon2RemoteErrorType
	ErrorString string
}

func (e *Argon2RemoteError) Error() string {
	str := new(bytes.Buffer)
	fmt.Fprintf(str, "cannot process KDF request: %v", e.ErrorType)
	if e.ErrorString != "" {
		fmt.Fprintf(str, " (%s)", e.ErrorString)
	}
	return str.String()
}

func (o *Argon2RemoteOutput) Err() error {
	if o.ErrorType == "" {
		return nil
	}
	return &Argon2RemoteError{
		ErrorType:   o.ErrorType,
		ErrorString: o.ErrorString,
	}
}

const (
	notArgon2RemoteProcess     uint32 = 0
	readyArgon2RemoteProcess   uint32 = 1
	expiredArgon2RemoteProcess uint32 = 2
)

var (
	argon2RemoteProcessStatus uint32 = notArgon2RemoteProcess
)

// SetIsArgon2RemoteProcess marks this process as being a remote processs capable of running
// Argon2 in process. After calling this, [InProcessArgon2KDF] will return a real implementation
// that runs in process.
func SetIsArgon2RemoteProcess() {
	if !atomic.CompareAndSwapUint32(&argon2RemoteProcessStatus, notArgon2RemoteProcess, readyArgon2RemoteProcess) {
		panic("cannot call SetIsArgon2RemoteProcess more than once")
	}
}

// RunArgon2RequestInRemoteProcess runs the specified argon2 request, and returns a response. This
// function can only be called once in a process. Subsequent calls in the same process will result
// in an error response being returned.
func RunArgon2RequestInRemoteProcess(input *Argon2RemoteInput) *Argon2RemoteOutput {
	if !atomic.CompareAndSwapUint32(&argon2RemoteProcessStatus, readyArgon2RemoteProcess, expiredArgon2RemoteProcess) {
		switch atomic.LoadUint32(&argon2RemoteProcessStatus) {
		case expiredArgon2RemoteProcess:
			return &Argon2RemoteOutput{
				Command:     input.Command,
				ErrorType:   Argon2RemoteErrorConsumedProcess,
				ErrorString: "cannot run more than once in the same process",
			}
		default:
			return &Argon2RemoteOutput{
				Command:     input.Command,
				ErrorType:   Argon2RemoteErrorProcessNotConfigured,
				ErrorString: "cannot run in a process that isn't configured as an Argon2 remote process",
			}
		}
	}

	switch input.Mode {
	case Argon2id, Argon2i:
		// ok
	default:
		return &Argon2RemoteOutput{
			Command:     input.Command,
			ErrorType:   Argon2RemoteErrorInvalidMode,
			ErrorString: fmt.Sprintf("invalid mode: %q", string(input.Mode)),
		}
	}

	costParams := &Argon2CostParams{
		Time:      input.Time,
		MemoryKiB: input.MemoryKiB,
		Threads:   input.Threads,
	}
	if costParams.Time == 0 {
		return &Argon2RemoteOutput{
			Command:     input.Command,
			ErrorType:   Argon2RemoteErrorInvalidTimeCost,
			ErrorString: "invalid time cost: cannot be zero",
		}
	}
	if costParams.Threads == 0 {
		return &Argon2RemoteOutput{
			Command:     input.Command,
			ErrorType:   Argon2RemoteErrorInvalidThreads,
			ErrorString: "invalid threads: cannot be zero",
		}
	}

	switch input.Command {
	case Argon2RemoteCommandDerive:
		key, err := InProcessArgon2KDF().Derive(input.Passphrase, input.Salt, input.Mode, costParams, input.Keylen)
		if err != nil {
			return &Argon2RemoteOutput{
				Command:     input.Command,
				ErrorType:   Argon2RemoteErrorUnexpected,
				ErrorString: fmt.Sprintf("cannot run derive command: %v", err),
			}

		}
		return &Argon2RemoteOutput{
			Command: input.Command,
			Key:     key,
		}
	case Argon2RemoteCommandTime:
		if len(input.Passphrase) > 0 {
			return &Argon2RemoteOutput{
				Command:     input.Command,
				ErrorType:   Argon2RemoteErrorUnexpectedInput,
				ErrorString: "cannot supply passphrase for \"time\" command",
			}
		}
		if len(input.Salt) > 0 {
			return &Argon2RemoteOutput{
				Command:     input.Command,
				ErrorType:   Argon2RemoteErrorUnexpectedInput,
				ErrorString: "cannot supply salt for \"time\" command",
			}
		}
		if input.Keylen > 0 {
			return &Argon2RemoteOutput{
				Command:     input.Command,
				ErrorType:   Argon2RemoteErrorUnexpectedInput,
				ErrorString: "cannot supply keylen for \"time\" command",
			}
		}

		duration, err := InProcessArgon2KDF().Time(input.Mode, costParams)
		if err != nil {
			return &Argon2RemoteOutput{
				Command:     input.Command,
				ErrorType:   Argon2RemoteErrorUnexpected,
				ErrorString: fmt.Sprintf("cannot run time command: %v", err),
			}
		}
		return &Argon2RemoteOutput{
			Command:  input.Command,
			Duration: duration,
		}
	default:
		return &Argon2RemoteOutput{
			Command:     input.Command,
			ErrorType:   Argon2RemoteErrorInvalidCommand,
			ErrorString: fmt.Sprintf("invalid command: %q", string(input.Command)),
		}
	}
}

// WaitAndRunArgon2RequestInRemoteProcess waits for a [Argon2RemoteInput] request on the
// supplied io.Reader before running it and sending a [Argon2RemoteOutput] response back via
// the supplied io.Writer. These will generally be connected to the process's os.Stdin and
// os.Stdout when using - certainly when using [NewRemoteArgon2KDF] on the parent side.
// This function can only be called once in a process. Subsequent calls in the same
// process will result in an error response being returned.
func WaitAndRunArgon2RequestInRemoteProcess(in io.Reader, out io.Writer) error {
	var input *Argon2RemoteInput
	dec := json.NewDecoder(in)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		return fmt.Errorf("cannot decode input: %w", err)
	}

	output := RunArgon2RequestInRemoteProcess(input)

	enc := json.NewEncoder(out)
	if err := enc.Encode(output); err != nil {
		return fmt.Errorf("cannot encode output: %w", err)
	}

	return nil
}

// remoteArgon2KDFImpl is an Argon2KDFImpl that runs the KDF in a remote process,
// using the remote JSON protocol defined in this package.
type remoteArgon2KDFImpl struct {
	newRemoteCommand func() (*exec.Cmd, error)
}

func (k *remoteArgon2KDFImpl) runInRemoteProcess(params *Argon2RemoteInput) (res *Argon2RemoteOutput, err error) {
	cmd, err := k.newRemoteCommand()
	if err != nil {
		return nil, fmt.Errorf("cannot create remote process: %w", err)
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
		return nil, fmt.Errorf("cannot start remote process: %w", err)
	}
	defer func() {
		// Run Cmd.Wait in a defer so that we shut down on error paths too,
		// and we capture the Wait error if there was no other error.
		waitErr := cmd.Wait()
		if waitErr != nil && err == nil {
			res = nil
			err = fmt.Errorf("cannot wait for remote process to finish: %w", waitErr)
		}
	}()

	// Send the input params to the remote process.
	enc := json.NewEncoder(stdinPipe)
	if err := enc.Encode(params); err != nil {
		return nil, fmt.Errorf("cannot encode parameters: %w", err)
	}

	// Wait for thre result from the remote process.
	dec := json.NewDecoder(stdoutPipe)
	if err := dec.Decode(&res); err != nil {
		return nil, fmt.Errorf("cannot decode result: %w", err)
	}

	return res, nil
}

func (k *remoteArgon2KDFImpl) Derive(passphrase string, salt []byte, mode Argon2Mode, params *Argon2CostParams, keyLen uint32) (key []byte, err error) {
	remoteParams := &Argon2RemoteInput{
		Command:    Argon2RemoteCommandDerive,
		Passphrase: passphrase,
		Salt:       salt,
		Keylen:     keyLen,
		Mode:       mode,
		Time:       params.Time,
		MemoryKiB:  params.MemoryKiB,
		Threads:    params.Threads,
	}
	res, err := k.runInRemoteProcess(remoteParams)
	if err != nil {
		return nil, err
	}
	if res.Err() != nil {
		return nil, res.Err()
	}
	return res.Key, nil
}

func (k *remoteArgon2KDFImpl) Time(mode Argon2Mode, params *Argon2CostParams) (duration time.Duration, err error) {
	remoteParams := &Argon2RemoteInput{
		Command:   Argon2RemoteCommandTime,
		Mode:      mode,
		Time:      params.Time,
		MemoryKiB: params.MemoryKiB,
		Threads:   params.Threads,
	}
	res, err := k.runInRemoteProcess(remoteParams)
	if err != nil {
		return 0, err
	}
	if res.Err() != nil {
		return 0, res.Err()
	}
	return res.Duration, nil
}

// NewRemoteArgon2KDF returns a new Argon2KDF that runs each KDF invocation in a
// short-lived remote process, using a *[exec.Cmd] created by the supplied function,
// and using a protocol compatibile with [WaitAndRunArgon2RequestInRemoteProcess]
// in the remote process.
//
// The supplied function must not start the process, nor should it set the Stdin or
// Stdout fields of the [exec.Cmd] structure, as 2 pipes will be created for sending
// and receiving, and these will be connected to stdin and stdout of the remote process.
func NewRemoteArgon2KDF(newRemoteCommand func() (*exec.Cmd, error)) Argon2KDF {
	return &remoteArgon2KDFImpl{
		newRemoteCommand: newRemoteCommand,
	}
}
