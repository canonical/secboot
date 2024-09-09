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
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/tomb.v2"
)

// Argon2OutOfProcessCommand represents an argon2 command to run out of process.
type Argon2OutOfProcessCommand string

const (
	// Argon2OutOfProcessCommandDerive requests to derive a key from a passphrase
	Argon2OutOfProcessCommandDerive Argon2OutOfProcessCommand = "derive"

	// Argon2OutOfProcessCommandTime requests the duration that the KDF took to
	// execute. This excludes additional costs such as process startup.
	Argon2OutOfProcessCommandTime Argon2OutOfProcessCommand = "time"

	// Argon2OutOfProcessCommandWatchdog requests a watchdog ping, when using
	// [WaitForAndRunArgon2OutOfProcessRequest]. This does not work with
	// [RunArgon2OutOfProcessRequest], which runs the supplied request synchronously
	// in the current go routine.
	Argon2OutOfProcessCommandWatchdog Argon2OutOfProcessCommand = "watchdog"
)

// Argon2OutOfProcessRequest is an input request for an argon2 operation in
// a remote process.
type Argon2OutOfProcessRequest struct {
	Command           Argon2OutOfProcessCommand `json:"command"`                      // The command to run
	Passphrase        string                    `json:"passphrase,omitempty"`         // If the command is "derive, the passphrase
	Salt              []byte                    `json:"salt,omitempty"`               // If the command is "derive", the salt
	Keylen            uint32                    `json:"keylen,omitempty"`             // If the command is "derive", the key length in bytes
	Mode              Argon2Mode                `json:"mode"`                         // The Argon2 mode
	Time              uint32                    `json:"time"`                         // The time cost
	MemoryKiB         uint32                    `json:"memory"`                       // The memory cost in KiB
	Threads           uint8                     `json:"threads"`                      // The number of threads to use
	WatchdogChallenge []byte                    `json:"watchdog-challenge,omitempty"` // A challenge value for watchdog pings (when the command is "watchdog")
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

	// Argon2OutOfProcessErrorUnexpectedInput means that there was an error with the combination
	// of inputs associated with the supplied request.
	Argon2OutOfProcessErrorUnexpectedInput Argon2OutOfProcessErrorType = "unexpected-input"

	// Argon2OutOfProcessErrorRestartProcess means that this process has already performed one
	// execution of the KDF, and the process should exit and be replaced by a new one.
	Argon2OutOfProcessErrorRestartProcess Argon2OutOfProcessErrorType = "restart-process"

	// Argon2OutOfProcessErrorUnexpected means that an unexpected error occurred when
	// running the operation.
	Argon2OutOfProcessErrorUnexpected Argon2OutOfProcessErrorType = "unexpected-error"
)

// Argon2OutOfProcessResponse is the response to a request for an argon2
// operation in a remote process.
type Argon2OutOfProcessResponse struct {
	Command          Argon2OutOfProcessCommand   `json:"command"`                     // The input command
	Key              []byte                      `json:"key,omitempty"`               // The derived key, if the input command was "derive"
	Duration         time.Duration               `json:"duration,omitempty"`          // The duration, if the input command was "duration"
	WatchdogResponse []byte                      `json:"watchdog-response,omitempty"` // The response to a watchdog ping, if the input command was "watchdog"
	ErrorType        Argon2OutOfProcessErrorType `json:"error-type,omitempty"`        // The error type, if an error occurred
	ErrorString      string                      `json:"error-string,omitempty"`      // The error string, if an error occurred
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

var errArgon2OutOfProcessHandlerExpired = errors.New("argon2 out-of-process handler has already been used to process a request - a new process should be started to handle another request")

// argon2OutOfProcessHandler is an implementation of Argon2KDF that will
// only process a single call before returning an error on subsequent calls.
type argon2OutOfProcessHandler struct {
	Status uint32
	KDF    Argon2KDF
}

// canHandleRequest returns whether this KDF can be used to handle a request.
// It will only ever return true once. If it returns false, the pending KDF
// request must be rejected. On the single occasion that it returns true
// true, then the pending KDF request can be handled, but subsequent calls to
// this function will always return false.
func (k *argon2OutOfProcessHandler) canHandleRequest() bool {
	return atomic.CompareAndSwapUint32(&k.Status, argon2Unused, argon2Expired)
}

func (k *argon2OutOfProcessHandler) Derive(passphrase string, salt []byte, mode Argon2Mode, params *Argon2CostParams, keyLen uint32) ([]byte, error) {
	if !k.canHandleRequest() {
		return nil, errArgon2OutOfProcessHandlerExpired
	}
	return k.KDF.Derive(passphrase, salt, mode, params, keyLen)
}

func (k *argon2OutOfProcessHandler) Time(mode Argon2Mode, params *Argon2CostParams) (time.Duration, error) {
	if !k.canHandleRequest() {
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
	// to both this function and SetArgon2KDF will panic.
	if !atomic.CompareAndSwapUint32(&argon2OutOfProcessStatus, notArgon2HandlerProcess, becomingArgon2HandlerProcess) {
		panic("cannot call SetIsArgon2HandlerProcess more than once")
	}

	// Take the lock that SetArgon2KDF uses to wait for existing calls to finish if there
	// are any pending.
	argon2Mu.Lock()
	defer argon2Mu.Unlock()

	// There currently aren't any callers inside SetArgon2KDF, and we have the lock. We
	// own the global KDF now - we're going to set the global implementation, overwriting
	// whatever was there previously. Any future calls to SetArgon2KDF will panic. The
	// implementation we set is a version of InProcessArgon2KDF that can only run a single
	// time.
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
//
// This is quite a low-level function, suitable for implementations that want to manage their own
// transport. In general, implementations will use [WaitForAndRunArgon2OutOfProcessRequest].
//
// This function does not service watchdog requests, as the KDF request happens synchronously in the
// current go routine. If this is required, it needs to be implemented in supporting code that makes
// use of other go routines. [WaitForAndRunArgon2OutOfProcessRequest] already does this.
//
// Unfortunately, there is no way to interrupt this function once it has been called. because the
// low-level crypto library does not support this.
func RunArgon2OutOfProcessRequest(request *Argon2OutOfProcessRequest) *Argon2OutOfProcessResponse {
	if atomic.LoadUint32(&argon2OutOfProcessStatus) < readyArgon2HandlerProcess {
		// SetIsArgon2HandlerProcess hasn't been called, or hasn't completed yet.
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorUnexpected,
			ErrorString: "cannot handle request in a process that isn't configured as an Argon2 handler process, try calling SetIsArgon2HandlerProcess",
		}
	}

	// Perform checks of arguments that are common to call requests
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

	if len(request.WatchdogChallenge) > 0 {
		// This function does everything in the same go routine, and therefore
		// has no ability to service a watchdog.
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
			ErrorString: "invalid watchdog challenge: cannot service a watchdog",
		}
	}

	switch request.Command {
	case Argon2OutOfProcessCommandDerive:
		// Perform key derivation
		key, err := argon2KDF().Derive(request.Passphrase, request.Salt, request.Mode, costParams, request.Keylen)
		if err != nil {
			errorType := Argon2OutOfProcessErrorUnexpected
			if errors.Is(err, errArgon2OutOfProcessHandlerExpired) {
				// This process has already processed a request, so it should be restarted.
				errorType = Argon2OutOfProcessErrorRestartProcess
			}
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   errorType,
				ErrorString: fmt.Sprintf("cannot run \"derive\" command: %v", err),
			}
		}
		return &Argon2OutOfProcessResponse{
			Command: request.Command,
			Key:     key,
		}
	case Argon2OutOfProcessCommandTime:
		// Make sure that redundant parameters haven't been set.
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

		// Perform timing of the supplied cost parameters.
		duration, err := argon2KDF().Time(request.Mode, costParams)
		if err != nil {
			errorType := Argon2OutOfProcessErrorUnexpected
			if errors.Is(err, errArgon2OutOfProcessHandlerExpired) {
				// This process has already processed a request, so it should be restarted.
				errorType = Argon2OutOfProcessErrorRestartProcess
			}
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   errorType,
				ErrorString: fmt.Sprintf("cannot run \"time\" command: %v", err),
			}
		}
		return &Argon2OutOfProcessResponse{
			Command:  request.Command,
			Duration: duration,
		}
	default:
		// This is an unrecognized commmand. This includes watchdog requests, which must be handled by
		// a higher level function.
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorInvalidCommand,
			ErrorString: fmt.Sprintf("invalid command: %q", string(request.Command)),
		}
	}
}

// Argon2OutOfProcessWatchdogHandler defines the behaviour of the watchdog
// service handler for out-of-process [Argon2KDF] implementations, and is on
// the remote side of the implementation (the process that generally calls
// [SetIsArgon2HandlerProcess]) if it using one of the built in functions.
// It is intended to be compatible with [WaitForAndRunArgon2OutOfProcessRequest].
//
// The out-of-process Argon2 implementation is expected to call this inline on
// the same goroutine that loops over received requests, as
// [WaitForAndRunArgon2OutOfProcessRequest] does.
//
// The out-of-process Argon2 implementation is expected to only send watchdog
// requests to this function, as [WaitForAndRunArgon2OutOfProcessRequest] does.
//
// Implementations of this should return the response or an error. If an error
// is returned, the calling loop should break and the remote process implementation
// should begin terminating (as [WaitForAndRunArgon2OutOfProcessRequest] does).
//
// Implementations must not return a nil response and a nil error.
type Argon2OutOfProcessWatchdogHandler = func(req *Argon2OutOfProcessRequest) (*Argon2OutOfProcessResponse, error)

// Argon2OutOfProcessWatchdogHandlerHMACSHA256 is the counterpart to
// [Argon2OutOfProcessWatchgogMonitorHMACSHA256]. It generates a HMAC-SHA256 of
// the received challenge, keyed with the previously transmitted response.
func Argon2OutOfProcessWatchdogHandlerHMACSHA256() Argon2OutOfProcessWatchdogHandler {
	lastWatchdogResponse := make([]byte, 32)

	return func(req *Argon2OutOfProcessRequest) (*Argon2OutOfProcessResponse, error) {
		if req.Command != Argon2OutOfProcessCommandWatchdog {
			return nil, fmt.Errorf("unexpected command %q", req.Command)
		}

		h := hmac.New(crypto.SHA256.New, lastWatchdogResponse)
		h.Write(req.WatchdogChallenge)

		// Generate the response structure
		rsp := &Argon2OutOfProcessResponse{
			Command:          Argon2OutOfProcessCommandWatchdog,
			WatchdogResponse: h.Sum(nil),
		}

		// Save the response we just sent because it's needed for the next
		// watchdog request.
		lastWatchdogResponse = rsp.WatchdogResponse

		return rsp, nil
	}
}

func NoArgon2OutOfProcessWatchdogHandler(req *Argon2OutOfProcessRequest) (*Argon2OutOfProcessResponse, error) {
	return nil, errors.New("unexpected watchdog request: no handler service for it")
}

// ErrKDFNotRequested is returned from [WaitForAndRunArgon2OutOfProcessRequest]
// if the supplied io.Reader is closed by the parent before a [Argon2OutOfProcessRequest]
// has been received.
var ErrKDFNotRequested = errors.New("no KDF request was received")

// WaitForAndRunArgon2OutOfProcessRequest waits for a [Argon2OutOfProcessRequest] request on the
// supplied io.Reader before running it and sending a [Argon2OutOfProcessResponse] response back via
// the supplied io.Writer. These will generally be connected to the process's os.Stdin and
// os.Stdout - at least they will need to be when using [NewOutOfProcessKDF] on the parent side.
//
// This function can only be called once in a process. Subsequent calls in the same process will
// result in an error response being returned via the io.Writer (after receiving a new request via
// the io.Reader).
//
// This function can service watchdog requests from the parent process by providing an appropriate
// watchdog handler. If no watchdog handler is supplied, [NoArgon2OutOfProcessWatchdogHandler] is used.
//
// Unfortunately, KDF requests cannot be interrupted once they have started because the low-level crypto
// library does not provide this functionality.
//
// This function requires [SetIsArgon2HandlerProcess] to have already been called in this process,
// else an error response will be returned via the io.Writer.
//
// Most errors are sent back to the parent process via the supplied io.Writer. In some cases, errors
// returned from go routines that are created during the handling of a request may be returned directly
// from this function.
//
// Note that this function won't return until the supplied io.Reader is closed (it returns [io.EOF]),
// and all created go routines terminate. As long as no go routines return an error and the io.Reader is
// closed after receiving a KDF request, then no error will be returned. If the io.Reader is closed before
// a KDF request is received, a [ErrKDFNotRequested] error will be returned.
//
// As this function cannot be used again, the calling process is expected to exit once this returns.
func WaitForAndRunArgon2OutOfProcessRequest(in io.Reader, out io.Writer, watchdog Argon2OutOfProcessWatchdogHandler) error {
	if watchdog == nil {
		watchdog = NoArgon2OutOfProcessWatchdogHandler
	}

	tmb := new(tomb.Tomb)

	// rspChan is sent a response which is received by another goroutine,
	// which serializes it and sends it to the parent process via the
	// supplied io.Writer.
	rspChan := make(chan *Argon2OutOfProcessResponse)

	// wdRspChan is send watchdog responses which are received by another
	// goroutine, which serializes them and sends them to the parent process
	// via the supplied io.Writer.
	wdRspChan := make(chan *Argon2OutOfProcessResponse)

	// Spin-up a routine for receiving incoming requests - this will include the initial
	// request and periodic watchdog requests if these are in use.
	tmb.Go(func() error {
		// Also spin-up the routine for sending outgoing responses that are generated internally.
		// This handles the receive ends of rspChan and wdRspChan, and serializes them to the
		// supplied io.Writer.
		tmb.Go(func() error {
			for {
				// Wait for a response from somewhere or wait for the tomb to
				// begin dying.
				var jsonRsp *Argon2OutOfProcessResponse
				select {
				case rsp := <-rspChan:
					jsonRsp = rsp
				case rsp := <-wdRspChan:
					jsonRsp = rsp
				case <-tmb.Dying():
					// The tomb has begun dying - this is a normal part of shutdown,
					// so return now. Senders to the channels we receive need to be
					// careful about handling this routine terminating before they
					// do in order to avoid deadlocks with unbuffered channels.
					return nil
				}
				// We've got a response from somewhere. Encode it send the
				// response out on the io.Writer. If this fails, return an error,
				// which begins the dying of this tomb and will result in an error
				// being returned to the caller.
				enc := json.NewEncoder(out)
				if err := enc.Encode(jsonRsp); err != nil {
					return fmt.Errorf("cannot encode response: %w", err)
				}
			}
			panic("not reached")
		})

		// kdfRequestReceived indicates that a KDF request was received. If one has been received,
		// it's not an error for the parent to close its side of the incoming channel.
		kdfRequestReceived := false

		// Run a loop for receiving incoming requests from the io.Reader as long
		// as the tomb remains alive.
		for tmb.Alive() {
			// Wait for a request from the io.Reader. The only way to unblock this is
			// if the parent sends something or closes its end of the OS pipe. If it's
			// closed before we've received a KDF request, then we terminate this routine
			// with an error to begin the process of the tomb dying and the function
			// eventually returning an error.
			var req *Argon2OutOfProcessRequest
			dec := json.NewDecoder(in)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				if errors.Is(err, io.EOF) {
					if !kdfRequestReceived {
						// The parent has closed their end of the connection before
						// sending a request, so we return an error here to begin
						// the shutdown of the entire tomb and return an appropriate
						// error to the caller.
						return ErrKDFNotRequested
					}
					// In any case, if the parent has closed their end of the pipe, there's
					// nothing else for us to process so we can break from this loop in order
					// to shutdown of this routine. We can't receive any more watchdog requests.
					break
				}
				return fmt.Errorf("cannot decode request: %w", err)
			}

			switch req.Command {
			case Argon2OutOfProcessCommandWatchdog:
				// Special case to handle watchdog requests
				rsp, err := watchdog(req)
				if err != nil {
					return fmt.Errorf("cannot run watchdog handler: %w", err)
				}

				// Send the response structure to be serialized and sent to the parent.
				// This blocks until the response is received by the other end of the
				// channel, or the tomb enters a dying state.
				select {
				case wdRspChan <- rsp:
					// The watchdog response was delivered to the receiving end ok
				case <-tmb.Dying():
					// The watchdog response was not delivered because the tomb entered
					// a dying state and the receive end of wdRspChan has already gone.
				}
			default:
				// Anything else is considered a KDF request
				kdfRequestReceived = true

				// Spin up a new routine to handle the request, as it blocks and is long running,
				// and we still want to be able to service watchdog requests. Block the current
				// routine until we know the new routine has started so that the watchdog handler
				// will fail if the new routine doesn't begin properly.
				var startupWg sync.WaitGroup
				startupWg.Add(1)
				tmb.Go(func() error {
					startupWg.Done() // Unblock the main routine.

					// Run the KDF request.
					rsp := RunArgon2OutOfProcessRequest(req)

					// Send the response structure to be serialized and sent to the parent.
					// This blocks until the response is received by the other end of the
					// channel, or the tomb enters a dying state.
					select {
					case rspChan <- rsp:
						// The response was delivered to the receiving end ok.
					case <-tmb.Dying():
						// The response was not delivered because the tomb entered
						// a dying state and the receive end of rspChan has already gone.
					}

					// As we only handle a single request, mark the tomb as dying to begin its
					// clean shutdown if it isn't shutting down already.
					tmb.Kill(nil)
					return nil
				})

				// Wait until the routine we spun up to run the KDF request is running before processing
				// watchdog requests. If we end up blocked here then the watchdog handler will fail
				// to respond.
				startupWg.Wait()
			}
		}
		return nil
	})

	// Wait for the tomb to die and return the first error that occurred to the caller if there was one.
	return tmb.Wait()
}

// Argon2OutOfProcessWatchdogMonitor defines the behaviour of a watchdog monitor
// for out-of-process [Argon2KDF] implementations, and is managed on the parent side
// of an implementation of [Argon2KDF].
//
// It is expected to be called in its own dedicated go routine that is tracked
// by the supplied tomb, as with the implementation of [Argon2KDF] returned by
// [NewOutOfProcessArgon2KDF].
//
// Implementations define their own protocol, with limitations. All requests and
// responses use the watchdog command [Argon2OutOfProcessCommandWatchdog]. The
// [Argon2OutOfProcessRequest] type has a WatchdogChallenge field. The
// [Argon2OutOfProcessResponse] type has a WatchdogResponse field. It's up
// to the implementation how they choose to use these fields.
//
// If the watchdog isn't serviced by the remote process correctly or within some
// time limit, the implementation is expected to return an error.
//
// The [Argon2KDF] implementation that manages this watchdog should kill the remote
// process in the event that the monitor implementation returns an error, as
// the one returned by [NewOutOfProcessArgon2KDF] does.
//
// The implementation of this should not close reqChan. It should also expect reqChan
// to be blocking (ie, not buffered), as is the case with the [Argon2KDF] implementaton
// returned from [NewOutOfProcessArgon2KDF].
//
// It is expected that the [Argon2KDF] implementation that manages this watchdog
// only sends watchdog requests via the rspChan channel (ie, it's verified that the
// Command field in the [Argon2OutOfProcessResponse] is [Argon2OutOfProcessCommandWatchdog]).
// The implementation returned by [NewOutOfProcessArgon2KDF] makes this assurance.
//
// It is expected that the [Argon2KDF] implementation doesn't close the suppled rspChan,
// as the one returned by [NewOutOfProcessArgon2KDF] doesn't.
//
// The implementation should continue to process requests as long as the supplied tomb
// is alive ([Tomb.Alive] returns true) before returning, unless an error occurs.
type Argon2OutOfProcessWatchdogMonitor = func(tmb *tomb.Tomb, reqChan chan<- *Argon2OutOfProcessRequest, rspChan <-chan *Argon2OutOfProcessResponse) error

func NoArgon2OutOfProcessWatchdogMonitor(tmb *tomb.Tomb, reqChan chan<- *Argon2OutOfProcessRequest, rspChan <-chan *Argon2OutOfProcessResponse) error {
	for {
		select {
		case <-rspChan:
			// We never sent a request, so this is an error
			return errors.New("unexpected watchdog response: no monitor sending requests")
		case <-tmb.Dying():
			return nil
		}
	}
	return nil
}

// Argon2OutOfProcessWatchdogMonitorHMACSHA256 returns a watchdog monitor that generates a
// challenge, computes a HMAC-SHA256 of this challenge, keyed with previously received
// watchdog response. It It stops and returns an error if we don't receive a respose
func Argon2OutOfProcessWatchdogMonitorHMACSHA256(period, timeout time.Duration) Argon2OutOfProcessWatchdogMonitor {
	lastWatchdogResponse := make([]byte, 32)

	return func(tmb *tomb.Tomb, reqChan chan<- *Argon2OutOfProcessRequest, rspChan <-chan *Argon2OutOfProcessResponse) error {
		for {
			timer := time.NewTimer(period)
			select {
			case <-timer.C: // run it every defined period
			case <-tmb.Dying(): // exit early if the tomb is dying
				timer.Stop() // Make sure the timer can be collected. Not necessary from go 1.23
				return nil
			}

			// Generate a new 32-byte challenge and calculate the expected response
			challenge := make([]byte, 32)
			if _, err := rand.Read(challenge); err != nil {
				return fmt.Errorf("cannot generate new watchdog challenge: %w", err)
			}
			// The expected response is the HMAC-SHA256 of the challenge, keyed with the
			// last response.
			h := hmac.New(crypto.SHA256.New, lastWatchdogResponse)
			h.Write(challenge)
			expectedWatchdogResponse := h.Sum(nil)

			req := &Argon2OutOfProcessRequest{
				Command:           Argon2OutOfProcessCommandWatchdog,
				WatchdogChallenge: challenge,
			}

			// Send the request. If reqChan is unbuffered, this blocks until the
			// request is received by the other end or the tomb enters a dying state.
			select {
			case reqChan <- req:
				// The watchdog request was sent ok.
			case <-tmb.Dying():
				// The watchdog request was not sent ok because the tomb is
				// in a dying state and receiving end has already gone away.
				// Just return now as we won't run another iteration of this
				// loop anyway.
				return nil
			}

			// Wait for the response from the remote process.
			timer = time.NewTimer(timeout)
			select {
			case <-timer.C: // Give it up to the time defined by the timeout
				return errors.New("timeout waiting for watchdog response from remote process")
			case rsp := <-rspChan:
				// We got a response from the remote process.
				timer.Stop() // Make sure the timer can be collected. Not necessary from go 1.23
				if err := rsp.Err(); err != nil {
					// We got an error response, so just return the error.
					return fmt.Errorf("cannot process watchdog response from remote process: %w", rsp.Err())
				}
				if !bytes.Equal(rsp.WatchdogResponse, expectedWatchdogResponse) {
					// We got an unexpected response, so return an error.
					return errors.New("unexpected watchdog response value from remote process")
				}
				// The response was good so save the value for the next iteration.
				lastWatchdogResponse = rsp.WatchdogResponse
			case <-tmb.Dying():
				// Don't need to wait any more as the tomb has begun dying.
				timer.Stop() // Make sure the timer can be collected. Not necessary from go 1.23
				return nil
			}
		}
		return nil
	}
}

// outOfProcessArgon2KDFImpl is an Argon2KDF implementation that runs the KDF in a short-lived
// remote process, using the remote JSON protocol defined in this package.
type outOfProcessArgon2KDFImpl struct {
	newHandlerCmd func() (*exec.Cmd, error)
	watchdog      Argon2OutOfProcessWatchdogMonitor
}

func (k *outOfProcessArgon2KDFImpl) sendRequestAndWaitForResponse(req *Argon2OutOfProcessRequest) (*Argon2OutOfProcessResponse, error) {
	// Use ther user-supplied function to create a new *exec.Cmd structure.
	cmd, err := k.newHandlerCmd()
	if err != nil {
		return nil, fmt.Errorf("cannot create new command: %w", err)
	}

	// Configure an OS pipe for stdin for sending requests.
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		// This doesn't fail once the OS pipe is created, so there's no
		// cleanup to do on failure paths.
		return nil, fmt.Errorf("cannot create stdin pipe: %w", err)
	}

	// Configure an OS pipe for stdout for receiving responses.
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		// This doesn't fail once the OS pipe is created, so there's no
		// cleanup to do on failure paths other than closing the stdinPipe
		stdinPipe.Close()
		return nil, fmt.Errorf("cannot create stdout pipe: %w", err)
	}

	// Start the remote process.
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cannot start handler process: %w", err)
	}

	var actualRsp *Argon2OutOfProcessResponse
	tmb := new(tomb.Tomb)

	// Spin up a routine to handle communications with the remote process and wait
	// for it to exit.
	tmb.Go(func() error {
		// wdReqChan is sent requests from the watchdog monitor which are then
		// received by another goroutine, which serializes them and sends them to
		// the remote process via its stdin.
		wdReqChan := make(chan *Argon2OutOfProcessRequest)

		// wdRspChan is sent watchdog responses received from the remote process
		// via stdout, and they are subsequently received by the watchdog monitor.
		wdRspChan := make(chan *Argon2OutOfProcessResponse)

		// reqChan is sent the main KDF request, which is received by another goroutine,
		// which serializes it and sends it to the remote process via its stdin.
		reqChan := make(chan *Argon2OutOfProcessRequest)

		// Spin up a routine for sending requests to the remote process via stdinPipe.
		tmb.Go(func() error {
			for {
				var jsonReq *Argon2OutOfProcessRequest

				// Handle serializing and sending requests until we begin the process of
				// dying.
				select {
				case req := <-reqChan:
					// We have the main KDF request to send.
					jsonReq = req
				case req := <-wdReqChan:
					// We have a request from the watchdog monitor to send.
					jsonReq = req
				case <-tmb.Dying():
					// The tomb has begun dying - this is a normal part of shutdown,
					// so return now. Senders to the channels we receive need to be
					// careful about handling this routine terminating before they
					// do in order to avoid deadlocks with unbuffered channels.
					return nil
				}

				// Send the request to the remote process via its stdin
				enc := json.NewEncoder(stdinPipe)
				if err := enc.Encode(jsonReq); err != nil {
					return fmt.Errorf("cannot encode request: %w", err)
				}

			}
			panic("not reached")
		})

		// Send the initial request. This will block until the request
		// is received by the other end (the previously started go
		// routine), or until the tomb enters a dying state.
		select {
		case reqChan <- req:
			// Initial request sent ok.
		case <-tmb.Dying():
			// Initial request was not sent, because the tomb is already
			// dying and the receiving end has already gone away.
			//
			// This is an abnormal condition - nothing should have
			// put the tomb into a dying state at this point. There
			// should already be an error associated with whatever
			// caused this, but just in case there isn't, we'll return
			// our own error from the current routine.
			return errors.New("internal error: cannot send KDF request because the tomb is already in a dying state for an unknown reason")
		}

		// Spin up another routine to run the supplied watchdog implementation.
		tmb.Go(func() error {
			err := k.watchdog(tmb, wdReqChan, wdRspChan)
			if err != nil {
				// If the watchdog returns an error, then we kill the remote process.
				if err := cmd.Process.Kill(); err != nil {
					return fmt.Errorf("cannot kill remote process that stopped responding to watchdog: %w", err)
				}
			}
			return err
		})

		// Wait for responses from the remote process whilst the tomb is alive.
		for tmb.Alive() {
			// Wait for a response from the io.Reader. The only way to unblock this is
			// if the remote process sends something, closes its end of the OS pipe
			// explicitly, or is terminated (either by its own choice or by us).
			//
			// In general, the last response received is the response to the initial KDF
			// request. When we receive this, we put the tomb into a dying state and therefore
			// there won't be another iteration of this loop and this code won't be reached
			// again.
			//
			// Of course, if this instance is created with a proper watchdog implementation,
			// we can kill processes that we know are genuinely not responding as well.
			dec := json.NewDecoder(stdoutPipe)
			dec.DisallowUnknownFields()
			var rsp *Argon2OutOfProcessResponse
			if err := dec.Decode(&rsp); err != nil {
				return fmt.Errorf("cannot decode response: %w", err)
			}

			switch rsp.Command {
			case Argon2OutOfProcessCommandWatchdog:
				// Direct watchdog responses to wdRspChan so they can be received by
				// the watchdog monitor. This blocks until the watchdog monitor receives
				// the response or the tomb enters a dying state.
				select {
				case wdRspChan <- rsp:
					// Watchdog response sent to watchdog monitor ok.
				case <-tmb.Dying():
					// Watchdog response was not sent to the watchdog
					// monitor because the tomb is in a dying state and
					// the receiving end has already gone away (watchdog
					// implementations are meant to end once the tomb enters
					// a dying state).
					//
					// There's nothing else to do as the outer loop will just
					// not run another iteration again.
				}
			default:
				// For any other response, first of all make sure that the command value is
				// consistent with the sent command.
				if rsp.Command != req.Command {
					// Unexpected command. Return an appropriate error to begin the process
					// of the tomb dying
					return fmt.Errorf("received a response with an unexpected command value (got %q, expected %q)", rsp.Command, req.Command)
				}
				// If it is consistent, save the response to return to the caller and begin a clean
				// shutdown of the tomb.
				actualRsp = rsp
				tmb.Kill(nil)
			}
		}

		// Set up a routine to kill the process if it doesn't terminate within 2 seconds.
		waitedChan := make(chan struct{})
		tmb.Go(func() error {
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-timer.C:
				// The process has not terminated cleanly, so kill it.
				if err := cmd.Process.Kill(); err != nil {
					return fmt.Errorf("cannot kill remote process that hasn't terminated properly: %w", err)
				}
			case <-waitedChan:
				// The process terminated cleanly
				timer.Stop() // Make sure the timer can be collected. Not necessary from go 1.23
			}
			return nil
		})

		// Closing the stdin pipe might be necessary to unblock a stuck goroutine in the
		// remote process. It is necessary for WaitForAndRunArgon2OutOfProcessRequest.
		if err := stdinPipe.Close(); err != nil {
			return fmt.Errorf("cannot close stdin pipe: %w", err)
		}
		// We can wait for the remote process to exit now.
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("an error occurred whilst waiting for the remote process to finish: %w", err)
		}
		close(waitedChan)
		return nil
	})

	// Wait for all go routines to finish.
	if err := tmb.Wait(); err != nil {
		// Don't wrap this error - this will be the first non-nil error passed
		// to Tomb.Kill. There's no benefit to adding additional context here.
		return nil, err
	}

	return actualRsp, nil
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
//
// An optional watchdog monitor can be supplied. If nil, the
// [NoArgon2OutOfProcessWatchdogMonitor] is used by default, providing no watchdog
// functionality.
func NewOutOfProcessArgon2KDF(newHandlerCmd func() (*exec.Cmd, error), watchdog Argon2OutOfProcessWatchdogMonitor) Argon2KDF {
	if newHandlerCmd == nil {
		panic("newHandlerCmd cannot be nil")
	}
	if watchdog == nil {
		watchdog = NoArgon2OutOfProcessWatchdogMonitor
	}

	return &outOfProcessArgon2KDFImpl{
		newHandlerCmd: newHandlerCmd,
		watchdog:      watchdog,
	}
}
