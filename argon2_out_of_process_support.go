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
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/snapcore/secboot/internal/testenv"
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
	// WaitForAndRunArgon2OutOfProcessRequest. This does not work with
	// RunArgon2OutOfProcessRequest, which runs the supplied request synchronously
	// in the current go routine.
	Argon2OutOfProcessCommandWatchdog Argon2OutOfProcessCommand = "watchdog"
)

// Argon2OutOfProcessRequest is an input request for an argon2 operation in
// a remote process.
type Argon2OutOfProcessRequest struct {
	Command           Argon2OutOfProcessCommand `json:"command"`                      // The command to run
	Timeout           time.Duration             `json:"timeout"`                      // The maximum amount of time to wait for the request to start before aborting it
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

	// Argon2OutOfProcessErrorTimeout means that the specified command timeout expired before
	// the request was given a chance to start.
	Argon2OutOfProcessErrorKDFTimeout Argon2OutOfProcessErrorType = "timeout-error"

	// Argon2OutOfProcessErrorUnexpected means that an unexpected error occurred without
	// a more specific error type, eg, an unexpected failure to acquire the system-wide
	// lock or an unexpected error returned from the underlying Argon2 KDF implementation.
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
// implementation created by [NewOutOfProcessArgon2KDF] when the received response indicates
// that an error ocurred.
type Argon2OutOfProcessError struct {
	ErrorType   Argon2OutOfProcessErrorType
	ErrorString string
}

// Error implements the error interface.
func (e *Argon2OutOfProcessError) Error() string {
	var b strings.Builder
	b.WriteString("cannot process request: " + string(e.ErrorType))
	if e.ErrorString != "" {
		b.WriteString(" (" + e.ErrorString + ")")
	}
	return b.String()
}

// Err returns an error associated with the response if one occurred (if the
// ErrorType field is not empty), or nil if no error occurred. If the response
// indicates an error, the returned error will be a *[Argon2OutOfProcessError].
func (o *Argon2OutOfProcessResponse) Err() error {
	if o.ErrorType == "" {
		return nil
	}
	return &Argon2OutOfProcessError{
		ErrorType:   o.ErrorType,
		ErrorString: o.ErrorString,
	}
}

// Argon2OutOfProcessWatchdogError is returned from [Argon2KDF] instances created by
// [NewOutOfProcessArgon2KDF] in the event of a watchdog failure.
type Argon2OutOfProcessWatchdogError struct {
	err error
}

// Error implements the error interface
func (e *Argon2OutOfProcessWatchdogError) Error() string {
	return "watchdog failure: " + e.err.Error()
}

func (e *Argon2OutOfProcessWatchdogError) Unwrap() error {
	return e.err
}

// Argon2OutOfProcessResponseCommandInvalidError is returned from [Argon2KDF] instances
// created by [NewOutOfProcessArgon2KDF] if the response contains an unexpected command
// field value.
type Argon2OutOfProcessResponseCommandInvalidError struct {
	Response Argon2OutOfProcessCommand
	Expected Argon2OutOfProcessCommand
}

// Error implements the error interface
func (e *Argon2OutOfProcessResponseCommandInvalidError) Error() string {
	return fmt.Sprintf("received a response with an unexpected command value (got %q, expected %q)", e.Response, e.Expected)
}

// RunArgon2OutOfProcessRequest runs the specified Argon2 request, and returns a response.
//
// In general, this is intended to be executed once in a short-lived process, before the process
// is discarded. It could be executed more than once in the same process, as long as the caller
// takes steps to ensure that memory consumed by previous calls has been reclaimed by the GC
// before calling this function again, but this isn't advised.
//
// Note that Argon2 requests are serialized using a system-wide lock, which this function does not
// explicitly release. If the lock is acquired, it returns a callback that the caller may choose
// to execute in order to explicitly release the lock, or the caller can just leave it to be
// implicitly released on process exit. If the lock is explicitly released, the caller must be
// sure that the large amount of memory allocated for the Argon2 operation has been reclaimed by
// the GC, else this defeats the point of having a system-wide lock (to avoid multiple operations
// consuming too much memory). If the process is re-used by calling this function more than once,
// the lock will have to be explcitly released. If the lock wasn't acquired, no release callback
// will be returned.
//
// This is quite a low-level function, suitable for implementations that want to manage their own
// transport and their own remote process management. In general, implementations will use
// [WaitForAndRunArgon2OutOfProcessRequest] in the remote process and [NewOutOfProcessArgonKDF]
// for process management in the parent process.
//
// This function does not service watchdog requests, as the KDF request happens synchronously in the
// current goroutine. If this is required, it needs to be implemented in supporting code that makes
// use of other go routines, noting that the watchdog handler should test that the input request and
// output response processing continues to function. [WaitForAndRunArgon2OutOfProcessRequest] already
// does this correctly, and most implementations should just use this.
//
// Unfortunately, there is no way to interrupt this function once the key derivation is in progress,
// because the low-level crypto library does not support this. This feature may be desired in the
// future, which might require replacing the existing library we use for Argon2.
func RunArgon2OutOfProcessRequest(request *Argon2OutOfProcessRequest) (response *Argon2OutOfProcessResponse, lockRelease func()) {
	// Perform checks of arguments that are common to call requests
	switch request.Mode {
	case Argon2id, Argon2i:
		// ok
	default:
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorInvalidMode,
			ErrorString: fmt.Sprintf("mode cannot be %q", string(request.Mode)),
		}, nil
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
			ErrorString: "time cannot be zero",
		}, nil
	}
	if costParams.Threads == 0 {
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorInvalidThreads,
			ErrorString: "threads cannot be zero",
		}, nil
	}

	// We don't validate the MemoryKiB parameter here. The Argon2 crypto package we use
	// will round up this value to the minimum required, which is 8KiB per thread (so if
	// we pass MemoryKiB==0 and Threads==4, then MemoryKiB will automatically be increased
	// to 32KiB).

	if len(request.WatchdogChallenge) > 0 {
		// This function does everything in the same go routine, and therefore
		// has no ability to service a watchdog. It's an error if we get here
		// with a watchdog request.
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
			ErrorString: "invalid watchdog challenge: cannot service a watchdog",
		}, nil
	}

	// Do some last minute, command-specific validation
	switch request.Command {
	case Argon2OutOfProcessCommandDerive:
		// ok
	case Argon2OutOfProcessCommandTime:
		// Make sure that redundant parameters haven't been set.
		if len(request.Passphrase) > 0 {
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
				ErrorString: "cannot supply passphrase for \"time\" command",
			}, nil
		}
		if len(request.Salt) > 0 {
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
				ErrorString: "cannot supply salt for \"time\" command",
			}, nil
		}
		if request.Keylen > 0 {
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   Argon2OutOfProcessErrorUnexpectedInput,
				ErrorString: "cannot supply keylen for \"time\" command",
			}, nil
		}
	default:
		// This is an unrecognized commmand. This includes watchdog requests, which must be handled by
		// a higher level function.
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   Argon2OutOfProcessErrorInvalidCommand,
			ErrorString: fmt.Sprintf("command cannot be %q", string(request.Command)),
		}, nil
	}

	// Acquire the system-wide lock.
	var err error
	lockRelease, err = acquireArgon2OutOfProcessHandlerSystemLock(request.Timeout)
	if err != nil {
		errorType := Argon2OutOfProcessErrorUnexpected
		if errors.Is(err, errArgon2OutOfProcessHandlerSystemLockTimeout) {
			errorType = Argon2OutOfProcessErrorKDFTimeout
		}
		return &Argon2OutOfProcessResponse{
			Command:     request.Command,
			ErrorType:   errorType,
			ErrorString: fmt.Sprintf("cannot acquire argon2 system lock: %v", err),
		}, nil
	}

	// We have the system-wide lock - execute the command
	switch request.Command {
	case Argon2OutOfProcessCommandDerive:
		// Perform key derivation
		key, err := InProcessArgon2KDF.Derive(request.Passphrase, request.Salt, request.Mode, costParams, request.Keylen)
		if err != nil {
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   Argon2OutOfProcessErrorUnexpected,
				ErrorString: fmt.Sprintf("cannot run derive command: %v", err),
			}, lockRelease
		}
		return &Argon2OutOfProcessResponse{
			Command: request.Command,
			Key:     key,
		}, lockRelease
	case Argon2OutOfProcessCommandTime:
		// Perform timing of the supplied cost parameters.
		duration, err := InProcessArgon2KDF.Time(request.Mode, costParams)
		if err != nil {
			return &Argon2OutOfProcessResponse{
				Command:     request.Command,
				ErrorType:   Argon2OutOfProcessErrorUnexpected,
				ErrorString: fmt.Sprintf("cannot run time command: %v", err),
			}, lockRelease
		}
		return &Argon2OutOfProcessResponse{
			Command:  request.Command,
			Duration: duration,
		}, lockRelease
	default:
		panic("not reachable")
	}
}

// Argon2OutOfProcessWatchdogHandler defines the behaviour of a watchdog handler
// for the remote side of an out-of-process [Argon2KDF] implementation, using
// [WaitForAndRunArgon2OutOfProcessRequest].
//
// If is called periodically on the same go routine that processes incoming requests
// to ensure that this routine is functioning correctly. The response makes use of the
// same code path that the eventual KDF response will be sent via, so that the watchdog
// handler tests all of the code associated with this and so the parent process can be
// assured that it will eventually receive a KDF response and won't be left waiting
// indefinitely for one.
//
// Implementations define their own protocol, with limitations. All requests and
// responses use the watchdog command [Argon2OutOfProcessCommandWatchdog]. The
// [Argon2OutOfProcessRequest] type has a WatchdogChallenge field (which is supplied
// as an argument to this function. The [Argon2OutOfProcessResponse] type has a
// WatchdogResponse field (which the response of this function is used for). It's up
// to the implementation how they choose to use these fields.
//
// If the implementation returns an error, it begins the shutdown of the processing
// of commands and the eventual return of [WaitForAndRunArgon2OutOfProcessRequest].
//
// The implementation is expected to be paired with an equivalent implementation of
// [Argon2OutOfProcessWatchdogMonitor] in the parent process.
type Argon2OutOfProcessWatchdogHandler func(challenge []byte) (response []byte, err error)

// HMACArgon2OutOfProcessWatchdogHandler returns the remote process counterpart to
// [HMACArgon2OutOfProcessWatchdogMonitor]. It receives a challenge from the monitor,
// computes a HMAC of this challenge, keyed with previously sent response. Both
// implementations must use the same algorithm.
//
// This implementation of [Argon2OutOfProcessWatchdogHandler] never returns an error.
func HMACArgon2OutOfProcessWatchdogHandler(alg crypto.Hash) Argon2OutOfProcessWatchdogHandler {
	if !alg.Available() {
		panic("digest algorithm unavailable")
	}

	lastResponse := make([]byte, 32)

	return func(challenge []byte) (response []byte, err error) {
		h := hmac.New(alg.New, lastResponse)
		h.Write(challenge)

		lastResponse = h.Sum(nil)
		return lastResponse, nil
	}
}

// NoArgon2OutOfProcessWatchdogHandler is an implmenentation of [Argon2OutOfProcessWatchdogHandler] that
// provides no watchdog functionality. It is paired with [NoArgon2OutOfProcessWatchdogMonitor] on the
// parent side. This implementation will return an error if a watchdog request is received.
func NoArgon2OutOfProcessWatchdogHandler() Argon2OutOfProcessWatchdogHandler {
	return func(_ []byte) ([]byte, error) {
		return nil, errors.New("unexpected watchdog request: no handler")
	}
}

var runArgon2OutOfProcessRequest = RunArgon2OutOfProcessRequest

// MockRunArgon2OutOfProcessRequestForTest mocks the call to [RunArgon2OutOfProcessRequest]
// from [WaitForAndRunArgon2OutOfProcessRequest]. This can only be used in test binaries, and
// will panic otherwise.
func MockRunArgon2OutOfProcessRequestForTest(fn func(*Argon2OutOfProcessRequest) (*Argon2OutOfProcessResponse, func())) (restore func()) {
	testenv.MustBeTestBinary()
	orig := runArgon2OutOfProcessRequest
	runArgon2OutOfProcessRequest = fn
	return func() {
		runArgon2OutOfProcessRequest = orig
	}
}

// WaitForAndRunArgon2OutOfProcessRequest waits for a [Argon2OutOfProcessRequest] request on the
// supplied io.Reader before running it and sending a [Argon2OutOfProcessResponse] response back via
// the supplied io.WriteCloser. These will generally be connected to the process's os.Stdin and
// os.Stdout - at least they will need to be when using [NewOutOfProcessArgon2KDF] on the parent side,
// which this function is intended to be compatible with.
//
// This function will service watchdog requests from the parent process if a watchdog handler is supplied.
// If supplied, it must match the corresponding monitor in the parent process. If not supplied, the default
// [NoArgon2OutOfProcessWatchdogHandler] will be used.
//
// This won't process more than one request, and in general is intended to be executed once in a process,
// before the process is discarded. This is how the function is used with [NewOutOfProcessArgon2KDF].
//
// Note that Argon2 requests are serialized using a system-wide lock, which this function does not
// explicitly release. If the lock is acquired, it returns a callback that the caller may choose
// to execute in order to explicitly release the lock, or the caller can just leave it to be
// implicitly released on process exit. If the lock is explicitly released, the caller must be
// sure that the large amount of memory allocated for the Argon2 operation has been freed and
// returned back to the OS, else this defeats the point of having a system-wide lock (to avoid
// having multiple processes with high physical memory requirements running at the same time). If
// the lock wasn't acquired, no release callback will be returned.
//
// This function may return a callback to release the system wide lock even if an error is returned,
// which will happen if an error occurs after the lock is acquired.
//
// Unfortunately, KDF requests cannot be interrupted once they have started because the low-level crypto
// library does not provide this functionality, although watchdog requests can still be serviced to provide
// assurance that a response will be received as long as the crypto algorithm completes. The ability to
// interrupt a KDF request in the future may be desired, although it may require replacing the existing
// library we use for Argon2.
//
// Most errors are sent back to the parent process via the supplied io.Writer. In some limited cases,
// errors returned from goroutines that are created during the handling of a request may be returned
// directly from this function to be handled by the current process. These limited examples are where
// the function receives input it can't decode, where a response cannot be encoded and sent to the parent,
// if the watchdog handler function returns an error, or if the supplied response channel returns an error
// when closing.
//
// Note that this function won't return until the supplied io.Reader is closed by the parent, or an internal
// error occurs in one of the goroutines created by this function. It will close the supplied io.WriteCloser
// before returning.
func WaitForAndRunArgon2OutOfProcessRequest(in io.Reader, out io.WriteCloser, watchdog Argon2OutOfProcessWatchdogHandler) (lockRelease func(), err error) {
	if watchdog == nil {
		watchdog = NoArgon2OutOfProcessWatchdogHandler()
	}

	tmb := new(tomb.Tomb)

	// Spin up a routine for receiving requests from the supplied io.Reader.
	tmb.Go(func() error {
		// reqChan is sent requests from this routine which are received by the dedicated
		// KDF routine.
		reqChan := make(chan *Argon2OutOfProcessRequest)

		// rspChan is sent responses from the KDF routine or watchdog, which are then received
		// by a dedicated output routine which serializes the response to the supplied io.Writer.
		rspChan := make(chan *Argon2OutOfProcessResponse)

		// Spin-up the routine for sending outgoing responses that are generated internally.
		// This handles the read end of rspChan, and serializes responses to the supplied io.WriteCloser.
		// This gets its own goroutine so that all responses are sent via the same code path - responses
		// can ultimately come directly from the request processing loop in this routine (in the event
		// of a watchdog request), or from a dedicated KDF routine which permits the request processing
		// loop in this routine to continue executing whilst the KDF is running, so we can continue to
		// process watchdog requests.
		tmb.Go(func() error {
			// Loop whilst the tomb is alive.
			for tmb.Alive() {
				// Wait for a response from somewhere or wait for the tomb to
				// begin dying.
				select {
				case rsp := <-rspChan:
					// We've got a response from somewhere. Encode it send the
					// response out on the io.Writer. If this fails, return an error,
					// which begins the dying of this tomb and will result in an error
					// being returned to the caller.
					enc := json.NewEncoder(out)
					if err := enc.Encode(rsp); err != nil {
						if errors.Is(err, os.ErrClosed) && !tmb.Alive() {
							// We close our side of the response channel when the
							// tomb enters a dying state, so this error is expected.
							return nil
						}
						return fmt.Errorf("cannot encode response: %w", err)
					}
				case <-tmb.Dying():
					// We've begun to die, and this loop will not run again.
				}
			}
			return tomb.ErrDying
		})

		// Spin up a routine which just waits for the tomb to enter a dying state, whether
		// requested by the parent by it closing its end of the request channel, or because
		// some other error happened, and then close our side of the response channel. The
		// netpoller will wake up any pending writers, unblocking any in-progress calls to
		// out.Write in the json encoder.
		tmb.Go(func() error {
			<-tmb.Dying()
			return out.Close()
		})

		// Spin up a goroutine for running the KDF without blocking the request handling
		// loop on this routine. This reads from reqChan.
		tmb.Go(func() (err error) {
			defer func() {
				// The tomb package doesn't handle panics very well - it won't result
				// in the routine count being decremented and nor will it put it into
				// a dying state. Ensure we put it into a dying state if we encounter
				// a panic, else this routine will disappear and we'll continue serving
				// watchdog requests forever.
				if r := recover(); r != nil {
					err = fmt.Errorf("goroutine for KDF encountered a panic: %v", r)
				}
			}()

			select {
			case req := <-reqChan:
				// Run the KDF request. This performs a lot of checking of the supplied
				// request, so there's no need to repeat any of that here.
				rsp, release := runArgon2OutOfProcessRequest(req)

				// Ensure the release callback for the system lock gets returned
				// to the caller.
				lockRelease = release

				// Send the response.
				select {
				case rspChan <- rsp: // Unbuffered channel, but read end is always there unless the tomb is dying.
				case <-tmb.Dying():
					// The tomb began dying before the response was sent,
					// so exit early.
					return tomb.ErrDying
				}
			case <-tmb.Dying():
				return tomb.ErrDying
			}

			// We don't handle any more requests. Run a loop for processing additional
			// requests in order to return errors, until the tomb enters a dying state.
			for tmb.Alive() {
				select {
				case req := <-reqChan:
					rsp := &Argon2OutOfProcessResponse{
						Command:     req.Command,
						ErrorType:   Argon2OutOfProcessErrorInvalidCommand,
						ErrorString: "a command has already been executed",
					}
					// Send the response.
					select {
					case rspChan <- rsp: // Unbuffered channel, but read end is always there unless the tomb is dying.
					case <-tmb.Dying():
						// The tomb began dying before the response was sent. The
						// loop won't run again.
					}
				case <-tmb.Dying():
					// The loop won't run again.
				}
			}
			return tomb.ErrDying
		})

		// Run a loop for receiving and processing incoming requests from the io.Reader as
		// long as the tomb remains alive.
		for tmb.Alive() {
			// Wait for a request from the io.Reader. The only way to unblock this is
			// if the parent sends something or closes its end of the OS pipe. If it's
			// closed before we've received a KDF request, then we terminate this routine
			// with an error to begin the process of the tomb dying and the function
			// eventually returning an error to the caller.
			var req *Argon2OutOfProcessRequest
			dec := json.NewDecoder(in)
			if err := dec.Decode(&req); err != nil {
				// Decoding returned an error.
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					// The parent has closed their end of the io.Reader, which
					// is our signal to return, so kill the tomb normally to
					// begin the process of dying.
					tmb.Kill(nil)
					break // Break out of the request processing loop
				}

				// We failed to decode an incoming request for an unknown reason. We'll
				// handle this by putting the tomb into a dying state and returning an
				// error to the caller.
				tmb.Kill(fmt.Errorf("cannot decode request: %w", err))
				break
			}

			// We have a request!

			switch req.Command {
			case Argon2OutOfProcessCommandWatchdog:
				// Special case to handle watchdog requests.
				wdRsp, err := watchdog(req.WatchdogChallenge)
				if err != nil {
					// As is documented for Argon2OutOfProcessWatchdogHandler, we don't
					// expect the handler to return an error, so begin the shutdown of
					// the tomb so that this function eventually returns with an error.
					return fmt.Errorf("cannot handle watchdog request: %w", err)
				}

				// Generate the response structure to send to the same goroutine that
				// will eventually encode and send the KDF response back to the parent.
				rsp := &Argon2OutOfProcessResponse{
					Command:          Argon2OutOfProcessCommandWatchdog,
					WatchdogResponse: wdRsp,
				}
				select {
				case rspChan <- rsp: // Unbuffered channel, but read end is always there unless the tomb is dying.
				case <-tmb.Dying():
					// The tomb began dying before the response was sent, so
					// the outer loop won't run again.
				}
			default:
				// Treat everything else as a KDF request. We don't actually check the
				// request here - this is done by RunArgon2OutOfProcessRequest which runs
				// on a dedicated routine.
				select {
				case reqChan <- req: // Unbuffered channel, but read end is always there unless the tomb is dying.
				case <-tmb.Dying():
					// The tomb began dying before the rquest was sent, so
					// the outer loop won't run again.
				}
			}
		}
		return tomb.ErrDying
	})

	// Wait here for the tomb to die and return the first error that occurred.
	return lockRelease, tmb.Wait()
}

// Argon2OutOfProcessWatchdogMonitor defines the behaviour of a watchdog monitor
// for out-of-process [Argon2KDF] implementations created by [NewOutOfProcessArgon2KDF],
// and is managed on the parent side of an implementation of [Argon2KDF].
//
// It will be called in its own dedicated go routine that is tracked by the supplied
// tomb.
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
// The [Argon2KDF] implementation created by [NewOutOfProcessArgon2KDF] will terminate the
// remote process in the event that the monitor implementation returns an error. It also
// kills the supllied tomb, resuling in the eventual return of an error to the caller.
//
// The implementation of this should not close reqChan. The [Argon2KDF] implementation
// created by [NewOutOfProcessArgon2KDF] will not close rspChan.
//
// The [Argon2KDF] implementation created by [NewOutOfProcessArgon2KDF] will only send
// watchdog requests via rspChan.
//
// The supplied reqChan is unbuffered, but the [Argon2KDF] implementation created by
// [NewOutOfProcessArgon2KDF] guarantees there is a reader until the tomb enters a
// dying state.
//
// The supplied rspChan is unbuffered. The monitor implementation should guarantee that
// there is a reader as long as the supplied tomb is alive.
type Argon2OutOfProcessWatchdogMonitor func(tmb *tomb.Tomb, reqChan chan<- *Argon2OutOfProcessRequest, rspChan <-chan *Argon2OutOfProcessResponse) error

// HMACArgon2OutOfProcessWatchdogMonitor returns a watchdog monitor that generates a
// challenge every period, computes a HMAC of this challenge, keyed with previously received
// watchdog response. It stops and returns an error if it doen't receive a valid response
// before the next cycle is meant to run. This is intended be paired with
// [HMACArgon2OutOfProcessWatchdogHandler] on the remote side.
func HMACArgon2OutOfProcessWatchdogMonitor(alg crypto.Hash, period time.Duration) Argon2OutOfProcessWatchdogMonitor {
	if !alg.Available() {
		panic("specified digest algorithm not available")
	}

	return func(tmb *tomb.Tomb, reqChan chan<- *Argon2OutOfProcessRequest, rspChan <-chan *Argon2OutOfProcessResponse) error {
		lastWatchdogResponse := make([]byte, 32) // the last response received from the child.
		ticker := time.NewTicker(period)

		// Run the watchdog whilst the tomb is alive.
		for tmb.Alive() {
			// Wait for the next tick
			select {
			case <-ticker.C:
			case <-tmb.Dying():
				// Handle the tomb dying before the end of the period.
				return tomb.ErrDying
			}

			// Generate a new 32-byte challenge and calculate the expected response
			challenge := make([]byte, 32)
			if _, err := rand.Read(challenge); err != nil {
				return fmt.Errorf("cannot generate new watchdog challenge: %w", err)
			}

			// The expected response is the HMAC of the challenge, keyed with the
			// last response.
			h := hmac.New(alg.New, lastWatchdogResponse)
			h.Write(challenge)
			expectedWatchdogResponse := h.Sum(nil)

			req := &Argon2OutOfProcessRequest{
				Command:           Argon2OutOfProcessCommandWatchdog,
				WatchdogChallenge: challenge,
			}

			// Send the request.
			select {
			case reqChan <- req: // Unbuffered channel, but read end is always there unless the tomb is dying.
			case <-tmb.Dying():
				// The tomb began dying before we finished sending the request (reqChan is blocking).
				return tomb.ErrDying
			}

			// Reset the ticker to remove the cost of gathering entropy, calculating the
			// challenge and sending it.
			ticker.Reset(period)

			// Wait for the response from the remote process.
			select {
			case <-ticker.C:
				// We didn't receive a response before the next tick.
				return errors.New("timeout waiting for watchdog response from remote process")
			case rsp := <-rspChan:
				// We got a response from the remote process.
				if err := rsp.Err(); err != nil {
					// We got an error response, so just return the error.
					return rsp.Err()
				}
				if !bytes.Equal(rsp.WatchdogResponse, expectedWatchdogResponse) {
					// We got an unexpected response, so return an error.
					return errors.New("unexpected watchdog response value from remote process")
				}
				// The response was good so save the value for the next iteration.
				lastWatchdogResponse = rsp.WatchdogResponse
			case <-tmb.Dying():
				// The loop won't run again
			}
		}
		return tomb.ErrDying
	}
}

// NoArgon2OutOfProcessWatchdogMonitor is an implmenentation of Argon2OutOfProcessWatchdogMonitor that
// provides no watchdog functionality. It is paired with [NoArgon2OutOfProcessWatchdogHandler] on the
// remote side. It holds the watchdog goroutine in a parked state for the lifetime of the tomb.
func NoArgon2OutOfProcessWatchdogMonitor() Argon2OutOfProcessWatchdogMonitor {
	return func(tmb *tomb.Tomb, reqChan chan<- *Argon2OutOfProcessRequest, rspChan <-chan *Argon2OutOfProcessResponse) error {
		select {
		case <-tmb.Dying():
			return tomb.ErrDying
		case <-rspChan:
			return errors.New("unexpected watchdog response")
		}
	}
}

type outOfProcessArgon2KDFImpl struct {
	newHandlerCmd func() (*exec.Cmd, error)
	timeout       time.Duration
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
		// cleanup to do on failure paths other than closing the stdinPipe.
		// Note that we need to close both ends of it.
		stdinPipe.Close()            // The parent end
		cmd.Stdin.(*os.File).Close() // The child end
		return nil, fmt.Errorf("cannot create stdout pipe: %w", err)
	}

	// Start the remote process.
	if err := cmd.Start(); err != nil {
		// This takes care of closing both ends of each of the pipes
		// we created earlier.
		return nil, fmt.Errorf("cannot start handler process: %w", err)
	}

	defer func() {
		// The remote process may release the system-wide lock implicitly on process
		// termination. In this case, we make an attempt to cleanup the lock-file on
		// behalf of the remote process. This isn't strictly necessary, which is why
		// we set the timeout to 0, which makes it completely non-blocking - we don't
		// want to wait if someone else has already managed to grab the lock and we
		// don't want to delay the return of the response from this function.
		release, err := acquireArgon2OutOfProcessHandlerSystemLock(0)
		if err != nil {
			// We didn't acquire the lock with a single attempt, so never mind.
			return
		}
		// We have the lock. Explicitly releasing it again will unlink the lock file.
		release()
	}()

	var actualRsp *Argon2OutOfProcessResponse // The response to return to the caller
	exitWaitCh := make(chan struct{})         // A channel which signals successful exit of the child process when closed
	tmb := new(tomb.Tomb)                     // To track all goroutines

	// Spin up a routine to bootstrap the parent side and handle responses from
	// the remote process.
	tmb.Go(func() error {
		// Spin up a routine for killing the child process if it doesn't
		// die cleanly
		tmb.Go(func() error {
			<-tmb.Dying() // Wait here until the tomb enters a dying state

			select {
			case <-exitWaitCh:
				// The command closed cleanly, so there's nothing to do.
				return tomb.ErrDying
			case <-time.NewTimer(5 * time.Second).C:
				// We've waited 5 seconds - kill the child process instead. Go 1.20
				// has a new feature (WaitDelay) which might make things a bit better
				// here because I don't know how racey things are here - exec.Cmd is
				// quite complicated.
				//
				// Note that this only kills the process launched by us - it's not expected
				// that processes launched to handle KDF requests fork or clone any other
				// processes, as these will continue running, being reparented to the nearest
				// reaper.
				if err := cmd.Process.Kill(); err != nil {
					if err != os.ErrProcessDone {
						return fmt.Errorf("failed to kill blocked remote process: %w", err)
					}
				}
				return errors.New("killed blocked remote process")
			}
		})

		// wdRspChan is sent watchdog responses on this goroutine, received from
		// the remote process via stdout, and they are subsequently received by
		// the watchdog monitor for processing.
		wdRspChan := make(chan *Argon2OutOfProcessResponse)

		// reqChan is sent the initial request from this goroutine and watchdog requests
		// from the watchdog routine, which are received by a dedicated goroutine to
		// serialize then and sends them to the remote process via its stdin.
		reqChan := make(chan *Argon2OutOfProcessRequest)

		// Spin up a routine for encoding and sending requests to the remote process via stdinPipe.
		tmb.Go(func() error {
			// Run a loop to send requests as long as the tomb is alive.
			for tmb.Alive() {
				select {
				case req := <-reqChan:
					// Send the request to the remote process via its stdin
					enc := json.NewEncoder(stdinPipe)
					if err := enc.Encode(req); err != nil {
						return fmt.Errorf("cannot encode request: %w", err)
					}
				case <-tmb.Dying():
					// The tomb is dying, so this loop will stop iterating.
				}
			}
			return tomb.ErrDying
		})

		// Send the main request before starting the watchdog or running the response loop.
		select {
		case reqChan <- req: // Unbuffered channel, but read end is always there unless the tomb is dying.
		case <-tmb.Dying():
			// The tomb has begun dying before we had a chance to send the initial request.
			return tomb.ErrDying
		}

		// Spin up another routine to run the watchdog
		tmb.Go(func() error {
			err := k.watchdog(tmb, reqChan, wdRspChan)
			switch {
			case err == tomb.ErrDying:
				// Return this error unmodified.
				return err
			case err != nil:
				// Unexpected error.
				return &Argon2OutOfProcessWatchdogError{err: err}
			case tmb.Alive():
				// The watchdog returned no error whilst the tomb is still alive,
				// which is unexpected. In this case, begin the termination of the
				// tomb.
				return &Argon2OutOfProcessWatchdogError{err: errors.New("watchdog monitor terminated unexpectedly without an error")}
			case err == nil:
				// The tomb is in a dying state, and it's fine to return a nil error
				// in this case. We'll return tomb.ErrDying for consistency though.
				return tomb.ErrDying
			default:
				panic("not reached")
			}
		})

		// Run a loop to wait for responses from the remote process whilst the tomb is alive.
		for tmb.Alive() {
			// Wait for a response from the io.Reader. The only way to unblock this is
			// if the remote process sends something or closes its end of the OS pipe.
			// We do no special error handling here like we do on the remote side for the
			// request channel - in general, the last response is the result of the KDF
			// operation which begins the tomb's dying process anyway.
			dec := json.NewDecoder(stdoutPipe)
			var rsp *Argon2OutOfProcessResponse
			if err := dec.Decode(&rsp); err != nil {
				return fmt.Errorf("cannot decode response: %w", err)
			}

			if rsp.Err() != nil {
				// If we receive an error response, begin the process of the tomb dying.
				// Don't wrap the error - this will be returned directly to the caller.
				return rsp.Err()
			}

			switch rsp.Command {
			case Argon2OutOfProcessCommandWatchdog:
				// Direct watchdog responses to wdRspChan so they can be picked up by
				// the watchdog handler.
				select {
				case wdRspChan <- rsp: // Unbuffered channel, but read end is always there unless the tomb is dying.
				case <-tmb.Dying():
					// The loop will no longer iterate
				}
			default:
				// For any other response, first of all make sure that the command value is
				// consistent with the sent command.
				if rsp.Command != req.Command {
					// Unexpected command. Return an appropriate error to begin the process
					// of the tomb dying
					return &Argon2OutOfProcessResponseCommandInvalidError{
						Response: rsp.Command,
						Expected: req.Command,
					}
				}
				// If it is consistent, save the response to return to the caller and begin a clean
				// shutdown of the tomb.
				actualRsp = rsp
				tmb.Kill(nil)
				// This loop will no longer iterate
			}
		}
		return tomb.ErrDying
	})

	// Wait here until the tomb enters a dying state.
	<-tmb.Dying()

	// [exec.Cmd.Wait] will close parent FDs for us once the process has exitted. However, closing
	// the stdin pipe is necessary to unblock WaitForAndRunArgon2OutOfProcessRequest on the remote
	// side, if it is blocked in a read. We don't do the same for stdoutPipe (the request channel)
	// because the remote process is expected to close its end of it, freeing up any of its own
	// goroutines that are blocked on writing a response to us.
	if err := stdinPipe.Close(); err != nil {
		return nil, fmt.Errorf("cannot close stdin pipe: %w", err)
	}

	// We can wait for the remote process to exit now.
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("an error occurred whilst waiting for the remote process to finish: %w", err)
	}
	// Stop the 5 second kill timer
	close(exitWaitCh)

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
		Timeout:    k.timeout,
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
		Timeout:   k.timeout,
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
// and using a protocol compatibile with [WaitForAndRunArgon2OutOfProcessRequest], which
// will be expected to run in the remote handler process.
//
// The supplied function must not start the process, nor should it set the Stdin or
// Stdout fields of the [exec.Cmd] structure, as 2 pipes will be created for sending
// the request to the process via its stdin and receiving the response from the process
// via its stdout.
//
// KDF requests are serialized system-wide so that only 1 runs at a time. The supplied
// timeout specifies the maximum amount of time a request will wait to be started before
// giving up with an error.
//
// The optional watchdog field makes it possible to send periodic pings to the remote
// process to ensure that it is still alive and still processing IPC requests, given that
// the KDF may be asked to run for a long time, and the KDF itself is not interruptible.
// The supplied monitor must be paired with a matching handler on the remote side (passed to
// [WaitForAndRunArgon2OutOfProcessRequest] for this to work properly. If no monitor is
// supplied, [NoArgon2OutOfProcessWatchdogMonitor] is used, which provides no watchdog monitor
// functionality.
//
// The watchdog functionality is recommended for KDF uses that are more than 1 second long.
//
// The errors returned from methods of the returned Argon2KDF may be instances of
// *[Argon2OutOfProcessError].
func NewOutOfProcessArgon2KDF(newHandlerCmd func() (*exec.Cmd, error), timeout time.Duration, watchdog Argon2OutOfProcessWatchdogMonitor) Argon2KDF {
	if newHandlerCmd == nil {
		panic("newHandlerCmd cannot be nil")
	}
	if watchdog == nil {
		watchdog = NoArgon2OutOfProcessWatchdogMonitor()
	}
	return &outOfProcessArgon2KDFImpl{
		newHandlerCmd: newHandlerCmd,
		timeout:       timeout,
		watchdog:      watchdog,
	}
}
