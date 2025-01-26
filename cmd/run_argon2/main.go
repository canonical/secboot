// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024-2024 Canonical Ltd
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
package main

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/paths"
)

func run() error {
	if len(os.Args) < 3 {
		return errors.New("usage: echo <input_request_json> | run_argon2 <lockpath> <watchdog> [<optional_params>] [kdf_panic]")
	}

	paths.Argon2OutOfProcessHandlerSystemLockPath = os.Args[1]

	var watchdog secboot.Argon2OutOfProcessWatchdogHandler
	var remaining []string
	switch os.Args[2] {
	case "none":
		watchdog = secboot.NoArgon2OutOfProcessWatchdogHandler()
		remaining = os.Args[3:]
	case "hmac":
		if len(os.Args) < 4 {
			return errors.New("usage: echo <input_request_json> | run_argon2 hmac <alg>")
		}
		var alg crypto.Hash
		switch os.Args[3] {
		case "sha1":
			alg = crypto.SHA1
		case "sha224":
			alg = crypto.SHA224
		case "sha256":
			alg = crypto.SHA256
		case "sha384":
			alg = crypto.SHA384
		case "sha512":
			alg = crypto.SHA512
		default:
			return fmt.Errorf("unrecognized HMAC digest algorithm %q", os.Args[3])
		}
		watchdog = secboot.HMACArgon2OutOfProcessWatchdogHandler(alg)
		remaining = os.Args[4:]
	}

	if len(remaining) > 0 && remaining[0] == "kdf_panic" {
		secboot.MockRunArgon2OutOfProcessRequestForTest(func(*secboot.Argon2OutOfProcessRequest) (*secboot.Argon2OutOfProcessResponse, func()) {
			<-time.NewTimer(500 * time.Millisecond).C
			panic("KDF panic")
		})
	}

	// Ignore the lock release callback and use implicit release on process termination.
	_, err := secboot.WaitForAndRunArgon2OutOfProcessRequest(os.Stdin, os.Stdout, watchdog)
	if err != nil {
		return fmt.Errorf("cannot run request: %w", err)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
