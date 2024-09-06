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
	"errors"
	"fmt"
	"os"

	"github.com/snapcore/secboot"
)

func run() error {
	if len(os.Args) != 1 {
		return errors.New("usage: echo <input_request_json> | run_argon2")
	}

	secboot.SetIsArgon2HandlerProcess()

	err := secboot.WaitForAndRunArgon2OutOfProcessRequest(os.Stdin, os.Stdout)
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
