// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/snapcore/secboot/internal/keyring"
	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"
)

var initThreadId int

func init() {
	// We lock the current goroutine to the current OS thread, which should be the
	// main thread. The go runtime calls the init functions from the main goroutine
	// which should already be locked to the main OS thread. The go runtime calls
	// runtime.UnlockOSThread before calling main, so we do this here to ensure that
	// the main function remains bound to the main OS thread.
	runtime.LockOSThread()

	// Check that we are actually on the main OS thread, just in case this behaviour
	// changes or breaks in the future.
	initThreadId = unix.Gettid()
	if initThreadId != unix.Getpid() {
		panic("called on unexpected OS thread (expected it to be the main thread)")
	}
}

func Test(t *testing.T) { TestingT(t) }

func TestMain(m *testing.M) {
	// Make sure that we are still on the main OS thread, which init bound the main
	// goroutine to already.
	if unix.Gettid() != initThreadId {
		panic("called on unexpected OS thread (expected it to be the main thread)")
	}

	os.Exit(func() int {
		// Now we know we are still on the main OS thread, we join a new anonymous
		// session keyring and then add a link from that to the user keyring so that
		// tests which require possession of keys inside the user keyring work
		// properly. This has to be done on the main application thread, so that
		// subsequently created threads inherit the same session keyring so that
		// tests will work regardless of which OS thread the goroutine is running
		// on. In general, KEYCTL_JOIN_SESSION_KEYRING is normally called in an
		// execution context with only a single thread because it only operates
		// on the calling thread.
		id, err := keyring.JoinSessionKeyring("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot join anonymous session keyring: %v\n", err)
			return 1
		}

		if err := keyring.LinkKey(keyring.UserKeyring, id); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot add link to user keyring in session keyring: %v\n", err)
			return 1
		}

		return m.Run()
	}())
}
