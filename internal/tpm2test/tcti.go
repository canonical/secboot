// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package tpm2test

import (
	"os"
	"time"

	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
)

// TCTI is a wrapper around tpm2_testutil.TCTI that provides a mechanism
// to keep the underlying connection open when Close is called.
type TCTI struct {
	tcti         *tpm2_testutil.TCTI
	keepOpen     bool
	markedClosed bool
	closed       bool
}

func (t *TCTI) Read(data []byte) (int, error) {
	if t.markedClosed {
		return 0, os.ErrClosed
	}
	return t.tcti.Read(data)
}

func (t *TCTI) Write(data []byte) (int, error) {
	if t.markedClosed {
		return 0, os.ErrClosed
	}
	return t.tcti.Write(data)
}

// Close closes the underlying connection unless SetKeepOpen has
// been called with keepOpen set to true, in which case, the
// interface is marked as closed without actually closing it.
func (t *TCTI) Close() error {
	if t.markedClosed {
		return os.ErrClosed
	}
	t.markedClosed = true
	if t.keepOpen {
		return nil
	}
	t.closed = true
	return t.tcti.Close()
}

func (t *TCTI) SetTimeout(timeout time.Duration) error {
	return t.tcti.SetTimeout(timeout)
}

func (t *TCTI) MakeSticky(handle tpm2.Handle, sticky bool) error {
	return t.tcti.MakeSticky(handle, sticky)
}

// SetKeepOpen provides a mechanism to keep the underlying connection
// open when Close is called. If keepOpen is true, calling Close will
// mark the connection as closed without actually closing it. This
// makes it possible to reuse the underlying connection in another
// secboot_tpm2.Connection.
func (t *TCTI) SetKeepOpen(keepOpen bool) error {
	t.keepOpen = keepOpen
	if !t.keepOpen && t.markedClosed && !t.closed {
		t.closed = true
		return t.tcti.Close()
	}
	return nil
}

func (t *TCTI) Unwrap() tpm2.TCTI {
	return t.tcti
}

func WrapTCTI(tcti *tpm2_testutil.TCTI) *TCTI {
	return &TCTI{tcti: tcti}
}
