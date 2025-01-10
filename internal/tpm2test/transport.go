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
	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
)

// Transport is a wrapper around tpm2_testutil.Transport that provides a mechanism
// to keep the underlying connection open when Close is called.
type Transport struct {
	transport    *tpm2_testutil.Transport
	keepOpen     bool
	markedClosed bool
	closed       bool
}

func (t *Transport) Read(data []byte) (int, error) {
	if t.markedClosed {
		return 0, tpm2.ErrTransportClosed
	}
	return t.transport.Read(data)
}

func (t *Transport) Write(data []byte) (int, error) {
	if t.markedClosed {
		return 0, tpm2.ErrTransportClosed
	}
	return t.transport.Write(data)
}

// Close closes the underlying connection unless SetKeepOpen has
// been called with keepOpen set to true, in which case, the
// interface is marked as closed without actually closing it.
func (t *Transport) Close() error {
	if t.markedClosed {
		return tpm2.ErrTransportClosed
	}
	t.markedClosed = true
	if t.keepOpen {
		return nil
	}
	t.closed = true
	return t.transport.Close()
}

// SetKeepOpen provides a mechanism to keep the underlying connection
// open when Close is called. If keepOpen is true, calling Close will
// mark the connection as closed without actually closing it. This
// makes it possible to reuse the underlying connection in another
// secboot_tpm2.Connection.
func (t *Transport) SetKeepOpen(keepOpen bool) error {
	t.keepOpen = keepOpen
	if !t.keepOpen && t.markedClosed && !t.closed {
		t.closed = true
		return t.transport.Close()
	}
	return nil
}

func (t *Transport) Unwrap() tpm2.Transport {
	return t.transport
}

func WrapTransport(transport *tpm2_testutil.Transport) *Transport {
	return &Transport{transport: transport}
}
