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

package testutil

import (
	"io"
	"math/rand"
)

type testRng struct{}

func (r *testRng) Read(p []byte) (int, error) {
	return rand.Read(p)
}

var RandReader = &testRng{}

type maybeReadByteBypasser struct {
	bypassAll     bool
	bypassOffsets []int64

	rand   io.Reader
	offset int64
}

// BypassMaybeReadByte returns a new io.Reader that can be used to make functions
// inside go's crypto library that take a source of randomness from an io.Reader behave
// deterministically for the same sequence of random bytes, even where they make use of
// the internal randutil.MaybeReadByte function to introduce non-determinism.
//
// It can operate in one of 2 modes - it can ignore all single byte reads, or it's possible
// to ignore single byte reads at specific offsets. For ignored single byte reads, the io.Reader
// implementation just returns (1, nil) without consuming any bytes from the supplied io.Reader.
func BypassMaybeReadByte(rand io.Reader, bypassAll bool, bypassOffsets ...int64) io.Reader {
	if bypassAll && len(bypassOffsets) > 0 {
		panic("cannot use bypassAll with bypassOffsets")
	}

	return &maybeReadByteBypasser{
		bypassAll:     bypassAll,
		bypassOffsets: bypassOffsets,
		rand:          rand,
		offset:        0,
	}
}

func (r *maybeReadByteBypasser) Read(data []byte) (int, error) {
	if len(data) == 1 {
		// Single byte read, potentially from randutil.MaybeReadByte
		if r.bypassAll {
			// Treat all single byte reads as coming from randutil.MaybeReadByte
			return 1, nil
		}
	Outer:
		for len(r.bypassOffsets) > 0 {
			// We were given a set of offsets at which to ignore single byte reads,
			// and there are still some left.
			nextBoundary := r.bypassOffsets[0]
			switch {
			case r.offset > nextBoundary:
				// We've passed this boundary - pop it and try the next one
				r.bypassOffsets = r.bypassOffsets[1:]
			case r.offset == nextBoundary:
				// We have a hit - treat this single byte read as coming from
				// randutil.MaybeReadByte, pop this boundary from the top of the
				// slice and return the appropriate value.
				r.bypassOffsets = r.bypassOffsets[1:]
				return 1, nil
			case r.offset < nextBoundary:
				// We haven't reached the next boundary, so break from the loop
				// and perform a normal read from the underlying io.Reader.
				break Outer
			}
		}
	}

	// Perform a normal read
	n, err := r.rand.Read(data)
	r.offset += int64(n)
	return n, err
}
