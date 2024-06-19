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

package testutil_test

import (
	"bytes"
	"io"
	"sync"

	. "github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

var (
	closedChanOnce sync.Once
	closedChan     chan struct{}
)

// maybeReadByte is a copy of go's internal randutil.MaybeReadByte.
func maybeReadByte(r io.Reader) {
	closedChanOnce.Do(func() {
		closedChan = make(chan struct{})
		close(closedChan)
	})

	select {
	case <-closedChan:
		return
	case <-closedChan:
		var buf [1]byte
		r.Read(buf[:])
	}
}

type randSuite struct{}

var _ = Suite(&randSuite{})

func (s *randSuite) TestBypassMaybeReadByteAll(c *C) {
	r := BypassMaybeReadByte(bytes.NewReader(DecodeHexString(c, "f84361c102a4c3ade37248e7f3579f8fffa02e70f378f6c0423d98fa773a8303142500212be037688e07f1277d8e4ac3894cf28cb7d39a81d6dfd14d57783b04")), true)

	var x [32]byte
	var y [16]byte
	var z [16]byte

	maybeReadByte(r)
	_, err := io.ReadFull(r, x[:])
	c.Check(err, IsNil)
	c.Check(x[:], DeepEquals, DecodeHexString(c, "f84361c102a4c3ade37248e7f3579f8fffa02e70f378f6c0423d98fa773a8303"))

	maybeReadByte(r)
	_, err = io.ReadFull(r, y[:])
	c.Check(err, IsNil)
	c.Check(y[:], DeepEquals, DecodeHexString(c, "142500212be037688e07f1277d8e4ac3"))

	maybeReadByte(r)
	_, err = io.ReadFull(r, z[:])
	c.Check(err, IsNil)
	c.Check(z[:], DeepEquals, DecodeHexString(c, "894cf28cb7d39a81d6dfd14d57783b04"))
}

func (s *randSuite) TestBypassMaybeReadByteWithOffsets(c *C) {
	r := BypassMaybeReadByte(bytes.NewReader(DecodeHexString(c, "f84361c102a4c3ade37248e7f3579f8fffa02e70f378f6c0423d98fa773a8303142500212be037688e07f1277d8e4ac3894cf28cb7d39a81d6dfd14d57783b04")), false, 0, 32, 48)

	var x [32]byte
	var y [16]byte
	var z [16]byte

	maybeReadByte(r)
	_, err := io.ReadFull(r, x[:])
	c.Check(err, IsNil)
	c.Check(x[:], DeepEquals, DecodeHexString(c, "f84361c102a4c3ade37248e7f3579f8fffa02e70f378f6c0423d98fa773a8303"))

	maybeReadByte(r)
	_, err = io.ReadFull(r, y[:])
	c.Check(err, IsNil)
	c.Check(y[:], DeepEquals, DecodeHexString(c, "142500212be037688e07f1277d8e4ac3"))

	maybeReadByte(r)
	_, err = io.ReadFull(r, z[:])
	c.Check(err, IsNil)
	c.Check(z[:], DeepEquals, DecodeHexString(c, "894cf28cb7d39a81d6dfd14d57783b04"))
}

func (s *randSuite) TestBypassMaybeReadByteWithOffsetsHandleSingleByteReadBeforeNextBoundary(c *C) {
	r := BypassMaybeReadByte(bytes.NewReader(DecodeHexString(c, "f84361c102a4c3ade37248e7f3579f8f01ffa02e70f378f6c0423d98fa773a8303142500212be037688e07f1277d8e4ac3894cf28cb7d39a81d6dfd14d57783b04")), false, 0, 33, 49)

	var x1 [16]byte
	var x2 [1]byte
	var x3 [16]byte
	var y [16]byte
	var z [16]byte

	maybeReadByte(r)
	_, err := io.ReadFull(r, x1[:])
	c.Check(err, IsNil)
	c.Check(x1[:], DeepEquals, DecodeHexString(c, "f84361c102a4c3ade37248e7f3579f8f"))

	_, err = io.ReadFull(r, x2[:])
	c.Check(err, IsNil)
	c.Check(x2[:], DeepEquals, []byte{1})

	_, err = io.ReadFull(r, x3[:])
	c.Check(err, IsNil)
	c.Check(x3[:], DeepEquals, DecodeHexString(c, "ffa02e70f378f6c0423d98fa773a8303"))

	maybeReadByte(r)
	_, err = io.ReadFull(r, y[:])
	c.Check(err, IsNil)
	c.Check(y[:], DeepEquals, DecodeHexString(c, "142500212be037688e07f1277d8e4ac3"))

	maybeReadByte(r)
	_, err = io.ReadFull(r, z[:])
	c.Check(err, IsNil)
	c.Check(z[:], DeepEquals, DecodeHexString(c, "894cf28cb7d39a81d6dfd14d57783b04"))
}

func (s *randSuite) TestBypassMaybeReadByteWithOffsetsHandleOvershootingBoundary(c *C) {
	r := BypassMaybeReadByte(bytes.NewReader(DecodeHexString(c, "f84361c102a4c3ade37248e7f3579f8fffa02e70f378f6c0423d98fa773a8303142500212be037688e07f1277d8e4ac3894cf28cb7d39a81d6dfd14d57783b04")), false, 0, 32, 48)

	var x [48]byte
	var y [16]byte

	maybeReadByte(r)
	_, err := io.ReadFull(r, x[:])
	c.Check(err, IsNil)
	c.Check(x[:], DeepEquals, DecodeHexString(c, "f84361c102a4c3ade37248e7f3579f8fffa02e70f378f6c0423d98fa773a8303142500212be037688e07f1277d8e4ac3"))

	maybeReadByte(r)
	_, err = io.ReadFull(r, y[:])
	c.Check(err, IsNil)
	c.Check(y[:], DeepEquals, DecodeHexString(c, "894cf28cb7d39a81d6dfd14d57783b04"))
}

func (s *randSuite) TestBypassMaybeReadByteWithOffsetsPassSingleByteReadsWhenNoMoreOffsets(c *C) {
	r := BypassMaybeReadByte(bytes.NewReader(DecodeHexString(c, "f84361c102a4c3ade37248e7f3579f8fffa02e70f378f6c0423d98fa773a8303142500212be037688e07f1277d8e4ac3894cf28cb7d39a81d6dfd14d57783b04ff")), false, 0, 32, 48)

	var x [32]byte
	var y [16]byte
	var z [16]byte
	var a [1]byte

	maybeReadByte(r)
	_, err := io.ReadFull(r, x[:])
	c.Check(err, IsNil)
	c.Check(x[:], DeepEquals, DecodeHexString(c, "f84361c102a4c3ade37248e7f3579f8fffa02e70f378f6c0423d98fa773a8303"))

	maybeReadByte(r)
	_, err = io.ReadFull(r, y[:])
	c.Check(err, IsNil)
	c.Check(y[:], DeepEquals, DecodeHexString(c, "142500212be037688e07f1277d8e4ac3"))

	maybeReadByte(r)
	_, err = io.ReadFull(r, z[:])
	c.Check(err, IsNil)
	c.Check(z[:], DeepEquals, DecodeHexString(c, "894cf28cb7d39a81d6dfd14d57783b04"))

	_, err = io.ReadFull(r, a[:])
	c.Check(err, IsNil)
	c.Check(a[:], DeepEquals, []byte{0xff})
}
