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

package pbkdf2_test

import (
	"crypto"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"math"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/internal/pbkdf2"
)

func Test(t *testing.T) { TestingT(t) }

type pbkdf2Suite struct{}

func (s *pbkdf2Suite) mockTimeExecution(c *C, expectedHash crypto.Hash) (restore func()) {
	return MockTimeExecution(func(params *Params) time.Duration {
		c.Check(params.HashAlg, Equals, expectedHash)
		// hardcode 1us per iteration
		return time.Duration(params.Iterations) * time.Microsecond
	})
}

var _ = Suite(&pbkdf2Suite{})

func (s *pbkdf2Suite) TestBenchmark(c *C) {
	restore := s.mockTimeExecution(c, crypto.SHA256)
	defer restore()

	iterations, err := Benchmark(250*time.Millisecond, crypto.SHA256)
	c.Check(err, IsNil)
	c.Check(iterations, Equals, uint(250000))
}

func (s *pbkdf2Suite) TestBenchmarkDifferentHash(c *C) {
	restore := s.mockTimeExecution(c, crypto.SHA512)
	defer restore()

	iterations, err := Benchmark(250*time.Millisecond, crypto.SHA512)
	c.Check(err, IsNil)
	c.Check(iterations, Equals, uint(250000))
}

func (s *pbkdf2Suite) TestBenchmarkDifferentTarget(c *C) {
	restore := s.mockTimeExecution(c, crypto.SHA256)
	defer restore()

	iterations, err := Benchmark(2*time.Second, crypto.SHA256)
	c.Check(err, IsNil)
	c.Check(iterations, Equals, uint(2000000))
}

func (s *pbkdf2Suite) TestBenchmarkDifferentTarget2(c *C) {
	restore := s.mockTimeExecution(c, crypto.SHA256)
	defer restore()

	iterations, err := Benchmark(10*time.Millisecond, crypto.SHA256)
	c.Check(err, IsNil)
	c.Check(iterations, Equals, uint(10000))
}

func (s *pbkdf2Suite) TestBenchmarkInvalidHash(c *C) {
	_, err := Benchmark(2*time.Second, 0)
	c.Check(err, ErrorMatches, `unavailable digest algorithm`)
}

func (s *pbkdf2Suite) TestBenchmarkOverflow(c *C) {
	restore := MockTimeExecution(func(params *Params) time.Duration {
		return 50 * time.Millisecond
	})
	defer restore()

	_, err := Benchmark(450*time.Second, crypto.SHA256)
	c.Check(err, ErrorMatches, `iteration count result will overflow`)
}

func (s *pbkdf2Suite) TestKey(c *C) {
	salt := make([]byte, 16)
	rand.Read(salt)

	key, err := Key("foo", salt, &Params{Iterations: 1000, HashAlg: crypto.SHA256}, 32)
	c.Check(err, IsNil)
	expectedKey := pbkdf2.Key([]byte("foo"), salt, 1000, 32, crypto.SHA256.New)
	c.Check(key, DeepEquals, expectedKey)
}

func (s *pbkdf2Suite) TestKeyDifferentArgs(c *C) {
	salt := make([]byte, 32)
	rand.Read(salt)

	key, err := Key("bar", salt, &Params{Iterations: 200000, HashAlg: crypto.SHA512}, 64)
	c.Check(err, IsNil)
	expectedKey := pbkdf2.Key([]byte("bar"), salt, 200000, 64, crypto.SHA512.New)
	c.Check(key, DeepEquals, expectedKey)
}

func (s *pbkdf2Suite) TestKeyNilParams(c *C) {
	_, err := Key("foo", nil, nil, 32)
	c.Check(err, ErrorMatches, `nil params`)
}

func (s *pbkdf2Suite) TestKeyInvalidIterations(c *C) {
	_, err := Key("foo", nil, &Params{Iterations: math.MaxUint, HashAlg: crypto.SHA256}, 32)
	c.Check(err, ErrorMatches, `too many iterations`)
}

func (s *pbkdf2Suite) TestKeyInvalidHash(c *C) {
	_, err := Key("foo", nil, &Params{Iterations: 1000}, 32)
	c.Check(err, ErrorMatches, `unavailable digest algorithm`)
}

func (s *pbkdf2Suite) TestKeyInvalidKeyLen(c *C) {
	_, err := Key("foo", nil, &Params{Iterations: 1000, HashAlg: crypto.SHA256}, math.MaxUint)
	c.Check(err, ErrorMatches, `invalid key length`)
}
