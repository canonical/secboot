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

package secboot_test

import (
	"crypto"
	"time"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/pbkdf2"
)

type pbkdf2Suite struct{}

var _ = Suite(&pbkdf2Suite{})

func (s *pbkdf2Suite) TestKDFParamsDefault(c *C) {
	var expectedTime int
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Check(targetDuration, Equals, 2*time.Second)
		c.Check(hashAlg, Equals, crypto.SHA256)
		iter, err := pbkdf2.Benchmark(targetDuration, hashAlg)
		c.Check(err, IsNil)
		expectedTime = int(iter)
		return iter, err
	})
	defer restore()

	var opts PBKDF2Options
	params, err := opts.KdfParams(2*time.Second, 32)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Time, Equals, expectedTime)
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA256))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}

func (s *pbkdf2Suite) TestKDFParamsDefaultWithDifferentTargetDuration(c *C) {
	var expectedTime int
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Check(targetDuration, Equals, 200*time.Millisecond)
		c.Check(hashAlg, Equals, crypto.SHA256)
		iter, err := pbkdf2.Benchmark(targetDuration, hashAlg)
		c.Check(err, IsNil)
		expectedTime = int(iter)
		return iter, err
	})
	defer restore()

	var opts PBKDF2Options
	params, err := opts.KdfParams(200*time.Millisecond, 32)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Time, Equals, expectedTime)
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA256))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}

func (s *pbkdf2Suite) TestKDFParamsDefault48(c *C) {
	var expectedTime int
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Check(targetDuration, Equals, 2*time.Second)
		c.Check(hashAlg, Equals, crypto.SHA384)
		iter, err := pbkdf2.Benchmark(targetDuration, hashAlg)
		c.Check(err, IsNil)
		expectedTime = int(iter)
		return iter, err
	})
	defer restore()

	var opts PBKDF2Options
	params, err := opts.KdfParams(2*time.Second, 48)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Time, Equals, expectedTime)
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA384))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}

func (s *pbkdf2Suite) TestKDFParamsDefault64(c *C) {
	var expectedTime int
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Check(targetDuration, Equals, 2*time.Second)
		c.Check(hashAlg, Equals, crypto.SHA512)
		iter, err := pbkdf2.Benchmark(targetDuration, hashAlg)
		c.Check(err, IsNil)
		expectedTime = int(iter)
		return iter, err
	})
	defer restore()

	var opts PBKDF2Options
	params, err := opts.KdfParams(2*time.Second, 64)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Time, Equals, expectedTime)
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA512))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}

func (s *pbkdf2Suite) TestKDFParamsTargetDuration(c *C) {
	var expectedTime int
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Check(targetDuration, Equals, 200*time.Millisecond)
		c.Check(hashAlg, Equals, crypto.SHA256)
		iter, err := pbkdf2.Benchmark(targetDuration, hashAlg)
		c.Check(err, IsNil)
		expectedTime = int(iter)
		return iter, err
	})
	defer restore()

	var opts PBKDF2Options
	opts.TargetDuration = 200 * time.Millisecond
	params, err := opts.KdfParams(2*time.Second, 32)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Time, Equals, expectedTime)
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA256))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}

func (s *pbkdf2Suite) TestKDFParamsForceIterations(c *C) {
	var opts PBKDF2Options
	opts.ForceIterations = 2000
	params, err := opts.KdfParams(2*time.Second, 32)
	c.Assert(err, IsNil)
	c.Check(params, DeepEquals, &KdfParams{
		Type: "pbkdf2",
		Time: 2000,
		Hash: HashAlg(crypto.SHA256),
	})
}

func (s *pbkdf2Suite) TestKDFParamsCustomHash(c *C) {
	var expectedTime int
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Check(targetDuration, Equals, 2*time.Second)
		c.Check(hashAlg, Equals, crypto.SHA512)
		iter, err := pbkdf2.Benchmark(targetDuration, hashAlg)
		c.Check(err, IsNil)
		expectedTime = int(iter)
		return iter, err
	})
	defer restore()

	var opts PBKDF2Options
	opts.HashAlg = crypto.SHA512
	params, err := opts.KdfParams(2*time.Second, 32)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Time, Equals, expectedTime)
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA512))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}
