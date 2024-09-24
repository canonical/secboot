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
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Check(targetDuration, Equals, 2*time.Second)
		c.Check(hashAlg, Equals, crypto.SHA256)
		return pbkdf2.Benchmark(targetDuration, hashAlg)
	})
	defer restore()

	var opts PBKDF2Options
	params, err := opts.KdfParams(32)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA256))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}

func (s *pbkdf2Suite) TestKDFParamsDefault48(c *C) {
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Check(targetDuration, Equals, 2*time.Second)
		c.Check(hashAlg, Equals, crypto.SHA384)
		return pbkdf2.Benchmark(targetDuration, hashAlg)
	})
	defer restore()

	var opts PBKDF2Options
	params, err := opts.KdfParams(48)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA384))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}

func (s *pbkdf2Suite) TestKDFParamsDefault64(c *C) {
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Check(targetDuration, Equals, 2*time.Second)
		c.Check(hashAlg, Equals, crypto.SHA512)
		return pbkdf2.Benchmark(targetDuration, hashAlg)
	})
	defer restore()

	var opts PBKDF2Options
	params, err := opts.KdfParams(64)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA512))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}

func (s *pbkdf2Suite) TestKDFParamsTargetDuration(c *C) {
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Logf("benchmarking (%d)", targetDuration)
		if targetDuration != 200*time.Millisecond {
			panic("")
		}
		c.Check(targetDuration, Equals, 200*time.Millisecond)
		c.Check(hashAlg, Equals, crypto.SHA256)
		return pbkdf2.Benchmark(targetDuration, hashAlg)
	})
	defer restore()

	var opts PBKDF2Options
	opts.TargetDuration = 200 * time.Millisecond
	params, err := opts.KdfParams(32)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA256))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}

func (s *pbkdf2Suite) TestKDFParamsForceIterations(c *C) {
	var opts PBKDF2Options
	opts.ForceIterations = 2000
	params, err := opts.KdfParams(32)
	c.Assert(err, IsNil)
	c.Check(params, DeepEquals, &KdfParams{
		Type: "pbkdf2",
		Time: 2000,
		Hash: HashAlg(crypto.SHA256),
	})
}

func (s *pbkdf2Suite) TestKDFParamsCustomHash(c *C) {
	restore := MockPBKDF2Benchmark(func(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
		c.Check(targetDuration, Equals, 2*time.Second)
		c.Check(hashAlg, Equals, crypto.SHA512)
		return pbkdf2.Benchmark(targetDuration, hashAlg)
	})
	defer restore()

	var opts PBKDF2Options
	opts.HashAlg = crypto.SHA512
	params, err := opts.KdfParams(32)
	c.Assert(err, IsNil)
	c.Check(params.Type, Equals, "pbkdf2")
	c.Check(params.Hash, Equals, HashAlg(crypto.SHA512))
	c.Check(params.Memory, Equals, 0)
	c.Check(params.CPUs, Equals, 0)
}
