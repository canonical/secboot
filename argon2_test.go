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
	"math"
	"runtime"
	"time"

	snapd_testutil "github.com/snapcore/snapd/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
)

type argon2Suite struct {
	snapd_testutil.BaseTest

	kdf testutil.MockArgon2KDF

	halfTotalRamKiB uint32
	cpus            uint8
}

func (s *argon2Suite) SetUpSuite(c *C) {
	var sysInfo unix.Sysinfo_t
	c.Check(unix.Sysinfo(&sysInfo), IsNil)

	halfTotalRamKiB := uint64(sysInfo.Totalram) * uint64(sysInfo.Unit) / 2048
	if halfTotalRamKiB > math.MaxUint32 {
		halfTotalRamKiB = math.MaxUint32
	}
	s.halfTotalRamKiB = uint32(halfTotalRamKiB)

	cpus := runtime.NumCPU()
	if cpus > math.MaxUint8 {
		cpus = math.MaxUint8
	}
	s.cpus = uint8(cpus)
}

func (s *argon2Suite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.kdf = testutil.MockArgon2KDF{}

	origKdf := SetArgon2KDF(&s.kdf)
	s.AddCleanup(func() { SetArgon2KDF(origKdf) })
}

func (s *argon2Suite) checkParams(c *C, opts *Argon2Options, ncpus uint8, params *KdfParams) {
	expectedMode := Argon2id
	if opts.Mode != Argon2Default {
		expectedMode = opts.Mode
	}
	c.Check(params.Type, Equals, string(expectedMode))

	if opts.ForceIterations != 0 {
		c.Check(params.Time, Equals, int(opts.ForceIterations))

		expectedMem := opts.MemoryKiB
		if expectedMem == 0 {
			expectedMem = 1 * 1024 * 1024
		}
		c.Check(params.Memory, Equals, int(expectedMem))

		expectedThreads := opts.Parallel
		if expectedThreads == 0 {
			expectedThreads = uint8(ncpus)
		}
		c.Check(params.CPUs, Equals, int(expectedThreads))
	} else {
		targetDuration := opts.TargetDuration
		if targetDuration == 0 {
			targetDuration = 2 * time.Second
		}
		var kdf testutil.MockArgon2KDF
		duration, _ := kdf.Time(Argon2Default, &Argon2CostParams{
			Time:      uint32(params.Time),
			MemoryKiB: uint32(params.Memory),
			Threads:   uint8(params.CPUs),
		})
		c.Check(duration, Equals, targetDuration)

		maxMem := opts.MemoryKiB
		if maxMem == 0 {
			maxMem = 1 * 1024 * 1024
		}
		if maxMem > s.halfTotalRamKiB {
			maxMem = s.halfTotalRamKiB
		}
		c.Check(params.Memory, snapd_testutil.IntLessEqual, int(maxMem))

		expectedThreads := opts.Parallel
		if expectedThreads == 0 {
			expectedThreads = uint8(ncpus)
		}
		if expectedThreads > 4 {
			expectedThreads = 4
		}
		c.Check(params.CPUs, Equals, int(expectedThreads))
	}
}

var _ = Suite(&argon2Suite{})

func (s *argon2Suite) TestKDFParamsDefault(c *C) {
	var opts Argon2Options
	params, err := opts.KdfParams(0)
	c.Assert(err, IsNil)
	c.Check(s.kdf.BenchmarkMode, Equals, Argon2id)

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestKDFParamsExplicitMode(c *C) {
	var opts Argon2Options
	opts.Mode = Argon2i
	params, err := opts.KdfParams(9)
	c.Assert(err, IsNil)
	c.Check(s.kdf.BenchmarkMode, Equals, Argon2i)

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestKDFParamsMemoryLimit(c *C) {
	var opts Argon2Options
	opts.MemoryKiB = 32 * 1024
	params, err := opts.KdfParams(0)
	c.Assert(err, IsNil)
	c.Check(s.kdf.BenchmarkMode, Equals, Argon2id)

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestKDFParamsForceBenchmarkedThreads(c *C) {
	var opts Argon2Options
	opts.Parallel = 1
	params, err := opts.KdfParams(0)
	c.Assert(err, IsNil)
	c.Check(s.kdf.BenchmarkMode, Equals, Argon2id)

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestKDFParamsForceIterations(c *C) {
	restore := MockRuntimeNumCPU(2)
	defer restore()

	var opts Argon2Options
	opts.ForceIterations = 3
	params, err := opts.KdfParams(0)
	c.Assert(err, IsNil)
	c.Check(s.kdf.BenchmarkMode, Equals, Argon2Default)

	s.checkParams(c, &opts, 2, params)
}

func (s *argon2Suite) TestKDFParamsForceMemory(c *C) {
	restore := MockRuntimeNumCPU(2)
	defer restore()

	var opts Argon2Options
	opts.ForceIterations = 3
	opts.MemoryKiB = 32 * 1024
	params, err := opts.KdfParams(0)
	c.Assert(err, IsNil)
	c.Check(s.kdf.BenchmarkMode, Equals, Argon2Default)

	s.checkParams(c, &opts, 2, params)
}

func (s *argon2Suite) TestKDFParamsForceIterationsDifferentCPUNum(c *C) {
	restore := MockRuntimeNumCPU(8)
	defer restore()

	var opts Argon2Options
	opts.ForceIterations = 3
	params, err := opts.KdfParams(0)
	c.Assert(err, IsNil)
	c.Check(s.kdf.BenchmarkMode, Equals, Argon2Default)

	s.checkParams(c, &opts, 4, params)
}

func (s *argon2Suite) TestKDFParamsForceThreads(c *C) {
	restore := MockRuntimeNumCPU(8)
	defer restore()

	var opts Argon2Options
	opts.ForceIterations = 3
	opts.Parallel = 1
	params, err := opts.KdfParams(9)
	c.Assert(err, IsNil)
	c.Check(s.kdf.BenchmarkMode, Equals, Argon2Default)

	s.checkParams(c, &opts, 1, params)
}

func (s *argon2Suite) TestKDFParamsForceThreadsGreatherThanCPUNum(c *C) {
	restore := MockRuntimeNumCPU(2)
	defer restore()

	var opts Argon2Options
	opts.ForceIterations = 3
	opts.Parallel = 8
	params, err := opts.KdfParams(0)
	c.Assert(err, IsNil)
	c.Check(s.kdf.BenchmarkMode, Equals, Argon2Default)

	s.checkParams(c, &opts, 8, params)
}

func (s *argon2Suite) TestKDFParamsInvalidForceIterations(c *C) {
	var opts Argon2Options
	opts.ForceIterations = math.MaxUint32
	_, err := opts.KdfParams(0)
	c.Check(err, ErrorMatches, `invalid iterations count 4294967295`)
}

func (s *argon2Suite) TestKDFParamsInvalidMemoryKiB(c *C) {
	var opts Argon2Options
	opts.ForceIterations = 4
	opts.MemoryKiB = math.MaxUint32
	_, err := opts.KdfParams(0)
	c.Check(err, ErrorMatches, `invalid memory cost 4294967295KiB`)
}
