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
	"encoding/binary"
	"math"
	"runtime"
	"time"

	"github.com/canonical/go-sp800.108-kdf"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
)

type mockKDF struct {
	lastBenchmarkKeyLen uint32
}

func (_ *mockKDF) Derive(passphrase string, salt []byte, params *CostParams, keyLen uint32) ([]byte, error) {
	context := make([]byte, len(salt)+9)
	copy(context, salt)
	binary.LittleEndian.PutUint32(context[len(salt):], params.Time)
	binary.LittleEndian.PutUint32(context[len(salt)+4:], params.MemoryKiB)
	context[len(salt)+8] = params.Threads

	return kdf.CounterModeKey(kdf.NewHMACPRF(crypto.SHA256), []byte(passphrase), nil, context, keyLen*8), nil
}

func (k *mockKDF) Time(params *CostParams, keyLen uint32) (time.Duration, error) {
	k.lastBenchmarkKeyLen = keyLen

	const memBandwidthKiBPerMs = 2048
	duration := (time.Duration(float64(params.MemoryKiB)/float64(memBandwidthKiBPerMs)) * time.Duration(params.Time)) * time.Millisecond
	return duration, nil
}

type argon2Suite struct {
	halfTotalRamKiB uint64
	cpus            int
}

func (s *argon2Suite) SetUpSuite(c *C) {
	var sysInfo unix.Sysinfo_t
	c.Check(unix.Sysinfo(&sysInfo), IsNil)

	s.halfTotalRamKiB = uint64(sysInfo.Totalram) * uint64(sysInfo.Unit) / 2048
	if s.halfTotalRamKiB > math.MaxUint32 {
		s.halfTotalRamKiB = math.MaxUint32
	}

	s.cpus = runtime.NumCPU()
}

func (s *argon2Suite) checkParams(c *C, opts *KDFOptions, ncpus int, params *CostParams) {
	if opts.ForceIterations != 0 {
		c.Check(params.Time, Equals, uint32(opts.ForceIterations))

		expectedMem := opts.MemoryKiB
		if expectedMem == 0 {
			expectedMem = 1 * 1024 * 1024
		}
		c.Check(params.MemoryKiB, Equals, uint32(expectedMem))
	} else {
		targetDuration := opts.TargetDuration
		if targetDuration == 0 {
			targetDuration = 2 * time.Second
		}
		var kdf mockKDF
		duration, _ := kdf.Time(params, 0)
		c.Check(duration, Equals, targetDuration)

		maxMem := uint64(opts.MemoryKiB)
		if maxMem == 0 {
			maxMem = 1 * 1024 * 1024
		}
		if maxMem > s.halfTotalRamKiB {
			maxMem = s.halfTotalRamKiB
		}
		c.Check(int(params.MemoryKiB), snapd_testutil.IntLessEqual, int(maxMem))
	}

	expectedThreads := opts.Parallel
	if expectedThreads == 0 {
		expectedThreads = ncpus
	}
	if expectedThreads > 4 {
		expectedThreads = 4
	}
	c.Check(params.Threads, Equals, uint8(expectedThreads))
}

var _ = Suite(&argon2Suite{})

func (s *argon2Suite) TestDeriveCostParamsDefault(c *C) {
	var kdf mockKDF

	var opts KDFOptions
	params, err := opts.DeriveCostParams(48, &kdf)
	c.Assert(err, IsNil)
	c.Check(kdf.lastBenchmarkKeyLen, Equals, uint32(48))

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestDeriveCostParamsMemoryLimit(c *C) {
	var kdf mockKDF

	var opts KDFOptions
	opts.MemoryKiB = 32 * 1024
	params, err := opts.DeriveCostParams(48, &kdf)
	c.Assert(err, IsNil)
	c.Check(kdf.lastBenchmarkKeyLen, Equals, uint32(48))

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceBenchmarkedThreads(c *C) {
	var kdf mockKDF

	var opts KDFOptions
	opts.Parallel = 1
	params, err := opts.DeriveCostParams(48, &kdf)
	c.Assert(err, IsNil)
	c.Check(kdf.lastBenchmarkKeyLen, Equals, uint32(48))

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestDeriveCostParamsDifferentKeyLen(c *C) {
	var kdf mockKDF

	var opts KDFOptions
	params, err := opts.DeriveCostParams(32, &kdf)
	c.Assert(err, IsNil)
	c.Check(kdf.lastBenchmarkKeyLen, Equals, uint32(32))

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceIterations(c *C) {
	restore := MockRuntimeNumCPU(2)
	defer restore()

	var kdf mockKDF

	var opts KDFOptions
	opts.ForceIterations = 3
	params, err := opts.DeriveCostParams(48, &kdf)
	c.Assert(err, IsNil)
	c.Check(kdf.lastBenchmarkKeyLen, Equals, uint32(0))

	s.checkParams(c, &opts, 2, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceMemory(c *C) {
	restore := MockRuntimeNumCPU(2)
	defer restore()

	var kdf mockKDF

	var opts KDFOptions
	opts.ForceIterations = 3
	opts.MemoryKiB = 32 * 1024
	params, err := opts.DeriveCostParams(48, &kdf)
	c.Assert(err, IsNil)
	c.Check(kdf.lastBenchmarkKeyLen, Equals, uint32(0))

	s.checkParams(c, &opts, 2, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceIterationsDifferentCPUNum(c *C) {
	restore := MockRuntimeNumCPU(8)
	defer restore()

	var kdf mockKDF

	var opts KDFOptions
	opts.ForceIterations = 3
	params, err := opts.DeriveCostParams(48, &kdf)
	c.Assert(err, IsNil)
	c.Check(kdf.lastBenchmarkKeyLen, Equals, uint32(0))

	s.checkParams(c, &opts, 4, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceThreads(c *C) {
	restore := MockRuntimeNumCPU(8)
	defer restore()

	var kdf mockKDF

	var opts KDFOptions
	opts.ForceIterations = 3
	opts.Parallel = 1
	params, err := opts.DeriveCostParams(48, &kdf)
	c.Assert(err, IsNil)
	c.Check(kdf.lastBenchmarkKeyLen, Equals, uint32(0))

	s.checkParams(c, &opts, 1, params)
}