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
	"os"
	"runtime"
	"time"

	snapd_testutil "github.com/snapcore/snapd/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/argon2"
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

func (s *argon2Suite) TestInProcessKDFDeriveInvalidMode(c *C) {
	_, err := InProcessArgon2KDF.Derive("foo", nil, Argon2Default, &Argon2CostParams{Time: 4, MemoryKiB: 32, Threads: 1}, 32)
	c.Check(err, ErrorMatches, `invalid mode`)
}

func (s *argon2Suite) TestInProcessKDFDeriveInvalidParams(c *C) {
	_, err := InProcessArgon2KDF.Derive("foo", nil, Argon2id, nil, 32)
	c.Check(err, ErrorMatches, `nil params`)
}

func (s *argon2Suite) TestInProcessKDFDeriveInvalidTime(c *C) {
	_, err := InProcessArgon2KDF.Derive("foo", nil, Argon2id, &Argon2CostParams{Time: 0, MemoryKiB: 32, Threads: 1}, 32)
	c.Check(err, ErrorMatches, `invalid time cost`)
}

func (s *argon2Suite) TestInProcessKDFDeriveInvalidThreads(c *C) {
	_, err := InProcessArgon2KDF.Derive("foo", nil, Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32, Threads: 0}, 32)
	c.Check(err, ErrorMatches, `invalid number of threads`)
}

func (s *argon2Suite) TestInProcessKDFTimeInvalidMode(c *C) {
	_, err := InProcessArgon2KDF.Time(Argon2Default, &Argon2CostParams{Time: 4, MemoryKiB: 32, Threads: 1})
	c.Check(err, ErrorMatches, `invalid mode`)
}

func (s *argon2Suite) TestInProcessKDFTimeInvalidParams(c *C) {
	_, err := InProcessArgon2KDF.Time(Argon2id, nil)
	c.Check(err, ErrorMatches, `nil params`)
}

func (s *argon2Suite) TestInProcessKDFTimeInvalidTime(c *C) {
	_, err := InProcessArgon2KDF.Time(Argon2id, &Argon2CostParams{Time: 0, MemoryKiB: 32, Threads: 1})
	c.Check(err, ErrorMatches, `invalid time cost`)
}

func (s *argon2Suite) TestInProcessKDFTimeInvalidThreads(c *C) {
	_, err := InProcessArgon2KDF.Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32, Threads: 0})
	c.Check(err, ErrorMatches, `invalid number of threads`)
}

type argon2SuiteExpensive struct{}

func (s *argon2SuiteExpensive) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_ARGON2_TESTS"); exists {
		c.Skip("skipping expensive argon2 tests")
	}
}

var _ = Suite(&argon2SuiteExpensive{})

type testInProcessArgon2KDFDeriveData struct {
	passphrase string
	salt       []byte
	mode       Argon2Mode
	params     *Argon2CostParams
	keyLen     uint32
}

func (s *argon2SuiteExpensive) testInProcessKDFDerive(c *C, data *testInProcessArgon2KDFDeriveData) {
	key, err := InProcessArgon2KDF.Derive(data.passphrase, data.salt, data.mode, data.params, data.keyLen)
	c.Check(err, IsNil)
	runtime.GC()

	expected := argon2.Key(data.passphrase, data.salt, argon2.Mode(data.mode), &argon2.CostParams{
		Time:      data.params.Time,
		MemoryKiB: data.params.MemoryKiB,
		Threads:   data.params.Threads}, data.keyLen)
	runtime.GC()

	c.Check(key, DeepEquals, expected)
}

func (s *argon2SuiteExpensive) TestInProcessKDFDerive(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestInProcessKDFDeriveDifferentPassphrase(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "bar",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestInProcessKDFiDeriveDifferentSalt(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "foo",
		salt:       []byte("zyxwvutsrqponmlkjihgfedcba987654"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestInProcessKDFDeriveDifferentMode(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2i,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestInProcessKDFDeriveDifferentParams(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      48,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestInProcessKDFDeriveDifferentKeyLen(c *C) {
	s.testInProcessKDFDerive(c, &testInProcessArgon2KDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		mode:       Argon2id,
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen: 64})
}

func (s *argon2SuiteExpensive) TestInProcessKDFTime(c *C) {
	time1, err := InProcessArgon2KDF.Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32 * 1024, Threads: 4})
	runtime.GC()
	c.Check(err, IsNil)

	time2, err := InProcessArgon2KDF.Time(Argon2id, &Argon2CostParams{Time: 16, MemoryKiB: 32 * 1024, Threads: 4})
	runtime.GC()
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)

	time2, err = InProcessArgon2KDF.Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 128 * 1024, Threads: 4})
	runtime.GC()
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)

	time2, err = InProcessArgon2KDF.Time(Argon2id, &Argon2CostParams{Time: 4, MemoryKiB: 32 * 1024, Threads: 1})
	runtime.GC()
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)
}
