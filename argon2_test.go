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

func (s *argon2Suite) checkParams(c *C, opts *Argon2Options, ncpus uint8, params *Argon2CostParams) {
	if opts.ForceIterations != 0 {
		c.Check(params.Time, Equals, opts.ForceIterations)

		expectedMem := opts.MemoryKiB
		if expectedMem == 0 {
			expectedMem = 1 * 1024 * 1024
		}
		c.Check(params.MemoryKiB, Equals, expectedMem)

		expectedThreads := opts.Parallel
		if expectedThreads == 0 {
			expectedThreads = ncpus
		}
		c.Check(params.Threads, Equals, expectedThreads)
	} else {
		targetDuration := opts.TargetDuration
		if targetDuration == 0 {
			targetDuration = 2 * time.Second
		}
		var kdf testutil.MockArgon2KDF
		duration, _ := kdf.Time(params)
		c.Check(duration, Equals, targetDuration)

		maxMem := opts.MemoryKiB
		if maxMem == 0 {
			maxMem = 1 * 1024 * 1024
		}
		if maxMem > s.halfTotalRamKiB {
			maxMem = s.halfTotalRamKiB
		}
		c.Check(int(params.MemoryKiB), snapd_testutil.IntLessEqual, int(maxMem))

		expectedThreads := opts.Parallel
		if expectedThreads == 0 {
			expectedThreads = ncpus
		}
		if expectedThreads > 4 {
			expectedThreads = 4
		}
		c.Check(params.Threads, Equals, expectedThreads)
	}
}

var _ = Suite(&argon2Suite{})

func (s *argon2Suite) TestDeriveCostParamsDefault(c *C) {
	var opts Argon2Options
	params, err := opts.DeriveCostParams(0)
	c.Assert(err, IsNil)

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestDeriveCostParamsMemoryLimit(c *C) {
	var opts Argon2Options
	opts.MemoryKiB = 32 * 1024
	params, err := opts.DeriveCostParams(0)
	c.Assert(err, IsNil)

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceBenchmarkedThreads(c *C) {
	var opts Argon2Options
	opts.Parallel = 1
	params, err := opts.DeriveCostParams(0)
	c.Assert(err, IsNil)

	s.checkParams(c, &opts, s.cpus, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceIterations(c *C) {
	restore := MockRuntimeNumCPU(2)
	defer restore()

	var opts Argon2Options
	opts.ForceIterations = 3
	params, err := opts.DeriveCostParams(0)
	c.Assert(err, IsNil)

	s.checkParams(c, &opts, 2, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceMemory(c *C) {
	restore := MockRuntimeNumCPU(2)
	defer restore()

	var opts Argon2Options
	opts.ForceIterations = 3
	opts.MemoryKiB = 32 * 1024
	params, err := opts.DeriveCostParams(0)
	c.Assert(err, IsNil)

	s.checkParams(c, &opts, 2, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceIterationsDifferentCPUNum(c *C) {
	restore := MockRuntimeNumCPU(8)
	defer restore()

	var opts Argon2Options
	opts.ForceIterations = 3
	params, err := opts.DeriveCostParams(0)
	c.Assert(err, IsNil)

	s.checkParams(c, &opts, 4, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceThreads(c *C) {
	restore := MockRuntimeNumCPU(8)
	defer restore()

	var opts Argon2Options
	opts.ForceIterations = 3
	opts.Parallel = 1
	params, err := opts.DeriveCostParams(0)
	c.Assert(err, IsNil)

	s.checkParams(c, &opts, 1, params)
}

func (s *argon2Suite) TestDeriveCostParamsForceThreadsGreatherThanCPUNum(c *C) {
	restore := MockRuntimeNumCPU(2)
	defer restore()

	var opts Argon2Options
	opts.ForceIterations = 3
	opts.Parallel = 8
	params, err := opts.DeriveCostParams(0)
	c.Assert(err, IsNil)

	s.checkParams(c, &opts, 8, params)
}

type argon2SuiteExpensive struct{}

func (s *argon2SuiteExpensive) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_ARGON2_TESTS"); exists {
		c.Skip("skipping expensive argon2 tests")
	}
}

var _ = Suite(&argon2SuiteExpensive{})

type testArgon2iKDFDeriveData struct {
	passphrase string
	salt       []byte
	params     *Argon2CostParams
	keyLen     uint32
}

func (s *argon2SuiteExpensive) testArgon2iKDFDerive(c *C, data *testArgon2iKDFDeriveData) {
	key, err := InProcessArgon2KDF.Derive(data.passphrase, data.salt, data.params, data.keyLen)
	c.Check(err, IsNil)
	runtime.GC()

	expected := argon2.Key(data.passphrase, data.salt, &argon2.CostParams{
		Time:      data.params.Time,
		MemoryKiB: data.params.MemoryKiB,
		Threads:   data.params.Threads}, data.keyLen)
	runtime.GC()

	c.Check(key, DeepEquals, expected)
}

func (s *argon2SuiteExpensive) TestArgon2iKDFDerive(c *C) {
	s.testArgon2iKDFDerive(c, &testArgon2iKDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestArgon2iKDFDeriveDifferentPassphrase(c *C) {
	s.testArgon2iKDFDerive(c, &testArgon2iKDFDeriveData{
		passphrase: "bar",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestArgon2iKDFiDeriveDifferentSalt(c *C) {
	s.testArgon2iKDFDerive(c, &testArgon2iKDFDeriveData{
		passphrase: "foo",
		salt:       []byte("zyxwvutsrqponmlkjihgfedcba987654"),
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestArgon2iKDFDeriveDifferentParams(c *C) {
	s.testArgon2iKDFDerive(c, &testArgon2iKDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		params: &Argon2CostParams{
			Time:      48,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestArgon2iKDFDeriveDifferentKeyLen(c *C) {
	s.testArgon2iKDFDerive(c, &testArgon2iKDFDeriveData{
		passphrase: "foo",
		salt:       []byte("0123456789abcdefghijklmnopqrstuv"),
		params: &Argon2CostParams{
			Time:      4,
			MemoryKiB: 32,
			Threads:   4},
		keyLen: 64})
}

func (s *argon2SuiteExpensive) TestArgon2iKDFTime(c *C) {
	time1, err := InProcessArgon2KDF.Time(&Argon2CostParams{Time: 4, MemoryKiB: 32 * 1024, Threads: 4})
	runtime.GC()
	c.Check(err, IsNil)

	time2, err := InProcessArgon2KDF.Time(&Argon2CostParams{Time: 16, MemoryKiB: 32 * 1024, Threads: 4})
	runtime.GC()
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)

	time2, err = InProcessArgon2KDF.Time(&Argon2CostParams{Time: 4, MemoryKiB: 128 * 1024, Threads: 4})
	runtime.GC()
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)

	time2, err = InProcessArgon2KDF.Time(&Argon2CostParams{Time: 4, MemoryKiB: 32 * 1024, Threads: 1})
	runtime.GC()
	c.Check(err, IsNil)
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)
}
