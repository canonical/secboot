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

package argon2_test

import (
	"math/rand"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/internal/argon2"
	"github.com/snapcore/secboot/internal/testutil"
)

func Test(t *testing.T) { TestingT(t) }

type argon2Suite struct{}

var _ = Suite(&argon2Suite{})

func (s *argon2Suite) newMockKeyDurationFunc(c *C, memBandwidthKiBPerMs uint32, expectedThreads uint8) KeyDurationFunc {
	return func(params *CostParams) (time.Duration, error) {
		c.Check(params.Threads, Equals, expectedThreads)

		duration := (time.Duration(float64(params.MemoryKiB)/float64(memBandwidthKiBPerMs)) * time.Duration(params.Time)) * time.Millisecond
		c.Logf("params: %#v, duration: %v", params, duration)
		return duration, nil
	}
}

type testBenchmarkData struct {
	numCPU               int
	totalRam             uint
	memUnit              uint32
	params               *BenchmarkParams
	memBandwidthKiBPerMs uint32
	expected             *CostParams
}

func (s *argon2Suite) testBenchmark(c *C, data *testBenchmarkData) {
	restoreNumCPU := MockRuntimeNumCPU(data.numCPU)
	defer restoreNumCPU()

	var si unix.Sysinfo_t
	// struct sysinfo uses unsigned long integers which are 32-bits
	// wide on 32-bit platforms (defined as uint32 in x/sys/unix) and
	// 64-bits wide on 64-bit platforms (defined as uint64). Go's
	// stricter type-safety checks compared to C makes it difficult to
	// write code that can compile on all architectures.
	// We use the unsafe package here to write it as a uint, which has
	// the same size as C's unsigned long.
	*(*uint)(unsafe.Pointer(&si.Totalram)) = data.totalRam
	si.Unit = uint32(data.memUnit)

	restoreSysinfo := MockUnixSysinfo(&si)
	defer restoreSysinfo()

	costParams, err := Benchmark(data.params, s.newMockKeyDurationFunc(c, data.memBandwidthKiBPerMs, data.expected.Threads))
	c.Assert(err, IsNil)
	c.Check(costParams, DeepEquals, data.expected)
}

func (s *argon2Suite) TestBenchmark1(c *C) {
	// Test where the initial target duration (250ms) is met with minimum cost parameters
	// and the supplied target duration is less than this.
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   100 * time.Millisecond},
		memBandwidthKiBPerMs: 512,
		expected:             &CostParams{Time: 4, MemoryKiB: 32768, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmark2(c *C) {
	// Test where the initial target duration (250ms) is met with minimum cost parameters
	// and the supplied target duration is met by increased memory cost.
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second},
		memBandwidthKiBPerMs: 512,
		expected:             &CostParams{Time: 4, MemoryKiB: 256000, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmark3(c *C) {
	// Test where the initial target duration (250ms) is met by increasing memory cost
	// and the supplied target duration is met be decreasing memory cost.
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   100 * time.Millisecond},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 4, MemoryKiB: 51203, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmark4(c *C) {
	// Test where the initial target duration (250ms) is met by increasing memory cost
	// and the supplied target duration is met be increasing memory cost.
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 4, MemoryKiB: 1024063, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmark5(c *C) {
	// Test where the initial target duration (250ms) is met by increasing memory
	// and time cost, and the supplied target duration is met by further increasing
	// time cost.
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 64 * 1024,
			TargetDuration:   2 * time.Second},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 62, MemoryKiB: 65536, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmark6(c *C) {
	// Test where the initial target duration (250ms) is met by increasing memory
	// and time cost, and the supplied target duration is met by decreasing the
	// time cost.
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 64 * 1024,
			TargetDuration:   200 * time.Millisecond},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 6, MemoryKiB: 65536, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmark7(c *C) {
	// Test where the initial target duration (250ms) is met by increasing memory
	// and time cost, and the supplied target duration is met by decreasing the
	// time and memory cost.
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 64 * 1024,
			TargetDuration:   100 * time.Millisecond},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 4, MemoryKiB: 51200, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmark8(c *C) {
	// Test where the initial target duration (250ms) is met by increasing memory
	// and time cost, and the supplied target duration is met with minimum cost
	// parameters.
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 64 * 1024,
			TargetDuration:   50 * time.Millisecond},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 4, MemoryKiB: 32768, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmarkLowMem1(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 1 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 7, MemoryKiB: 524288, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmarkLowMem2(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 1 * 1024 * 1024,
		memUnit:  1024,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 7, MemoryKiB: 524288, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmarkMoreCPUs(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   8,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 4, MemoryKiB: 1024063, Threads: 4},
	})
}

func (s *argon2Suite) TestBenchmarkSpecifyThreads(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second,
			Threads:          4},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 4, MemoryKiB: 1024063, Threads: 4},
	})
}

func (s *argon2Suite) TestBenchmarkSpecifyMoreThreads(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second,
			Threads:          8},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 4, MemoryKiB: 1024063, Threads: 4},
	})
}

func (s *argon2Suite) TestBenchmarkBiggerKey(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  1,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 4, MemoryKiB: 1024063, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmarkLotsOfMemory(c *C) {
	// Specify an amount of system memory that overflows uint32
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  4096,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second},
		memBandwidthKiBPerMs: 2048,
		expected:             &CostParams{Time: 4, MemoryKiB: 1024063, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmarkBuiltinMaxMemoryCost(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		numCPU:   2,
		totalRam: 4 * 1024 * 1024 * 1024,
		memUnit:  16,
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 8 * 1024 * 1024,
			TargetDuration:   2 * time.Second},
		memBandwidthKiBPerMs: 16384,
		expected:             &CostParams{Time: 7, MemoryKiB: 4194304, Threads: 2},
	})
}

func (s *argon2Suite) TestBenchmarkNoProgress(c *C) {
	params := &BenchmarkParams{
		MaxMemoryCostKiB: 1 * 1024 * 1024,
		TargetDuration:   100 * time.Millisecond}

	keyDuration := func(params *CostParams) (time.Duration, error) {
		c.Logf("params: %#v", params)
		return 30 * time.Millisecond, nil
	}

	_, err := Benchmark(params, keyDuration)
	c.Check(err, ErrorMatches, "not making sufficient progress")
}

type argon2SuiteExpensive struct{}

var _ = Suite(&argon2SuiteExpensive{})

func (s *argon2SuiteExpensive) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_ARGON2_TESTS"); exists {
		c.Skip("skipping expensive argon2 tests")
	}
}

type testKeyData struct {
	passphrase string
	saltLen    int
	params     *CostParams
	keyLen     uint32
}

func (s *argon2SuiteExpensive) testKey(c *C, data *testKeyData) {
	salt := make([]byte, data.saltLen)
	rand.Read(salt[:])

	maxThreads := uint8(runtime.NumCPU())
	if maxThreads > 4 {
		maxThreads = 4
	}

	if data.params.Threads > maxThreads {
		data.params.Threads = maxThreads
	}

	key := Key(data.passphrase, salt, data.params, data.keyLen)
	expectedKey := argon2.Key([]byte(data.passphrase), salt, data.params.Time, data.params.MemoryKiB, data.params.Threads, data.keyLen)
	c.Check(key, DeepEquals, expectedKey)
}

func (s *argon2SuiteExpensive) TestKey1(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "ubuntu",
		saltLen:    16,
		params: &CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestKey2(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "bar",
		saltLen:    16,
		params: &CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestKey3(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "ubuntu",
		saltLen:    16,
		params: &CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen: 16})
}

func (s *argon2SuiteExpensive) TestKey4(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "ubuntu",
		saltLen:    16,
		params: &CostParams{
			Time:      10,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestKey5(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "ubuntu",
		saltLen:    16,
		params: &CostParams{
			Time:      4,
			MemoryKiB: 64 * 1024,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestKey6(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "ubuntu",
		saltLen:    16,
		params: &CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   1},
		keyLen: 32})
}

func (s *argon2SuiteExpensive) TestKeyDuration(c *C) {
	time1 := KeyDuration(&CostParams{Time: 4, MemoryKiB: 32 * 1024, Threads: 4}, 32)
	runtime.GC()

	time2 := KeyDuration(&CostParams{Time: 16, MemoryKiB: 32 * 1024, Threads: 4}, 32)
	runtime.GC()
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)

	time2 = KeyDuration(&CostParams{Time: 4, MemoryKiB: 128 * 1024, Threads: 4}, 32)
	runtime.GC()
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)

	time2 = KeyDuration(&CostParams{Time: 4, MemoryKiB: 32 * 1024, Threads: 1}, 32)
	runtime.GC()
	// XXX: this needs a checker like go-tpm2/testutil's IntGreater, which copes with
	// types of int64 kind
	c.Check(time2 > time1, testutil.IsTrue)
}
