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

	"github.com/snapcore/snapd/testutil"

	"golang.org/x/crypto/argon2"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/internal/argon2"
	_ "github.com/snapcore/secboot/internal/testutil"
)

func Test(t *testing.T) { TestingT(t) }

type argon2Suite struct{}

var _ = Suite(&argon2Suite{})

func (s *argon2Suite) SetUpSuite(c *C) {
	for _, e := range os.Environ() {
		if e == "NO_ARGON2_TESTS=1" {
			c.Skip("skipping expensive argon2 tests")
		}
	}
}

type testBenchmarkData struct {
	params *BenchmarkParams
	keyLen uint32
}

func keyDuration(params *CostParams, keyLen uint32) (time.Duration, error) {
	defer runtime.GC()
	return KeyDuration(params, keyLen), nil
}

func (s *argon2Suite) testBenchmark(c *C, data *testBenchmarkData) {
	costParams, err := Benchmark(data.params, data.keyLen, keyDuration)
	c.Assert(err, IsNil)

	maxMemoryCostKiB := data.params.MaxMemoryCostKiB
	if maxMemoryCostKiB < MinMemoryCostKiB {
		maxMemoryCostKiB = MinMemoryCostKiB
	}

	c.Check(int(costParams.Time), testutil.IntGreaterEqual, MinTimeCost)
	c.Check(int(costParams.MemoryKiB), testutil.IntLessEqual, int(maxMemoryCostKiB))
	expectedThreads := uint8(runtime.NumCPU())
	if expectedThreads > 4 {
		expectedThreads = 4
	}
	c.Check(costParams.Threads, Equals, expectedThreads)

	start := time.Now()
	Key("foo", []byte("0123456789abcdefghijklmnopqrstuv"), costParams, data.keyLen)
	elapsed := time.Now().Sub(start)
	// Check KDF time here with +/-20% tolerance
	c.Check(int(elapsed/time.Millisecond), testutil.IntGreaterThan, int(float64(data.params.TargetDuration/time.Millisecond)*0.8))
	c.Check(int(elapsed/time.Millisecond), testutil.IntLessThan, int(float64(data.params.TargetDuration/time.Millisecond)*1.2))
}

func (s *argon2Suite) TestBenchmark2s(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second},
		keyLen: 32})
}

func (s *argon2Suite) TestBenchmark100ms(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   100 * time.Millisecond},
		keyLen: 32})
}

func (s *argon2Suite) TestBenchmarkReducedMemory(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		params: &BenchmarkParams{TargetDuration: 2 * time.Second},
		keyLen: 32})
}

func (s *argon2Suite) TestBenchmarkShorterKey(c *C) {
	s.testBenchmark(c, &testBenchmarkData{
		params: &BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second},
		keyLen: 16})
}

type testKeyData struct {
	passphrase string
	saltLen    int
	params     *CostParams
	keyLen     uint32
}

func (s *argon2Suite) testKey(c *C, data *testKeyData) {
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

func (s *argon2Suite) TestKey1(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "ubuntu",
		saltLen:    16,
		params: &CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2Suite) TestKey2(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "bar",
		saltLen:    16,
		params: &CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2Suite) TestKey3(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "ubuntu",
		saltLen:    16,
		params: &CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen: 16})
}

func (s *argon2Suite) TestKey4(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "ubuntu",
		saltLen:    16,
		params: &CostParams{
			Time:      10,
			MemoryKiB: 32 * 1024,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2Suite) TestKey5(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "ubuntu",
		saltLen:    16,
		params: &CostParams{
			Time:      4,
			MemoryKiB: 64 * 1024,
			Threads:   4},
		keyLen: 32})
}

func (s *argon2Suite) TestKey6(c *C) {
	s.testKey(c, &testKeyData{
		passphrase: "ubuntu",
		saltLen:    16,
		params: &CostParams{
			Time:      4,
			MemoryKiB: 32 * 1024,
			Threads:   1},
		keyLen: 32})
}
