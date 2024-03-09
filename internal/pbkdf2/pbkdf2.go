// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package pbkdf2

import (
	"crypto"
	"errors"
	"math"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	benchmarkPassword = "foo"
)

var (
	benchmarkSalt = []byte("0123456789abcdefghijklmnopqrstuv")
)

var timeExecution = func(params *Params) time.Duration {
	start := time.Now()
	if _, err := Key(benchmarkPassword, benchmarkSalt, params, uint(params.HashAlg.Size())); err != nil {
		panic(err)
	}
	return time.Now().Sub(start)
}

// Benchmark computes the number of iterations for desired duration
// with the specified digest algorithm. The specified algorithm must
// be available. This benchmark is largely based on that implemented
// by cryptsetup.
//
// When producing keys that are larger than the output size of the
// digest algorithm, PBKDF2 runs the specified number of iterations
// multiple times - eg, to produce a 64-byte key with SHA-256, PBKDF2
// runs the specified number of iterations twice to produce the key in
// 2 rounds and this takes twice as long as it takes to produce a
// 32-byte key. This runs the benchmark for a single round by selecting a
// key length that is the same size as the output of the digest algorithm,
// which means that if SHA-256 is selected with a target duration of 1 second
// and the result is subsequently used to derive a 64-byte key, it will take 2
// seconds. This is safer than the alternative which is that all rounds are
// benchmarked (eg, using SHA-256 to produce a 64-byte key) for 1 second, and
// then it's subsequently possible to run a single round in order to produce
// 32-bytes of output key material in 500ms.
func Benchmark(targetDuration time.Duration, hashAlg crypto.Hash) (uint, error) {
	if !hashAlg.Available() {
		return 0, errors.New("unavailable digest algorithm")
	}

	// Start with 1000 iterations.
	iterationsOut := uint(1000)
	iterations := iterationsOut

	for i := 1; ; i++ {
		// time the key derivation
		duration := timeExecution(&Params{Iterations: iterations, HashAlg: hashAlg})
		if duration > 0 {
			// calculate the required number of iterations to return, based on the tested
			// iterations, measured duration and target duration.
			newIterationsOut := (int64(iterations) * int64(targetDuration)) / int64(duration)
			if newIterationsOut > math.MaxInt {
				return 0, errors.New("iteration count result overflow")
			}
			iterationsOut = uint(newIterationsOut)
		}

		// scale up the number of iterations to test next
		var scale uint
		switch {
		case i > 10:
			return 0, errors.New("insufficient progress")
		case duration > 500*time.Millisecond:
			return iterationsOut, nil
		case duration <= 62*time.Millisecond:
			scale = 16
		case duration <= 125*time.Millisecond:
			scale = 8
		case duration <= 250*time.Millisecond:
			scale = 4
		default:
			scale = 2
		}
		if math.MaxInt/scale < iterations {
			// It's only possible to hit this on 32-bit platforms. On
			// 64-bit platforms, we'll always hit the "insufficient progress"
			// branch first.
			return 0, errors.New("test iteration count overflow")
		}
		iterations *= scale
		if int64(iterations) > math.MaxInt64/int64(targetDuration) {
			return 0, errors.New("iteration count result will overflow")
		}
	}
}

// Params are the key derivation parameters for PBKDF2.
type Params struct {
	// Iterations are the number of iterations. This can't be
	// greater than math.MaxInt.
	Iterations uint

	// HashAlg is the digest algorithm to use. The algorithm
	// must be available
	HashAlg crypto.Hash
}

// Key derives a key of the desired length from the supplied passphrase and salt,
// using the supplied parameters.
//
// This will return an error if the key length or number of iterations are greater
// than the maximum value of a signed integer, or the supplied digest algorithm is
// not available.
func Key(passphrase string, salt []byte, params *Params, keyLen uint) ([]byte, error) {
	switch {
	case params == nil:
		return nil, errors.New("nil params")
	case params.Iterations > math.MaxInt:
		return nil, errors.New("too many iterations")
	case !params.HashAlg.Available():
		return nil, errors.New("unavailable digest algorithm")
	case keyLen > math.MaxInt:
		return nil, errors.New("invalid key length")
	}
	return pbkdf2.Key([]byte(passphrase), salt, int(params.Iterations), int(keyLen), params.HashAlg.New), nil
}
