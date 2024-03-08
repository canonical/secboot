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

package secboot

import (
	"errors"
	"math"
	"runtime"
	"time"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot/internal/argon2"
)

var (
	runtimeNumCPU = runtime.NumCPU
)

// KDFOptions specifies parameters for the Argon2 KDF used by cryptsetup
// and for passphrase support.
type KDFOptions struct {
	// MemoryKiB specifies the maximum memory cost in KiB when ForceIterations
	// is zero. If ForceIterations is not zero, then this is used as the
	// memory cost.
	MemoryKiB int

	// TargetDuration specifies the target duration for the KDF which
	// is used to benchmark the time and memory cost parameters. If it
	// is zero then the default is used. If ForceIterations is not zero
	// then this field is ignored.
	TargetDuration time.Duration

	// ForceIterations can be used to turn off KDF benchmarking by
	// setting the time cost directly. If this is zero then the cost
	// parameters are benchmarked based on the value of TargetDuration.
	ForceIterations int

	// Parallel sets the maximum number of parallel threads for the
	// KDF (up to 4). This will be adjusted downwards based on the
	// actual number of CPUs.
	Parallel int
}

func (o *KDFOptions) deriveCostParams(keyLen int, kdf KDF) (*KDFCostParams, error) {
	switch {
	case int64(o.ForceIterations) > math.MaxUint32:
		return nil, errors.New("ForceIterations too large")
	case int64(o.MemoryKiB) > math.MaxUint32:
		return nil, errors.New("MemoryKiB too large")
	case o.Parallel > math.MaxUint8:
		return nil, errors.New("Parallel too large")
	case o.ForceIterations < 0:
		return nil, errors.New("ForceIterations can't be negative")
	case int64(keyLen) > math.MaxUint32:
		return nil, errors.New("keyLen too large")
	case o.ForceIterations > 0:
		threads := runtimeNumCPU()
		if threads > 4 {
			threads = 4
		}
		params := &KDFCostParams{
			Time:      uint32(o.ForceIterations),
			MemoryKiB: 1 * 1024 * 1024,
			Threads:   uint8(threads)}

		if o.MemoryKiB != 0 {
			params.MemoryKiB = uint32(o.MemoryKiB)
		}
		if o.Parallel != 0 {
			params.Threads = uint8(o.Parallel)
			if o.Parallel > 4 {
				params.Threads = 4
			}
		}

		return params, nil
	default:
		benchmarkParams := &argon2.BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024,
			TargetDuration:   2 * time.Second}

		if o.MemoryKiB != 0 {
			benchmarkParams.MaxMemoryCostKiB = uint32(o.MemoryKiB)
		}
		if o.TargetDuration != 0 {
			benchmarkParams.TargetDuration = o.TargetDuration
		}
		if o.Parallel != 0 {
			benchmarkParams.Threads = uint8(o.Parallel)
			if o.Parallel > 4 {
				benchmarkParams.Threads = 4
			}
		}

		params, err := argon2.Benchmark(benchmarkParams, func(params *argon2.CostParams) (time.Duration, error) {
			return kdf.Time(&KDFCostParams{
				Time:      params.Time,
				MemoryKiB: params.MemoryKiB,
				Threads:   params.Threads}, uint32(keyLen))
		})
		if err != nil {
			return nil, xerrors.Errorf("cannot benchmark KDF: %w", err)
		}

		return &KDFCostParams{
			Time:      params.Time,
			MemoryKiB: params.MemoryKiB,
			Threads:   params.Threads}, nil
	}
}

// KDFCostParams defines the cost parameters for key derivation using Argon2.
type KDFCostParams struct {
	// Time corresponds to the number of iterations of the algorithm
	// that the key derivation will use.
	Time uint32

	// MemoryKiB is the amount of memory in KiB that the key derivation
	// will use.
	MemoryKiB uint32

	// Threads is the number of parallel threads that will be used
	// for the key derivation.
	Threads uint8
}

func (p *KDFCostParams) internalParams() *argon2.CostParams {
	return &argon2.CostParams{
		Time:      p.Time,
		MemoryKiB: p.MemoryKiB,
		Threads:   p.Threads}
}

// KDF is an interface to abstract use of the Argon2 KDF to make it possible
// to delegate execution to a short-lived utility process where required.
type KDF interface {
	// Derive derives a key of the specified length in bytes, from the supplied
	// passphrase and salt and using the supplied cost parameters.
	Derive(passphrase string, salt []byte, params *KDFCostParams, keyLen uint32) ([]byte, error)

	// Time measures the amount of time the KDF takes to execute with the
	// specified cost parameters and key length in bytes.
	Time(params *KDFCostParams, keyLen uint32) (time.Duration, error)
}

type argon2iKDFImpl struct{}

func (_ argon2iKDFImpl) Derive(passphrase string, salt []byte, params *KDFCostParams, keyLen uint32) ([]byte, error) {
	return argon2.Key(passphrase, salt, params.internalParams(), keyLen), nil
}

func (_ argon2iKDFImpl) Time(params *KDFCostParams, keyLen uint32) (time.Duration, error) {
	return argon2.KeyDuration(params.internalParams(), keyLen), nil
}

var argon2iKDF = argon2iKDFImpl{}

// Argon2iKDF returns the in-process Argon2i implementation of KDF. This
// shouldn't be used in long-lived system processes - these processes should
// instead provide their own KDF implementation which delegates to a short-lived
// utility process which will use the in-process implementation.
func Argon2iKDF() KDF {
	return argon2iKDF
}
