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
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot/internal/argon2"
)

var (
	argon2Mu   sync.Mutex
	argon2Impl Argon2KDF = nullArgon2KDFImpl{}

	runtimeNumCPU = runtime.NumCPU
)

// SetArgon2KDF sets the KDF implementation for Argon2. The default here is
// the null implementation which returns an error, so this will need to be
// configured explicitly in order to use Argon2.
//
// Passing nil will configure the null implementation as well.
//
// This returns the currently set implementation.
func SetArgon2KDF(kdf Argon2KDF) Argon2KDF {
	argon2Mu.Lock()
	defer argon2Mu.Unlock()

	orig := argon2Impl
	if kdf == nil {
		argon2Impl = nullArgon2KDFImpl{}
	} else {
		argon2Impl = kdf
	}
	return orig
}

func argon2KDF() Argon2KDF {
	argon2Mu.Lock()
	defer argon2Mu.Unlock()
	return argon2Impl
}

// Argon2Mode describes the Argon2 mode to use.
type Argon2Mode = argon2.Mode

const (
	// Argon2Default is used by Argon2Options to select the default
	// Argon2 mode, which is currently Argon2id.
	Argon2Default Argon2Mode = ""

	// Argon2i is the data-independent mode of Argon2.
	Argon2i = argon2.ModeI

	// Argon2id is the hybrid mode of Argon2.
	Argon2id = argon2.ModeID
)

// Argon2Options specifies parameters for the Argon2 KDF used for passphrase support.
type Argon2Options struct {
	// Mode specifies the KDF mode to use.
	Mode Argon2Mode

	// MemoryKiB specifies the maximum memory cost in KiB when ForceIterations
	// is zero. In this case, it will be capped at 4GiB or half of the available
	// memory, whichever is less. If ForceIterations is not zero, then this is
	// used as the memory cost and is not limited.
	MemoryKiB uint32

	// TargetDuration specifies the target duration for the KDF which
	// is used to benchmark the time and memory cost parameters. If it
	// is zero then the default is used. If ForceIterations is not zero
	// then this field is ignored.
	TargetDuration time.Duration

	// ForceIterations can be used to turn off KDF benchmarking by
	// setting the time cost directly. If this is zero then the cost
	// parameters are benchmarked based on the value of TargetDuration.
	ForceIterations uint32

	// Parallel sets the maximum number of parallel threads for the KDF. If
	// it is zero, then it is set to the number of CPUs or 4, whichever is
	// less. This will always be automatically limited to 4 when ForceIterations
	// is zero.
	Parallel uint8
}

func (o *Argon2Options) kdfParams(defaultTargetDuration time.Duration, keyLen uint32) (*kdfParams, error) {
	switch o.Mode {
	case Argon2Default, Argon2i, Argon2id:
		// ok
	default:
		return nil, errors.New("invalid argon2 mode")
	}

	mode := o.Mode
	if mode == Argon2Default {
		mode = Argon2id
	}

	switch {
	case o.ForceIterations > 0:
		// The non-benchmarked path. Ensure that ForceIterations
		// and MemoryKiB fit into an int32 so that it always fits
		// into an int
		switch {
		case o.ForceIterations > math.MaxInt32:
			return nil, fmt.Errorf("invalid iterations count %d", o.ForceIterations)
		case o.MemoryKiB > math.MaxInt32:
			return nil, fmt.Errorf("invalid memory cost %dKiB", o.MemoryKiB)
		}

		defaultThreads := runtimeNumCPU()
		if defaultThreads > 4 {
			// limit the default threads to 4
			defaultThreads = 4
		}

		params := &kdfParams{
			Type:   string(mode),
			Time:   int(o.ForceIterations), // no limit to the time cost.
			Memory: 1 * 1024 * 1024,        // the default memory cost is 1GiB.
			CPUs:   defaultThreads,         // the default number of threads is min(4,nr_of_cpus).
		}
		if o.MemoryKiB != 0 {
			// no limit to the memory cost.
			params.Memory = int(o.MemoryKiB)
		}
		if o.Parallel != 0 {
			// no limit to the threads if set explicitly.
			params.CPUs = int(o.Parallel)
		}

		return params, nil
	default:
		benchmarkParams := &argon2.BenchmarkParams{
			MaxMemoryCostKiB: 1 * 1024 * 1024, // the default maximum memory cost is 1GiB.
			TargetDuration:   defaultTargetDuration,
		}

		if o.MemoryKiB != 0 {
			benchmarkParams.MaxMemoryCostKiB = o.MemoryKiB // this is capped to 4GiB by internal/argon2.
		}
		if o.TargetDuration != 0 {
			benchmarkParams.TargetDuration = o.TargetDuration
		}
		if o.Parallel != 0 {
			benchmarkParams.Threads = o.Parallel // this is capped to 4 by internal/argon2.
		}

		params, err := argon2.Benchmark(benchmarkParams, func(params *argon2.CostParams) (time.Duration, error) {
			return argon2KDF().Time(mode, &Argon2CostParams{
				Time:      params.Time,
				MemoryKiB: params.MemoryKiB,
				Threads:   params.Threads})
		})
		if err != nil {
			return nil, xerrors.Errorf("cannot benchmark KDF: %w", err)
		}

		o = &Argon2Options{
			Mode:            mode,
			MemoryKiB:       params.MemoryKiB,
			ForceIterations: params.Time,
			Parallel:        params.Threads}
		return o.kdfParams(defaultTargetDuration, keyLen)
	}
}

// Argon2CostParams defines the cost parameters for key derivation using Argon2.
type Argon2CostParams struct {
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

func (p *Argon2CostParams) internalParams() *argon2.CostParams {
	if p == nil {
		return nil
	}
	return &argon2.CostParams{
		Time:      p.Time,
		MemoryKiB: p.MemoryKiB,
		Threads:   p.Threads}
}

// Argon2KDF is an interface to abstract use of the Argon2 KDF to make it possible
// to delegate execution to a short-lived utility process where required.
type Argon2KDF interface {
	// Derive derives a key of the specified length in bytes, from the supplied
	// passphrase and salt and using the supplied mode and cost parameters.
	Derive(passphrase string, salt []byte, mode Argon2Mode, params *Argon2CostParams, keyLen uint32) ([]byte, error)

	// Time measures the amount of time the KDF takes to execute with the
	// specified cost parameters and mode.
	Time(mode Argon2Mode, params *Argon2CostParams) (time.Duration, error)
}

type inProcessArgon2KDFImpl struct{}

func (_ inProcessArgon2KDFImpl) Derive(passphrase string, salt []byte, mode Argon2Mode, params *Argon2CostParams, keyLen uint32) ([]byte, error) {
	if mode != Argon2i && mode != Argon2id {
		return nil, errors.New("invalid mode")
	}

	return argon2.Key(passphrase, salt, argon2.Mode(mode), params.internalParams(), keyLen)
}

func (_ inProcessArgon2KDFImpl) Time(mode Argon2Mode, params *Argon2CostParams) (time.Duration, error) {
	if mode != Argon2i && mode != Argon2id {
		return 0, errors.New("invalid mode")
	}

	return argon2.KeyDuration(argon2.Mode(mode), params.internalParams())
}

// InProcessArgon2KDF is the in-process implementation of the Argon2 KDF. This
// shouldn't be used in long-lived system processes - these processes should
// instead provide their own KDF implementation which delegates to a short-lived
// utility process which will use the in-process implementation.
var InProcessArgon2KDF = inProcessArgon2KDFImpl{}

type nullArgon2KDFImpl struct{}

func (_ nullArgon2KDFImpl) Derive(passphrase string, salt []byte, mode Argon2Mode, params *Argon2CostParams, keyLen uint32) ([]byte, error) {
	return nil, errors.New("no argon2 KDF: please call secboot.SetArgon2KDF")
}

func (_ nullArgon2KDFImpl) Time(mode Argon2Mode, params *Argon2CostParams) (time.Duration, error) {
	return 0, errors.New("no argon2 KDF: please call secboot.SetArgon2KDF")
}
