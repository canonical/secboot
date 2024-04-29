// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2022 Canonical Ltd
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

package testutil

import (
	"crypto"
	_ "crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	kdf "github.com/canonical/go-sp800.108-kdf"

	"github.com/snapcore/secboot"
)

// MockArgon2KDF provides a mock implementation of secboot.Argon2KDF that isn't
// memory intensive.
type MockArgon2KDF struct {
	// BenchmarkMode is the mode that Time was last called with. Set this
	// to Argon2Default before running a mock benchmark.
	BenchmarkMode secboot.Argon2Mode
}

// Derive implements secboot.KDF.Derive and derives a key from the supplied
// passphrase and parameters. This is only intended for testing and is not
// meant to be secure in any way.
func (_ *MockArgon2KDF) Derive(passphrase string, salt []byte, mode secboot.Argon2Mode, params *secboot.Argon2CostParams, keyLen uint32) ([]byte, error) {
	context := make([]byte, len(salt)+10)
	copy(context, salt)
	switch mode {
	case secboot.Argon2i:
		context[len(salt)] = 0
	case secboot.Argon2id:
		context[len(salt)] = 1
	default:
		return nil, errors.New("invalid mode")
	}
	binary.LittleEndian.PutUint32(context[len(salt)+1:], params.Time)
	binary.LittleEndian.PutUint32(context[len(salt)+5:], params.MemoryKiB)
	context[len(salt)+9] = params.Threads

	return kdf.CounterModeKey(kdf.NewHMACPRF(crypto.SHA256), []byte(passphrase), nil, context, keyLen*8), nil
}

// Time implements secboot.KDF.Time and returns a time that is linearly
// related to the specified cost parameters, suitable for mocking benchmarking.
func (k *MockArgon2KDF) Time(mode secboot.Argon2Mode, params *secboot.Argon2CostParams) (time.Duration, error) {
	if k.BenchmarkMode != secboot.Argon2Default && k.BenchmarkMode != mode {
		return 0, errors.New("unexpected mode")
	}
	k.BenchmarkMode = mode

	const memBandwidthKiBPerMs = 2048
	duration := (time.Duration(float64(params.MemoryKiB)/float64(memBandwidthKiBPerMs)) * time.Duration(params.Time)) * time.Millisecond
	return duration, nil
}
