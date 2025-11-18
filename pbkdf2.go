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

package secboot

import (
	"crypto"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/snapcore/secboot/internal/pbkdf2"
	"golang.org/x/xerrors"
)

const (
	pbkdf2Type = "pbkdf2"
)

var (
	pbkdf2Benchmark = pbkdf2.Benchmark
)

type PBKDF2Options struct {
	TargetDuration time.Duration

	ForceIterations uint32

	HashAlg crypto.Hash
}

func (o *PBKDF2Options) kdfParams(defaultTargetDuration time.Duration, keyLen uint32) (*kdfParams, error) {
	if keyLen > math.MaxInt32 {
		return nil, errors.New("invalid key length")
	}

	defaultHashAlg := crypto.SHA256
	switch {
	case keyLen >= 48 && keyLen < 64:
		defaultHashAlg = crypto.SHA384
	case keyLen >= 64:
		defaultHashAlg = crypto.SHA512
	}

	switch {
	case o.ForceIterations > 0:
		// The non-benchmarked path. Ensure that ForceIterations
		// fits into an int32 so that it always fits into an int
		switch {
		case o.ForceIterations > math.MaxInt32:
			return nil, fmt.Errorf("invalid iterations count %d", o.ForceIterations)
		}

		params := &kdfParams{
			Type: pbkdf2Type,
			Time: int(o.ForceIterations), // no limit to the time cost.
			Hash: HashAlg(defaultHashAlg),
		}
		if o.HashAlg != crypto.Hash(0) {
			switch o.HashAlg {
			case crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
				params.Hash = HashAlg(o.HashAlg)
			default:
				return nil, errors.New("invalid hash algorithm")
			}
		}

		return params, nil
	default:
		targetDuration := defaultTargetDuration
		hashAlg := defaultHashAlg

		if o.TargetDuration != 0 {
			targetDuration = o.TargetDuration
		}
		if o.HashAlg != crypto.Hash(0) {
			hashAlg = o.HashAlg
		}

		iterations, err := pbkdf2Benchmark(targetDuration, hashAlg)
		if err != nil {
			return nil, xerrors.Errorf("cannot benchmark KDF: %w", err)
		}

		o = &PBKDF2Options{
			ForceIterations: uint32(iterations),
			HashAlg:         hashAlg}
		return o.kdfParams(defaultTargetDuration, keyLen)
	}
}
