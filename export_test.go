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
	"crypto"
	"io"
	"time"

	"golang.org/x/sys/unix"

	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luksview"
)

const (
	NilHash = nilHash
)

var (
	UnmarshalV1KeyPayload  = unmarshalV1KeyPayload
	UnmarshalProtectedKeys = unmarshalProtectedKeys
)

type (
	KdfParams     = kdfParams
	ProtectedKeys = protectedKeys
)

func KDFOptionsKdfParams(o KDFOptions, keyLen uint32) (*KdfParams, error) {
	return o.kdfParams(keyLen)
}

func (o *Argon2Options) KdfParams(keyLen uint32) (*KdfParams, error) {
	return o.kdfParams(keyLen)
}

func (o *PBKDF2Options) KdfParams(keyLen uint32) (*KdfParams, error) {
	return o.kdfParams(keyLen)
}

func MockLUKS2Activate(fn func(string, string, []byte, int) error) (restore func()) {
	origActivate := luks2Activate
	luks2Activate = fn
	return func() {
		luks2Activate = origActivate
	}
}

func MockLUKS2AddKey(fn func(string, []byte, []byte, *luks2.AddKeyOptions) error) (restore func()) {
	origAddKey := luks2AddKey
	luks2AddKey = fn
	return func() {
		luks2AddKey = origAddKey
	}
}

func MockLUKS2Deactivate(fn func(string) error) (restore func()) {
	origDeactivate := luks2Deactivate
	luks2Deactivate = fn
	return func() {
		luks2Deactivate = origDeactivate
	}
}

func MockLUKS2Format(fn func(string, string, []byte, *luks2.FormatOptions) error) (restore func()) {
	origFormat := luks2Format
	luks2Format = fn
	return func() {
		luks2Format = origFormat
	}
}

func MockLUKS2ImportToken(fn func(string, luks2.Token, *luks2.ImportTokenOptions) error) (restore func()) {
	origImportToken := luks2ImportToken
	luks2ImportToken = fn
	return func() {
		luks2ImportToken = origImportToken
	}
}

func MockLUKS2KillSlot(fn func(string, int) error) (restore func()) {
	origKillSlot := luks2KillSlot
	luks2KillSlot = fn
	return func() {
		luks2KillSlot = origKillSlot
	}
}

func MockLUKS2RemoveToken(fn func(string, int) error) (restore func()) {
	origRemoveToken := luks2RemoveToken
	luks2RemoveToken = fn
	return func() {
		luks2RemoveToken = origRemoveToken
	}
}

func MockLUKS2SetSlotPriority(fn func(string, int, luks2.SlotPriority) error) (restore func()) {
	origSetSlotPriority := luks2SetSlotPriority
	luks2SetSlotPriority = fn
	return func() {
		luks2SetSlotPriority = origSetSlotPriority
	}
}

func MockNewLUKSView(fn func(string, luks2.LockMode) (*luksview.View, error)) (restore func()) {
	origNewLUKSView := newLUKSView
	newLUKSView = fn
	return func() {
		newLUKSView = origNewLUKSView
	}
}

func MockPBKDF2Benchmark(fn func(time.Duration, crypto.Hash) (uint, error)) (restore func()) {
	orig := pbkdf2Benchmark
	pbkdf2Benchmark = fn
	return func() {
		pbkdf2Benchmark = orig
	}
}

func MockRuntimeNumCPU(n int) (restore func()) {
	orig := runtimeNumCPU
	runtimeNumCPU = func() int {
		return n
	}
	return func() {
		runtimeNumCPU = orig
	}
}

func MockStderr(w io.Writer) (restore func()) {
	orig := osStderr
	osStderr = w
	return func() {
		osStderr = orig
	}
}

func MockKeyDataGeneration(n int) (restore func()) {
	orig := KeyDataGeneration
	KeyDataGeneration = n
	return func() {
		KeyDataGeneration = orig
	}
}

func MockHashAlgAvailable() (restore func()) {
	orig := hashAlgAvailable
	hashAlgAvailable = func(*HashAlg) bool {
		return false
	}
	return func() {
		hashAlgAvailable = orig
	}
}

func (d *KeyData) DerivePassphraseKeys(passphrase string) (key, iv, auth []byte, err error) {
	return d.derivePassphraseKeys(passphrase)
}

func MockUnixStat(f func(devicePath string, st *unix.Stat_t) error) (restore func()) {
	old := unixStat
	unixStat = f
	return func() {
		unixStat = old
	}
}
