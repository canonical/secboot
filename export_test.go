// go:build test
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
	"context"
	"crypto"
	"io"
	"math/big"
	"time"

	"golang.org/x/sys/unix"

	"github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luksview"
	"github.com/snapcore/secboot/internal/paths"
)

const (
	AuthRequestorKey                = authRequestorKey
	AuthRequestorUserVisibleNameKey = authRequestorUserVisibleNameKey
	ExternalKeyDataKey              = externalKeyDataKey
	KeyringDescPrefixKey            = keyringDescPrefixKey
	KeyringKeyPurposeAuxiliary      = keyringKeyPurposeAuxiliary
	LegacyKeyringKeyDescPathsKey    = legacyKeyringKeyDescPathsKey
	NilHash                         = nilHash
	RecoveryKeyTriesKey             = recoveryKeyTriesKey
	StderrLoggerKey                 = stderrLoggerKey
)

var (
	AcquireArgon2OutOfProcessHandlerSystemLock    = acquireArgon2OutOfProcessHandlerSystemLock
	AddKeyToUserKeyring                           = addKeyToUserKeyring
	AddKeyToUserKeyringLegacy                     = addKeyToUserKeyringLegacy
	ErrArgon2OutOfProcessHandlerSystemLockTimeout = errArgon2OutOfProcessHandlerSystemLockTimeout
	FormatKeyringKeyDesc                          = formatKeyringKeyDesc
	ParseKeyringKeyDesc                           = parseKeyringKeyDesc
	StorageContainerHandlers                      = storageContainerHandlers
	UnmarshalV1KeyPayload                         = unmarshalV1KeyPayload
	UnmarshalProtectedKeys                        = unmarshalProtectedKeys
)

type (
	ActivateConfigImpl = activateConfig
	ActivateConfigKey  = activateConfigKey
	KdfParams          = kdfParams
	ProtectedKeys      = protectedKeys
)

func KDFOptionsKdfParams(opts KDFOptions, defaultTargetDuration time.Duration, keyLen uint32) (*KdfParams, error) {
	return opts.kdfParams(defaultTargetDuration, keyLen)
}

func (c activateConfig) Len() int {
	return len(c)
}

// XXX: This will eventually be part of the ActivateContext API.
func (c *ActivateContext) State() *ActivateState {
	return c.state
}

func (c *ActivateContext) Config() ActivateConfigGetter {
	return c.cfg
}

func (c *ActivateContext) PrimaryKey() PrimaryKey {
	return c.primaryKey
}

func (s *ActivateState) Copy() *ActivateState {
	out := &ActivateState{
		PrimaryKeyID: s.PrimaryKeyID,
	}
	if s.Activations != nil {
		out.Activations = make(map[string]*ContainerActivateState)
	}
	for k, v := range s.Activations {
		vc := *v
		out.Activations[k] = &vc
	}
	return out
}

func (o *Argon2Options) KdfParams(defaultTargetDuration time.Duration, keyLen uint32) (*KdfParams, error) {
	return o.kdfParams(defaultTargetDuration, keyLen)
}

func (o *PBKDF2Options) KdfParams(defaultTargetDuration time.Duration, keyLen uint32) (*KdfParams, error) {
	return o.kdfParams(defaultTargetDuration, keyLen)
}

func MockAddKeyToUserKeyring(fn func([]byte, StorageContainer, KeyringKeyPurpose, string) (keyring.KeyID, error)) (restore func()) {
	orig := addKeyToUserKeyring
	addKeyToUserKeyring = fn
	return func() {
		addKeyToUserKeyring = orig
	}
}

func MockArgon2OutOfProcessHandlerSystemLockPath(path string) (restore func()) {
	orig := paths.Argon2OutOfProcessHandlerSystemLockPath
	paths.Argon2OutOfProcessHandlerSystemLockPath = path
	return func() {
		paths.Argon2OutOfProcessHandlerSystemLockPath = orig
	}
}

func MockAcquireArgon2OutOfProcessHandlerSystemLockAcquiredCheckpoint(fn func()) (restore func()) {
	orig := acquireArgon2OutOfProcessHandlerSystemLockAcquiredCheckpoint
	acquireArgon2OutOfProcessHandlerSystemLockAcquiredCheckpoint = fn
	return func() {
		acquireArgon2OutOfProcessHandlerSystemLockAcquiredCheckpoint = orig
	}
}

func MockArgon2SysLockStderr(w io.Writer) (restore func()) {
	orig := argon2SysLockStderr
	argon2SysLockStderr = w
	return func() {
		argon2SysLockStderr = orig
	}
}

func MockKeyringAddKey(fn func([]byte, keyring.KeyType, string, keyring.KeyID) (keyring.KeyID, error)) (restore func()) {
	orig := keyringAddKey
	keyringAddKey = fn
	return func() {
		keyringAddKey = orig
	}
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

func MockNewLUKSView(fn func(context.Context, string) (*luksview.View, error)) (restore func()) {
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

func MakePIN(length int, data []byte) PIN {
	val := new(big.Int).SetBytes(data)
	return PIN{
		length: uint8(length - 1),
		value:  *val,
	}
}
