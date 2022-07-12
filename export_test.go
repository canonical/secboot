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
	"fmt"
	"strconv"
	"time"
)

func (o *InitializeLUKS2ContainerOptions) CryptsetupArguments() []string {
	if o == nil {
		o = &InitializeLUKS2ContainerOptions{}
	}
	kdfOptions := o.KDFOptions
	if kdfOptions == nil {
		kdfOptions = &KDFOptions{ForceIterations: 4, MemoryKiB: 32}
	}

	args := []string{"--pbkdf", "argon2i"}

	switch {
	case kdfOptions.ForceIterations != 0:
		args = append(args, "--pbkdf-force-iterations", strconv.Itoa(kdfOptions.ForceIterations))
	case kdfOptions.TargetDuration != 0:
		args = append(args, "--iter-time", strconv.FormatInt(int64(kdfOptions.TargetDuration/time.Millisecond), 10))
	}

	if kdfOptions.MemoryKiB != 0 {
		args = append(args, "--pbkdf-memory", strconv.Itoa(kdfOptions.MemoryKiB))
	}

	if kdfOptions.Parallel != 0 {
		args = append(args, "--pbkdf-parallel", strconv.Itoa(kdfOptions.Parallel))
	}

	if o.MetadataKiBSize != 0 {
		args = append(args, "--luks2-metadata-size", fmt.Sprintf("%dk", o.MetadataKiBSize))
	}
	if o.KeyslotsAreaKiBSize != 0 {
		args = append(args, "--luks2-keyslots-size", fmt.Sprintf("%dk", o.KeyslotsAreaKiBSize))
	}

	return args
}

func (o *KDFOptions) DeriveCostParams(keyLen int, kdf KDF) (*KDFCostParams, error) {
	return o.deriveCostParams(keyLen, kdf)
}

func MockLUKS2Activate(fn func(string, string, []byte) error) (restore func()) {
	origActivate := luks2Activate
	luks2Activate = fn
	return func() {
		luks2Activate = origActivate
	}
}

func MockLUKS2Deactivate(fn func(string) error) (restore func()) {
	origDeactivate := luks2Deactivate
	luks2Deactivate = fn
	return func() {
		luks2Deactivate = origDeactivate
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
