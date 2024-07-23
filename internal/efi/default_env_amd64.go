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

package efi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/intel-go/cpuid"
)

var (
	cpuidHasFeature = cpuid.HasFeature
	devcpuPath      = "/dev/cpu"
)

type defaultEnvAMD64Impl struct{}

// CPUVendorIdentificator implements [HostEnvironmentAMD64.CPUVendorIdentificator].
func (defaultEnvAMD64Impl) CPUVendorIdentificator() string {
	return cpuid.VendorIdentificatorString
}

// HasCPUIDFeature implements [HostEnvironmentAMD64.HasCPUIDFeature].
func (defaultEnvAMD64Impl) HasCPUIDFeature(feature uint64) bool {
	return cpuidHasFeature(feature)
}

// ReadMSR implements [HostEnvironmentAMD64.ReadMSRs].
func (defaultEnvAMD64Impl) ReadMSRs(msr uint32) (map[uint32]uint64, error) {
	dir, err := os.Open(devcpuPath)
	switch {
	case os.IsNotExist(err):
		return nil, ErrNoKernelMSRSupport
	case err != nil:
		return nil, err
	}
	defer dir.Close()

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	out := make(map[uint32]uint64)

	for _, entry := range entries {
		cpuNo, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid CPU number for name %s: %w", entry.Name(), err)
		}

		val, err := func(name string) (uint64, error) {
			f, err := os.Open(filepath.Join(dir.Name(), name, "msr"))
			switch {
			case os.IsNotExist(err):
				return 0, ErrNoKernelMSRSupport
			case errors.Is(err, syscall.EIO):
				return 0, ErrNoMSRSupport
			case err != nil:
				return 0, err
			}
			defer f.Close()

			var data [8]byte
			_, err = f.ReadAt(data[:], int64(msr))
			switch {
			case errors.Is(err, syscall.EIO): // I think the kernel returns -EIO if the MSR is not supported, but this is poorly documented.
				return 0, ErrNoMSRSupport
			case err != nil:
				return 0, fmt.Errorf("cannot read from MSR device: %w", err)
			}

			return binary.LittleEndian.Uint64(data[:]), nil
		}(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("cannot read value for CPU %s: %w", entry.Name(), err)
		}

		out[uint32(cpuNo)] = val
	}

	return out, nil
}

// AMD64 implements [HostEnvironment.AMD64].
func (defaultEnvImpl) AMD64() (HostEnvironmentAMD64, error) {
	return defaultEnvAMD64Impl{}, nil
}
