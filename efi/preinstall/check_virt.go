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

package preinstall

import (
	"errors"
	"fmt"

	internal_efi "github.com/snapcore/secboot/internal/efi"
)

type detectVirtResult int

const (
	detectVirtNone detectVirtResult = iota
	detectVirtVM
)

// detectVirtualization detects if the supplied environment is virtualized,
// returning the type of virtualization - container or VM.
func detectVirtualization(env internal_efi.HostEnvironment) (detectVirtResult, error) {
	// First check for any virtualization
	virt, err := env.DetectVirtMode(internal_efi.DetectVirtModeAll)
	if err != nil {
		return 0, fmt.Errorf("cannot detect if environment if virtualized: %w", err)
	}
	if virt == internal_efi.VirtModeNone {
		// we're not in a containerized or virtualized environment
		return detectVirtNone, nil
	}

	// We're in a containerized or virtualized environment. Test for container
	// first.
	containerVirt, err := env.DetectVirtMode(internal_efi.DetectVirtModeContainer)
	if err != nil {
		return 0, fmt.Errorf("cannot detect if environment is a container: %w", err)
	}
	if containerVirt != internal_efi.VirtModeNone {
		// We're in a containerized environment, which is never supported
		return 0, errors.New("container environments are not supported")
	}

	// We're in a virtualized (VM) environment. We expect the following call to return
	// the same value as our original call here.
	vmVirt, err := env.DetectVirtMode(internal_efi.DetectVirtModeVM)
	if err != nil {
		return 0, fmt.Errorf("cannot detect if environment is a VM: %w", err)
	}
	if vmVirt != virt {
		return 0, fmt.Errorf("unexpected return value from HostEnvironment.DetectVirtMode(DetectVirtModeVM) (got:%q, expected:%q)", vmVirt, virt)
	}

	return detectVirtVM, nil
}
