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
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// readLoadOptionFromLog reads the corresponding Boot#### load option from the log,
// which reflects the value of it at boot time, as opposed to reading it from an
// EFI variable which may have been modified since booting.
func readLoadOptionFromLog(log *tcglog.Log, n uint16) (*efi.LoadOption, error) {
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex != internal_efi.PlatformConfigPCR {
			continue
		}

		if ev.EventType != tcglog.EventTypeEFIVariableBoot && ev.EventType != tcglog.EventTypeEFIVariableBoot2 {
			// not a boot variable
			continue
		}

		data, ok := ev.Data.(*tcglog.EFIVariableData)
		if !ok {
			// decode error data is guaranteed to implement the error interface
			return nil, fmt.Errorf("boot variable measurement has wrong data format: %w", ev.Data.(error))
		}
		if data.VariableName != efi.GlobalVariable {
			// not a global variable
			continue
		}
		if !strings.HasPrefix(data.UnicodeName, "Boot") || len(data.UnicodeName) != 8 {
			// name has unexpected prefix or length
			continue
		}

		var x uint16
		if c, err := fmt.Sscanf(data.UnicodeName, "Boot%x", &x); err != nil || c != 1 {
			continue
		}
		if x != n {
			// wrong load option
			continue
		}

		// We've found the correct load option. Decode it from the data stored in the log.
		opt, err := efi.ReadLoadOption(bytes.NewReader(data.VariableData))
		if err != nil {
			return nil, fmt.Errorf("cannot read load option from event data: %w", err)
		}
		return opt, nil
	}

	return nil, errors.New("cannot find specified boot option")
}

// readCurrentBootLoadOptionFromLog reads the load option associated with the current boot.
// It reads the BootCurrent global EFI variable and then looks up the corresponding BootXXXX
// entry that was measured to the TPM and present in the log, as BootXXXX variables are mutable
// and could have been modified between boot time and now.
func readCurrentBootLoadOptionFromLog(ctx context.Context, log *tcglog.Log) (*efi.LoadOption, error) {
	current, err := efi.ReadBootCurrentVariable(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot read BootCurrent variable: %w", err)
	}
	opt, err := readLoadOptionFromLog(log, current)
	if err != nil {
		return nil, fmt.Errorf("cannot read current Boot%04X load option from log: %w", current, err)
	}
	return opt, nil
}
