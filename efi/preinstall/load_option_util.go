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

func readOrderedLoadOptionVariables(ctx context.Context, class efi.LoadOptionClass) (opts []*efi.LoadOption, order []uint16, err error) {
	switch class {
	case efi.LoadOptionClassDriver, efi.LoadOptionClassSysPrep, efi.LoadOptionClassBoot:
		// ok
	default:
		return nil, nil, fmt.Errorf("invalid class %q", class)
	}

	origOrder, err := efi.ReadLoadOrderVariable(ctx, class)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read load order variable: %w", err)
	}

	for _, n := range origOrder {
		switch opt, err := efi.ReadLoadOptionVariable(ctx, class, n); {
		case errors.Is(err, efi.ErrVarNotExist):
			// ok
		case err != nil:
			return nil, nil, fmt.Errorf("cannot read load option %d variable: %w", n, err)
		default:
			order = append(order, n)
			opts = append(opts, opt)
		}
	}

	return opts, order, nil
}

// isLaunchedFromLoadOption returns true if the supplied launch event is associated with the supplied
// load option. This works by doing a device path match, which can either be a full match, or a
// recognized short-form match. This also handles the case where the boot option points to a removable
// device and the executable associated with the load event is loaded from that device.
func isLaunchedFromLoadOption(ev *tcglog.Event, opt *efi.LoadOption) (yes bool, err error) {
	if opt.Attributes&efi.LoadOptionActive == 0 {
		// the load option isn't active.
		return false, nil
	}

	// The caller should check this.
	switch ev.EventType {
	case tcglog.EventTypeEFIBootServicesDriver, tcglog.EventTypeEFIRuntimeServicesDriver, tcglog.EventTypeEFIBootServicesApplication:
		// ok
	default:
		return false, fmt.Errorf("unexpected event type %v", ev.EventType)
	}

	data, ok := ev.Data.(*tcglog.EFIImageLoadEvent)
	if !ok {
		return false, fmt.Errorf("event has invalid event data: %w", ev.Data.(error))
	}

	// Grab the device path from the event. For the launch of the initial boot loader, this
	// will always be a full path.
	eventDevicePath := data.DevicePath
	if len(eventDevicePath) == 0 {
		return false, errors.New("event has empty device path")
	}

	// Now try to match the load option.

	// Test to see if the load option path matches the load event path in some way. Note
	// that the load option might be in short-form, but this function takes that into
	// account.
	if eventDevicePath.Matches(opt.FilePath) != efi.DevicePathNoMatch {
		// We have a match. This is very likely to be a launch of the
		// load option.
		return true, nil
	}

	// There's no match with the load option. This might happen when booting from
	// removable media where the load option specifies the device path pointing to
	// the bus that the removable media is connected to, but the load event contains
	// the full path to the initial boot loader, using some extra components.
	// Unless the load option is already using a short-form path, try appending the
	// extra components for the removable media from the load event to the load option
	// path and try testing for a match again.
	if opt.FilePath.ShortFormType().IsShortForm() {
		// The load option path is in short-form. We aren't going to find a match.
		return false, nil
	}

	// Copy the load option path
	optFilePath := append(efi.DevicePath{}, opt.FilePath...)
	if cdrom := efi.DevicePathFindFirstOccurrence[*efi.CDROMDevicePathNode](eventDevicePath); len(cdrom) > 0 {
		// Booting from CD-ROM.
		optFilePath = append(optFilePath, cdrom...)
	} else if hd := efi.DevicePathFindFirstOccurrence[*efi.HardDriveDevicePathNode](eventDevicePath); len(hd) > 0 {
		// Booting from any removable device with a GPT, such as a USB drive.
		optFilePath = append(optFilePath, hd...)
	}

	// With the CDROM() or HD() components of the event file path appended to the
	// load option path, test for a match again. In this case, we expect a full
	// match as neither paths are in short-form.
	return eventDevicePath.Matches(optFilePath) == efi.DevicePathFullMatch, nil
}

// matchLaunchToLoadOption matches the supplied launch event to one of the supplied load
// options. The order argument contains the load option number for each of the supplied
// load options. Matching is performed using a device path match on each of the supplied
// load options in turn. When a match is found, the load option and its corresponding load
// option number are returned. If no match is found, then nil is returned.
func matchLaunchToLoadOption(ev *tcglog.Event, order []uint16, opts ...*efi.LoadOption) (*efi.LoadOption, uint16, error) {
	if len(order) != len(opts) {
		return nil, 0, errors.New("order length should match the number of options")
	}

	for i, opt := range opts {
		match, err := isLaunchedFromLoadOption(ev, opt)
		if err != nil {
			// We only get errors for invalid event data. As we'll see the
			// same error for every option that is probed, just return now.
			return nil, 0, err
		}
		if match {
			return opt, order[i], nil
		}
	}

	return nil, 0, nil
}
