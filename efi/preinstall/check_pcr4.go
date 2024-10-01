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
	"io"
	"strings"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	secboot_efi "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

var (
	efiComputePeImageDigest = efi.ComputePeImageDigest
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
		if y, err := fmt.Sscanf(data.UnicodeName, "Boot%x", &x); err != nil || y != 1 {
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

// isLaunchedFromLoadOption returns true if the supplied EV_EFI_BOOT_SERVICES_APPLICATION event
// is associated with the supplied load option. This will panic if the event is of the
// wrong type or the event data decodes incorrectly. This works by doing a device path match,
// which can either be a full match, or a recognized short-form match. This also handles the case
// where the boot option points to a removable device and the executable associated with the load
// event is loaded from that device.
func isLaunchedFromLoadOption(ev *tcglog.Event, opt *efi.LoadOption) (yes bool, err error) {
	if ev.EventType != tcglog.EventTypeEFIBootServicesApplication {
		// The caller should check this.
		panic("unexpected event type")
	}

	// Grab the device path from the event. For the launch of the initial boot loader, this
	// will always be a full path.
	eventDevicePath := ev.Data.(*tcglog.EFIImageLoadEvent).DevicePath
	if len(eventDevicePath) == 0 {
		return false, errors.New("EV_EFI_BOOT_SERVICES_APPLICATION event has empty device path")
	}

	// Try to match the load option.
	if opt.Attributes&efi.LoadOptionActive == 0 {
		// the load option isn't active.
		return false, errors.New("boot option is not active")
	}

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

type bootManagerCodeResultFlags int

const (
	bootManagerCodeSysprepAppsPresent bootManagerCodeResultFlags = 1 << iota
	bootManagerCodeAbsoluteComputraceRunning
	bootManagerCodeNotAllLaunchDigestsVerified
)

// checkBootManagerCodeMeasurements performs some checks on the boot manager code PCR (4).
//
// The supplied context is used to attach an EFI variable backend to, for functions that read
// from EFI variables. The supplied env and log arguments provide other inputs to this function.
// The pcrAlg argument is the PCR bank that is chosen as the best one to use. The loadImages
// argument provides a way to supply the load images associated with the current boot, in the
// order in which they are loaded. The caller must supply at least the IBL (initial boot loader,
// loaded by the firmware), and the SBL (secondary boot loader, loaded by the IBL), if there is an
// event in the log for it. These images are used to verify the digests of the
// EV_EFI_BOOT_SERVICES_APPLICATION events. Other images are optional, but if not all
// EV_EFI_BOOT_SERVICES_APPLICATION events can be verified, this will set the
// bootManagerCodeNotAllLaunchDigestsVerified flag.
//
// This function ensures that the pre-OS environment is well formed. Either it contains a single
// EV_OMIT_BOOT_DEVICE_EVENT event or an optional EV_EFI_ACTION "Calling EFI Application from Boot
// Option" event if the EV_OMIT_BOOT_DEVICE_EVENT event is not present. If the EV_EFI_ACTION event
// is present, then the next expected event is the EV_SEPARATOR to signal the transition to OS-present.
// The function considers any EV_EFI_BOOT_SERVICES_APPLICATION events before this to be system
// preparation applications, and it will set the bootManagerCodeSysprepAppsPresent flag if any are
// detected. If the BootOptionSupport EFI variable indicates that sysprep apps are not supported but
// they are present, then an error is returned.
//
// The function expects the next event after the EV_SEPARATOR to be a EV_EFI_BOOT_SERVICES_APPLICATION
// event, either the one associated with the IBL (initial boot loader), or a component of Absolute. If
// it is Absolute, then this sets the bootManagerCodeAbsoluteComputraceRunning flag, and it then expects
// the next event to be the one associated with the IBL (based on the value of the BootCurrent EFI variable,
// and the corresponding EFI_LOAD_OPTION in the TCG log). If the event data is inconsistent with the
// EFI_LOAD_OPTION for BootCurrent, it returns an error. It verifies that the digest of the event matches
// the Authenticode digest of the first supplied image, and returns an error if it isn't.
//
// Once the IBL image digest is verified, then the digests of all other EV_EFI_BOOT_SERVICES_APPLICATION
// events in the log are checked, if enough images associated with the current boot are supplied via the
// loadImages argument. It isn't possible to determine whether these events are generated by the firmware
// via a call to LoadImage, or whether they are generated by an OS component using the EFI_TCG2_PROTOCOL.
// In any case, if any OS component loads the next component itself and measures a digest directly without
// using the LoadImage API, it depends on the presence of the EFI_TCG2_PROTOCOL interface with support for
// the PE_COFF_IMAGE flag. There's no direct way to test for this, so for this reason, this function requires
// that the EV_EFI_BOOT_SERVICES_APPLICATION digest associated with the SBL (secondary boot-loader), if
// there is one, matches the Authenticode digest of the second image supplied via the loadImages argument,
// and this must be supplied. It's not necessary to supply additional load images, although if there are any
// more EV_EFI_BOOT_SERVICES_APPLICATION events without a corresponding boot image to test it against, the
// function sets the bootManagerCodeNotAllLaunchDigestsVerified flag.
func checkBootManagerCodeMeasurements(ctx context.Context, env internal_efi.HostEnvironment, log *tcglog.Log, pcrAlg tpm2.HashAlgorithmId, loadImages []secboot_efi.Image) (result bootManagerCodeResultFlags, err error) {
	if len(loadImages) == 0 {
		return 0, errors.New("at least the initial EFI application loaded during this boot must be supplied")
	}
	varCtx := env.VarContext(ctx)

	// Obtain the boot option support
	opts, err := efi.ReadBootOptionSupportVariable(varCtx)
	if err != nil {
		return 0, fmt.Errorf("cannot obtain boot option support: %w", err)
	}

	// Obtain the BootCurrent variable and use this to obtain the corresponding load entry
	// that was measured to the log. BootXXXX variables are measured to the TPM and so we don't
	// need to read back from an EFI variable that could have been modified between boot time
	// and now.
	current, err := efi.ReadBootCurrentVariable(varCtx)
	if err != nil {
		return 0, fmt.Errorf("cannot read BootCurrent variable: %w", err)
	}
	bootOpt, err := readLoadOptionFromLog(log, current)
	if err != nil {
		return 0, fmt.Errorf("cannot read current Boot%04x load option from log: %w", current, err)
	}

	var (
		sysprepSupported               = opts&efi.BootOptionSupportSysPrep > 0 // The firmware supports SysPrep applications
		omitBootDeviceEventsSeen       = false                                 // a EV_OMIT_BOOT_DEVICE_EVENTS event has been seen
		expectingTransitionToOSPresent = false                                 // The next events in PCR4 are expected to be the transition to OS-present
		seenOSComponentLaunches        = 0                                     // The number of EV_EFI_BOOT_SERVICES_APPLICATION events associated with OS component launches we've seen
	)

	phaseTracker := newTcgLogPhaseTracker()
NextEvent:
	for _, ev := range log.Events {
		phase, err := phaseTracker.processEvent(ev)
		if err != nil {
			return 0, err
		}

		switch phase {
		case tcglogPhasePreOSBeforeMeasureSecureBootConfig, tcglogPhasePreOSAfterMeasureSecureBootConfig, tcglogPhasePreOSAfterMeasureSecureBootConfigUnterminated:
			if ev.PCRIndex != internal_efi.BootManagerCodePCR {
				// Not PCR4
				continue NextEvent
			}

			// Make sure the event data is valid
			if err, isErr := ev.Data.(error); isErr {
				return 0, fmt.Errorf("invalid %v event data: %w", ev.EventType, err)
			}

			if expectingTransitionToOSPresent {
				// The next events in PCR4 should have taken us to OS-present
				return 0, fmt.Errorf("unexpected event type %v: expecting transition from pre-OS to OS-present event", ev.EventType)
			}

			switch ev.EventType {
			case tcglog.EventTypeOmitBootDeviceEvents:
				// The digest is the tagged hash of the event data, but we don't bother verifying
				// that because we just copy this event into the profile if it's present.
				if omitBootDeviceEventsSeen {
					return 0, errors.New("already seen a EV_OMIT_BOOT_DEVICE_EVENTS event")
				}
				omitBootDeviceEventsSeen = true
			case tcglog.EventTypeEFIAction:
				// ok, although 1.05 of the TCG PFP spec is a bit ambiguous here, section 8.2.4 says
				// the event associated with the first boot attempt, if it is measured, occurs before
				// the separator (as part of pre-OS). The actual PCR usage section 3.3.4.5 in this version
				// of the spec and older contradicts this and mentions a bunch of EV_ACTION events that
				// pertain to BIOS boot. On every device we've tested, this event occurs before the
				// separator and there are no BIOS boot related EV_ACTION events. 1.06 of the TCG PFP
				// spec tries to clean this up a bit, removing reference to the EV_ACTION events and
				// correcting the "Method for measurement" subsection of section 3.3.4.5 to match
				// section 8.2.4. We reject any EV_ACTION events in PCR4 here anyway.
				//
				// EV_EFI_ACTION event digests are the tagged hash of the event data, but we don't bother
				// verifying this because we just copy the events into the profile.
				if ev.Data == tcglog.EFICallingEFIApplicationEvent {
					// This is the signal from BDS that we're about to hand over to the OS.
					if phase == tcglogPhasePreOSBeforeMeasureSecureBootConfig {
						return 0, fmt.Errorf("unexpected %v event %q (before secure boot config was measured)", ev.EventType, ev.Data)
					}
					if omitBootDeviceEventsSeen {
						return 0, fmt.Errorf("unexpected %v event %q (because of earlier EV_OMIT_BOOT_DEVICE_EVENTS event)", ev.EventType, ev.Data)
					}

					// The next event we're expecting is the pre-OS to OS-present transition.
					//
					// TODO(chrisccoulson): The TCG PFP spec 1.06 r49 expects there to be a
					// EV_EFI_ACTION event immediately following this one with the string
					// "Booting to <Boot####> Option". Whilst the current profile generation code
					// will preserve what's currently in the log, there needs to be an API for boot
					// configuration code to specificy the actual boot option to ensure that we
					// predict the correct value. We currently fail support for PCR4 if this
					// unsupported EV_EFI_ACTION event is present next.
					expectingTransitionToOSPresent = true
				} else {
					// We're not expecting any other EV_EFI_ACTION event types, although see
					// the TODO above.
					return 0, fmt.Errorf("unexpected %s event %q", ev.EventType, ev.Data)
				}
			case tcglog.EventTypeEFIBootServicesApplication:
				// Assume all pre-OS application launches are SysPrep applications. There shouldn't
				// really be anything else here and there isn't really a reliable way to detect.
				// It might be possible to match the device path with the next variable in SysPrepOrder,
				// but these can be modified at runtime to not reflect what they were at boot time,
				// and SysPrep variables are not measured to the TCG log.
				//
				// As we don't do any prediction of sysprep applications (yet - never say never), we
				// don't verify that the measured Authenticode digest matches the binary at the end of the
				// device path, if it's reachable from the OS. Although this also suffers from a similar
				// variation of the issue described above - that path could have been updated between
				// booting and now.
				if phase == tcglogPhasePreOSBeforeMeasureSecureBootConfig {
					// Application launches before the secure boot configuration has been measured is a bug.
					return 0, fmt.Errorf("encountered pre-OS %v event for %v before secure boot configuration has been measured", ev.EventType, ev.Data.(*tcglog.EFIImageLoadEvent).DevicePath)
				}
				if !sysprepSupported {
					// The firmware indicated that sysprep applications aren't supported yet it still
					// loaded one!
					return 0, fmt.Errorf("encountered pre-OS %v event for %v when SysPrep applications are not supported", ev.EventType, ev.Data.(*tcglog.EFIImageLoadEvent).DevicePath)

				}
				result |= bootManagerCodeSysprepAppsPresent // Record that this boot contains system preparation applications.
			default:
				// We're not expecting any other event types during the pre-OS phase.
				return 0, fmt.Errorf("unexpected pre-OS event type %v", ev.EventType)
			}
		case tcglogPhaseOSPresent:
			if ev.PCRIndex != internal_efi.BootManagerCodePCR {
				// Not PCR4
				continue NextEvent
			}

			if ev.EventType != tcglog.EventTypeEFIBootServicesApplication {
				// Only care about EV_EFI_BOOT_SERVICES_APPLICATION events for checking
				if seenOSComponentLaunches == 0 {
					// The only events we're expecting in OS-present for now is EV_EFI_BOOT_SERVICES_APPLICATION.
					return 0, fmt.Errorf("unexpected OS-present log event type %v (expected EV_EFI_BOOT_SERVICES_APPLICATION)", ev.EventType)
				}
				// Once the IBL has launched, other event types are acceptable as long as the policy generation
				// code associated with the component in the secboot efi package emits them.
				continue NextEvent
			}

			data, eventDataOk := ev.Data.(*tcglog.EFIImageLoadEvent)

			switch seenOSComponentLaunches {
			case 0:
				if !eventDataOk {
					// Only require the event data to be ok for firmware generated events. This is because
					// OS components might create invalid data (and shim actually does), so we ignore those
					// errors.
					return 0, fmt.Errorf("invalid OS-present EV_EFI_BOOT_SERVICES_APPLICATION event data: %w", ev.Data.(error))
				}
				// Check if this launch is associated with the EFI_LOAD_OPTION associated with
				// the current boot.
				isBootOptLaunch, err := isLaunchedFromLoadOption(ev, bootOpt)
				if err != nil {
					return 0, fmt.Errorf("cannot determine if OS-present EV_EFI_BOOT_SERVICES_APPLICATION event for %v is associated with the current boot load option: %w", data.DevicePath, err)
				}
				if isBootOptLaunch {
					// We have the EV_EFI_BOOT_SERVICES_APPLICATION event associated with the IBL launch.
					seenOSComponentLaunches += 1
				} else {
					// We have an EV_EFI_BOOT_SERVICES_APPLICATION that didn't come from the load option
					// associated with the current boot.
					// Test to see if it's part of Absolute. If it is, that's fine - we copy this into
					// the profile, so we don't need to do any other verification of it and we don't have
					// anything to verify the Authenticode digest against anyway. We have a device path,
					// but not one that we're able to read back from.
					//
					// If this isn't Absolute, we bail with an error. We don't support anything else being
					// loaded here, and ideally Absolute will be turned off as well.
					if result&bootManagerCodeAbsoluteComputraceRunning > 0 {
						return 0, fmt.Errorf("OS-present EV_EFI_BOOT_SERVICES_APPLICATION event for %v is not associated with the current boot load option and is not Absolute", data.DevicePath)
					}

					isAbsolute, err := internal_efi.IsAbsoluteAgentLaunch(ev)
					if err != nil {
						return 0, fmt.Errorf("cannot determine if OS-present EV_EFI_BOOT_SERVICES_APPLICATION event for %v is associated with Absolute: %w", data.DevicePath, err)
					}
					if !isAbsolute {
						return 0, fmt.Errorf("OS-present EV_EFI_BOOT_SERVICES_APPLICATION event for %v is not associated with the current boot load option and is not Absolute", data.DevicePath)
					}
					result |= bootManagerCodeAbsoluteComputraceRunning
					continue NextEvent // We want to start a new iteration, else we'll consume one of the loadImages below.
				}
			default:
				seenOSComponentLaunches += 1
			}

			if len(loadImages) == 0 {
				result |= bootManagerCodeNotAllLaunchDigestsVerified
				if seenOSComponentLaunches < 3 {
					// This launch is associated with a SBL - we know this because we check that
					// len(loadImages) > 0 at the start of the function, so we will never reach
					// this condition for the IBL.
					return 0, errors.New("cannot verify digest for EV_EFI_BOOT_SERVICES_APPLICATION event associated with the secondary boot loader")
				}
				continue NextEvent
			}

			image := loadImages[0]
			loadImages = loadImages[1:]

			err := func() error {
				r, err := image.Open()
				if err != nil {
					return fmt.Errorf("cannot open image %s: %w", image, err)
				}
				defer r.Close()

				digest, err := efiComputePeImageDigest(pcrAlg.GetHash(), r, r.Size())
				if err != nil {
					return fmt.Errorf("cannot compute Authenticode digest of OS-present application %s: %w", image, err)
				}
				if bytes.Equal(digest, ev.Digests[pcrAlg]) {
					// The PE digest of the application matches what's in the log, so we're all good.
					return nil
				}

				// Digest in log does not match PE image digest. Compute flat-file digest and compare against that
				// for diagnostic purposes.
				r2 := io.NewSectionReader(r, 0, r.Size())
				h := pcrAlg.NewHash()
				if _, err := io.Copy(h, r2); err != nil {
					return fmt.Errorf("cannot compute flat file digest of OS-present application %s: %w", image, err)
				}
				if !bytes.Equal(h.Sum(nil), ev.Digests[pcrAlg]) {
					// Still no digest match
					return fmt.Errorf("log contains unexpected EV_EFI_BOOT_SERVICES_APPLICATION digest for OS-present application %s (calculated PE digest: %#x, log value: %#x) - were the correct boot images supplied?",
						image, digest, ev.Digests[pcrAlg])
				}
				// We have a digest match, so something loaded this component outside of the LoadImage API and used the
				// legacy EFI_TCG_PROTOCOL API to measure it, or used the proper EFI_TCG2_PROTOCOL API without the
				// PE_COFF_IMAGE flag. In any case, WithBootManagerCodeProfile() will mis-predict the loading of this.
				return fmt.Errorf("log contains unexpected EV_EFI_BOOT_SERVICES_APPLICATION digest for OS-present application %s: log digest matches flat file digest (%#x) which suggests an image loaded outside of the LoadImage API and firmware lacking support for the EFI_TCG2_PROTOCOL and/or the PE_COFF_IMAGE flag", image, h.Sum(nil))
			}()
			if err != nil {
				return 0, err
			}
		}
	}
	return result, nil
}
