// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"golang.org/x/xerrors"
)

const (
	sbStateName              = "SecureBoot"                  // Unicode variable name for the EFI secure boot configuration (enabled/disabled)
	dmaProtectionDisabled    = "DMA Protection Disabled"     // ASCII string measured to PCR7 if DMA remapping is disabled in the pre-OS environment
	dmaProtectionDisabledNul = "DMA Protection Disabled\x00" // TCG PC Client Profile spec says no NUL-terminator, but some firmware is buggy
)

// fwLoadHandler is an implementation of imageLoadHandler that measures firmware
// events (pre-OS events and events related to loading of OS components).
type fwLoadHandler struct {
	log *tcglog.Log
}

var newFwLoadHandler = func(log *tcglog.Log) imageLoadHandler {
	return &fwLoadHandler{log: log}
}

func (h *fwLoadHandler) measureSeparator(ctx pcrBranchContext, pcr tpm2.Handle, event *tcglog.Event) error {
	if event.EventType != tcglog.EventTypeSeparator {
		return fmt.Errorf("unexpected event type %v", event.EventType)
	}

	data, ok := event.Data.(*tcglog.SeparatorEventData)
	if !ok {
		// if the event data failed to decode, the resulting implementation is guaranteed to implement error.
		return fmt.Errorf("cannot measure invalid separator event: %w", event.Data.(error))
	}
	if data.IsError() {
		return fmt.Errorf("separator indicates that a firmware error occurred (error code from log: %d)", binary.LittleEndian.Uint32(data.Bytes()))
	}
	ctx.ExtendPCR(pcr, event.Digests[ctx.PCRAlg()])
	return nil
}

func (h *fwLoadHandler) readAndMeasureSignatureDb(ctx pcrBranchContext, name efi.VariableDescriptor) ([]byte, error) {
	db, _, err := ctx.Vars().ReadVar(name.Name, name.GUID)
	if err != nil && err != efi.ErrVarNotExist {
		return nil, xerrors.Errorf("cannot read current variable: %w", err)
	}

	ctx.MeasureVariable(internal_efi.SecureBootPolicyPCR, name.GUID, name.Name, db)
	return db, nil
}

func (h *fwLoadHandler) measureAuthorizedSignatureDb(ctx pcrBranchContext) error {
	data, err := h.readAndMeasureSignatureDb(ctx, Db)
	if err != nil {
		return err
	}

	db, err := efi.ReadSignatureDatabase(bytes.NewReader(data))
	if err != nil {
		return xerrors.Errorf("cannot decode signatures: %w", err)
	}
	ctx.FwContext().Db = &secureBootDB{Name: Db, Contents: db}
	return nil
}

func (h *fwLoadHandler) measureSecureBootPolicyPreOS(ctx pcrBranchContext) error {
	// This hard-codes a profile that will only work on devices with secure boot enabled,
	// deployed mode on (where UEFI >= 2.5), without a UEFI debugger enabled and which
	// measure events in the correct order.
	//
	// It doesn't support firmware that implements timestamp revocation (there will be a
	// dbt variable that needs to be measured), OS recovery (which implies a dbr variable,
	// to be measured, but we'll likely never encounter this) or where secure boot is
	// enabled but the platform is in user mode rather than deployed mode. User mode and
	// dbt will be supported in the future.
	//
	// We do permit the presence of an EV_EFI_ACTION event that indicates that pre-boot DMA
	// protection was disabled if the appropriate options are supplied. However, this event
	// is poorly documented so we don't really know where in the measurement order it's
	// meant to be. The only place this is documented is in the tianocore documentation,
	// but there's not a reference implementation in the EDK2 source code and we've seen 2
	// different devices with different measurement orders, so we'll have to acommodate all
	// possible measurement ordering. Ideally we wouldn't be supporting poorly documented
	// events such as this, because, in addition to weakening security, it also makes this
	// code more complicated.
	//
	// The TCG PC Client PFP spec is vague wrt where EV_EFI_VARIABLE_AUTHORITY events
	// associated with verification of third party code in the pre-OS environment should be
	// measured. EDK2 measures a EV_SEPARATOR event to PCR7 as soon as it has measured all
	// of the secure boot configuration. In this case, EV_EFI_VARIABLE_AUTHORITY events
	// associated with third party code in the pre-OS environment are measured *after* this
	// separator, with the EV_SEPARATOR events in PCRs 0-6 later on indicating the transition
	// to OS present. The comments in EDK2 imply that the EV_SEPARATOR in PCR7 is the boundary
	// between configuration and image verification. Some other firmware implementations do not
	// measure the EV_SEPARATOR event to PCR7 as soon as the secure boot configuration has been
	// measured, opting to do this during the transition to OS present. In this case,
	// EV_EFI_VARIABLE_AUTHORITY events associated with third party pre-OS code are measured
	// *before* the separator, with EV_SEPARATOR events measured to PCRs 0-7 indicating the
	// transition to OS present. This code handles both cases for now until this is documented
	// properly, in which case we would want to gradually transition to considering other
	// measurement orders a bug.

	events := h.log.Events

	// allowInsfficientDMAProtection indicates that we should permit generating profiles
	// that are compatible with PCR7 even if pre-boot DMA protection is disabled.
	allowInsufficientDMAProtection := boolParamOrFalse(ctx.Params(), allowInsufficientDMAProtectionParamKey)

	// includeInsufficientDMAProtection indicates that where allowInsufficientDMAProtection
	// is set to true, this branch should be a branch that includes the corresponding
	// EV_EFI_ACTION event in the profile if it is present.
	includeInsufficientDMAProtection := boolParamOrFalse(ctx.Params(), includeInsufficientDMAProtectionParamKey)

	// Wind the log forward to the first EV_EFI_VARIABLE_DRIVER_CONFIG event, including
	// any EV_EFI_ACTION "DMA Protection Disabled" measurement before this in the target
	// profile, if this measurement is encountered and the supplied options permit it.
	// Return an error if other unexpected events are encountered, as the profile will be
	// wrong in this case anyway. This will implicitly catch the EV_EFI_ACTION "UEFI
	// Debug Mode" measurement and return an error if the platform firmware has a debugger
	// enabled. A firmware debugger permits an adversary with local access to control
	// firmware execution, bypassing any protections offered by measuredboot or verified
	// boot, and the presence of one should prevent FDE from being enabled.
	for len(events) > 0 {
		e := events[0]
		events = events[1:]

		if e.PCRIndex == internal_efi.SecureBootPolicyPCR && e.EventType == tcglog.EventTypeEFIVariableDriverConfig {
			// This is the first secure boot configuration measurement. In most
			// circumstances, this will be the first measurement to PCR7. Only
			// in the case where the first event is a EV_EFI_ACTION "DMA Protection
			// Disabled" event will this not be true.
			break
		}

		switch {
		case e.PCRIndex == internal_efi.SecureBootPolicyPCR && e.EventType == tcglog.EventTypeEFIAction &&
			(bytes.Equal(e.Data.Bytes(), []byte(dmaProtectionDisabled)) || bytes.Equal(e.Data.Bytes(), []byte(dmaProtectionDisabledNul))) &&
			allowInsufficientDMAProtection:
			// This is a EV_EFI_ACTION "DMA Protection Disabled" measurement and is
			// allowed to appear in PCR7. In this case, it is before the secure
			// boot configuration measurements.
			// Now we use the includeInsufficientDMAProtection flag to determine if
			// this run of fwLoadHandler should really measure it to this profile
			// branch as well. Including a branch in the profile that skips this
			// measurement makes it possible for the firmware setting to be corrected
			// without invalidating the profile, which would require a recovery key.
			// Future runs can then drop the option to permit it.
			if includeInsufficientDMAProtection {
				ctx.ExtendPCR(internal_efi.SecureBootPolicyPCR, e.Digests[ctx.PCRAlg()])
			}
			allowInsufficientDMAProtection = false // Only allow this event to appear once
		case e.PCRIndex == internal_efi.SecureBootPolicyPCR && e.EventType != tcglog.EventTypeEFIVariableDriverConfig:
			return fmt.Errorf("unexpected event type (%v) found in log, before config", e.EventType)
		default:
			// we don't care about this event.
		}
	}

	// Measure a secure boot configuration.
	ctx.MeasureVariable(internal_efi.SecureBootPolicyPCR, efi.GlobalVariable, sbStateName, []byte{1})
	if _, err := h.readAndMeasureSignatureDb(ctx, PK); err != nil {
		return xerrors.Errorf("cannot measure PK: %w", err)
	}
	if _, err := h.readAndMeasureSignatureDb(ctx, KEK); err != nil {
		return xerrors.Errorf("cannot measure KEK: %w", err)
	}
	if err := h.measureAuthorizedSignatureDb(ctx); err != nil {
		return xerrors.Errorf("cannot measure db: %w", err)
	}
	if _, err := h.readAndMeasureSignatureDb(ctx, Dbx); err != nil {
		return xerrors.Errorf("cannot measure dbx: %w", err)
	}

	// TODO: Support optional dbt/dbr database

	// Include the user mode related measurements if the system is in user mode, it is
	// permitted with the WithSecureBootUserMode option and they are being included in this
	// branch.
	includeUserMode := boolParamOrFalse(ctx.Params(), includeSecureBootUserModeParamKey)
	switch deployedMode, _, err := ctx.Vars().ReadVar("DeployedMode", efi.GlobalVariable); {
	case errors.Is(err, efi.ErrVarNotExist):
		// pre-2.5 UEFI system
	case err != nil:
		return fmt.Errorf("cannot read DeployedMode variable: %w", err)
	case len(deployedMode) != 1:
		return fmt.Errorf("invalid DeployedMode value %#x", deployedMode)
	case deployedMode[0] == 0 && includeUserMode:
		// System is in user mode, the WithSecureBootUserMode option was supplied and
		// we are including the user mode related measurements in this branch.
		ctx.MeasureVariable(internal_efi.SecureBootPolicyPCR, efi.GlobalVariable, "AuditMode", []byte{0})
		ctx.MeasureVariable(internal_efi.SecureBootPolicyPCR, efi.GlobalVariable, "DeployedMode", []byte{0})
	default:
		// Do nothing for the deployed mode case, or where the system is in user mode
		// but where the WithSecureBootUserMode option is not supplied or we are creating
		// a branch that allows for deployed mode to be enabled.
	}

	// We don't measure a EV_SEPARATOR here yet because we need to preserve the
	// device-specific measurement ordering - see the notes above about when the
	// verification of third-party pre-OS code is measured. We don't know whether
	// the EV_SEPARATOR in PCR7 on this platform signals the transition to OS-present,
	// or signals the boundary between config (EV_EFI_VARIABLE_DRIVER_CONFIG) and
	// verification (EV_EFI_VARIABLE_AUTHORITY). We may have to measure any
	// EV_EFI_VARIABLE_AUTHORITY events associated with third-party pre-OS code
	// *before* measuring the separator in the case that this platform measures the
	// separator as part of the transition to OS-present.

	// Wind the log further forwards to the transition to OS-present, past the secure
	// boot configuration, whilst retaining any verification events associated with
	// third party code executed from the pre-OS environment. This includes UEFI
	// drivers or system preparation applications, although note that these make a
	// profile inherently fragile. See the comment in measureBootManagerCodePreOS
	// regarding event ordering. This loop retains the device specific ordering, eg,
	// whether the EV_SEPARATOR in PCR7 signals the end of the configuration
	// measurements of whether it is measured as part of the transition to OS-present.
	foundOsPresent := false              // true when we enounter the first EV_SEPARATOR in PCRs 0-6.
	measuredSecureBootSeparator := false // true when we encounter the EV_SEPARATOR in PCR7.
	measuredPreOSVerification := false   // true when we encounter a EV_EFI_VARIABLE_AUTHORITY event.
	for len(events) > 0 {
		e := events[0]
		events = events[1:]

		switch {
		case e.PCRIndex < internal_efi.SecureBootPolicyPCR && e.EventType == tcglog.EventTypeSeparator:
			// Pre-OS to OS-present signal. We abort this loop once we've seen
			// this *and* the EV_SEPARATOR event in PCR7.
			foundOsPresent = true
		case e.PCRIndex == internal_efi.SecureBootPolicyPCR && e.EventType == tcglog.EventTypeSeparator && !measuredSecureBootSeparator:
			// End of secure boot configuration signal or transition to OS-present.
			if err := h.measureSeparator(ctx, internal_efi.SecureBootPolicyPCR, e); err != nil {
				return err
			}

			// Record that we've seen this - we should only see it once. We abort
			// once we've seen this *and* the transition to OS-present.
			measuredSecureBootSeparator = true
		case e.PCRIndex == internal_efi.SecureBootPolicyPCR && e.EventType == tcglog.EventTypeEFIVariableAuthority:
			// Pre-OS secure boot verification event. This must be retained, and we
			// support this being measured either before or after the EV_SEPARATOR event
			// in PCR7, preserving the original measurement order. If
			// measuredSecureBootSeparator is false at this point, then the EV_SEPARATOR
			// in PCR7 is measured as part of the transition to OS-present on this platform,
			// otherwise it is measured immediately after the secure boot configuration
			// measurements.
			digest := e.Digests[ctx.PCRAlg()]
			ctx.FwContext().AppendVerificationEvent(digest)
			ctx.ExtendPCR(internal_efi.SecureBootPolicyPCR, digest)
			measuredPreOSVerification = true
		case e.PCRIndex == internal_efi.SecureBootPolicyPCR && e.EventType == tcglog.EventTypeEFIVariableDriverConfig &&
			!measuredPreOSVerification && !measuredSecureBootSeparator:
			// Ignore: part of the secure boot configuration - we shouldn't see these
			// once we've encountered the first EV_EFI_VARIABLE_AUTHORITY event and
			// we'll likely generate an invalid profile if we do. The preinstall
			// checks will catch this.
		case e.PCRIndex == internal_efi.SecureBootPolicyPCR && e.EventType == tcglog.EventTypeEFIAction &&
			(bytes.Equal(e.Data.Bytes(), []byte(dmaProtectionDisabled)) || bytes.Equal(e.Data.Bytes(), []byte(dmaProtectionDisabledNul))) &&
			allowInsufficientDMAProtection:
			// This is a EV_EFI_ACTION "DMA Protection Disabled" measurement and is
			// allowed to appear in PCR7. In this case, it is after the secure
			// boot configuration measurements, and may be after the separator (if
			// the separator indicates the end of the configuration) or before the
			// separator (if the separator is measured as part of the transition to
			// OS-present).
			// Now we use the includeInsufficientDMAProtection flag to determine if
			// this run of fwLoadHandler should really measure it to this profile
			// branch as well. Including a branch in the profile that skips this
			// measurement makes it possible for the firmware setting to be corrected
			// without invalidating the profile, which would require a recovery key.
			// Future runs can then drop the option to permit it.
			if includeInsufficientDMAProtection {
				ctx.ExtendPCR(internal_efi.SecureBootPolicyPCR, e.Digests[ctx.PCRAlg()])
			}
			allowInsufficientDMAProtection = false // Only allow this event to appear once
		case e.PCRIndex == internal_efi.SecureBootPolicyPCR:
			return fmt.Errorf("unexpected event type (%v) found in log", e.EventType)
		default:
			// not a secure boot event
		}

		if foundOsPresent && measuredSecureBootSeparator {
			// We've encountered the signal to OS-present (EV_SEPARATOR events in PCRs
			// 0-6) *and* we've seen the EV_SEPARATOR for PCR7. At this point we can
			// abort - the next events are associated with verification of the OS
			// components.
			break
		}
	}

	if !measuredSecureBootSeparator {
		return errors.New("missing separator in log")
	}
	return nil
}

func boolParamOrFalse(loadParams loadParams, key loadParamsKey) bool {
	val, ok := loadParams[key]
	if !ok {
		return false
	}
	return val.(bool)
}

func (h *fwLoadHandler) measurePlatformFirmware(ctx pcrBranchContext) error {
	donePcrReset := false

	for _, event := range h.log.Events {
		if event.PCRIndex != internal_efi.PlatformFirmwarePCR {
			continue
		}
		if event.EventType == tcglog.EventTypeNoAction {
			if err, isErr := event.Data.(error); isErr {
				return fmt.Errorf("cannot decode EV_NO_ACTION event data: %w", err)
			}
			if loc, isLoc := event.Data.(*tcglog.StartupLocalityEventData); isLoc {
				if donePcrReset {
					return errors.New("log for PCR0 has an unexpected StartupLocality event")
				}
				ctx.ResetCRTMPCR(loc.StartupLocality)
				donePcrReset = true
			}
			continue
		}

		if !donePcrReset {
			ctx.ResetPCR(internal_efi.PlatformFirmwarePCR)
			donePcrReset = true
		}

		if event.EventType == tcglog.EventTypeSeparator {
			return h.measureSeparator(ctx, internal_efi.PlatformFirmwarePCR, event)
		}
		ctx.ExtendPCR(internal_efi.PlatformFirmwarePCR, event.Digests[ctx.PCRAlg()])
	}

	return errors.New("missing separator in log")
}

func (h *fwLoadHandler) measureDriversAndApps(ctx pcrBranchContext) error {
	for _, event := range h.log.Events {
		if event.PCRIndex != internal_efi.DriversAndAppsPCR {
			continue
		}

		if event.EventType == tcglog.EventTypeSeparator {
			return h.measureSeparator(ctx, internal_efi.DriversAndAppsPCR, event)
		}
		ctx.ExtendPCR(internal_efi.DriversAndAppsPCR, event.Digests[ctx.PCRAlg()])
	}

	return errors.New("missing separator in log")
}

func (h *fwLoadHandler) measureBootManagerCodePreOS(ctx pcrBranchContext) error {
	// Replay the log until the transition to the OS. Different firmware implementations and
	// configurations perform different pre-OS measurements, and these events need to be preserved
	// in the profile.
	//
	// This assumes that any events associated with the first boot attempt other than the
	// EV_EFI_BOOT_SERVICES_APPLICATION event containing the digest are recorded before the
	// separator. The TCG PC Client PFP spec v1.05r23 has some inconsistencies here - section
	// 3.3.4.5 mentions a EV_ACTION "Ready to Boot" signal and that the separator must be recorded
	// prior to this event. It also implies EV_EFI_ACTION events associated with each boot attempt
	// occur after the separator. Section 8.2.4 contradicts this - it makes no mention of any EV_ACTION
	// events and says that the EV_EFI_ACTION "Calling EFI Application from Boot Option" event
	// associated with the first boot attempt must be before the separator. In practise, devices
	// we've enabled follow section 8.2.4 when they measure the first EV_EFI_ACTION event (which is
	// optional - firmware should measure a EV_OMIT_BOOT_DEVICE_EVENTS event if they are not measured,
	// although some implementations don't do this either). I've not seen any implementations use the
	// mentioned EV_ACTION events, and these look like they are only relevant to BIOS boot anyway.
	//
	// The TCG PFP 1.06 r49 cleans this up a bit - it removes reference to the EV_ACTION events, and
	// corrects the "Method for measurement" subsection of section 3.3.4.5 to describe that things work
	// how we previously assumed. It does introduce a new EV_EFI_ACTION event ("Booting to <Boot####> Option")
	// which will require explicit support in this package so it is currently rejected by the
	// preinstall.RunChecks logic.
	//
	// This also retains measurements associated with the launch of any system preparation applications,
	// although note that the inclusion of these make a profile inherently fragile. The TCG PC Client PFP
	// spec v1.05r23 doesn't specify whether these are launched as part of the pre-OS environment or as
	// part of the OS-present environment. It defines the boundary between the pre-OS environment and
	// OS-present environment as a separator event measured to PCRs 0-7, but EDK2 measures a separator to
	// PCR7 as soon as the secure boot configuration is measured and system preparation applications are
	// considered part of the pre-OS environment - they are measured to PCR4 before the pre-OS to OS-present
	// transition is signalled by measuring separators to the remaining PCRs. The UEFI specification says that
	// system preparation applications are executed before the ready to boot signal, which is when the transition
	// from pre-OS to OS-present occurs, so I think we can be confident that we're correct here.
	events := h.log.Events
	measuredSeparator := false
	for len(events) > 0 {
		event := events[0]
		events = events[1:]

		if event.PCRIndex != internal_efi.BootManagerCodePCR {
			continue
		}

		if event.EventType == tcglog.EventTypeSeparator {
			if err := h.measureSeparator(ctx, internal_efi.BootManagerCodePCR, event); err != nil {
				return err
			}
			measuredSeparator = true
			break
		}
		ctx.ExtendPCR(internal_efi.BootManagerCodePCR, event.Digests[ctx.PCRAlg()])
	}

	if !measuredSeparator {
		return errors.New("missing separator in log")
	}

	// Some newer laptops including those from Dell and Lenovo execute code from a firmware volume as part
	// of the OS-present environment, before shim runs, and using the LoadImage API which results in an
	// additional measurement to PCR4. Copy this into the profile if it's part of a well-known endpoint
	// management application known as "Absolute" (formerly "Computrace"). Discard anything else which
	// will result in an invalid profile but will be picked up by the preinstall.RunChecks API anyway.
	for len(events) > 0 {
		event := events[0]
		events = events[1:]

		if event.PCRIndex != internal_efi.BootManagerCodePCR {
			continue
		}
		if event.EventType != tcglog.EventTypeEFIBootServicesApplication {
			return fmt.Errorf("unexpected OS-present event type: %v", event.EventType)
		}

		// once we encounter the first EV_EFI_BOOT_SERVICES_APPLICATION event in PCR4, this loop alway
		// breaks or returns an error.

		isAbsolute, err := internal_efi.IsAbsoluteAgentLaunch(event)
		if err != nil {
			return fmt.Errorf("encountered an error determining whether an OS-present launch is related to Absolute: %w", err)
		}
		if isAbsolute {
			// copy the digest to the policy
			ctx.ExtendPCR(internal_efi.BootManagerCodePCR, event.Digests[ctx.PCRAlg()])
		}
		// If it's not Absolute, we assume it's related to the OS launch which we will predict
		// later on. If it's something else, discarding it here creates an invalid policy but this is
		// picked up by the preinstall.RunChecks API anyway.
		break
	}

	return nil
}

// MeasureImageStart implements imageLoadHandler.MeasureImageStart.
func (h *fwLoadHandler) MeasureImageStart(ctx pcrBranchContext) error {
	if !h.log.Algorithms.Contains(ctx.PCRAlg()) {
		return errors.New("the TCG event log does not have the requested algorithm")
	}

	// Ensure each PCR in the policy is enabled to its reset value now in case nothing
	// extends it later on. We ignore PCR0 here as a special case because it doesn't
	// necessarily have a zero reset value.
	for _, pcr := range ctx.PCRs().PCRs() {
		if pcr == internal_efi.PlatformFirmwarePCR {
			continue
		}
		ctx.ResetPCR(pcr)
	}

	if ctx.PCRs().Contains(internal_efi.PlatformFirmwarePCR) {
		if err := h.measurePlatformFirmware(ctx); err != nil {
			return fmt.Errorf("cannot measure platform firmware: %w", err)
		}
	}
	if ctx.PCRs().Contains(internal_efi.DriversAndAppsPCR) {
		if err := h.measureDriversAndApps(ctx); err != nil {
			return fmt.Errorf("cannot measure drivers and apps: %w", err)
		}
	}
	if ctx.PCRs().Contains(internal_efi.BootManagerCodePCR) {
		if err := h.measureBootManagerCodePreOS(ctx); err != nil {
			return fmt.Errorf("cannot measure boot manager code: %w", err)
		}
	}
	if ctx.PCRs().Contains(internal_efi.SecureBootPolicyPCR) {
		if err := h.measureSecureBootPolicyPreOS(ctx); err != nil {
			return xerrors.Errorf("cannot measure secure boot policy: %w", err)
		}
	}

	return nil
}

// MeasureImageLoad implements imageLoadHandler.MeasureImageLoad.
func (h *fwLoadHandler) MeasureImageLoad(ctx pcrBranchContext, image peImageHandle) (imageLoadHandler, error) {
	m := newFwImageLoadMeasurer(ctx, image)
	if err := m.measure(); err != nil {
		return nil, xerrors.Errorf("cannot measure image: %w", err)
	}
	return lookupImageLoadHandler(ctx, image)
}

type fwImageLoadMeasurer struct {
	secureBootPolicyMixin
	pcrBranchContext
	image peImageHandle
}

func newFwImageLoadMeasurer(bc pcrBranchContext, image peImageHandle) *fwImageLoadMeasurer {
	return &fwImageLoadMeasurer{
		pcrBranchContext: bc,
		image:            image}
}

func (m *fwImageLoadMeasurer) measureVerification() error {
	authority, err := m.DetermineAuthority([]*secureBootDB{m.FwContext().Db}, m.image)
	if err != nil {
		return err
	}

	// Firmware always measures the entire EFI_SIGNATURE_DATA including the SignatureOwner
	varData := new(bytes.Buffer)
	if err := authority.Signature.Write(varData); err != nil {
		return xerrors.Errorf("cannot encode authority EFI_SIGNATURE_DATA: %w", err)
	}

	digest := tcglog.ComputeEFIVariableDataDigest(
		m.PCRAlg().GetHash(),
		authority.Source.Name,
		authority.Source.GUID,
		varData.Bytes())

	// Don't measure events that have already been measured
	if m.FwContext().HasVerificationEvent(digest) {
		return nil
	}
	m.FwContext().AppendVerificationEvent(digest)
	m.ExtendPCR(internal_efi.SecureBootPolicyPCR, digest)
	return nil
}

func (m *fwImageLoadMeasurer) measurePEImageDigest() error {
	digest, err := m.image.ImageDigest(m.PCRAlg().GetHash())
	if err != nil {
		return xerrors.Errorf("cannot compute PE digest: %w", err)
	}
	m.ExtendPCR(internal_efi.BootManagerCodePCR, digest)
	return nil
}

func (m *fwImageLoadMeasurer) measure() error {
	if m.PCRs().Contains(internal_efi.SecureBootPolicyPCR) {
		if err := m.measureVerification(); err != nil {
			return xerrors.Errorf("cannot measure secure boot event: %w", err)
		}
	}

	if m.PCRs().Contains(internal_efi.BootManagerCodePCR) {
		if err := m.measurePEImageDigest(); err != nil {
			return xerrors.Errorf("cannot measure boot manager code event: %w", err)
		}
	}

	return nil
}
