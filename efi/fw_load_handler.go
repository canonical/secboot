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
	"errors"
	"fmt"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	"golang.org/x/xerrors"
)

const (
	sbStateName = "SecureBoot" // Unicode variable name for the EFI secure boot configuration (enabled/disabled)
)

// fwLoadHandler is an implementation of imageLoadHandler that measures firmware
// events (pre-OS events and events related to loading of OS components).
type fwLoadHandler struct {
	log *tcglog.Log
}

var newFwLoadHandler = func(log *tcglog.Log) imageLoadHandler {
	return &fwLoadHandler{log: log}
}

func (h *fwLoadHandler) measureSignatureDb(ctx pcrBranchContext, name efi.VariableDescriptor) ([]byte, error) {
	db, _, err := ctx.Vars().ReadVar(name.Name, name.GUID)
	if err != nil && err != efi.ErrVarNotExist {
		return nil, xerrors.Errorf("cannot read current variable: %w", err)
	}

	ctx.MeasureVariable(secureBootPCR, name.GUID, name.Name, db)
	return db, nil
}

func (h *fwLoadHandler) measureAuthorizedSignatureDb(ctx pcrBranchContext) error {
	data, err := h.measureSignatureDb(ctx, Db)
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
	ctx.ResetPCR(secureBootPCR)

	// This hard-codes a profile that will only work on devices with secure boot enabled,
	// deployed mode on (where UEFI >= 2.5), without a UEFI debugger enabled and which
	// measure events in the correct order.
	ctx.MeasureVariable(secureBootPCR, efi.GlobalVariable, sbStateName, []byte{1})
	if _, err := h.measureSignatureDb(ctx, PK); err != nil {
		return xerrors.Errorf("cannot measure PK: %w", err)
	}
	if _, err := h.measureSignatureDb(ctx, KEK); err != nil {
		return xerrors.Errorf("cannot measure KEK: %w", err)
	}
	if err := h.measureAuthorizedSignatureDb(ctx); err != nil {
		return xerrors.Errorf("cannot measure db: %w", err)
	}
	if _, err := h.measureSignatureDb(ctx, Dbx); err != nil {
		return xerrors.Errorf("cannot measure dbx: %w", err)
	}
	// TODO: Support optional dbt/dbr databases

	// Retain any verification events associated with pre-OS components such as UEFI drivers
	// or system preparation applications. Note that these make a profile inherently fragile.
	// See the comment in measureBootManagerCodePreOS regarding event ordering.
	events := h.log.Events
	foundOsPresent := false
	foundSecureBootSeparator := false

	for len(events) > 0 {
		e := events[0]
		events = events[1:]

		switch {
		case e.PCRIndex < secureBootPCR && e.EventType == tcglog.EventTypeSeparator:
			// pre-OS to OS-present signal
			foundOsPresent = true
		case e.PCRIndex == secureBootPCR && e.EventType == tcglog.EventTypeSeparator:
			// end of secure boot configuration signal
			if foundSecureBootSeparator {
				return errors.New("unexpected separator")
			}
			ctx.ExtendPCR(secureBootPCR, tpm2.Digest(e.Digests[ctx.PCRAlg()]))
			foundSecureBootSeparator = true
		case e.PCRIndex == secureBootPCR && e.EventType == tcglog.EventTypeEFIVariableAuthority:
			// secure boot verification event
			if !foundSecureBootSeparator {
				return errors.New("unexpected verification event")
			}
			digest := tpm2.Digest(e.Digests[ctx.PCRAlg()])
			ctx.FwContext().AppendVerificationEvent(digest)
			ctx.ExtendPCR(secureBootPCR, digest)
		case e.PCRIndex == secureBootPCR && e.EventType == tcglog.EventTypeEFIVariableDriverConfig:
			// ignore: part of the secure boot configuration
		case e.PCRIndex == secureBootPCR:
			return fmt.Errorf("unexpected event type (%v) found in log", e.EventType)
		default:
			// not a secure boot event
		}

		if foundOsPresent && foundSecureBootSeparator {
			break
		}
	}

	return nil
}

func (h *fwLoadHandler) measureBootManagerCodePreOS(ctx pcrBranchContext) {
	ctx.ResetPCR(bootManagerCodePCR)

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
	// EV_ACTION events, and these would probably require explicit support here.
	//
	// This also retains measurements associated with the launch of any system preparation applications,
	// although note that the inclusion of these make a profile inherently fragile. The TCG PC Client PFP
	// spec v1.05r23 doesn't specify whether these are launched as part of the pre-OS environment or as
	// part of the OS-present environment. It defines the boundary between the pre-OS environment and
	// OS-present environment as a separator event measured to PCRs 0-7, but EDK2 measures a separator to
	// PCR7 as soon as the secure boot policy is measured and system preparation applications are considered
	// part of the pre-OS environment - they are measured to PCR4 before the pre-OS to OS-present transition
	// is signalled by measuring separators to the remaining PCRs. This seems sensible, but newer Dell
	// devices load an agent from firmware before shim is executed and measure this to PCR4 as part of the
	// OS-present environment, which seems wrong. The approach here assumes that the EDK2 behaviour is
	// correct.
	for _, event := range h.log.Events {
		if event.PCRIndex != bootManagerCodePCR {
			continue
		}

		ctx.ExtendPCR(bootManagerCodePCR, tpm2.Digest(event.Digests[ctx.PCRAlg()]))
		if event.EventType == tcglog.EventTypeSeparator {
			break
		}
	}
}

// MeasureImageStart implements imageLoadHandler.MeasureImageStart.
func (h *fwLoadHandler) MeasureImageStart(ctx pcrBranchContext) error {
	if !h.log.Algorithms.Contains(ctx.PCRAlg()) {
		return errors.New("the TCG event log does not have the requested algorithm")
	}

	if ctx.Flags()&secureBootPolicyProfile > 0 {
		if err := h.measureSecureBootPolicyPreOS(ctx); err != nil {
			return xerrors.Errorf("cannot measure secure boot policy: %w", err)
		}
	}
	if ctx.Flags()&bootManagerCodeProfile > 0 {
		h.measureBootManagerCodePreOS(ctx)
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
	m.ExtendPCR(secureBootPCR, digest)
	return nil
}

func (m *fwImageLoadMeasurer) measurePEImageDigest() error {
	digest, err := m.image.ImageDigest(m.PCRAlg().GetHash())
	if err != nil {
		return xerrors.Errorf("cannot compute PE digest: %w", err)
	}
	m.ExtendPCR(bootManagerCodePCR, digest)
	return nil
}

func (m *fwImageLoadMeasurer) measure() error {
	if m.Flags()&secureBootPolicyProfile > 0 {
		if err := m.measureVerification(); err != nil {
			return xerrors.Errorf("cannot measure secure boot event: %w", err)
		}
	}

	if m.Flags()&bootManagerCodeProfile > 0 {
		if err := m.measurePEImageDigest(); err != nil {
			return xerrors.Errorf("cannot measure boot manager code event: %w", err)
		}
	}

	return nil
}
