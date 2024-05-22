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
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
	"golang.org/x/xerrors"
)

// PCRProfileEnablePCRsOption is an option for AddPCRProfile that adds one or more PCRs.
type PCRProfileEnablePCRsOption interface {
	PCRProfileOption
	PCRs() tpm2.HandleList
}

// PCRProfileOption is an option for AddPCRProfile
type PCRProfileOption interface {
	applyOptionTo(gen *pcrProfileGenerator)
}

type pcrProfileSetPcrsOption struct {
	PCRProfileOption
	pcrs pcrFlags
}

func newPcrProfileSetPcrsOption(pcrs pcrFlags) *pcrProfileSetPcrsOption {
	out := &pcrProfileSetPcrsOption{
		pcrs: pcrs,
	}
	out.PCRProfileOption = out
	return out
}

func (o *pcrProfileSetPcrsOption) applyOptionTo(gen *pcrProfileGenerator) {
	gen.pcrs |= o.pcrs
}

func (o *pcrProfileSetPcrsOption) PCRs() tpm2.HandleList {
	return o.pcrs.PCRs()
}

// WithPlatformFirmwareProfile adds the SRTM, POST BIOS and Embedded Drivers
// profile (measured to PCR0). This is copied directly from the current host
// environment configuration.
//
// It is suitable in environments where platform firmware is measured by a
// hardware root of trust as opposed to being verified as authentic and prevented
// from running otherwise.
func WithPlatformFirmwareProfile() PCRProfileEnablePCRsOption {
	return newPcrProfileSetPcrsOption(makePcrFlags(platformFirmwarePCR))
}

// WithDriversAndAppsProfile adds the UEFI Drivers and UEFI Applications profile
// (measured to PCR2). This is copied directly from the current host environment
// configiguration.
func WithDriversAndAppsProfile() PCRProfileEnablePCRsOption {
	return newPcrProfileSetPcrsOption(makePcrFlags(driversAndAppsPCR))
}

// WithSecureBootPolicyProfile requests that the UEFI secure boot policy profile is
// added, which restricts access to a resource based on a set of secure boot policies
// measured to PCR7. The secure boot policy that is measured to PCR7 is defined in
// section 2.3.4.8 of the "TCG PC Client Platform Firmware Profile Specification".
//
// This will only generate a policy that works for devices with secure boot enabled,
// deployed mode enabled (for UEFI >= 2.5), without a debugger enabled and which measure
// the secure boot configuration events in the correct order (SecureBoot -> PK -> KEK ->
// db -> dbx).
//
// The secure boot policy includes events that correspond to the authentication of EFI
// applications. All images supplied to AddPCRProfile must have one ore more Authenticode
// signatures that have a trust anchor in the host environment's signature database,
// else an error will be returned. If any image has a non Authenticode signature or an
// Authenticode signature with a digest algorithm other than SHA-256, then an error
// will be returned.
//
// This does not support generating policy for images that are authenticated by adding
// their digests to the signature database. If a supplied image has a valid Authenticode
// signature with a trust anchor in the signature database but it is subsequently
// authenticated by its image digest, the generated policy will be incorrect.
//
// If an image has an Authenticode signature with more than one trust anchor in the
// signature database, this assumes that the platform firmware will try them in the
// order in which they appear and authenticate the image with the first one.
//
// If an image has multiple Authenticode signatures, this assumes that the platform
// firmware will test each Authenticode signature in the order they appear in the
// image against the signature database, as opposed to testing each entry in the
// signature database against each Authenticode signature, ie:
//
//	for each signature in image {
//	  for each certificate sigdb {
//	    <test>
//	  }
//	}
//
// If the platform firmware doesn't behave like this, then this may generate a policy
// that is incorrect in some specific circumstances - ie, if an image contains 2
// Authenticode signatures with their own trust anchors in the signature database, but
// the signatures are in reverse order with respect to how their trust anchors are
// enrolled.
//
// Note that AddPCRProfile does not consider the host's revocation policy.
//
// The secure boot policy includes information about the secure boot configuration,
// including signature databases. In order to support atomic updates to these databases,
// it is possible to pre-generate a policy that includes these updates by supplying
// details of the updates to AddPCRProfile using [WithSignatureDBUpdates].
//
// Note that the policy generated by this will include authentication events associated
// with UEFI drivers and system preparation applications that were included in the
// current boot, as long as they are measured as part of the pre-OS environment
// (before the EV_SEPARATOR events are measured to PCRs 0-6). Note that the inclusion
// of these makes a policy inherently fragile because it is not possible to pre-generate
// policy to accomodate updates of these components.
func WithSecureBootPolicyProfile() PCRProfileEnablePCRsOption {
	return newPcrProfileSetPcrsOption(makePcrFlags(secureBootPolicyPCR))
}

// WithBootManagerCodeProfile requests that the UEFI boot manager code and boot attempts
// profile is added, which restricts access to a resource to a specific set of UEFI
// applications that are measured to PCR4. Events that are measured to this PCR are
// detailed in section 2.3.4.5 of the "TCG PC Client Platform Firmware Profile Specification".
//
// There is some variation in behaviour between different platform firmware
// implementations, and this will generate a policy that is specific for the current
// host's platform firmware, based on the contents of the TCG event log. This assumes
// that any events associated with the first boot attempt (other than the
// EV_EFI_BOOT_SERVICES_APPLICATION containing the image digest) are measured before
// the EV_SEPARATOR event. There are some inconsistencies in the TCG PC Client PFP
// spec v1.05r23 here - section 3.3.4.5 mentions a EV_ACTION "Ready to Boot" signal
// and that the separator must be recorded prior to this event. It also implies
// EV_EFI_ACTION events associated with each boot attempt occur after the separator.
// Section 8.2.4 contradicts this - it makes no mention of any EV_ACTION events and says
// that the EV_EFI_ACTION "Calling EFI Application from Boot Option" event associated
// with the first boot attempt must be before the separator. In practise, devices we've
// enabled follow section 8.2.4 when they measure the first EV_EFI_ACTION event (which
// is optional - firmware should measure a EV_OMIT_BOOT_DEVICE_EVENTS event if they
// are not measured, although some implementations don't do this either).
//
// Note that on supported platforms, the policy generated by this will include any
// system preparation applications that were executed during the current boot, as long
// as they are measured as part of the pre-OS environment (before the EV_SEPARATOR
// event). Note that the inclusion of these makes a policy inherently fragile because
// it is not possible to pre-generate policy to accomodate updates of these components.
//
// If the EV_OMIT_BOOT_DEVICE_EVENTS is not recorded to PCR 4, the platform firmware
// may perform meaurements of all boot attempts, even if they fail. The generated policy
// will be invalid if the platform firmware performs boot attempts that subsequently
// fail before performing a successful attempt, even if the images associated with the
// successful attempt are included in this policy.
func WithBootManagerCodeProfile() PCRProfileEnablePCRsOption {
	return newPcrProfileSetPcrsOption(makePcrFlags(bootManagerCodePCR))
}

// WithKernelConfigProfile adds the kernel config profile. This binds a policy to a
// set of externally supplied commandlines. On Ubuntu Core, this also binds a policy
// to a set of model assertions and the initrd phase of the boot.
//
// Kernel commandlines can be injected into the profile with [KernelCommandlineParams].
// Snap models can be injected into the profile with [SnapModelParams]. Note that a model
// assertion is mandatory for profiles that include a UKI for Ubuntu Core.
func WithKernelConfigProfile() PCRProfileEnablePCRsOption {
	return newPcrProfileSetPcrsOption(makePcrFlags(kernelConfigPCR))
}

// AddPCRProfile adds a profile defined by the supplied options to the supplied
// secboot_tpm2.PCRProtectionProfileBranch, using the specified digest algorithm
// for the PCR digest. The generated profile is defined by the supplied load
// sequences and options.
func AddPCRProfile(pcrAlg tpm2.HashAlgorithmId, branch *secboot_tpm2.PCRProtectionProfileBranch, loadSequences *ImageLoadSequences, options ...PCRProfileOption) error {
	gen := newPcrProfileGenerator(pcrAlg, loadSequences, options...)

	if gen.pcrs == 0 {
		return errors.New("must specify a profile to add")
	}

	return gen.addPCRProfile(branch)
}

type pcrProfileGenerator struct {
	// pcrAlg is the PCR digest algorithm to add to the profile.
	pcrAlg tpm2.HashAlgorithmId

	// loadSequences describes the sequences of image loads from which
	// to construct the profile.
	loadSequences *ImageLoadSequences

	// env is the host EFI environment, providing access to the host's EFI variables
	// and TCG log. This can be overridden with the WithHostEnvironment option.
	env HostEnvironment

	// handlers is used to map an image in the supplied loadSequences to the
	// corresponding imageLoadHandler, which determines how an image affects a
	// profile.
	handlers imageLoadHandlerMap

	// pcrs is used to specify the PCRs to generate profiles for.
	pcrs pcrFlags

	// varModifiers is a set of callbacks that can apply customizations to
	// EFI variables supplied from the HostEnvironment. This creates a sequence
	// of every possible EFI variable starting state, and is used for generating
	// profiles that incorporate signature database updates and changest to
	// SbatPolicy.
	varModifiers []rootVarsModifier

	// log is the host TCG log, which is read from the associated env.
	log *tcglog.Log
}

func newPcrProfileGenerator(pcrAlg tpm2.HashAlgorithmId, loadSequences *ImageLoadSequences, options ...PCRProfileOption) *pcrProfileGenerator {
	gen := &pcrProfileGenerator{
		pcrAlg:        pcrAlg,
		loadSequences: loadSequences,
		env:           defaultEnv,
		handlers:      makeImageLoadHandlerMap(),
	}
	for _, opt := range options {
		opt.applyOptionTo(gen)
	}
	return gen
}

func (g *pcrProfileGenerator) addPCRProfile(branch *secboot_tpm2.PCRProtectionProfileBranch) error {
	bp := branch.AddBranchPoint()
	defer bp.EndBranchPoint()

	log, err := g.env.ReadEventLog()
	if err != nil {
		return xerrors.Errorf("cannot read TCG event log: %w", err)
	}
	g.log = log

	// Collect all of the starting EFI variable states that we need to
	// generate branches for.
	collector := newRootVarsCollector(g.env)

	// Collect the starting EFI variable states from the supplied options
	for i, mod := range g.varModifiers {
		if err := mod(collector); err != nil {
			return xerrors.Errorf("cannot process host variable modifier %d: %w", i, err)
		}
	}

	// For each starting state...
	for collector.More() {
		if err := g.addPCRProfileBranchForVars(bp, collector.Next()); err != nil {
			return err
		}
	}

	return nil
}

func (g *pcrProfileGenerator) addPCRProfileBranchForVars(bp *secboot_tpm2.PCRProtectionProfileBranchPoint, rootVars *varBranch) error {
	// Build a list of parameters
	params := g.loadSequences.params.Resolve(new(loadParams))

	for _, p := range params {
		if err := g.addOnePCRProfileBranch(bp, rootVars, &p); err != nil {
			return err
		}
	}

	return nil
}

func (g *pcrProfileGenerator) addOnePCRProfileBranch(bp *secboot_tpm2.PCRProtectionProfileBranchPoint, rootVars *varBranch, params *loadParams) error {
	rootBranch := newRootPcrBranchCtx(g, bp.AddBranch(), params, rootVars)

	handler := newFwLoadHandler(g.log)
	if err := handler.MeasureImageStart(rootBranch); err != nil {
		return xerrors.Errorf("cannot measure pre-OS: %w", err)
	}

	todo := []*pcrImagesMeasurer{newPcrImagesMeasurer(rootBranch, handler, g.loadSequences.images...)}

	for len(todo) > 0 {
		m := todo[0]
		todo = todo[1:]

		next, err := m.Measure()
		if err != nil {
			return err
		}
		todo = append(todo, next...)
	}

	return nil
}

// PCRAlg implements pcrProfileContext.PCRAlg.
func (g *pcrProfileGenerator) PCRAlg() tpm2.HashAlgorithmId {
	return g.pcrAlg
}

// PCRS implements pcrProfileContext.PCRs.
func (g *pcrProfileGenerator) PCRs() pcrFlags {
	return g.pcrs
}

func (g *pcrProfileGenerator) ImageLoadHandlerMap() imageLoadHandlerMap {
	return g.handlers
}

// pcrProfileContext corresponds to the global environment of an EFI PCR profile generation.
type pcrProfileContext interface {
	PCRAlg() tpm2.HashAlgorithmId // the PCR digest algorithm for the profile
	PCRs() pcrFlags

	ImageLoadHandlerMap() imageLoadHandlerMap
}
