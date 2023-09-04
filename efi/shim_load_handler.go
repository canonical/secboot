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
	"crypto/x509"
	"errors"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	"golang.org/x/xerrors"
)

// shimLoadHandler is an implementation of imageLoadHandler for shim.
type shimLoadHandler struct {
	Flags     shimFlags
	VendorDb  *secureBootDB
	SbatLevel shimSbatLevel
}

// shimLoadHandlerConstructor is used to construct a function with the same
// signature as newShimLoadHandler which can be used to construct a custom
// shimLoadHandler.
type shimLoadHandlerConstructor struct {
	version   *shimVersion
	sbatLevel *shimSbatLevel
}

func newShimLoadHandlerConstructor() *shimLoadHandlerConstructor {
	return new(shimLoadHandlerConstructor)
}

func (c *shimLoadHandlerConstructor) WithVersion(ver shimVersion) *shimLoadHandlerConstructor {
	c.version = &ver
	return c
}

func (c *shimLoadHandlerConstructor) WithSbatLevel(level shimSbatLevel) *shimLoadHandlerConstructor {
	c.sbatLevel = &level
	return c
}

func (c *shimLoadHandlerConstructor) New(image peImageHandle) (imageLoadHandler, error) {
	shim := newShimImageHandle(image)
	var ver shimVersion
	if c.version != nil {
		ver = *c.version
	} else {
		var err error
		ver, err = shim.Version()
		if err != nil {
			return nil, xerrors.Errorf("cannot obtain shim version: %w", err)
		}
	}

	if ver.Compare(mustParseShimVersion("15.2")) < 0 {
		// Releases prior to 15.2 contain bugs that aren't accommodated here,
		// fixed by https://github.com/rhboot/shim/commit/58df8d745c6516818ba6ebfa8fe826702c1621a0
		// and https://github.com/rhboot/shim/commit/9f80be9f16a854e3946568fa92edebe26eb79e78
		return nil, errors.New("unsupported shim version < 15.2")
	}

	var flags shimFlags
	if ver.Compare(mustParseShimVersion("15.3")) >= 0 {
		// 15.3 is the first release to include SBAT support which
		// means that it measures the SBAT revocation level to PCR7
		flags |= shimHasSbatVerification

		// 15.3 includes this fix
		flags |= shimFixVariableAuthorityEventsMatchSpec
	}
	if ver.Compare(mustParseShimVersion("15.6")) >= 0 {
		// 15.6 contains the SBAT revocation management
		flags |= shimHasSbatRevocationManagement
	}

	// Read the built in vendor cert
	vendorDb, format, err := shim.ReadVendorDB()
	if err != nil {
		return nil, xerrors.Errorf("cannot read vendor DB: %w", err)
	}
	vendorDbName := efi.VariableDescriptor{Name: shimName, GUID: shimGuid}

	switch {
	case format == shimVendorCertIsDb:
		flags |= shimVendorCertContainsDb

		// This is surely wrong
		vendorDbName = efi.VariableDescriptor{
			Name: shimVendorDbName,
			GUID: efi.ImageSecurityDatabaseGuid}
	case format == shimVendorCertIsX509 && ver.Compare(mustParseShimVersion("15.7")) >= 0:
		// Because of https://github.com/rhboot/shim/commit/092c2b2bbed950727e41cf450b61c794881c33e7,
		// shim marks verification events that use the built-in vendor cert with the MokListRT name
		// and includes the shim GUID as the signature's owner GUID.
		// 15.7 introduced this bug
		vendorDbName = efi.VariableDescriptor{
			Name: shimMokListRTName,
			GUID: shimGuid}
		vendorDb[0].Signatures[0].Owner = shimGuid

		// set this because the bug also changes the measurement format - it measures the entire
		// EFI_SIGNATURE_DATA structure rather than just the certificate.
		flags |= shimVendorCertContainsDb
	}

	// Newer versions of shim carry a payload which it writes to a BS+NV variable to set the SBAT
	// revocation policy (SbatLevel). Note that shim uses "SBAT policy" for another meaning,
	// which makes it a bit confusing here.
	//
	// If the section doesn't exist, then the payload must be supplied externally.
	var sbatLevel shimSbatLevel
	if c.sbatLevel != nil {
		sbatLevel = *c.sbatLevel
	} else if shim.HasSbatLevelSection() {
		sbatLevel, err = shim.ReadSbatLevel()
		if err != nil {
			return nil, xerrors.Errorf("cannot read SbatLevel from shim: %w", err)
		}
	}

	return &shimLoadHandler{
		Flags: flags,
		VendorDb: &secureBootDB{
			Name:     vendorDbName,
			Contents: vendorDb,
		},
		SbatLevel: sbatLevel}, nil
}

func newShimLoadHandler(image peImageHandle) (imageLoadHandler, error) {
	return newShimLoadHandlerConstructor().New(image)
}

// VendorAuthorities implements vendorAuthorityGetter.
func (h *shimLoadHandler) VendorAuthorities() ([]*x509.Certificate, error) {
	var vendorCerts []*x509.Certificate
	for i, esl := range h.VendorDb.Contents {
		if esl.Type != efi.CertX509Guid {
			continue
		}
		if len(esl.Signatures) == 0 {
			continue
		}

		cert, err := x509.ParseCertificate(esl.Signatures[0].Data)
		if err != nil {
			return nil, xerrors.Errorf("cannot parse vendor cert at %d: %w", i, err)
		}
		vendorCerts = append(vendorCerts, cert)
	}
	return vendorCerts, nil
}

// MeasureImageStart implements imageLoadHandler.MeasureImageStart.
func (h *shimLoadHandler) MeasureImageStart(ctx pcrBranchContext) error {
	// Update the context for this branch
	ctx.ShimContext().Flags = h.Flags
	ctx.ShimContext().VendorDb = h.VendorDb

	if ctx.Flags()&secureBootPolicyProfile == 0 {
		// We're not generating secure boot policy
		return nil
	}
	if h.Flags&shimHasSbatVerification == 0 {
		// This shim doesn't support SBAT verification
		return nil
	}

	// Shim binaries with SBAT support measure the current SBAT revocation policy
	// (SbatLevel), but they do this after updating it if the selected built-in
	// payload is newer. Shim selects one of 2 built-in payloads based on the value
	// of the SbatPolicy variable. It selects either a more conservative revocation
	// level (previous) which is intended to give vendors an opportunity to update
	// components, or a more aggressive level (latest).
	//
	// Read the policy first.
	policy := shimSbatPolicyLatest
	if h.Flags&shimHasSbatRevocationManagement != 0 {
		var err error
		policy, err = readShimSbatPolicy(ctx.Vars())
		switch {
		case err != nil:
			return xerrors.Errorf("cannot read shim SbatPolicy: %w", err)
		case policy == shimSbatPolicyReset:
			return errors.New("cannot handle SbatPolicy == reset")
		}

		// shim resets this back to previous for the next boot.
		if policy == shimSbatPolicyLatest {
			if err := ctx.Vars().WriteVar(
				shimSbatPolicyName, shimGuid,
				efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess,
				[]byte{uint8(shimSbatPolicyPrevious)}); err != nil {
				return xerrors.Errorf("cannot clear SbatPolicy: %w", err)
			}
		}
	}
	// Determine the SBAT level that will be measured by shim
	var sbatLevel []byte

	// Obtain the current host level
	hostSbatLevel, _, err := ctx.Vars().ReadVar(shimSbatLevelRTName, shimGuid)
	switch {
	case err == efi.ErrVarNotExist:
		// shim will program and measure one of its built in values.
		sbatLevel = h.SbatLevel.ForPolicy(policy)
	case err != nil:
		return xerrors.Errorf("cannot obtain current SbatLevel: %w", err)
	default:
		// Determine which is the newest
		sbatLevel, err = newestSbatLevel(hostSbatLevel, h.SbatLevel.ForPolicy(policy))
		if err != nil {
			return xerrors.Errorf("cannot determine newest SbatLevel payload: %w", err)
		}
	}

	// Measure SbatLevel
	ctx.MeasureVariable(secureBootPCR, shimGuid, shimSbatLevelName, sbatLevel)

	if !bytes.Equal(sbatLevel, hostSbatLevel) {
		// This branch applies a new SBAT update
		if err := ctx.Vars().WriteVar(
			shimSbatLevelRTName, shimGuid,
			efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess,
			sbatLevel); err != nil {
			return xerrors.Errorf("cannot update SbatLevel: %w", err)
		}
	}

	return nil
}

// MeasureImageLoad implements imageLoadHandler.MeasureImageLoad.
func (h *shimLoadHandler) MeasureImageLoad(ctx pcrBranchContext, image peImageHandle) (imageLoadHandler, error) {
	m := newShimImageLoadMeasurer(ctx, image)
	if err := m.measure(); err != nil {
		return nil, xerrors.Errorf("cannot measure image: %w", err)
	}
	return lookupImageLoadHandler(ctx, image)
}

type shimImageLoadMeasurer struct {
	secureBootPolicyMixin
	pcrBranchContext
	image peImageHandle
}

func newShimImageLoadMeasurer(bc pcrBranchContext, image peImageHandle) *shimImageLoadMeasurer {
	return &shimImageLoadMeasurer{
		pcrBranchContext: bc,
		image:            image}
}

func (m *shimImageLoadMeasurer) measurePEImageDigest() error {
	digest, err := m.image.ImageDigest(m.PCRAlg().GetHash())
	if err != nil {
		return xerrors.Errorf("cannot compute PE digest: %w", err)
	}
	m.ExtendPCR(bootManagerCodePCR, digest)
	return nil
}

func (m *shimImageLoadMeasurer) measureVerification() error {
	sc := m.ShimContext()

	authority, err := m.DetermineAuthority([]*secureBootDB{sc.VendorDb, m.FwContext().Db}, m.image)
	if err != nil {
		return err
	}

	// Shim before https://github.com/rhboot/shim/commit/e3325f8100f5a14e0684ff80290e53975de1a5d9
	// only measured the SignatureData field of the EFI_SIGNATURE_DATA structure. After this commit,
	// it measures the entire EFI_SIGNATURE_DATA structure unless the built-in vendor cert is used
	// for authentication and the .vendor_cert section contains a single X.509 certificate.
	//
	// Note that https://github.com/rhboot/shim/commit/092c2b2bbed950727e41cf450b61c794881c33e7
	// affects this as well. When this bug is present, shim measures the entire EFI_SIGNATURE_DATA
	// even for the built in vendor cert. This is handled correctly here because we set the flag
	// that indicates the .vendor_cert section contains a database.
	var data *bytes.Buffer
	if sc.Flags&shimFixVariableAuthorityEventsMatchSpec == 0 ||
		(authority.Source == sc.VendorDb.Name && sc.Flags&shimVendorCertContainsDb == 0) {
		data = bytes.NewBuffer(authority.Signature.Data)
	} else {
		data = new(bytes.Buffer)
		if err := authority.Signature.Write(data); err != nil {
			return xerrors.Errorf("cannot encode authority EFI_SIGNATURE_DATA: %w", err)
		}
	}

	digest := tcglog.ComputeEFIVariableDataDigest(
		m.PCRAlg().GetHash(),
		authority.Source.Name,
		authority.Source.GUID,
		data.Bytes())

	// Don't measure events that have already been measured
	if sc.HasVerificationEvent(digest) {
		return nil
	}
	sc.AppendVerificationEvent(digest)
	m.ExtendPCR(secureBootPCR, digest)
	return nil
}

func (m *shimImageLoadMeasurer) measure() error {
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
