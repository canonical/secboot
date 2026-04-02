// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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

package efi_test

import (
	"context"
	"crypto"
	"errors"

	efi "github.com/canonical/go-efilib"
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
)

type imageTrustSuite struct {
	mockImageHandleMixin
}

var _ = Suite(&imageTrustSuite{})

func (s *imageTrustSuite) SetUpTest(c *C) {
	s.mockImageHandleMixin.SetUpTest(c)
}

func (s *imageTrustSuite) TearDownTest(c *C) {
	s.mockImageHandleMixin.TearDownTest(c)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostGood(c *C) {
	// Image signed by MS UEFI CA, db contains MS UEFI CA - should succeed.
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4))

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, IsNil)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostMultipleCAsInDb(c *C) {
	// Image signed by MS UEFI CA, db contains both MS PCA and MS UEFI CA - should succeed.
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4))

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msPCACert, msOwnerGuid),
		efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, IsNil)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostMultipleX509EntriesInSingleSignatureList(c *C) {
	// Image signed by MS UEFI CA, db contains one EFI_SIGNATURE_LIST with
	// multiple X.509 signature entries where only one entry matches.
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4))
	invalidCert := make([]byte, len(msUefiCACert))

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		&efi.SignatureList{
			Type: efi.CertX509Guid,
			Signatures: []*efi.SignatureData{
				{Owner: msOwnerGuid, Data: invalidCert},
				{Owner: msOwnerGuid, Data: msUefiCACert},
			},
		},
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, IsNil)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostWrongCA(c *C) {
	// Image signed by MS UEFI CA, but db only has Canonical CA - should fail.
	// This simulates the scenario where old hardware has a different CA.
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4))

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{}),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, ErrorMatches, `cannot find any secure boot signature that is trusted by the current host's authorized signature database`)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostUnsignedImage(c *C) {
	// Unsigned image - should fail.
	image := newMockImage()

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, ErrorMatches, `image has no secure boot signatures`)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostNoDb(c *C) {
	// Image is signed but no db variable exists - treat as empty DB and fail
	// with no matching trust anchor.
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4))

	vars := efitest.MakeMockVars()
	// Don't set db
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, ErrorMatches, `cannot find any secure boot signature that is trusted by the current host's authorized signature database`)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostNoVarsBackend(c *C) {
	// No EFI variables backend at all - should fail.
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4))

	env := efitest.NewMockHostEnvironment(nil, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, ErrorMatches, `cannot read forbidden signature database:.*`)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostCanonicalCA(c *C) {
	// Image signed by Canonical CA, db contains Canonical CA - should succeed.
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3))

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{}),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, IsNil)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostBadImage(c *C) {
	// Mock openPeImage to fail to test error handling.
	restoreOpen := MockOpenPeImage(func(image Image) (PeImageHandle, error) {
		return nil, errors.New("mock open error")
	})
	defer restoreOpen()

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	image := newMockImage()
	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, ErrorMatches, `cannot open image: mock open error`)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostNoDbx(c *C) {
	// Image is signed and db exists but no dbx variable exists - treat as empty
	// DBX and succeed.
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4))

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
	})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, IsNil)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostRevokedByDbxCert(c *C) {
	// Image signed by MS UEFI CA and db trusts that CA, but dbx revokes it.
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4))

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
	})
	vars.SetDbx(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
	})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, ErrorMatches, `secure boot signature is forbidden by the current host's signature databases`)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostRevokedByDbxDigest(c *C) {
	// Image signed by MS UEFI CA and db trusts it, but dbx revokes the image digest.
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)
	image := newMockImage().appendSignatures(sig)

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
	})
	vars.SetDbx(c, efi.SignatureDatabase{
		efitest.NewSignatureListDigests(c, sig.DigestAlgorithm(), msOwnerGuid, sig.Digest()),
	})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, ErrorMatches, `secure boot signature is forbidden by the current host's signature databases`)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostDigestAuthorized(c *C) {
	// Image signed and its digest is in db (not via CA chain);
	// should succeed.
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)
	image := newMockImage().appendSignatures(sig)

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListDigests(c, sig.DigestAlgorithm(), msOwnerGuid, sig.Digest()),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, IsNil)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostDigestAuthorizedWithSha384DbEntry(c *C) {
	// Signatures are SHA256 Authenticode, but DB authorization should use the
	// image digest for the signature list algorithm (SHA384 here).
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)
	sha384Digest := make([]byte, crypto.SHA384.Size())
	for i := range sha384Digest {
		sha384Digest[i] = 0x3c
	}
	image := newMockImage().withDigest(crypto.SHA384, sha384Digest).appendSignatures(sig)

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListDigests(c, crypto.SHA384, msOwnerGuid, sha384Digest),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, IsNil)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostDigestNotAuthorized(c *C) {
	// Image signed but its digest is not in db - should fail.
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)
	image := newMockImage().appendSignatures(sig)

	vars := efitest.MakeMockVars()
	// Set db with a wrong digest
	wrongDigest := make([]byte, len(sig.Digest()))
	for i := range wrongDigest {
		wrongDigest[i] = 0xFF
	}
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListDigests(c, sig.DigestAlgorithm(), msOwnerGuid, wrongDigest),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, ErrorMatches, `cannot find any secure boot signature that is trusted by the current host's authorized signature database`)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostMixedCaAndDigest(c *C) {
	// db has both CA entries and digest entries; image matches neither CA (db
	// has wrong CA) but does match digest - should succeed.
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)
	image := newMockImage().appendSignatures(sig)

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{}),
		efitest.NewSignatureListDigests(c, sig.DigestAlgorithm(), msOwnerGuid, sig.Digest()),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, IsNil)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostDigestRevokedByDbx(c *C) {
	// Image digest is in db but the same digest is also in dbx - dbx revocation
	// should take precedence, so should fail.
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)
	image := newMockImage().appendSignatures(sig)

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListDigests(c, sig.DigestAlgorithm(), msOwnerGuid, sig.Digest()),
	})
	vars.SetDbx(c, efi.SignatureDatabase{
		efitest.NewSignatureListDigests(c, sig.DigestAlgorithm(), msOwnerGuid, sig.Digest()),
	})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, ErrorMatches, `secure boot signature is forbidden by the current host's signature databases`)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostDigestRevokedByDbxWithSha384Entry(c *C) {
	// Signatures are SHA256 Authenticode, but DBX revocation should use the
	// image digest for the signature list algorithm (SHA384 here).
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)
	sha384Digest := make([]byte, crypto.SHA384.Size())
	for i := range sha384Digest {
		sha384Digest[i] = 0x4d
	}
	image := newMockImage().withDigest(crypto.SHA384, sha384Digest).appendSignatures(sig)

	vars := efitest.MakeMockVars()
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
	})
	vars.SetDbx(c, efi.SignatureDatabase{
		efitest.NewSignatureListDigests(c, crypto.SHA384, msOwnerGuid, sha384Digest),
	})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, ErrorMatches, `secure boot signature is forbidden by the current host's signature databases`)
}

func (s *imageTrustSuite) TestCheckImageSignatureIsValidForHostMultipleDigestsInDb(c *C) {
	// db has multiple digest entries whereas only one matches the image -
	// should succeed.
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)
	image := newMockImage().appendSignatures(sig)

	vars := efitest.MakeMockVars()
	wrongDigest1 := make([]byte, len(sig.Digest()))
	for i := range wrongDigest1 {
		wrongDigest1[i] = 0xAA
	}
	wrongDigest2 := make([]byte, len(sig.Digest()))
	for i := range wrongDigest2 {
		wrongDigest2[i] = 0xBB
	}
	vars.SetDb(c, efi.SignatureDatabase{
		efitest.NewSignatureListDigests(c, sig.DigestAlgorithm(), msOwnerGuid,
			wrongDigest1, sig.Digest(), wrongDigest2),
	})
	vars.SetDbx(c, efi.SignatureDatabase{})
	env := efitest.NewMockHostEnvironment(vars, nil)
	ctx := env.VarContext(context.Background())

	err := CheckImageSignatureIsValidForHost(ctx, image)
	c.Check(err, IsNil)
}
