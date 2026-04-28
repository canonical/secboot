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

package efi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"

	efi "github.com/canonical/go-efilib"
	"golang.org/x/xerrors"
)

var mockedCheckImageSignatureIsValidForHost func(ctx context.Context, image Image) error

// CheckImageSignatureIsValidForHost checks whether the supplied image has at
// least one Authenticode signature that is authorized by the host's authorized
// signature database (the UEFI "db" variable).
//
// The image must have at least one Authenticode signature. It is not possible
// to authorize an unsigned image based solely on its digest being present in db.
//
// The image is authorized if:
//   - At least one of its Authenticode signatures chains to an X.509 certificate
//     authority that is enrolled in db, OR
//   - The PE image digest matches a digest entry in db, where the PE image digest
//     is computed for the hash algorithm implied by the EFI_SIGNATURE_LIST type
//     (e.g., CertSHA256Guid implies SHA256, CertSHA384Guid implies SHA384).
//
// For digest-based authorization, the function computes the PE image digest for
// each digest algorithm present in db and checks for a match against the
// corresponding signature list entries. This allows an image to be verified
// against digest entries regardless of the hash algorithm used by its
// Authenticode signature.
//
// This is intended to be used during boot asset updates to verify that a new
// image will actually be loadable, when secure boot is enforced, by the host's
// firmware before it is installed.
//
// For example, a shim binary signed only by a newer Microsoft UEFI CA will not
// be loadable on older hardware whose db only contains the older CA. Similarly,
// an image whose digest is not in db (if digest-based authorization is used) will
// not be loadable. An unsigned image cannot be loadable even if its digest is
// enrolled in db.
//
// The context must provide access to the EFI variable backend via go-efilib's
// context mechanism. In general, pass the result of
// [HostEnvironment.VarContext] or [efi.DefaultVarContext].
//
// Possible error conditions:
//   - The image cannot be opened or is not a valid PE binary.
//   - The image has no secure boot signatures.
//   - The host's db variable cannot be read (eg, if EFI variables are unavailable).
//   - The host's dbx variable cannot be read (eg, if EFI variables are unavailable).
//   - The image is revoked by a certificate or digest entry in the host's dbx.
//   - No signature on the image is authorized by the host's db.
func CheckImageSignatureIsValidForHost(ctx context.Context, image Image) error {
	if mockedCheckImageSignatureIsValidForHost != nil {
		return mockedCheckImageSignatureIsValidForHost(ctx, image)
	}

	// Extract signatures from the image, and check for the presence of at
	// least one signature before doing any further work, to give a more
	// specific error if the image is not signed at all.
	pei, err := openPeImage(image)
	if err != nil {
		return xerrors.Errorf("cannot open image: %w", err)
	}

	defer pei.Close()

	sigs, err := pei.SecureBootSignatures()
	if err != nil {
		return xerrors.Errorf("cannot obtain secure boot signatures for image: %w", err)
	}

	if len(sigs) == 0 {
		return errors.New("image has no secure boot signatures")
	}

	// Check for forbidden signatures in DBX first, to give a more specific
	// error if the image is actually signed by a trusted CA but is revoked
	// by DBX.
	if err := checkDbxRevocation(ctx, pei, sigs); err != nil {
		return err
	}

	// Check for a trusted signature in DB.
	return checkDbAuthorization(ctx, pei, sigs)
}

func checkDbxRevocation(ctx context.Context, pei peImageHandle, sigs []*efi.WinCertificateAuthenticode) error {
	dbx, err := efi.ReadSignatureDatabaseVariable(ctx, Dbx)
	if err != nil {
		if !errors.Is(err, efi.ErrVarNotExist) {
			return xerrors.Errorf("cannot read forbidden signature database: %w", err)
		}

		// If DBX doesn't exist, then there are no forbidden signatures, so we can
		// just treat it as empty and allow the image to be authorized by DB.
		return nil
	}

	digests := newImageDigestCache(pei)
	revokedByDigest, err := imageDigestIsForbiddenByDbx(digests, dbx)
	if err != nil {
		return err
	}

	if revokedByDigest {
		return errors.New("secure boot signature is forbidden by the current host's signature databases")
	}

	// Per UEFI secure boot semantics, any match in DBX is sufficient to
	// revoke an image, even if it has additional valid signatures.
	for _, sig := range sigs {
		if certIsForbiddenByDbx(sig, dbx) {
			return errors.New("secure boot signature is forbidden by the current host's signature databases")
		}
	}

	return nil
}

var errNoTrustedSignature = errors.New("cannot find any secure boot signature that is trusted by the current host's authorized signature database")

func checkDbAuthorization(ctx context.Context, pei peImageHandle, imageSigs []*efi.WinCertificateAuthenticode) error {
	db, err := efi.ReadSignatureDatabaseVariable(ctx, Db)
	if err != nil {
		if !errors.Is(err, efi.ErrVarNotExist) {
			return xerrors.Errorf("cannot read authorized signature database: %w", err)
		}
		// If DB doesn't exist, then there are no authorized signatures, so the image cannot be
		// authorized.
		return errNoTrustedSignature
	}

	digests := newImageDigestCache(pei)

	for _, sigList := range db {
		// Check for X.509 certificate-based authorization
		if sigList.Type == efi.CertX509Guid {
			for _, sigEntry := range sigList.Signatures {
				cert, err := x509.ParseCertificate(sigEntry.Data)
				if err != nil {
					continue
				}

				for _, imageSig := range imageSigs {
					if !imageSig.CertWithIDLikelyTrustAnchor(efi.NewX509CertIDFromCertificate(cert)) {
						continue
					}

					// If the signature chains to a trusted certificate, then the image is authorized.
					return nil
				}
			}
		} else {
			// Skip unrecognized signature list types since we cannot use them for verification
			alg := efiSignatureListTypeToDigestAlg(sigList.Type)
			if alg == crypto.Hash(0) {
				continue
			}

			// Check for digest-based authorization
			match, err := imageDigestMatchesDbSignatureList(digests, sigList)
			if err != nil {
				return err
			}

			if match {
				return nil
			}
		}
	}

	return errNoTrustedSignature
}

func certIsForbiddenByDbx(sig *efi.WinCertificateAuthenticode, dbx efi.SignatureDatabase) bool {
	for _, sigList := range dbx {
		if sigList.Type != efi.CertX509Guid {
			continue
		}

		for _, sigEntry := range sigList.Signatures {
			revokedCert, err := x509.ParseCertificate(sigEntry.Data)
			if err != nil {
				continue
			}

			if sig.CertWithIDLikelyTrustAnchor(efi.NewX509CertIDFromCertificate(revokedCert)) {
				return true
			}
		}
	}

	return false
}

type imageDigestCache struct {
	pei     peImageHandle
	digests map[crypto.Hash][]byte
}

func newImageDigestCache(pei peImageHandle) *imageDigestCache {
	return &imageDigestCache{
		pei:     pei,
		digests: make(map[crypto.Hash][]byte),
	}
}

func (c *imageDigestCache) digestForAlg(alg crypto.Hash) ([]byte, error) {
	if digest, exists := c.digests[alg]; exists {
		return digest, nil
	}

	digest, err := c.pei.ImageDigest(alg)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute image digest with %v: %w", alg, err)
	}

	c.digests[alg] = digest
	return digest, nil
}

func imageDigestMatchesDbSignatureList(digests *imageDigestCache, sigList *efi.SignatureList) (bool, error) {
	alg := efiSignatureListTypeToDigestAlg(sigList.Type)
	if alg == crypto.Hash(0) {
		return false, nil
	}

	digest, err := digests.digestForAlg(alg)
	if err != nil {
		return false, err
	}

	for _, sigEntry := range sigList.Signatures {
		if bytes.Equal(sigEntry.Data, digest) {
			return true, nil
		}
	}

	return false, nil
}

func imageDigestIsForbiddenByDbx(digests *imageDigestCache, dbx efi.SignatureDatabase) (bool, error) {
	for _, sigList := range dbx {
		match, err := imageDigestMatchesDbSignatureList(digests, sigList)
		if err != nil {
			return false, err
		}

		if match {
			return true, nil
		}
	}

	return false, nil
}

func efiSignatureListTypeToDigestAlg(guid efi.GUID) crypto.Hash {
	switch guid {
	case efi.CertSHA1Guid:
		return crypto.SHA1
	case efi.CertSHA224Guid:
		return crypto.SHA224
	case efi.CertSHA256Guid:
		return crypto.SHA256
	case efi.CertSHA384Guid:
		return crypto.SHA384
	case efi.CertSHA512Guid:
		return crypto.SHA512
	default:
		return crypto.Hash(0)
	}
}
