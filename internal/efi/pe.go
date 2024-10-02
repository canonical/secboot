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
	"crypto"
	"errors"
	"fmt"
	"io"

	efi "github.com/canonical/go-efilib"
	pe "github.com/snapcore/secboot/internal/pe1.14"
)

const (
	certTableIndex = 4 // Index of the Certificate Table entry in the Data Directory of a PE image optional header
)

func SecureBootSignaturesFromPEFile(pefile *pe.File, r io.ReaderAt) ([]*efi.WinCertificateAuthenticode, error) {
	// Obtain security directory entry from optional header
	var dd []pe.DataDirectory
	switch oh := pefile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd = oh.DataDirectory[0:oh.NumberOfRvaAndSizes]
	case *pe.OptionalHeader64:
		dd = oh.DataDirectory[0:oh.NumberOfRvaAndSizes]
	default:
		return nil, errors.New("cannot obtain security directory entry: no optional header")
	}

	if len(dd) <= certTableIndex {
		// This image doesn't include a certificate table entry, so has no signatures.
		return nil, nil
	}

	// Create a reader for the security directory entry, which points to one or more WIN_CERTIFICATE structs
	certReader := io.NewSectionReader(
		r,
		int64(dd[certTableIndex].VirtualAddress),
		int64(dd[certTableIndex].Size))

	// Binaries can have multiple signers - this is achieved using multiple single-signed Authenticode
	// signatures - see section 32.5.3.3 ("Secure Boot and Driver Signing - UEFI Image Validation -
	// Signature Database Update - Authorization Process") of the UEFI Specification, version 2.8.
	var sigs []*efi.WinCertificateAuthenticode

SignatureLoop:
	for i := 0; ; i++ {
		// Signatures in this section are 8-byte aligned - see the PE spec:
		// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
		off, _ := certReader.Seek(0, io.SeekCurrent)
		alignSize := (8 - (off & 7)) % 8
		certReader.Seek(alignSize, io.SeekCurrent)

		c, err := efi.ReadWinCertificate(certReader)
		switch {
		case errors.Is(err, io.EOF):
			break SignatureLoop
		case err != nil:
			return nil, fmt.Errorf("cannot decode WIN_CERTIFICATE from security directory entry %d: %w", i, err)
		}

		sig, ok := c.(*efi.WinCertificateAuthenticode)
		if !ok {
			return nil, fmt.Errorf("unexpected WIN_CERTIFICATE type from security directory entry %d: not an Authenticode signature", i)
		}

		// Reject any signature with a digest algorithm other than SHA256, as that's the only algorithm used
		// for binaries we're expected to support, and therefore required by the UEFI implementation.
		if sig.DigestAlgorithm() != crypto.SHA256 {
			return nil, fmt.Errorf("signature from security directory entry %d has unexpected digest algorithm", i)
		}

		sigs = append(sigs, sig)
	}

	return sigs, nil
}
