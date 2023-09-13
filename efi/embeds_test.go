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

package efi_test

import (
	_ "embed"

	"github.com/snapcore/secboot/internal/testutil"
)

var (
	//go:embed testdata/src/certs/MicrosoftKEK.crt
	msKEKCertPEM []byte

	//go:embed testdata/src/certs/MicrosoftPCA.crt
	msPCACertPEM []byte

	//go:embed testdata/src/certs/MicrosoftUefiCA.crt
	msUefiCACertPEM []byte

	//go:embed testdata/src/certs/canonical-uefi-ca.crt
	canonicalCACertPEM []byte
)

var (
	//go:embed testdata/src/keys/TestPk1.key
	testPKKey1PEM []byte

	//go:embed testdata/src/keys/TestPk2.key
	testPKKey2PEM []byte

	//go:embed testdata/src/keys/TestRoot1.key
	testRootKeyPEM []byte

	//go:embed testdata/src/keys/TestKek1.1.key
	testKEKKeyPEM []byte

	//go:embed testdata/src/keys/TestUefiCA1.1.key
	testUefiCAKey1PEM []byte

	//go:embed testdata/src/keys/TestUefiSigning1.1.1.key
	testUefiSigningKey1_1PEM []byte

	//go:embed testdata/src/keys/TestUefiCA1.2.key
	testUefiCAKey2PEM []byte
)

var (
	//go:embed testdata/src/sigs/shim-signed_1.41+15+1552672080.a4a1fbe-0ubuntu1_amd64.pk7
	shimUbuntuSig1PEM []byte

	//go:embed testdata/src/sigs/shim-signed_1.40.4+15+1552672080.a4a1fbe-0ubuntu2_amd64.pk7
	shimUbuntuSig2PEM []byte

	//go:embed testdata/src/sigs/shim-signed_1.51+15.4-0ubuntu9_amd64.pk7
	shimUbuntuSig3PEM []byte

	//go:embed testdata/src/sigs/shim-signed_1.54+15.7-0ubuntu1_amd64_latest.pk7
	shimUbuntuSig4PEM []byte

	//go:embed testdata/src/sigs/grub-efi-amd64-signed_1.142+2.04-1ubuntu26_amd64.pk7
	grubUbuntuSig1PEM []byte

	//go:embed testdata/src/sigs/grub-efi-amd64-signed_1.173.4+2.04-1ubuntu47.5_amd64.pk7
	grubUbuntuSig2PEM []byte

	//go:embed testdata/src/sigs/grub-efi-amd64-signed_1.187.3~20.04.1+2.06-2ubuntu14.1_amd64.pk7
	grubUbuntuSig3PEM []byte

	//go:embed testdata/src/sigs/pc-kernel_1178.snap.amd64.pk7
	kernelUbuntuSig1PEM []byte

	//go:embed testdata/src/sigs/pc-kernel_1277.snap.amd64.pk7
	kernelUbuntuSig2PEM []byte

	//go:embed testdata/src/sigs/pc-kernel_1291.snap.amd64.pk7
	kernelUbuntuSig3PEM []byte

	//go:embed testdata/src/sigs/pc-kernel_1299.snap.amd64.pk7
	kernelUbuntuSig4PEM []byte
)

var (
	//go:embed testdata/src/uefi.org/revocationlistfile/2016-08-08/dbxupdate.bin
	msDbxUpdate1 []byte

	//go:embed testdata/src/uefi.org/revocationlistfile/2020-10-12/dbxupdate_x64_1.bin
	msDbxUpdate2 []byte
)

var (
	shimUbuntuSig1 []byte
	shimUbuntuSig2 []byte
	shimUbuntuSig3 []byte
	shimUbuntuSig4 []byte

	grubUbuntuSig1 []byte
	grubUbuntuSig2 []byte
	grubUbuntuSig3 []byte

	kernelUbuntuSig1 []byte
	kernelUbuntuSig2 []byte
	kernelUbuntuSig3 []byte
	kernelUbuntuSig4 []byte
)

func init() {
	shimUbuntuSig1 = testutil.MustDecodePEMType("PKCS7", shimUbuntuSig1PEM)
	shimUbuntuSig2 = testutil.MustDecodePEMType("PKCS7", shimUbuntuSig2PEM)
	shimUbuntuSig3 = testutil.MustDecodePEMType("PKCS7", shimUbuntuSig3PEM)
	shimUbuntuSig4 = testutil.MustDecodePEMType("PKCS7", shimUbuntuSig4PEM)

	grubUbuntuSig1 = testutil.MustDecodePEMType("PKCS7", grubUbuntuSig1PEM)
	grubUbuntuSig2 = testutil.MustDecodePEMType("PKCS7", grubUbuntuSig2PEM)
	grubUbuntuSig3 = testutil.MustDecodePEMType("PKCS7", grubUbuntuSig3PEM)

	kernelUbuntuSig1 = testutil.MustDecodePEMType("PKCS7", kernelUbuntuSig1PEM)
	kernelUbuntuSig2 = testutil.MustDecodePEMType("PKCS7", kernelUbuntuSig2PEM)
	kernelUbuntuSig3 = testutil.MustDecodePEMType("PKCS7", kernelUbuntuSig3PEM)
	kernelUbuntuSig4 = testutil.MustDecodePEMType("PKCS7", kernelUbuntuSig4PEM)
}
