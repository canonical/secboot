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

package preinstall_test

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"testing"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	secboot_efi "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

var (
	//go:embed testdata/MicrosoftUefiCA.crt
	msUefiCACertPEM []byte

	//go:embed testdata/MicrosoftUefiCA2023.crt
	msUefiCACert2023PEM []byte

	//go:embed testdata/shim-signed_1.54+15.7-0ubuntu1_amd64_latest.pk7
	shimUbuntuSig4PEM []byte

	//go:embed testdata/PkKek-1-snakeoil.pem
	snakeoilCertPEM []byte

	msUefiCACert     []byte
	msUefiCACert2023 []byte
	shimUbuntuSig4   []byte
	snakeoilCert     []byte
)

func init() {
	tpm2_testutil.AddCommandLineFlags()

	msUefiCACert = testutil.MustDecodePEMType("CERTIFICATE", msUefiCACertPEM)
	msUefiCACert2023 = testutil.MustDecodePEMType("CERTIFICATE", msUefiCACert2023PEM)
	shimUbuntuSig4 = testutil.MustDecodePEMType("PKCS7", shimUbuntuSig4PEM)
	snakeoilCert = testutil.MustDecodePEMType("CERTIFICATE", snakeoilCertPEM)
}

func Test(t *testing.T) { TestingT(t) }

type invalidEventData struct {
	err error
}

func (e *invalidEventData) String() string        { return "invalid event data: " + e.err.Error() }
func (*invalidEventData) Bytes() []byte           { return nil }
func (*invalidEventData) Write(w io.Writer) error { return errors.New("not supported") }
func (e *invalidEventData) Error() string         { return e.err.Error() }

type mockImageReader struct {
	contents   []byte
	digest     tpm2.Digest
	signatures []*efi.WinCertificateAuthenticode
	closed     bool
}

func (r *mockImageReader) ReadAt(data []byte, offset int64) (int, error) {
	copy(data, r.contents[offset:])
	return len(data), nil
}

func (r *mockImageReader) Close() error {
	if r.closed {
		return errors.New("already closed")
	}
	r.closed = true
	return nil
}

func (r *mockImageReader) Size() int64 {
	return int64(len(r.contents))
}

type mockImage struct {
	contents   []byte      // Used to produce a flat-file digest
	digest     tpm2.Digest // Authenticode digest
	signatures []*efi.WinCertificateAuthenticode
}

func (i *mockImage) String() string {
	return "mock image"
}

func (i *mockImage) Open() (secboot_efi.ImageReader, error) {
	return &mockImageReader{
		contents:   i.contents,
		digest:     i.digest,
		signatures: i.signatures}, nil
}

func TestMain(m *testing.M) {
	// Provide a way for run-tests to configure this in a way that
	// can be ignored by other suites
	if _, ok := os.LookupEnv("USE_MSSIM"); ok {
		tpm2_testutil.TPMBackend = tpm2_testutil.TPMBackendMssim
	}

	flag.Parse()
	os.Exit(func() int {
		if tpm2_testutil.TPMBackend == tpm2_testutil.TPMBackendMssim {
			simulatorCleanup, err := tpm2_testutil.LaunchTPMSimulator(nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot launch TPM simulator: %v\n", err)
				return 1
			}
			defer simulatorCleanup()
		}

		return m.Run()
	}())
}
