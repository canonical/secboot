// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package tpm2_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mssim"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

var (
	testCACert []byte
	testEkCert []byte

	testAuth = []byte("1234")
)

func init() {
	tpm2_testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

func secureConnectToDefaultTPMHelper() (*Connection, error) {
	buf := new(bytes.Buffer)

	caCert, err := x509.ParseCertificate(testCACert)
	if err != nil {
		return nil, err
	}

	if err := EncodeEKCertificateChain(nil, []*x509.Certificate{caCert}, buf); err != nil {
		return nil, err
	}

	return SecureConnectToDefaultTPM(buf, nil)
}

// Set the hierarchy auth to testAuth. Fatal on failure
func setHierarchyAuthForTest(t *testing.T, tpm *Connection, hierarchy tpm2.ResourceContext) {
	if err := tpm.HierarchyChangeAuth(hierarchy, testAuth, nil); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
}

func TestMain(m *testing.M) {
	// Provide a way for run-tests to configure this in a way that
	// can be ignored by other suites
	if _, ok := os.LookupEnv("USE_MSSIM"); ok {
		tpm2_testutil.TPMBackend = tpm2_testutil.TPMBackendMssim
	}

	flag.Parse()
	rand.Seed(time.Now().UnixNano())
	os.Exit(func() int {
		if tpm2_testutil.TPMBackend == tpm2_testutil.TPMBackendMssim {
			simulatorCleanup, err := tpm2_testutil.LaunchTPMSimulator(nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot launch TPM simulator: %v\n", err)
				return 1
			}
			defer simulatorCleanup()

			var caKey crypto.PrivateKey
			testCACert, caKey, err = tpm2test.CreateTestCA()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot create test TPM CA certificate and private key: %v\n", err)
				return 1
			}

			restoreCAHashes := tpm2test.TrustCA(testCACert)
			defer restoreCAHashes()

			if err := func() error {
				tcti, err := mssim.OpenConnection("", tpm2_testutil.MssimPort)
				if err != nil {
					return fmt.Errorf("cannot open connection: %w", err)
				}
				tpm := tpm2.NewTPMContext(tcti)
				defer tpm.Close()

				testEkCert, err = tpm2test.CreateTestEKCert(tpm, testCACert, caKey)
				if err != nil {
					return fmt.Errorf("cannot create test EK certificate: %w", err)
				}
				return tpm2test.CertifyTPM(tpm, testEkCert)
			}(); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot certify TPM simulator: %v\n", err)
				return 1
			}
		}

		return m.Run()
	}())
}
