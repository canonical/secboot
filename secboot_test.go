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

package secboot_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	"golang.org/x/xerrors"

	. "gopkg.in/check.v1"
)

var (
	testCACert []byte
	testEkCert []byte

	testAuth = []byte("1234")
)

func Test(t *testing.T) { TestingT(t) }

// resetTPMSimulator executes reset sequence of the TPM (Shutdown(CLEAR) -> reset -> Startup(CLEAR)) and the re-initializes the
// TPMConnection.
func resetTPMSimulator(t *testing.T, tpm *TPMConnection, tcti *tpm2.TctiMssim) (*TPMConnection, *tpm2.TctiMssim) {
	tpm, tcti, err := testutil.ResetTPMSimulator(tpm, tcti)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return tpm, tcti
}

func openTPMSimulatorForTesting(t *testing.T) (*TPMConnection, *tpm2.TctiMssim) {
	tpm, tcti, err := testutil.OpenTPMSimulatorForTesting()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if tpm == nil {
		t.SkipNow()
	}
	return tpm, tcti
}

func openTPMForTesting(t *testing.T) *TPMConnection {
	tpm, err := testutil.OpenTPMForTesting()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if tpm == nil {
		t.SkipNow()
	}
	return tpm
}

func decodeHexStringT(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("DecodeHexString failed: %v", err)
	}
	return b
}

// Flush a handle context. Fails the test if it doesn't succeed.
func flushContext(t *testing.T, tpm *TPMConnection, context tpm2.HandleContext) {
	if err := tpm.FlushContext(context); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}
}

// Set the hierarchy auth to testAuth. Fatal on failure
func setHierarchyAuthForTest(t *testing.T, tpm *TPMConnection, hierarchy tpm2.ResourceContext) {
	if err := tpm.HierarchyChangeAuth(hierarchy, testAuth, nil); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
}

// Reset the hierarchy auth to nil.
func resetHierarchyAuth(t *testing.T, tpm *TPMConnection, hierarchy tpm2.ResourceContext) {
	if err := tpm.HierarchyChangeAuth(hierarchy, nil, nil); err != nil {
		t.Errorf("HierarchyChangeAuth failed: %v", err)
	}
}

// Undefine a NV index set by a test. Fails the test if it doesn't succeed.
func undefineNVSpace(t *testing.T, tpm *TPMConnection, context, authHandle tpm2.ResourceContext) {
	if err := tpm.NVUndefineSpace(authHandle, context, nil); err != nil {
		t.Errorf("NVUndefineSpace failed: %v", err)
	}
}

func undefineKeyNVSpace(t *testing.T, tpm *TPMConnection, path string) {
	k, err := ReadSealedKeyObject(path)
	if err != nil {
		t.Fatalf("ReadSealedKeyObject failed: %v", err)
	}
	rc, err := tpm.CreateResourceContextFromTPM(k.PINIndexHandle())
	if err != nil {
		t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
	}
	undefineNVSpace(t, tpm, rc, tpm.OwnerHandleContext())
}

// clearTPMWithPlatformAuth clears the TPM with platform hierarchy authorization - something that we can only do on the simulator
func clearTPMWithPlatformAuth(t *testing.T, tpm *TPMConnection) {
	if err := tpm.ClearControl(tpm.PlatformHandleContext(), false, nil); err != nil {
		t.Fatalf("ClearControl failed: %v", err)
	}
	if err := tpm.Clear(tpm.PlatformHandleContext(), nil); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}
}

func closeTPM(t *testing.T, tpm *TPMConnection) {
	if err := tpm.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())
	os.Exit(func() int {
		if testutil.UseMssim {
			simulatorCleanup, err := testutil.LaunchTPMSimulator(nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot launch TPM simulator: %v\n", err)
				return 1
			}
			defer simulatorCleanup()

			var caKey crypto.PrivateKey
			testCACert, caKey, err = testutil.CreateTestCA()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot create test TPM CA certificate and private key: %v\n", err)
				return 1
			}

			restoreCAHashes := testutil.TrustCA(testCACert)
			defer restoreCAHashes()

			if err := func() error {
				tpm, _, err := testutil.OpenTPMSimulatorForTesting()
				if err != nil {
					return xerrors.Errorf("cannot open connection: %w", err)
				}
				defer tpm.Close()

				testEkCert, err = testutil.CreateTestEKCert(tpm.TPMContext, testCACert, caKey)
				if err != nil {
					return xerrors.Errorf("cannot create test EK certificate: %w", err)
				}
				return testutil.CertifyTPM(tpm.TPMContext, testEkCert)
			}(); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot certify TPM simulator: %v\n", err)
				return 1
			}

			caCert, _ := x509.ParseCertificate(testCACert)
			b := new(bytes.Buffer)
			if err := EncodeEKCertificateChain(nil, []*x509.Certificate{caCert}, b); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot encode EK certificate chain: %v\n", err)
				return 1
			}
			testutil.EncodedTPMSimulatorEKCertChain = b.Bytes()
		}

		return m.Run()
	}())
}
