// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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

package tpm2_fido2_test

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	"github.com/canonical/go-tpm2"
	. "gopkg.in/check.v1"

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
		}

		return m.Run()
	}())
}
