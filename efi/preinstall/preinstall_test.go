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
	"flag"
	"fmt"
	"os"
	"testing"

	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	. "gopkg.in/check.v1"
)

func init() {
	tpm2_testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

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
