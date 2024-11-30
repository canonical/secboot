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

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/snapcore/secboot"
)

var (
	clear           bool
	lockoutAuth     string
	noLockoutAuth   bool
	ownerAuth       string
	endorsementAuth string
	requestClear    bool
)

func init() {
	flag.BoolVar(&clear, "clear", false, "Attempt to clear the TPM before provisioning")
	flag.StringVar(&lockoutAuth, "lockout-auth", "", "The current lockout hierarchy authorization value")
	flag.BoolVar(&noLockoutAuth, "no-lockout-auth", false,
		"Don't perform provisioning actions that require the use of the lockout hierarchy authorization")
	flag.StringVar(&ownerAuth, "owner-auth", "", "The current storage hierarchy authorization value")
	flag.StringVar(&endorsementAuth, "endorsement-auth", "", "The current endorsement hierarchy authorization value")
	flag.BoolVar(&requestClear, "request-clear", false, "Request to clear the TPM via the physical presence interface")
}

func run() int {
	args := flag.Args()

	if requestClear {
		if err := secboot.RequestTPMClearUsingPPI(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to request clearing the TPM via the PPI: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Request to clear the TPM submitted successfully. Now perform a system restart")
		return 0
	}

	if clear && noLockoutAuth {
		fmt.Fprintf(os.Stderr, "-clear and -no-lockout-auth can't be used at the same time\n")
		return 1
	}

	var newLockoutAuth string
	if len(args) > 0 {
		newLockoutAuth = args[0]
	}

	tpm, err := secboot.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to TPM: %v\n", err)
		return 1
	}
	defer tpm.Close()

	var mode secboot.ProvisionMode
	switch {
	case clear:
		mode = secboot.ProvisionModeClear
	case noLockoutAuth:
		mode = secboot.ProvisionModeWithoutLockout
	default:
		mode = secboot.ProvisionModeFull
	}

	tpm.OwnerHandleContext().SetAuthValue([]byte(ownerAuth))
	tpm.EndorsementHandleContext().SetAuthValue([]byte(endorsementAuth))
	tpm.LockoutHandleContext().SetAuthValue([]byte(lockoutAuth))

	if err := secboot.ProvisionTPM(tpm, mode, []byte(newLockoutAuth)); err != nil {
		switch err {
		case secboot.ErrTPMClearRequiresPPI:
			fmt.Fprintf(os.Stderr, "Clearing requires the use of the physical presence interface. Re-run with -request-clear\n")
		case secboot.ErrTPMLockout:
			fmt.Fprintf(os.Stderr, "The lockout hierarchy is in dictionary attack lockout mode. Either wait for the recovery time to expire, "+
				"or request to clear the TPM with -request-clear\n")
		default:
			fmt.Fprintf(os.Stderr, "Failed to provision the TPM: %v\n", err)
		}
		return 1
	}

	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
