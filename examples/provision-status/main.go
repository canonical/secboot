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
	"fmt"
	"os"

	"github.com/snapcore/secboot"
)

func run() int {
	tpm, err := secboot.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to TPM: %v\n", err)
		return 1
	}
	defer tpm.Close()

	status, err := secboot.ProvisionStatus(tpm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot determine status: %v\n", err)
		return 1
	}

	if status&secboot.AttrValidSRK > 0 {
		fmt.Println("Valid SRK found in TPM")
	} else {
		fmt.Println("** ERROR: TPM does not have a valid SRK **")
	}

	if status&secboot.AttrValidEK > 0 {
		fmt.Println("Valid EK found in TPM")
	} else {
		fmt.Println("** ERROR: TPM does not have a valid EK **")
	}

	if status&secboot.AttrDAParamsOK > 0 {
		fmt.Println("TPM's DA parameters are correct")
	} else {
		fmt.Println("** ERROR: TPM's DA parameters are not the values set during provisioning **")
	}

	if status&secboot.AttrOwnerClearDisabled > 0 {
		fmt.Println("TPM does not allow clearing with the lockout hierarchy authorization")
	} else {
		fmt.Println("** ERROR: TPM allows clearing with the lockout hierarchy authorization **")
	}

	if status&secboot.AttrLockoutAuthSet > 0 {
		fmt.Println("The lockout hierarchy authorization is set")
	} else {
		fmt.Println("** ERROR: The lockout hierarchy authorization is not set **")
	}

	if status&secboot.AttrValidLockNVIndex > 0 {
		fmt.Println("Valid lock NV index found in TPM")
	} else {
		fmt.Println("** ERROR: TPM does not have a valid lock NV index **")
	}

	return 0
}

func main() {
	os.Exit(run())
}
