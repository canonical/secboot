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
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/snapcore/secboot"
)

func run() int {
	args := flag.Args()
	if len(args) == 0 {
		fmt.Printf("Usage: activate-volume VOLUME SOURCE-DEVICE SEALED-KEY-FILE [AUTH-FILE] [OPTIONS]\n")
		return 0
	}

	if len(args) < 3 {
		fmt.Fprintf(os.Stderr, "Cannot activate device: insufficient arguments\n")
		return 1
	}

	volume := args[0]
	sourceDevice := args[1]

	var keyFilePath string
	if args[2] != "" && args[2] != "-" && args[2] != "none" {
		keyFilePath = args[2]
	}

	var authFilePath string
	if len(args) >= 4 && args[3] != "" && args[3] != "-" && args[3] != "none" {
		authFilePath = args[3]
	}

	var lock bool
	var forceRecovery bool
	pinTries := 1
	recoveryTries := 1
	var activateOptions []string

	if len(args) >= 5 && args[4] != "" && args[4] != "-" && args[4] != "none" {
		opts := strings.Split(args[4], ",")
		for _, opt := range opts {
			switch {
			case opt == "lock":
				lock = true
			case opt == "force-recovery":
				forceRecovery = true
			case strings.HasPrefix(opt, "pin-tries="):
				u, err := strconv.ParseUint(strings.TrimPrefix(opt, "pin-tries="), 10, 8)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Cannot activate device %s: invalid value for \"recovery-tries=\"\n", sourceDevice)
					return 1
				}
				pinTries = int(u)
			case strings.HasPrefix(opt, "recovery-tries="):
				u, err := strconv.ParseUint(strings.TrimPrefix(opt, "recovery-tries="), 10, 8)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Cannot activate device %s: invalid value for \"recovery-tries=\"\n", sourceDevice)
					return 1
				}
				recoveryTries = int(u)
			default:
				activateOptions = append(activateOptions, opt)
			}
		}
	}

	var authReader io.Reader
	if authFilePath != "" {
		f, err := os.Open(authFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open auth file: %v\n", err)
			return 1
		}
		defer f.Close()
		authReader = f
	}

	if !forceRecovery {
		tpm, err := secboot.ConnectToDefaultTPM()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot connect to TPM: %v\n", err)
			return 1
		}
		defer tpm.Close()

		options := secboot.ActivateWithTPMSealedKeyOptions{
			PINTries:            pinTries,
			RecoveryKeyTries:    recoveryTries,
			ActivateOptions:     activateOptions,
			LockSealedKeyAccess: lock}
		if success, err := secboot.ActivateVolumeWithTPMSealedKey(tpm, volume, sourceDevice, keyFilePath, authReader, &options); err != nil {
			if !success {
				fmt.Fprintf(os.Stderr, "Activation failed: %v\n", err)
				return 1
			}
			fmt.Printf("Activation succeeded with fallback recovery key: %v\n", err)
		}
	} else {
		options := secboot.ActivateWithRecoveryKeyOptions{
			Tries:           recoveryTries,
			ActivateOptions: activateOptions}
		if err := secboot.ActivateVolumeWithRecoveryKey(volume, sourceDevice, authReader, &options); err != nil {
			fmt.Fprintf(os.Stderr, "Activation with recovery key failed: %v\n", err)
			return 1
		}
	}

	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
