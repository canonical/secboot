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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot"
)

type pathList []string

func (l *pathList) String() string {
	var builder bytes.Buffer
	for i, path := range *l {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(path)
	}
	return builder.String()
}

func (l *pathList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

var create bool
var clearKeyFile string
var keyFile string
var policyUpdateDataFile string
var pinIndex string
var ownerAuth string
var kernels pathList
var grubs pathList
var shims pathList

func init() {
	flag.BoolVar(&create, "new", false, "Create a new key file using the SealKeyToTPM API")
	flag.StringVar(&clearKeyFile, "clear-key-file", "", "Path of the file containing the cleartext key to seal (with -new)")
	flag.StringVar(&keyFile, "key-file", "", "Path of the sealed key data file to create (with -new) or to update (without -new)")
	flag.StringVar(&policyUpdateDataFile, "policy-update-data-file", "",
		"Path of the file containing data required for updating policy, to create (with -new) or to use (without -new)")
	flag.StringVar(&pinIndex, "pin-index", "", "Handle to use for the PIN NV index (with -new)")
	flag.StringVar(&ownerAuth, "auth", "", "Authorization value for the storage hierarchy (with -new)")
	flag.Var(&kernels, "with-kernel", "")
	flag.Var(&grubs, "with-grub", "")
	flag.Var(&shims, "with-shim", "")
}

func run() int {
	if keyFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -key-file\n")
		return 1
	}

	tpm, err := secboot.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to TPM: %v\n", err)
		return 1
	}
	defer tpm.Close()

	pcrProfile := secboot.NewPCRProtectionProfile()
	if len(shims) == 0 && len(grubs) == 0 && len(kernels) == 0 {
		pcrProfile.AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7)
	} else {
		secureBootParams := &secboot.EFISecureBootPolicyProfileParams{PCRAlgorithm: tpm2.HashAlgorithmSHA256}
		for _, shim := range shims {
			s := &secboot.EFIImageLoadEvent{Source: secboot.Firmware, Image: secboot.FileEFIImage(shim)}
			for _, grub := range grubs {
				g := &secboot.EFIImageLoadEvent{Source: secboot.Shim, Image: secboot.FileEFIImage(grub)}
				for _, kernel := range kernels {
					k := &secboot.EFIImageLoadEvent{Source: secboot.Shim, Image: secboot.FileEFIImage(kernel)}
					g.Next = append(g.Next, k)
				}
				s.Next = append(s.Next, g)
			}
			secureBootParams.LoadSequences = append(secureBootParams.LoadSequences, s)
		}
		if err := secboot.AddEFISecureBootPolicyProfile(pcrProfile, secureBootParams); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot add EFI secure boot policy profile to PCR profile: %v\n", err)
			return 1
		}
	}

	if create {
		if clearKeyFile == "" {
			fmt.Fprintf(os.Stderr, "Missing -master-key-file\n")
			return 1
		}
		if pinIndex == "" {
			fmt.Fprintf(os.Stderr, "Missing -pin-index\n")
			return 1
		}

		var in *os.File
		if clearKeyFile == "-" {
			in = os.Stdin
		} else {
			f, err := os.Open(clearKeyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot open key file: %v\n", err)
				return 1
			}
			in = f
			defer in.Close()
		}

		var pinHandle tpm2.Handle
		if h, err := hex.DecodeString(pinIndex); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid -pin-index: %v\n", err)
			return 1
		} else {
			pinHandle = tpm2.Handle(binary.BigEndian.Uint32(h))
		}

		key, err := ioutil.ReadAll(in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read key: %v\n", err)
			return 1
		}

		createParams := secboot.KeyCreationParams{PCRProfile: pcrProfile, PINHandle: pinHandle}
		tpm.OwnerHandleContext().SetAuthValue([]byte(ownerAuth))

		if err := secboot.SealKeyToTPM(tpm, key, keyFile, policyUpdateDataFile, &createParams); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot seal key to TPM: %v\n", err)
			return 1
		}
	} else {
		if policyUpdateDataFile == "" {
			fmt.Fprintf(os.Stderr, "Missing -policy-update-data-file\n")
			return 1
		}

		if err := secboot.UpdateKeyPCRProtectionPolicy(tpm, keyFile, policyUpdateDataFile, pcrProfile); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot update key PCR protection policy: %v\n", err)
			return 1
		}
	}

	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
