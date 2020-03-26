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

var keyFile string
var outFile string
var pin string

func init() {
	flag.StringVar(&keyFile, "key-file", "", "Path of the sealed key data file")
	flag.StringVar(&outFile, "out-file", "", "Path of the file to store the cleartext key in")
	flag.StringVar(&pin, "pin", "", "")
}

func run() int {
	if keyFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -key-file\n")
		return 1
	}
	if outFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -out-file\n")
		return 1
	}

	var out *os.File
	if outFile == "-" {
		out = os.Stdout
	} else {
		f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open output file: %v\n", err)
			return 1
		}
		out = f
		defer out.Close()
	}

	tpm, err := secboot.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to TPM: %v\n", err)
		return 1
	}
	defer tpm.Close()

	k, err := secboot.ReadSealedKeyObject(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot load sealed key object: %v\n", err)
		return 1
	}

	key, err := k.UnsealFromTPM(tpm, pin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unseal key: %v\n", err)
		return 1
	}

	_, err = out.Write(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write unsealed key: %v\n", err)
		return 1
	}

	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
