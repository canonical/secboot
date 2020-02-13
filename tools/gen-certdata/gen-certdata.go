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
	"crypto"
	_ "crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: gen-certdata <dir> <out>\n")
		os.Exit(1)
	}

	in := os.Args[1]
	files, err := ioutil.ReadDir(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read directory contents: %v\n", err)
		os.Exit(1)
	}

	var buffer bytes.Buffer

	buffer.WriteString("package secboot\n\n")
	buffer.WriteString("var (\n")
	buffer.WriteString("\trootCAHashes = [][]byte{\n")

	for _, fi := range files {
		buffer.WriteString("\t\t[]byte{")
		path := filepath.Join(in, fi.Name())
		data, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read file: %v\n", err)
			os.Exit(1)
		}
		h := crypto.SHA256.New()
		h.Write(data)
		hash := h.Sum(nil)
		for i, b := range hash {
			if i > 0 {
				buffer.WriteString(", ")
			}
			buffer.WriteString(fmt.Sprintf("0x%02x", b))
		}
		buffer.WriteString("},\n")
	}

	buffer.WriteString("\t}\n")
	buffer.WriteString(")\n")

	if err := ioutil.WriteFile(os.Args[2], buffer.Bytes(), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write output file: %v\n", err)
		os.Exit(1)
	}
}
