// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package efi_test

import (
	"crypto"
	"os"

	. "github.com/snapcore/secboot/internal/efi"
	pe "github.com/snapcore/secboot/internal/pe1.14"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type secureBootSignaturesSuite struct{}

var _ = Suite(&secureBootSignaturesSuite{})

func (s *secureBootSignaturesSuite) testSecureBootSignatures(c *C, path string, digests [][]byte) {
	//path, err := filepath.EvalSymlinks(path)
	//c.Assert(err, IsNil)

	f, err := os.Open(path)
	c.Assert(err, IsNil)
	defer f.Close()

	pefile, err := pe.NewFile(f)
	c.Assert(err, IsNil)

	sigs, err := SecureBootSignaturesFromPEFile(pefile, f)
	c.Check(err, IsNil)
	c.Assert(sigs, HasLen, len(digests))

	for i, expected := range digests {
		h := crypto.SHA256.New()
		h.Write(sigs[i].GetSigner().RawTBSCertificate)
		c.Check(h.Sum(nil), DeepEquals, expected)
	}
}

func (s *secureBootSignaturesSuite) TestSecureBootSignatures(c *C) {
	s.testSecureBootSignatures(c,
		"testdata/amd64/mockshim.efi.signed.1.1.1",
		[][]byte{testutil.DecodeHexString(c, "4c503fa92a4d6ab180962c29aa8324cc873e8f74b259fb28347443ac8fef6af8")})
}

func (s *secureBootSignaturesSuite) TestSecureBootSignaturesUnsigned(c *C) {
	s.testSecureBootSignatures(c, "testdata/amd64/mockkernel1.efi", nil)
}

func (s *secureBootSignaturesSuite) TestSecureBootSignaturesDualSigned(c *C) {
	s.testSecureBootSignatures(c,
		"testdata/amd64/mockshim.efi.signed.1.2.1+1.1.1",
		[][]byte{
			testutil.DecodeHexString(c, "713af30678aba44b6c437cfc4fec26d386d3e2fea75b055df010d4af7b11b484"),
			testutil.DecodeHexString(c, "4c503fa92a4d6ab180962c29aa8324cc873e8f74b259fb28347443ac8fef6af8")})
}
