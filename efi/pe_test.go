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
	_ "crypto/sha1"
	_ "crypto/sha256"

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	. "github.com/snapcore/secboot/efi"
	pe "github.com/snapcore/secboot/internal/pe1.14"
	"github.com/snapcore/secboot/internal/testutil"
)

type peSuite struct{}

var _ = Suite(&peSuite{})

func (s *peSuite) testPeImageHandleSource(c *C) {
	source := NewFileImage("testdata/amd64/mockshim.efi.signed.1.1.1")

	image, err := OpenPeImage(source)
	c.Assert(err, IsNil)
	defer image.Close()

	c.Check(image.Source(), Equals, source)
}

func (s *peSuite) TestPeImageHandleOpenSection(c *C) {
	source := NewFileImage("testdata/amd64/mockshim.efi.signed.1.1.1")

	r, err := source.Open()
	c.Assert(err, IsNil)
	defer r.Close()

	pefile, err := pe.NewFile(r)
	c.Assert(err, IsNil)

	image, err := OpenPeImage(source)
	c.Assert(err, IsNil)
	defer image.Close()

	section := image.OpenSection(".text")
	c.Assert(section, NotNil)
	c.Check(section.Size(), Equals, int64(pefile.Section(".text").Size))
}

func (s *peSuite) TestPeImageHandleOpenSectionMissing(c *C) {
	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockshim.efi.signed.1.1.1"))
	c.Assert(err, IsNil)
	defer image.Close()

	section := image.OpenSection(".foo")
	c.Check(section, IsNil)
}

func (s *peSuite) TestPeImageHandleHasSectionTrue(c *C) {
	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockshim.efi.signed.1.1.1"))
	c.Assert(err, IsNil)
	defer image.Close()

	c.Check(image.HasSection(".text"), testutil.IsTrue)
}

func (s *peSuite) TestPeImageHandleHasSectionFalse(c *C) {
	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockshim.efi.signed.1.1.1"))
	c.Assert(err, IsNil)
	defer image.Close()

	c.Check(image.HasSection(".foo"), Not(testutil.IsTrue))
}

func (s *peSuite) TestPeImageHandleHasSbatSectionTrue(c *C) {
	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockshim.efi.signed.1.1.1"))
	c.Assert(err, IsNil)
	defer image.Close()

	c.Check(image.HasSbatSection(), testutil.IsTrue)
}

func (s *peSuite) TestPeImageHandleHasSbatSectionFalse(c *C) {
	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockshim_no_sbat.efi.signed.1.1.1"))
	c.Assert(err, IsNil)
	defer image.Close()

	c.Check(image.HasSbatSection(), Not(testutil.IsTrue))
}

func (s *peSuite) testPeImageHandleSbatComponents(c *C, path string, expected []SbatComponent) {
	image, err := OpenPeImage(NewFileImage(path))
	c.Assert(err, IsNil)
	defer image.Close()

	components, err := image.SbatComponents()
	c.Check(err, IsNil)
	c.Check(components, DeepEquals, expected)
}

func (s *peSuite) TestPeImageHandleSbatComponents1(c *C) {
	s.testPeImageHandleSbatComponents(
		c, "testdata/amd64/mockshim.efi.signed.1.1.1",
		[]SbatComponent{
			{Name: "shim", Generation: 1, VendorName: "UEFI shim", VendorPackageName: "shim", VendorVersion: "15.7", VendorUrl: "https://github.com/rhboot/shim"},
			{Name: "shim.acme", Generation: 1, VendorName: "Acme Corporation", VendorPackageName: "shim", VendorVersion: "1", VendorUrl: "https://acme.invalid/shim"},
		})
}

func (s *peSuite) TestPeImageHandleSbatComponents2(c *C) {
	s.testPeImageHandleSbatComponents(
		c, "testdata/amd64/mockgrub1.efi.signed.shim.1",
		[]SbatComponent{
			{Name: "grub", Generation: 1, VendorName: "Free Software Foundation", VendorPackageName: "grub", VendorVersion: "2.06", VendorUrl: "https://www.gnu.org/software/grub/"},
			{Name: "grub.acme", Generation: 1, VendorName: "Acme Corporation", VendorPackageName: "grub", VendorVersion: "1", VendorUrl: "https://acme.invalid/grub"},
		})
}

func (s *peSuite) testPeImageHandleImageDigest(c *C, path string, alg crypto.Hash) {
	source := NewFileImage(path)

	r, err := source.Open()
	c.Assert(err, IsNil)
	defer r.Close()

	image, err := OpenPeImage(source)
	c.Assert(err, IsNil)
	defer image.Close()

	expected, err := efi.ComputePeImageDigest(alg, r, r.Size())
	c.Check(err, IsNil)

	digest, err := image.ImageDigest(alg)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expected)
}

func (s *peSuite) TestPeImageHandleImageDigest1(c *C) {
	s.testPeImageHandleImageDigest(c, "testdata/amd64/mockshim.efi.signed.1.1.1", crypto.SHA256)
}

func (s *peSuite) TestPeImageHandleImageDigest2(c *C) {
	s.testPeImageHandleImageDigest(c, "testdata/amd64/mockgrub1.efi.signed.shim.1", crypto.SHA256)
}

func (s *peSuite) TestPeImageHandleImageDigestSHA1(c *C) {
	s.testPeImageHandleImageDigest(c, "testdata/amd64/mockshim.efi.signed.1.1.1", crypto.SHA1)
}

func (s *peSuite) testPeImageHandleSecureBootSignatures(c *C, path string, digests [][]byte) {
	image, err := OpenPeImage(NewFileImage(path))
	c.Assert(err, IsNil)
	defer image.Close()

	sigs, err := image.SecureBootSignatures()
	c.Check(err, IsNil)
	c.Assert(sigs, HasLen, len(digests))

	for i, expected := range digests {
		h := crypto.SHA256.New()
		h.Write(sigs[i].GetSigner().RawTBSCertificate)
		c.Check(h.Sum(nil), DeepEquals, expected)
	}
}

func (s *peSuite) TestPeImageHandleSecureBootSignatures(c *C) {
	s.testPeImageHandleSecureBootSignatures(c,
		"testdata/amd64/mockshim.efi.signed.1.1.1",
		[][]byte{testutil.DecodeHexString(c, "4c503fa92a4d6ab180962c29aa8324cc873e8f74b259fb28347443ac8fef6af8")})
}

func (s *peSuite) TestPeImageHandleSecureBootSignaturesUnsigned(c *C) {
	s.testPeImageHandleSecureBootSignatures(c, "testdata/amd64/mockkernel1.efi", nil)
}

func (s *peSuite) TestPeImageHandleSecureBootSignaturesDualSigned(c *C) {
	s.testPeImageHandleSecureBootSignatures(c,
		"testdata/amd64/mockshim.efi.signed.2.1.1+1.1.1",
		[][]byte{
			testutil.DecodeHexString(c, "f1260899324e0ba7d98058decd55df34faf9884b5429288e0e67bbb2917e4609"),
			testutil.DecodeHexString(c, "4c503fa92a4d6ab180962c29aa8324cc873e8f74b259fb28347443ac8fef6af8")})
}
