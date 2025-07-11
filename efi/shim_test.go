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
	"bytes"
	"io/ioutil"

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type shimSuite struct{}

var _ = Suite(&shimSuite{})

func (s *shimSuite) testReadShimSbatPolicy(c *C, data []byte, expected ShimSbatPolicy) error {
	env := efitest.NewMockHostEnvironment(efitest.MockVars{
		{Name: "SbatPolicy", GUID: ShimGuid}: {Payload: data, Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess},
	}, nil)
	policy, err := ReadShimSbatPolicy(newMockVarReader(env))
	if err != nil {
		return err
	}
	c.Check(policy, Equals, expected)
	return nil
}

func (s *shimSuite) TestReadShimSbatPolicyPrevious(c *C) {
	err := s.testReadShimSbatPolicy(c, []byte{2}, ShimSbatPolicyPrevious)
	c.Check(err, IsNil)
}

func (s *shimSuite) TestReadShimSbatPolicyLatest(c *C) {
	err := s.testReadShimSbatPolicy(c, []byte{1}, ShimSbatPolicyLatest)
	c.Check(err, IsNil)
}

func (s *shimSuite) TestReadShimSbatPolicyNotExist(c *C) {
	env := efitest.NewMockHostEnvironment(efitest.MockVars{}, nil)
	policy, err := ReadShimSbatPolicy(newMockVarReader(env))
	c.Check(err, IsNil)
	c.Check(policy, Equals, ShimSbatPolicyPrevious)
}

func (s *shimSuite) TestReadShimSbatPolicyInvalidLength(c *C) {
	err := s.testReadShimSbatPolicy(c, []byte{2, 0}, ShimSbatPolicyPrevious)
	c.Check(err, ErrorMatches, "invalid SbatPolicy length")
}

func (s *shimSuite) TestReadShimSbatPolicyInvalid(c *C) {
	err := s.testReadShimSbatPolicy(c, []byte{4}, ShimSbatPolicyPrevious)
	c.Check(err, ErrorMatches, "invalid SbatPolicy value")
}

func (s *shimSuite) TestNewestSbatLevel1(c *C) {
	levels := [][]byte{
		[]byte("sbat,1,2021030218\n"),
		[]byte("sbat,1,2022052400\ngrub,2\n")}
	newest, err := NewestSbatLevel(levels...)
	c.Check(err, IsNil)
	c.Check(newest, DeepEquals, levels[1])
}

func (s *shimSuite) TestNewestSbatLevel2(c *C) {
	levels := [][]byte{
		[]byte("sbat,1,2022052400\ngrub,2\n"),
		[]byte("sbat,1,2021030218\n")}
	newest, err := NewestSbatLevel(levels...)
	c.Check(err, IsNil)
	c.Check(newest, DeepEquals, levels[0])
}

func (s *shimSuite) TestNewestSbatLevel3(c *C) {
	levels := [][]byte{
		[]byte("sbat,1,2021030218\n"),
		[]byte("sbat,1,2022052400\ngrub,2\n"),
		[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n")}
	newest, err := NewestSbatLevel(levels...)
	c.Check(err, IsNil)
	c.Check(newest, DeepEquals, levels[2])
}

func (s *shimSuite) TestNewestSbatLevel4(c *C) {
	levels := [][]byte{
		[]byte("sbat,1,2022052400\ngrub,2\n"),
		[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"),
		[]byte("sbat,1,2021030218\n")}
	newest, err := NewestSbatLevel(levels...)
	c.Check(err, IsNil)
	c.Check(newest, DeepEquals, levels[1])
}

func (s *shimSuite) TestParseShimVersion15_6(c *C) {
	version, err := ParseShimVersion("15.6")
	c.Check(err, IsNil)
	c.Check(version, DeepEquals, ShimVersion{Major: 15, Minor: 6})
}

func (s *shimSuite) TestParseShimVersion15_7(c *C) {
	version, err := ParseShimVersion("15.7")
	c.Check(err, IsNil)
	c.Check(version, DeepEquals, ShimVersion{Major: 15, Minor: 7})
}

func (s *shimSuite) TestParseShimVersion15(c *C) {
	version, err := ParseShimVersion("15")
	c.Check(err, IsNil)
	c.Check(version, DeepEquals, ShimVersion{Major: 15, Minor: 0})
}

func (s *shimSuite) TestParseShimVersionError1(c *C) {
	_, err := ParseShimVersion("15.6.")
	c.Check(err, ErrorMatches, "invalid shim version format")
}

func (s *shimSuite) TestParseShimVersionError2(c *C) {
	_, err := ParseShimVersion("15.")
	c.Check(err, ErrorMatches, "invalid shim version format")
}

func (s *shimSuite) TestMustParseShimVersion1(c *C) {
	version := MustParseShimVersion("15.6")
	c.Check(version, DeepEquals, ShimVersion{Major: 15, Minor: 6})
}

func (s *shimSuite) TestMustParseShimVersion2(c *C) {
	version := MustParseShimVersion("15.7")
	c.Check(version, DeepEquals, ShimVersion{Major: 15, Minor: 7})
}

func (s *shimSuite) TestMustParseShimVersionPanics(c *C) {
	c.Check(func() { MustParseShimVersion("15.6.") }, PanicMatches, "invalid shim version format")
}

func (s *shimSuite) TestParseShimVersionDataIdent15_6(c *C) {
	version, err := ParseShimVersionDataIdent(bytes.NewReader([]byte("UEFI SHIM\n$Version: 15.6 $\nBuildMachine: foo $\nCommit: 010203040506 $\n")))
	c.Check(err, IsNil)
	c.Check(version, DeepEquals, ShimVersion{Major: 15, Minor: 6})
}

func (s *shimSuite) TestParseShimVersionDataIdent15_7(c *C) {
	version, err := ParseShimVersionDataIdent(bytes.NewReader([]byte("UEFI SHIM\n$Version: 15.7 $\nBuildMachine: foo $\nCommit: 010203040506 $\n")))
	c.Check(err, IsNil)
	c.Check(version, DeepEquals, ShimVersion{Major: 15, Minor: 7})
}

func (s *shimSuite) TestParseShimVersionDataIdent15(c *C) {
	version, err := ParseShimVersionDataIdent(bytes.NewReader([]byte("UEFI SHIM\n$Version: 15 $\nBuildMachine: foo $\nCommit: 010203040506 $\n")))
	c.Check(err, IsNil)
	c.Check(version, DeepEquals, ShimVersion{Major: 15, Minor: 0})
}

func (s *shimSuite) TestParseShimVersionDataIdentPermissive1(c *C) {
	version, err := ParseShimVersionDataIdent(bytes.NewReader([]byte("UEFI SHIM\n$Version:15.6     $\nBuildMachine: foo $\nCommit: 010203040506 $\n")))
	c.Check(err, IsNil)
	c.Check(version, DeepEquals, ShimVersion{Major: 15, Minor: 6})
}

func (s *shimSuite) TestParseShimVersionDataIdentPermissive2(c *C) {
	version, err := ParseShimVersionDataIdent(bytes.NewReader([]byte("UEFI SHIM\n$Version:     15.6$\nBuildMachine: foo $\nCommit: 010203040506 $\n")))
	c.Check(err, IsNil)
	c.Check(version, DeepEquals, ShimVersion{Major: 15, Minor: 6})
}

func (s *shimSuite) TestParseShimVersionDataIdentError1(c *C) {
	_, err := ParseShimVersionDataIdent(bytes.NewReader([]byte("UEFI SHIM\n$Version: 15.6. $\nBuildMachine: foo $\nCommit: 010203040506 $\n")))
	c.Check(err, ErrorMatches, "invalid shim version format")
}

func (s *shimSuite) TestParseShimVersionDataIdentError2(c *C) {
	_, err := ParseShimVersionDataIdent(bytes.NewReader([]byte("UEFI SHIM\n$Version: 15. $\nBuildMachine: foo $\nCommit: 010203040506 $\n")))
	c.Check(err, ErrorMatches, "invalid shim version format")
}

func (s *shimSuite) TestParseShimVersionDataIdentError3(c *C) {
	_, err := ParseShimVersionDataIdent(bytes.NewReader([]byte("not UEFI SHIM\n$Version: 15.6 $\nBuildMachine: foo $\nCommit: 010203040506 $\n")))
	c.Check(err, ErrorMatches, "unexpected .data.ident section contents \\(not shim\\?\\)")
}

func (s *shimSuite) TestShimVersionEqual(c *C) {
	a := ShimVersion{Major: 15, Minor: 7}
	b := ShimVersion{Major: 15, Minor: 7}
	c.Check(a.Compare(b), Equals, 0)
}

func (s *shimSuite) TestShimVersionLT1(c *C) {
	a := ShimVersion{Major: 14, Minor: 7}
	b := ShimVersion{Major: 15, Minor: 7}
	c.Check(a.Compare(b), Equals, -1)
}

func (s *shimSuite) TestShimVersionLT2(c *C) {
	a := ShimVersion{Major: 15, Minor: 6}
	b := ShimVersion{Major: 15, Minor: 7}
	c.Check(a.Compare(b), Equals, -1)
}

func (s *shimSuite) TestShimVersionGT1(c *C) {
	a := ShimVersion{Major: 15, Minor: 7}
	b := ShimVersion{Major: 14, Minor: 7}
	c.Check(a.Compare(b), Equals, 1)
}

func (s *shimSuite) TestShimVersionGT2(c *C) {
	a := ShimVersion{Major: 15, Minor: 7}
	b := ShimVersion{Major: 15, Minor: 6}
	c.Check(a.Compare(b), Equals, 1)
}

func (s *shimSuite) TestShimSbatLevelForPolicyPrevious(c *C) {
	level := ShimSbatLevel{
		[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"),
		[]byte("sbat,1,2022052400\ngrub,2\n")}
	c.Check(level.ForPolicy(ShimSbatPolicyPrevious), DeepEquals, level[1])
}

func (s *shimSuite) TestShimSbatLevelForPolicyLatest(c *C) {
	level := ShimSbatLevel{
		[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"),
		[]byte("sbat,1,2022052400\ngrub,2\n")}
	c.Check(level.ForPolicy(ShimSbatPolicyLatest), DeepEquals, level[0])
}

type testShimImageHandleVersionData struct {
	path            string
	expectedVersion ShimVersion
}

func (s *shimSuite) testShimImageHandleVersion(c *C, data *testShimImageHandleVersionData) {
	image, err := OpenPeImage(NewFileImage(data.path))
	c.Assert(err, IsNil)
	defer image.Close()

	shimImage := NewShimImageHandle(image)

	version, err := shimImage.Version()
	c.Check(err, IsNil)
	c.Check(version, DeepEquals, data.expectedVersion)
}

func (s *shimSuite) TestShimImageHandleVersion15_7(c *C) {
	s.testShimImageHandleVersion(c, &testShimImageHandleVersionData{
		path:            "testdata/amd64/mockshim.efi.signed.1.1.1",
		expectedVersion: MustParseShimVersion("15.7"),
	})
}

func (s *shimSuite) TestShimImageHandleVersion15_3(c *C) {
	s.testShimImageHandleVersion(c, &testShimImageHandleVersionData{
		path:            "testdata/amd64/mockshim_initial_sbat.efi.signed.1.1.1",
		expectedVersion: MustParseShimVersion("15.3"),
	})
}

type testShimImageHandleReadVendorDBData struct {
	path           string
	expectedDb     efi.SignatureDatabase
	expectedFormat ShimVendorCertFormat
}

func (s *shimSuite) testShimImageHandleReadVendorDB(c *C, data *testShimImageHandleReadVendorDBData) error {
	image, err := OpenPeImage(NewFileImage(data.path))
	c.Assert(err, IsNil)
	defer image.Close()

	shimImage := NewShimImageHandle(image)
	db, format, err := shimImage.ReadVendorDB()
	if err != nil {
		return err
	}
	c.Check(db, DeepEquals, data.expectedDb)
	c.Check(format, Equals, data.expectedFormat)
	return nil
}

func (s *shimSuite) TestShimImageHandleReadVendorDBCert(c *C) {
	data, err := ioutil.ReadFile("testdata/TestShimVendorCA.cer")
	c.Check(err, IsNil)

	err = s.testShimImageHandleReadVendorDB(c, &testShimImageHandleReadVendorDBData{
		path: "testdata/amd64/mockshim.efi.signed.1.1.1",
		expectedDb: efi.SignatureDatabase{
			{
				Type:       efi.CertX509Guid,
				Signatures: []*efi.SignatureData{{Data: data}},
			},
		},
		expectedFormat: ShimVendorCertIsX509})
	c.Check(err, IsNil)
}

func (s *shimSuite) TestShimImageHandleReadVendorDBEmpty(c *C) {
	err := s.testShimImageHandleReadVendorDB(c, &testShimImageHandleReadVendorDBData{
		path:           "testdata/amd64/mockshim_no_vendor_cert.efi.signed.1.1.1",
		expectedFormat: ShimVendorCertIsDb})
	c.Check(err, IsNil)
}

func (s *shimSuite) TestShimImageHandleReadVendorDBNoVendorCert(c *C) {
	err := s.testShimImageHandleReadVendorDB(c, &testShimImageHandleReadVendorDBData{
		path: "testdata/amd64/mockgrub.efi"})
	c.Check(err, ErrorMatches, "no .vendor_cert section")
}

func (s *shimSuite) TestShimImageHandleReadVendorDB(c *C) {
	data, err := ioutil.ReadFile("testdata/TestShimVendorCA.cer")
	c.Check(err, IsNil)

	err = s.testShimImageHandleReadVendorDB(c, &testShimImageHandleReadVendorDBData{
		path: "testdata/amd64/mockshim_vendor_db.efi.signed.1.1.1",
		expectedDb: efi.SignatureDatabase{
			{
				Type:       efi.CertX509Guid,
				Header:     []byte{},
				Signatures: []*efi.SignatureData{{Owner: efi.MakeGUID(0x84862e0b, 0x24ee, 0x412e, 0x97b0, [...]uint8{0x4f, 0x3a, 0x33, 0x7d, 0xd2, 0xbd}), Data: data}},
			},
		},
		expectedFormat: ShimVendorCertIsDb})
	c.Check(err, IsNil)
}

type testShimImageHandleReadSbatLevelData struct {
	path     string
	expected ShimSbatLevel
}

func (s *shimSuite) testShimImageHandleReadSbatLevel(c *C, data *testShimImageHandleReadSbatLevelData) error {
	image, err := OpenPeImage(NewFileImage(data.path))
	c.Assert(err, IsNil)
	defer image.Close()

	shimImage := NewShimImageHandle(image)
	level, err := shimImage.ReadSbatLevel()
	if err != nil {
		return err
	}
	c.Check(level, DeepEquals, data.expected)
	return nil
}

func (s *shimSuite) TestShimImageHandleReadSbatLevel(c *C) {
	err := s.testShimImageHandleReadSbatLevel(c, &testShimImageHandleReadSbatLevelData{
		path: "testdata/amd64/mockshim.efi.signed.1.1.1",
		expected: ShimSbatLevel{
			[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"),
			[]byte("sbat,1,2022052400\ngrub,2\n")}})
	c.Check(err, IsNil)
}

func (s *shimSuite) TestShimImageHandleReadSbatLevelMissing(c *C) {
	err := s.testShimImageHandleReadSbatLevel(c, &testShimImageHandleReadSbatLevelData{
		path: "testdata/amd64/mockshim_initial_sbat.efi.signed.1.1.1"})
	c.Check(err, ErrorMatches, "no .sbatlevel section")
}

func (s *shimSuite) TestShimImageHandleHasSbatLevelSectionTrue(c *C) {
	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockshim.efi.signed.1.1.1"))
	c.Assert(err, IsNil)
	defer image.Close()

	shimImage := NewShimImageHandle(image)
	c.Check(shimImage.HasSbatLevelSection(), testutil.IsTrue)
}

func (s *shimSuite) TestShimImageHandleHasSbatLevelSectionFalse(c *C) {
	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockshim_initial_sbat.efi.signed.1.1.1"))
	c.Assert(err, IsNil)
	defer image.Close()

	shimImage := NewShimImageHandle(image)
	c.Check(shimImage.HasSbatLevelSection(), Not(testutil.IsTrue))
}

func (s *shimSuite) TestShimSbatPolicyLatestUnset(c *C) {
	visitor := new(mockPcrProfileOptionVisitor)
	opt := WithShimSbatPolicyLatest()
	c.Check(opt.ApplyOptionTo(visitor), IsNil)

	c.Assert(visitor.varModifiers, HasLen, 1)

	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MockVars{}, nil))
	c.Check(visitor.varModifiers[0](collector.PeekAll()[0]), IsNil)

	c.Assert(collector.More(), testutil.IsTrue)
	vars := collector.Next()
	_, _, err := vars.ReadVar("SbatPolicy", ShimGuid)
	c.Check(err, Equals, efi.ErrVarNotExist)

	c.Assert(collector.More(), testutil.IsTrue)
	vars = collector.Next()
	data, attrs, err := vars.ReadVar("SbatPolicy", ShimGuid)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{0x1})

	c.Check(collector.More(), testutil.IsFalse)
}

func (s *shimSuite) TestShimSbatPolicyLatestFromPrevious(c *C) {
	visitor := new(mockPcrProfileOptionVisitor)
	opt := WithShimSbatPolicyLatest()
	c.Check(opt.ApplyOptionTo(visitor), IsNil)

	c.Assert(visitor.varModifiers, HasLen, 1)

	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MakeMockVars().AddVar("SbatPolicy", ShimGuid, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess, []byte{0x2}), nil))
	c.Check(visitor.varModifiers[0](collector.PeekAll()[0]), IsNil)

	c.Assert(collector.More(), testutil.IsTrue)
	vars := collector.Next()
	data, attrs, err := vars.ReadVar("SbatPolicy", ShimGuid)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{0x2})

	c.Assert(collector.More(), testutil.IsTrue)
	vars = collector.Next()
	data, attrs, err = vars.ReadVar("SbatPolicy", ShimGuid)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{0x1})

	c.Check(collector.More(), testutil.IsFalse)
}

func (s *shimSuite) TestShimSbatPolicyLatestFromLatest(c *C) {
	visitor := new(mockPcrProfileOptionVisitor)
	opt := WithShimSbatPolicyLatest()
	c.Check(opt.ApplyOptionTo(visitor), IsNil)

	c.Assert(visitor.varModifiers, HasLen, 1)

	collector := NewVariableSetCollector(efitest.NewMockHostEnvironment(efitest.MakeMockVars().AddVar("SbatPolicy", ShimGuid, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess, []byte{0x1}), nil))
	c.Check(visitor.varModifiers[0](collector.PeekAll()[0]), IsNil)

	c.Assert(collector.More(), testutil.IsTrue)
	vars := collector.Next()
	data, attrs, err := vars.ReadVar("SbatPolicy", ShimGuid)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
	c.Check(data, DeepEquals, []byte{0x1})

	c.Check(collector.More(), testutil.IsFalse)
}
