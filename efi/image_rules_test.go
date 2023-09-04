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
	"errors"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type mockImagePredicate struct {
	testedImages []PeImageHandle

	result bool
	err    error
}

func (p *mockImagePredicate) Matches(image PeImageHandle) (bool, error) {
	p.testedImages = append(p.testedImages, image)
	return p.result, p.err
}

type imageRulesSuite struct {
	mockShimImageHandleMixin
}

var _ = Suite(&imageRulesSuite{})

func (s *imageRulesSuite) TestImageMatchesAnyFalse1(c *C) {
	image := newMockImage().newPeImageHandle()

	cond := new(mockImagePredicate)
	pred := ImageMatchesAny(cond)
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
	c.Check(cond.testedImages, DeepEquals, []PeImageHandle{image})
}

func (s *imageRulesSuite) TestImageMatchesAnyFalse2(c *C) {
	image := newMockImage().newPeImageHandle()

	cond1 := new(mockImagePredicate)
	cond2 := new(mockImagePredicate)
	pred := ImageMatchesAny(cond1, cond2)
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
	c.Check(cond1.testedImages, DeepEquals, []PeImageHandle{image})
	c.Check(cond2.testedImages, DeepEquals, []PeImageHandle{image})
}

func (s *imageRulesSuite) TestImageMatchesAnyTrue1(c *C) {
	image := newMockImage().newPeImageHandle()

	cond := &mockImagePredicate{result: true}
	pred := ImageMatchesAny(cond)
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
	c.Check(cond.testedImages, DeepEquals, []PeImageHandle{image})
}

func (s *imageRulesSuite) TestImageMatchesAnyTrue2(c *C) {
	image := newMockImage().newPeImageHandle()

	cond1 := &mockImagePredicate{result: true}
	cond2 := new(mockImagePredicate)
	pred := ImageMatchesAny(cond1, cond2)
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
	c.Check(cond1.testedImages, DeepEquals, []PeImageHandle{image})
	c.Check(cond2.testedImages, IsNil)
}

func (s *imageRulesSuite) TestImageMatchesAnyTrue3(c *C) {
	image := newMockImage().newPeImageHandle()

	cond1 := new(mockImagePredicate)
	cond2 := &mockImagePredicate{result: true}
	pred := ImageMatchesAny(cond1, cond2)
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
	c.Check(cond1.testedImages, DeepEquals, []PeImageHandle{image})
	c.Check(cond2.testedImages, DeepEquals, []PeImageHandle{image})
}

func (s *imageRulesSuite) TestImageMatchesAllFalse1(c *C) {
	image := newMockImage().newPeImageHandle()

	cond := new(mockImagePredicate)
	pred := ImageMatchesAll(cond)
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
	c.Check(cond.testedImages, DeepEquals, []PeImageHandle{image})
}

func (s *imageRulesSuite) TestImageMatchesAllFalse2(c *C) {
	image := newMockImage().newPeImageHandle()

	cond1 := new(mockImagePredicate)
	cond2 := &mockImagePredicate{result: true}
	pred := ImageMatchesAll(cond1, cond2)
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
	c.Check(cond1.testedImages, DeepEquals, []PeImageHandle{image})
	c.Check(cond2.testedImages, IsNil)
}

func (s *imageRulesSuite) TestImageMatchesAllFalse3(c *C) {
	image := newMockImage().newPeImageHandle()

	cond1 := &mockImagePredicate{result: true}
	cond2 := new(mockImagePredicate)
	pred := ImageMatchesAll(cond1, cond2)
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
	c.Check(cond1.testedImages, DeepEquals, []PeImageHandle{image})
	c.Check(cond2.testedImages, DeepEquals, []PeImageHandle{image})
}

func (s *imageRulesSuite) TestImageMatchesAllTrue1(c *C) {
	image := newMockImage().newPeImageHandle()

	cond := &mockImagePredicate{result: true}
	pred := ImageMatchesAll(cond)
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
	c.Check(cond.testedImages, DeepEquals, []PeImageHandle{image})
}

func (s *imageRulesSuite) TestImageMatchesAllTrue2(c *C) {
	image := newMockImage().newPeImageHandle()

	cond1 := &mockImagePredicate{result: true}
	cond2 := &mockImagePredicate{result: true}
	pred := ImageMatchesAll(cond1, cond2)
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
	c.Check(cond1.testedImages, DeepEquals, []PeImageHandle{image})
	c.Check(cond2.testedImages, DeepEquals, []PeImageHandle{image})
}

func (s *imageRulesSuite) TestImageAlwaysMatches(c *C) {
	match, err := ImageAlwaysMatches.Matches(newMockImage().newPeImageHandle())
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestImageSectionExistsTrue1(c *C) {
	image := newMockImage().addSection(".foo", nil).newPeImageHandle()

	pred := ImageSectionExists(".foo")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestImageSectionExistsTrue2(c *C) {
	image := newMockImage().addSection(".bar", nil).newPeImageHandle()

	pred := ImageSectionExists(".bar")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestImageSectionExistsFalse(c *C) {
	image := newMockImage().newPeImageHandle()

	pred := ImageSectionExists(".foo")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestImageSignedByOrganizationTrue1(c *C) {
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)).newPeImageHandle()

	pred := ImageSignedByOrganization("Canonical Ltd.")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestImageSignedByOrganizationTrue2(c *C) {
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)
	image := newMockImage().withDigest(sig.DigestAlgorithm(), sig.Digest()).sign(c, testutil.ParsePKCS1PrivateKey(c, testUefiSigningKey1_1), testutil.ParseCertificate(c, testUefiSigningCert1_1)).appendSignatures(sig).newPeImageHandle()

	pred := ImageSignedByOrganization("Canonical Ltd.")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestImageSignedByOrganizationTrue3(c *C) {
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)
	image := newMockImage().withDigest(sig.DigestAlgorithm(), sig.Digest()).sign(c, testutil.ParsePKCS1PrivateKey(c, testUefiSigningKey1_1), testutil.ParseCertificate(c, testUefiSigningCert1_1)).newPeImageHandle()

	pred := ImageSignedByOrganization("Fake Corporation")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestImageSignedByOrganizationFalse1(c *C) {
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)
	image := newMockImage().withDigest(sig.DigestAlgorithm(), sig.Digest()).sign(c, testutil.ParsePKCS1PrivateKey(c, testUefiSigningKey1_1), testutil.ParseCertificate(c, testUefiSigningCert1_1)).newPeImageHandle()

	pred := ImageSignedByOrganization("Canonical Ltd.")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestImageSignedByOrganizationFalse2(c *C) {
	image := newMockImage().newPeImageHandle()

	pred := ImageSignedByOrganization("Canonical Ltd.")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestImageDigestMatchesTrue1(c *C) {
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)
	image := newMockImage().appendSignatures(sig).newPeImageHandle()

	pred := ImageDigestMatches(sig.DigestAlgorithm(), sig.Digest())
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestImageDigestMatchesTrue2(c *C) {
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)
	image := newMockImage().appendSignatures(sig).newPeImageHandle()

	pred := ImageDigestMatches(sig.DigestAlgorithm(), sig.Digest())
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestImageDigestMatchesFalse(c *C) {
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)
	image := newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)).newPeImageHandle()

	pred := ImageDigestMatches(sig.DigestAlgorithm(), sig.Digest())
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestImageDigestMatchesErr(c *C) {
	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig3)
	image := newMockImage().newPeImageHandle()

	pred := ImageDigestMatches(sig.DigestAlgorithm(), sig.Digest())
	_, err := pred.Matches(image)
	c.Check(err, ErrorMatches, `invalid alg`)
}

func (s *imageRulesSuite) TestSbatSectionExistsTrue(c *C) {
	image := newMockImage().withSbat(nil).newPeImageHandle()

	match, err := SbatSectionExists.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestSbatSectionExistsFalse(c *C) {
	image := newMockImage().newPeImageHandle()

	match, err := SbatSectionExists.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestSbatComponentExistsTrue1(c *C) {
	image := newMockImage().withSbat([]SbatComponent{{Name: "shim"}, {Name: "shim.ubuntu"}}).newPeImageHandle()

	pred := SbatComponentExists("shim.ubuntu")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestSbatComponentExistsTrue2(c *C) {
	image := newMockImage().withSbat([]SbatComponent{{Name: "grub"}, {Name: "grub.ubuntu"}}).newPeImageHandle()

	pred := SbatComponentExists("grub")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestSbatComponentExistsFalse(c *C) {
	image := newMockImage().withSbat([]SbatComponent{{Name: "grub"}, {Name: "grub.ubuntu"}}).newPeImageHandle()

	pred := SbatComponentExists("shim.ubuntu")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestSbatComponentExistsErr(c *C) {
	image := newMockImage().newPeImageHandle()

	pred := SbatComponentExists("shim.ubuntu")
	_, err := pred.Matches(image)
	c.Check(err, ErrorMatches, `no sbat`)
}

func (s *imageRulesSuite) TestShimVersionIsEqualTrue(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.7")).newPeImageHandle()

	pred := ShimVersionIs("==", "15.7")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestShimVersionIsEqualFalse(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.7")).newPeImageHandle()

	pred := ShimVersionIs("==", "15.6")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestShimVersionIsNotEqualTrue(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.4")).newPeImageHandle()

	pred := ShimVersionIs("!=", "15.7")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestShimVersionIsNotEqualFalse(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.4")).newPeImageHandle()

	pred := ShimVersionIs("!=", "15.4")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestShimVersionIsGTTrue(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.4")).newPeImageHandle()

	pred := ShimVersionIs(">", "15.2")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestShimVersionIsGTFalse1(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.4")).newPeImageHandle()

	pred := ShimVersionIs(">", "15.4")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestShimVersionIsGTFalse2(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.4")).newPeImageHandle()

	pred := ShimVersionIs(">", "15.4")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestShimVersionIsGETrue(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.4")).newPeImageHandle()

	pred := ShimVersionIs(">=", "15.2")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestShimVersionIsGETrue2(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.4")).newPeImageHandle()

	pred := ShimVersionIs(">=", "15.4")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestShimVersionIsGEFalse(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.4")).newPeImageHandle()

	pred := ShimVersionIs(">=", "15.7")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestShimVersionIsLTTrue(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.6")).newPeImageHandle()

	pred := ShimVersionIs("<", "15.7")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestShimVersionIsLTFalse1(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.6")).newPeImageHandle()

	pred := ShimVersionIs("<", "15.6")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestShimVersionIsLTFalse2(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.6")).newPeImageHandle()

	pred := ShimVersionIs("<", "15.4")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestShimVersionIsLETrue1(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.6")).newPeImageHandle()

	pred := ShimVersionIs("<=", "15.7")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestShimVersionIsLETrue2(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.6")).newPeImageHandle()

	pred := ShimVersionIs("<=", "15.6")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsTrue)
}

func (s *imageRulesSuite) TestShimVersionIsLEFalse(c *C) {
	image := newMockImage().withShimVersion(MustParseShimVersion("15.6")).newPeImageHandle()

	pred := ShimVersionIs("<=", "15.4")
	match, err := pred.Matches(image)
	c.Check(err, IsNil)
	c.Check(match, testutil.IsFalse)
}

func (s *imageRulesSuite) TestShimVersionErr(c *C) {
	image := newMockImage().newPeImageHandle()

	pred := ShimVersionIs("<=", "15.4")
	_, err := pred.Matches(image)
	c.Check(err, ErrorMatches, `cannot obtain shim version: no version`)
}

func (s *imageRulesSuite) TestImageRulesMatch1(c *C) {
	image := newMockImage().newPeImageHandle()

	rules := NewImageRules(
		"test",
		NewImageRule(
			"rule1",
			&mockImagePredicate{result: true},
			func(i PeImageHandle) (ImageLoadHandler, error) {
				c.Check(i, Equals, image)

				return newMockLoadHandler(), nil
			},
		),
	)
	handler, err := rules.NewImageLoadHandler(image)
	c.Check(err, IsNil)
	c.Check(handler, DeepEquals, newMockLoadHandler())
}

func (s *imageRulesSuite) TestImageRulesMatch2(c *C) {
	image := newMockImage().newPeImageHandle()

	rules := NewImageRules(
		"test",
		NewImageRule(
			"rule1",
			&mockImagePredicate{result: true},
			func(i PeImageHandle) (ImageLoadHandler, error) {
				c.Check(i, Equals, image)

				return newMockLoadHandler(), nil
			},
		),
		NewImageRule(
			"rule2",
			&mockImagePredicate{result: true},
			func(i PeImageHandle) (ImageLoadHandler, error) {
				return nil, errors.New("not reached")
			},
		),
	)
	handler, err := rules.NewImageLoadHandler(image)
	c.Check(err, IsNil)
	c.Check(handler, DeepEquals, newMockLoadHandler())
}

func (s *imageRulesSuite) TestImageRulesMatch3(c *C) {
	image := newMockImage().newPeImageHandle()

	rules := NewImageRules(
		"test",
		NewImageRule(
			"rule1",
			new(mockImagePredicate),
			func(i PeImageHandle) (ImageLoadHandler, error) {
				return nil, errors.New("not reached")
			},
		),
		NewImageRule(
			"rule2",
			&mockImagePredicate{result: true},
			func(i PeImageHandle) (ImageLoadHandler, error) {
				c.Check(i, Equals, image)

				return newMockLoadHandler(), nil
			},
		),
	)
	handler, err := rules.NewImageLoadHandler(image)
	c.Check(err, IsNil)
	c.Check(handler, DeepEquals, newMockLoadHandler())
}

func (s *imageRulesSuite) TestImageRulesNoMatch(c *C) {
	image := newMockImage().newPeImageHandle()

	rules := NewImageRules(
		"test",
		NewImageRule(
			"rule1",
			new(mockImagePredicate),
			func(i PeImageHandle) (ImageLoadHandler, error) {
				return nil, errors.New("not reached")
			},
		),
	)
	_, err := rules.NewImageLoadHandler(image)
	c.Check(err, Equals, ErrNoHandler)
}
