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

	efi "github.com/canonical/go-efilib"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type mockImageLoadHandlerConstructor struct {
	lastImage PeImageHandle
	err       error
}

func (c *mockImageLoadHandlerConstructor) String() string { return "mock handler" }

func (c *mockImageLoadHandlerConstructor) NewImageLoadHandler(image PeImageHandle) (ImageLoadHandler, error) {
	c.lastImage = image
	if c.err != nil {
		return nil, c.err
	}
	return newMockLoadHandler(), nil
}

type imageLoadHandlerSuite struct {
	mockShimImageHandleMixin
}

var _ = Suite(&imageLoadHandlerSuite{})

func (s *imageLoadHandlerSuite) TestImageLoadHandlerLazyMapLookupCache(c *C) {
	m := NewImageLoadHandlerLazyMap(new(mockImageLoadHandlerConstructor))

	image := newMockImage()
	handler1, err := m.LookupHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)

	handler2, err := m.LookupHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)

	c.Check(handler1, Equals, handler2)
}

func (s *imageLoadHandlerSuite) TestImageLoadHandlerLazyMapLookupDifferent(c *C) {
	m := NewImageLoadHandlerLazyMap(new(mockImageLoadHandlerConstructor))

	image1 := newMockImage()
	handler1, err := m.LookupHandler(image1.newPeImageHandle())
	c.Assert(err, IsNil)

	image2 := newMockImage()
	handler2, err := m.LookupHandler(image2.newPeImageHandle())
	c.Assert(err, IsNil)

	c.Check(handler1, Not(Equals), handler2)
}

func (s *imageLoadHandlerSuite) TestImageLoadHandlerLazyMapNoHandler(c *C) {
	m := NewImageLoadHandlerLazyMap(&mockImageLoadHandlerConstructor{err: ErrNoHandler})

	image := newMockImage()
	_, err := m.LookupHandler(image.newPeImageHandle())
	c.Check(err, ErrorMatches, `no handler for image`)
}

func (s *imageLoadHandlerSuite) TestImageLoadHandlerLazyMapSkipHandler(c *C) {
	m := NewImageLoadHandlerLazyMap(
		&mockImageLoadHandlerConstructor{err: ErrNoHandler},
		new(mockImageLoadHandlerConstructor),
	)

	image := newMockImage()
	handler, err := m.LookupHandler(image.newPeImageHandle())
	c.Check(err, IsNil)
	c.Check(handler, NotNil)
}

func (s *imageLoadHandlerSuite) TestImageLoadHandlerLazyMapError(c *C) {
	m := NewImageLoadHandlerLazyMap(&mockImageLoadHandlerConstructor{err: errors.New("some error")})

	image := newMockImage()
	_, err := m.LookupHandler(image.newPeImageHandle())
	c.Check(err, ErrorMatches, `cannot create image load handler using mock handler: some error`)
}

func (s *imageLoadHandlerSuite) TestDefaultLookupMS(c *C) {
	image := newMockUbuntuShimImage15_4(c)

	m := MakeImageLoadHandlerMap()
	handler, err := m.LookupHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{[]byte("sbat,1,2021030218\n"), []byte("sbat,1,2021030218\n")})
}

func (s *imageLoadHandlerSuite) TestDefaultLookupFallback(c *C) {
	image := newMockUbuntuGrubImage1(c).unsign()

	m := MakeImageLoadHandlerMap()
	handler, err := m.LookupHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &GrubLoadHandler{})
	c.Check(handler, DeepEquals, new(GrubLoadHandler))
}
