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

package efi

import (
	"errors"

	"golang.org/x/xerrors"
)

// imageLoadHandler is an abstraction for measuring boot events
// associated with a single image.
type imageLoadHandler interface {
	// MeasureImageStart measures events related to the start of execution
	// of the image associated with this handler to the supplied branch.
	MeasureImageStart(ctx pcrBranchContext) error

	// MeasureImageLoad measures events related to the verification
	// and loading of the supplied image by the image associated with
	// this handler, to the supplied branch.
	MeasureImageLoad(ctx pcrBranchContext, image peImageHandle) (imageLoadHandler, error)
}

// errNoHandler is returned from a imageLoadHandlerConstructor if there is
// no appropriate handler
var errNoHandler = errors.New("no handler")

// imageLoadHandlerConstructor is an abstraction for constructing a new imageLoadHandler
// for a specific image.
type imageLoadHandlerConstructor interface {
	NewImageLoadHandler(image peImageHandle) (imageLoadHandler, error)
}

// imageLoadHandlerMap is an abstraction for mapping an image to an
// imageLoadHandler.
type imageLoadHandlerMap interface {
	// LookupHandler returns an imageLoadHandler for the supplied image.
	// Callers should assume that calling this multiple times with an image
	// backed by the same source will return the same handler.
	LookupHandler(image peImageHandle) (imageLoadHandler, error)
}

type imageLoadHandlerLazyMap struct {
	handlers     map[Image]imageLoadHandler
	constructors []imageLoadHandlerConstructor
}

func newImageLoadHandlerLazyMap(constructors ...imageLoadHandlerConstructor) *imageLoadHandlerLazyMap {
	return &imageLoadHandlerLazyMap{
		handlers:     make(map[Image]imageLoadHandler),
		constructors: constructors,
	}
}

// LookupHandler implements imageLoadHandlerMap
func (m *imageLoadHandlerLazyMap) LookupHandler(image peImageHandle) (imageLoadHandler, error) {
	handler, exists := m.handlers[image.Source()]
	if exists {
		return handler, nil
	}

	for _, c := range m.constructors {
		handler, err := c.NewImageLoadHandler(image)
		switch {
		case err == errNoHandler:
			// skip
		case err != nil:
			return nil, xerrors.Errorf("cannot create image load handler using %v: %w", c, err)
		default:
			m.handlers[image.Source()] = handler
			return handler, nil
		}
	}

	// We shouldn't actually reach here because the fallback rules always returns
	// something.
	return nil, errors.New("no handler for image")
}

// makeImageLoadHandlerMap makes the default imageLoadHandlerMap, which maps
// images to imageLoadHandlers using 2 sets of rules:
//   - a set of rules specific to anything that exists inside of the Microsoft UEFI CA
//     secure boot namespace.
//   - a set of fallback rules for anything else.
var makeImageLoadHandlerMap = func() imageLoadHandlerMap {
	return newImageLoadHandlerLazyMap(
		makeMicrosoftUEFICASecureBootNamespaceRules(),
		makeFallbackImageRules(),
	)
}

// lookupImageLoadHandler returns an imageLoadHandler for the supplied image.
func lookupImageLoadHandler(pc pcrProfileContext, image peImageHandle) (imageLoadHandler, error) {
	return pc.ImageLoadHandlerMap().LookupHandler(image)
}

type nullLoadHandler struct{}

func newNullLoadHandler(_ peImageHandle) (imageLoadHandler, error) {
	return new(nullLoadHandler), nil
}

func (*nullLoadHandler) MeasureImageStart(_ pcrBranchContext) error {
	return nil
}

func (*nullLoadHandler) MeasureImageLoad(_ pcrBranchContext, _ peImageHandle) (imageLoadHandler, error) {
	return nil, errors.New("unrecognized image")
}
