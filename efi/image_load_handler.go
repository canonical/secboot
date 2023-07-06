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

// imageLoadHandlerMap is an abstraction for mapping an image to an
// imageLoadHandler.
type imageLoadHandlerMap interface {
	// LookupHandler returns an imageLoadHandler for the supplied image.
	// Callers should assume that calling this multiple times with an image
	// backed by the same source will return the same handler.
	LookupHandler(image peImageHandle) (imageLoadHandler, error)
}

var makeImageLoadHandlerMap = func() imageLoadHandlerMap {
	// TODO: implement
	panic("not implemented")
}

// lookupImageLoadHandler returns an imageLoadHandler for the supplied image.
func lookupImageLoadHandler(pc pcrProfileContext, image peImageHandle) (imageLoadHandler, error) {
	return pc.ImageLoadHandlerMap().LookupHandler(image)
}
