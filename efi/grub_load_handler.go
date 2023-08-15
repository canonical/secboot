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
	"golang.org/x/xerrors"
)

type grubFlags int

const (
	grubChainloaderUsesShimProtocol grubFlags = 1 << iota
)

// grubLoadHandler is an implementation of imageLoadHandler for grub.
type grubLoadHandler struct {
	Flags grubFlags
}

type grubLoadHandlerConstructor grubFlags

func newGrubLoadHandlerConstructor(flags grubFlags) grubLoadHandlerConstructor {
	return grubLoadHandlerConstructor(flags)
}

func (c grubLoadHandlerConstructor) New(_ peImageHandle) (imageLoadHandler, error) {
	return &grubLoadHandler{Flags: grubFlags(c)}, nil
}

func newGrubLoadHandler(image peImageHandle) (imageLoadHandler, error) {
	return newGrubLoadHandlerConstructor(0).New(image)
}

// MeasureImageStart implements imageLoadHandler.MeasureImageStart.
func (h *grubLoadHandler) MeasureImageStart(_ pcrBranchContext) error {
	return nil
}

// MeasureImageLoad implements imageLoadHandler.MeasureImageLoad.
func (h *grubLoadHandler) MeasureImageLoad(ctx pcrBranchContext, image peImageHandle) (imageLoadHandler, error) {
	var err error
	if h.Flags&grubChainloaderUsesShimProtocol != 0 {
		m := newShimImageLoadMeasurer(ctx, image)
		err = m.measure()
	} else {
		m := newFwImageLoadMeasurer(ctx, image)
		err = m.measure()
	}
	if err != nil {
		return nil, xerrors.Errorf("cannot measure image: %w", err)
	}

	return lookupImageLoadHandler(ctx, image)
}
