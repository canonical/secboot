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

// pcrImagesMeasurer binds a branch context, load handler and a set of images
// that can be loaded.
type pcrImagesMeasurer struct {
	context *pcrBranchCtx // the current branch context

	// loadHandler is associated with the image that has been measured into
	// the current branch context.
	loadHandler imageLoadHandler

	// images are the set of images that can be loaded by the image associated
	// with the loadHandler field. These loads will be measured into new branch
	// contexts descended from the current branch context.
	images []ImageLoadActivity

	nextToMeasure []*pcrImagesMeasurer
}

func newPcrImagesMeasurer(branchContext *pcrBranchCtx, handler imageLoadHandler, images ...ImageLoadActivity) *pcrImagesMeasurer {
	return &pcrImagesMeasurer{
		context:     branchContext,
		loadHandler: handler,
		images:      images}
}

func (m *pcrImagesMeasurer) measureOneImage(bp *pcrBranchPointCtx, image ImageLoadActivity) error {
	// Build a list of parameters based on the parameters attached
	// to the supplied image and inheriting from the parameters
	// associated with the current branch context.
	params := image.params().Resolve(m.context.params)

	handle, err := openPeImage(image.source())
	if err != nil {
		return xerrors.Errorf("cannot open image: %w", err)
	}
	defer handle.Close()

	// Create a new descendent branch for each parameter combination.
	for _, p := range params {
		context := bp.AddBranch(p)

		// Measure the verification and loading if the new image with the previous image's handler.
		handler, err := m.loadHandler.MeasureImageLoad(context, handle)
		if err != nil {
			return xerrors.Errorf("cannot measure image load: %w", err)
		}

		// Measure the execution of the new image using its own handler.
		if err := handler.MeasureImageStart(context); err != nil {
			return xerrors.Errorf("cannot measure image start for params %#v: %w", p, err)
		}

		next := image.next()
		if len(next) > 0 {
			m.nextToMeasure = append(m.nextToMeasure, newPcrImagesMeasurer(context, handler, next...))
		}
	}

	return nil
}

func (m *pcrImagesMeasurer) Measure() ([]*pcrImagesMeasurer, error) {
	bp := m.context.AddBranchPoint()
	m.nextToMeasure = nil

	for _, image := range m.images {
		if err := m.measureOneImage(bp, image); err != nil {
			return nil, xerrors.Errorf("cannot measure image %v: %w", image.source(), err)
		}
	}

	return m.nextToMeasure, nil
}
