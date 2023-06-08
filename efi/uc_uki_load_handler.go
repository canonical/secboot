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
)

type ubuntuCoreUKILoadHandler struct{}

func newUbuntuCoreUKILoadHandler(_ peImageHandle) (imageLoadHandler, error) {
	return new(ubuntuCoreUKILoadHandler), nil
}

func (h *ubuntuCoreUKILoadHandler) MeasureImageStart(_ pcrBranchContext) error {
	// TODO: Add stuff that the kernel measures here
	return nil
}

func (h *ubuntuCoreUKILoadHandler) MeasureImageLoad(_ pcrBranchContext, _ peImageHandle) (imageLoadHandler, error) {
	return nil, errors.New("kernel is a leaf image")
}
