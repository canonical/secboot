// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package secboot

import (
	"fmt"
	"github.com/snapcore/snapd/snap"
	"io"
	"os"
)

const (
	bootManagerCodePCR = 4 // Boot Manager Code and Boot Attempts PCR

	certTableIndex = 4 // Index of the Certificate Table entry in the Data Directory of a PE image optional header
)

// EFIImage corresponds to a binary that is loaded, verified and executed before ExitBootServices.
type EFIImage interface {
	fmt.Stringer
	Open() (interface {
		io.ReaderAt
		io.Closer
		Size() int64
	}, error) // Open a handle to the image for reading
}

// SnapFileEFIImage corresponds to a binary contained within a snap file that is loaded, verified and executed before ExitBootServices.
type SnapFileEFIImage struct {
	Container snap.Container
	Path      string // The path of the snap image (used by the implementation of fmt.Stringer)
	FileName  string // The filename within the snap squashfs
}

func (f SnapFileEFIImage) String() string {
	return "snap:" + f.Path + ":" + f.FileName
}

func (f SnapFileEFIImage) Open() (interface {
	io.ReaderAt
	io.Closer
	Size() int64
}, error) {
	return f.Container.RandomAccessFile(f.FileName)
}

type fileEFIImageHandle struct {
	*os.File
	size int64
}

func (h *fileEFIImageHandle) Size() int64 {
	return h.size
}

// FileEFIImage corresponds to a file on disk that is loaded, verified and executed before ExitBootServices.
type FileEFIImage string

func (p FileEFIImage) String() string {
	return string(p)
}

func (p FileEFIImage) Open() (interface {
	io.ReaderAt
	io.Closer
	Size() int64
}, error) {
	f, err := os.Open(string(p))
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return &fileEFIImageHandle{File: f, size: fi.Size()}, nil
}

// EFIImageLoadEventSource corresponds to the source of a EFIImageLoadEvent.
type EFIImageLoadEventSource int

const (
	// Firmware indicates that the source of a EFIImageLoadEvent was platform firmware, via the EFI_BOOT_SERVICES.LoadImage()
	// and EFI_BOOT_SERVICES.StartImage() functions, with the subsequently executed image being verified against the signatures
	// in the EFI authorized signature database.
	Firmware EFIImageLoadEventSource = iota

	// Shim indicates that the source of a EFIImageLoadEvent was shim, without relying on EFI boot services for loading, verifying
	// and executing the subsequently executed image. The image is verified by shim against the signatures in the EFI authorized
	// signature database, the MOK database or shim's built-in vendor certificate before being executed directly.
	Shim
)

// EFIImageLoadEvent corresponds to the execution of a verified EFIImage.
type EFIImageLoadEvent struct {
	Source EFIImageLoadEventSource // The source of the event
	Image  EFIImage                // The image
	Next   []*EFIImageLoadEvent    // A list of possible subsequent EFIImageLoadEvents
}
