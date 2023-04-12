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

package efi

import (
	"fmt"
	"io"
	"os"

	"github.com/snapcore/secboot"
	"github.com/snapcore/snapd/snap"
)

// ImageReader corresponds to an open handle from which to read a binary image from.
type ImageReader interface {
	io.ReaderAt
	io.Closer
	Size() int64
}

// Image provides an image that is loaded during the boot process before ExitBootServices.
type Image interface {
	fmt.Stringer
	Open() (ImageReader, error) // Open a handle to the image for reading
}

// SnapFileImage provides an image contained within a snap package that is loaded
// during the boot process before ExitBootServices.
type SnapFileImage struct {
	Container snap.Container
	FileName  string // The filename within the snap squashfs
}

// NewSnapFileImage creates a new SnapFileImage for the file at the
// specified relative path within the supplied snap.
func NewSnapFileImage(container snap.Container, filename string) *SnapFileImage {
	return &SnapFileImage{
		Container: container,
		FileName:  filename}
}

// String implements [fmt.Stringer].
func (f SnapFileImage) String() string {
	return fmt.Sprintf("%#v:%s", f.Container, f.FileName)
}

// Open implements [ImageSource.Open].
func (f SnapFileImage) Open() (ImageReader, error) {
	return f.Container.RandomAccessFile(f.FileName)
}

type fileImageReader struct {
	*os.File
	size int64
}

func (h *fileImageReader) Size() int64 {
	return h.size
}

// FileImage provides an image from a file that is loaded during the boot process
// before ExitBootServices.
type FileImage string

// NewFileImage creates a new FileImage for the file at the specified path.
func NewFileImage(path string) FileImage {
	return FileImage(path)
}

// String implements [fmt.Stringer].
func (p FileImage) String() string {
	return string(p)
}

// Open implements [ImageSource.Open].
func (p FileImage) Open() (ImageReader, error) {
	f, err := os.Open(string(p))
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &fileImageReader{File: f, size: fi.Size()}, nil
}

// loadParams correspond to a set of parameters that apply to a single branch
// in a PCR profile.
type loadParams struct {
	KernelCommandline string
	SnapModel         secboot.SnapModel
	Source            ImageLoadEventSource // XXX: This is temporary until efi/secureboot_policy.go has been ported to the new code
}

// ImageLoadParams provides one or more values for an external parameter that
// is supplied to an image which is loaded during the boot process.
type ImageLoadParams interface {
	// applyTo applies each of the parameters defined by this implementation to
	// each of the supplied loadParams, returning a new list of loadParams. If
	// there are n supplied initial loadParams and this implementation defines
	// m new parameters, it will return n x m new loadParams.
	applyTo(params ...loadParams) []loadParams
}

type kernelCommandlineParams []string

// KernelCommandlineParams returns a ImageLoadParams for the specified kernel
// commandlines.
func KernelCommandlineParams(commandlines ...string) ImageLoadParams {
	return kernelCommandlineParams(commandlines)
}

func (p kernelCommandlineParams) applyTo(params ...loadParams) []loadParams {
	var out []loadParams
	for _, cmdline := range []string(p) {
		p := make([]loadParams, len(params))
		copy(p, params)
		for i := range p {
			p[i].KernelCommandline = cmdline
		}
		out = append(out, p...)
	}
	return out
}

type snapModelParams []secboot.SnapModel

// SnapModelParams returns a ImageLoadParams for the specifed snap models.
func SnapModelParams(models ...secboot.SnapModel) ImageLoadParams {
	return snapModelParams(models)
}

func (p snapModelParams) applyTo(params ...loadParams) []loadParams {
	var out []loadParams
	for _, model := range []secboot.SnapModel(p) {
		p := make([]loadParams, len(params))
		copy(p, params)
		for i := range p {
			p[i].SnapModel = model
		}
		out = append(out, p...)
	}
	return out
}

// ImageLoadEventSource corresponds to the source of a ImageLoadActivity.
// XXX: This exists temporarily until efi/secureboot_policy.go has been ported to the new
// profile generation implementation.
type ImageLoadEventSource int

const (
	// Firmware indicates that the source of a ImageLoadActivity was platform firmware, via the EFI_BOOT_SERVICES.LoadImage()
	// and EFI_BOOT_SERVICES.StartImage() functions, with the subsequently executed image being verified against the signatures
	// in the EFI authorized signature database.
	Firmware ImageLoadEventSource = iota

	// Shim indicates that the source of a ImageLoadActivity was shim, without relying on EFI boot services for loading, verifying
	// and executing the subsequently executed image. The image is verified by shim against the signatures in the EFI authorized
	// signature database, the MOK database or shim's built-in vendor certificate before being executed directly.
	Shim
)

func (s ImageLoadEventSource) applyTo(params ...loadParams) []loadParams {
	var out []loadParams
	for _, param := range params {
		param.Source = s
		out = append(out, param)
	}
	return out
}

type imageLoadParamsSet []ImageLoadParams

func (s imageLoadParamsSet) Resolve(initial *loadParams) []loadParams {
	params := []loadParams{*initial}
	for _, p := range s {
		params = p.applyTo(params...)
	}
	return params
}

// ImageLoadActivity corresponds to the execution of an image during the boot
// process, before ExitBootServices. It is associated with an [Image] and an
// optional number of [ImageLoadParams].
type ImageLoadActivity interface {
	// Loads lets one specify a set of images that are permitted to be executed by the
	// image associated with this activity. The supplied images will inherit the
	// parameters associated with this image unless they are overridden explicitly.
	Loads(images ...ImageLoadActivity) ImageLoadActivity

	source() Image
	next() []ImageLoadActivity
	params() imageLoadParamsSet
}

// NewImageLoadActivity returns a new ImageLoadActivity for the specified image that will
// be executed during the boot process, before ExitBootServices. The caller can specify
// optional parameters that will apply to the specified image and which will be inherited
// by subsequent images (added by [ImageLoadActivity.Loads]). The supplied parameters will
// override any existing ones that would be inherited by this image. Parameters that
// provide multiple values will automatically create branches in the profile. If a parameter
// type is supplied more than once, only the last supplied one will be used.
func NewImageLoadActivity(image Image, params ...ImageLoadParams) ImageLoadActivity {
	return &baseImageLoadActivity{
		sourceImage: image,
		loadParams:  params}
}

type baseImageLoadActivity struct {
	sourceImage Image
	nextImages  []ImageLoadActivity
	loadParams  imageLoadParamsSet
}

func (e *baseImageLoadActivity) Loads(images ...ImageLoadActivity) ImageLoadActivity {
	e.nextImages = images
	return e
}

func (e *baseImageLoadActivity) source() Image {
	return e.sourceImage
}

func (e *baseImageLoadActivity) next() []ImageLoadActivity {
	return e.nextImages
}

func (e *baseImageLoadActivity) params() imageLoadParamsSet {
	return e.loadParams
}

// ImageLoadSequences corresponds to all of the boot paths for images executed before
// ExitBootServices.
type ImageLoadSequences struct {
	images []ImageLoadActivity
	params imageLoadParamsSet
}

// NewImageLoadSequences returns a new ImageLoadSequences object with the specified
// parameters, which will be inherited by all of the appended paths.
func NewImageLoadSequences(params ...ImageLoadParams) *ImageLoadSequences {
	return &ImageLoadSequences{params: params}
}

// Append appends the specified image load.
func (a *ImageLoadSequences) Append(images ...ImageLoadActivity) *ImageLoadSequences {
	a.images = append(a.images, images...)
	return a
}
