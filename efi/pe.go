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
	"bytes"
	"crypto"
	"encoding/csv"
	"errors"
	"io"
	"strconv"

	efi "github.com/canonical/go-efilib"
	"golang.org/x/xerrors"

	internal_efi "github.com/snapcore/secboot/internal/efi"
	pe "github.com/snapcore/secboot/internal/pe1.14"
)

type sbatComponent struct {
	Name              string
	Generation        int
	VendorName        string
	VendorPackageName string
	VendorVersion     string
	VendorUrl         string
}

// peImageHandle provides utilities for working with a PE image's sections and signatures.
type peImageHandle interface {
	// Close closes this image handle
	Close() error

	// Source returns the image source
	Source() Image

	// Machine is the target machine
	Machine() uint16

	// OpenSection returns a new io.SectionReader for the section with
	// the specified name, or nil if no section exists.
	OpenSection(name string) *io.SectionReader

	// HasSection indicates whether a section with the specified name
	// exists.
	HasSection(name string) bool

	// HasSbatSection indicates whether this image has section with the
	// name ".sbat".
	HasSbatSection() bool

	// SbatComponents returns all of the SBAT component descriptors associated
	// with this image from its .sbat section. These component descriptors are
	// tested against a device's revocation policy before being executed. If
	// the section does not exist, an error will be returned.
	SbatComponents() ([]sbatComponent, error)

	// ImageDigest returns the Authenticode hash for this image with the
	// specified algorithm.
	ImageDigest(alg crypto.Hash) ([]byte, error)

	// SecureBootSignatures returns all of the secure boot signatures for this
	// image if it is signed.
	SecureBootSignatures() ([]*efi.WinCertificateAuthenticode, error)
}

type peImageHandleImpl struct {
	source Image
	pefile *pe.File
	r      ImageReader
}

// openPeImage opens the supplied image and returns a new peImageHandle. The
// caller must call peImageHandle.Close whend done.
var openPeImage = func(image Image) (peImageHandle, error) {
	r, err := image.Open()
	if err != nil {
		return nil, xerrors.Errorf("cannot open image: %w", err)
	}

	pefile, err := pe.NewFile(r)
	if err != nil {
		r.Close()
		return nil, xerrors.Errorf("cannot decode image: %w", err)
	}

	return &peImageHandleImpl{source: image, pefile: pefile, r: r}, nil
}

func (h *peImageHandleImpl) Close() error {
	return h.r.Close()
}

func (h *peImageHandleImpl) Source() Image {
	return h.source
}

func (h *peImageHandleImpl) Machine() uint16 {
	return h.pefile.Machine
}

func (h *peImageHandleImpl) OpenSection(name string) *io.SectionReader {
	section := h.pefile.Section(name)
	if section == nil {
		return nil
	}
	// We don't use pe.Section.Open here because that only returns a
	// io.ReadSeeker - we want to return something that implements
	// io.ReaderAt as well.
	return io.NewSectionReader(section.ReaderAt, 0, int64(section.Size))
}

func (h *peImageHandleImpl) HasSection(name string) bool {
	return h.pefile.Section(name) != nil
}

func (h *peImageHandleImpl) HasSbatSection() bool {
	return h.HasSection(".sbat")
}

func (h *peImageHandleImpl) SbatComponents() ([]sbatComponent, error) {
	sr := h.OpenSection(".sbat")
	if sr == nil {
		return nil, errors.New("no .sbat section")
	}

	r := csv.NewReader(newCstringReader(sr))
	r.FieldsPerRecord = 6

	var components []sbatComponent
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, xerrors.Errorf("invalid SBAT record: %w", err)
		}

		gen, err := strconv.Atoi(record[1])
		if err != nil {
			return nil, xerrors.Errorf("invalid SBAT component generation: %w", err)
		}
		component := sbatComponent{
			Name:              record[0],
			Generation:        gen,
			VendorName:        record[2],
			VendorPackageName: record[3],
			VendorVersion:     record[4],
			VendorUrl:         record[5]}

		if component.Name == "sbat" {
			if component.Generation != 1 {
				return nil, xerrors.Errorf("invalid .sbat section version")
			}
			continue
		}

		components = append(components, component)
	}

	return components, nil
}

func (h *peImageHandleImpl) ImageDigest(alg crypto.Hash) ([]byte, error) {
	return efi.ComputePeImageDigest(alg, h.r, h.r.Size())
}

func (h *peImageHandleImpl) SecureBootSignatures() ([]*efi.WinCertificateAuthenticode, error) {
	return internal_efi.SecureBootSignaturesFromPEFile(h.pefile, h.r)
}

// cstringReader is a reader that can read a C-style NULL terminated string.
type cstringReader struct {
	r   io.Reader
	eof bool
}

func newCstringReader(r io.Reader) io.Reader {
	return &cstringReader{r: r}
}

func (r *cstringReader) Read(p []byte) (int, error) {
	if r.eof {
		return 0, io.EOF
	}
	n, err := r.r.Read(p)
	i := bytes.IndexByte(p[:n], 0)
	if i >= 0 {
		r.eof = true
		n = i
	}
	return n, err
}
