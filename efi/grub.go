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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	pe "github.com/snapcore/secboot/internal/pe1.14"
)

// grubObjTypePrefix is the module type for a module containing the
// grub prefix.
const grubObjTypePrefix uint32 = 3

// grubModuleHeader is an individual module header
type grubModuleHeader struct {
	Type uint32 // the module type
	Size uint32 // the module size, including the header
}

// grubModuleMagic represent the bytes that the mods section starts with.
const grubModuleMagic uint32 = 0x676d696d

// grubModuleInfo32 is the header at the start of the mods section, for
// 32 bit builds.
type grubModuleInfo32 struct {
	Magic  uint32
	Offset uint32 // the offset of the first module, from the start of this header
	Size   uint32 // the size of all modules, including this header
}

// grubModuleInfo64 is the header at the start of the mods section, for
// 64 bit builds.
type grubModuleInfo64 struct {
	Magic   uint32
	Padding uint32
	Offset  uint64 // the offset of the first module, from the start of this header
	Size    uint64 // the size of all modules, including this header
}

// grubModule represents a grub module
type grubModule struct {
	Type uint32
	*io.SectionReader
}

// grubImageHandle corresponds to a grub image.
type grubImageHandle interface {
	peImageHandle

	// Prefix returns the path that grub uses to load its configuration
	// from the ESP.
	Prefix() (string, error)
}

type grubImageHandleImpl struct {
	peImageHandle
}

// newGrubImageHandle returns a new grubImageHandle for the supplied peImageHandle.
var newGrubImageHandle = func(image peImageHandle) grubImageHandle {
	return &grubImageHandleImpl{peImageHandle: image}
}

func (h *grubImageHandleImpl) mods() ([]grubModule, error) {
	section := h.OpenSection("mods")
	if section == nil {
		return nil, errors.New("no mods section")
	}

	var r *io.SectionReader
	switch h.Machine() {
	case pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_ARM64, pe.IMAGE_FILE_MACHINE_RISCV64:
		var info grubModuleInfo64
		if err := binary.Read(section, binary.LittleEndian, &info); err != nil {
			return nil, fmt.Errorf("cannot obtain modules info: %w", err)
		}
		if info.Magic != grubModuleMagic {
			return nil, errors.New("invalid modules magic")
		}
		if info.Offset > math.MaxInt64 {
			return nil, errors.New("invalid modules offset")
		}
		if info.Size > math.MaxInt64 || info.Size < info.Offset {
			return nil, errors.New("invalid modules size")
		}
		r = io.NewSectionReader(section, int64(info.Offset), int64(info.Size)-int64(info.Offset))
	case pe.IMAGE_FILE_MACHINE_ARM, pe.IMAGE_FILE_MACHINE_I386, pe.IMAGE_FILE_MACHINE_RISCV32:
		var info grubModuleInfo32
		if err := binary.Read(section, binary.LittleEndian, &info); err != nil {
			return nil, fmt.Errorf("cannot obtain modules info: %w", err)
		}
		if info.Magic != grubModuleMagic {
			return nil, errors.New("invalid module magic")
		}
		if info.Size < info.Offset {
			return nil, errors.New("invalid modules size")
		}
		r = io.NewSectionReader(section, int64(info.Offset), int64(info.Size)-int64(info.Offset))
	default:
		return nil, fmt.Errorf("unrecognized machine: %d", h.Machine())
	}

	var mods []grubModule

	for {
		var hdr grubModuleHeader
		if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("cannot obtain module header: %w", err)
		}

		offset, _ := r.Seek(0, io.SeekCurrent)
		size := int64(hdr.Size) - int64(binary.Size(hdr))
		mods = append(mods, grubModule{
			Type:          hdr.Type,
			SectionReader: io.NewSectionReader(r, offset, size),
		})

		if _, err := r.Seek(size, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("cannot seek to next module: %w", err)
		}
	}

	return mods, nil
}

func (h *grubImageHandleImpl) Prefix() (string, error) {
	mods, err := h.mods()
	if err != nil {
		return "", err
	}

	for _, mod := range mods {
		if mod.Type != grubObjTypePrefix {
			continue
		}

		prefix, err := io.ReadAll(newCstringReader(mod))
		if err != nil {
			return "", fmt.Errorf("cannot obtain prefix: %w", err)
		}
		return string(prefix), nil
	}

	return "", nil
}
