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
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"

	"github.com/canonical/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
	"github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/pe1.14"

	"golang.org/x/xerrors"
)

// computePeImageDigest computes a hash of a PE image in accordance with the "Windows Authenticode Portable Executable Signature
// Format" specification. This function interprets the byte stream of the raw headers in some places, the layout of which are
// defined in the "PE Format" specification (https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
func computePeImageDigest(alg tpm2.HashAlgorithmId, image EFIImage) (tpm2.Digest, error) {
	r, err := image.Open()
	if err != nil {
		return nil, xerrors.Errorf("cannot open image: %w", err)
	}
	defer r.Close()

	var dosheader [96]byte
	if _, err := r.ReadAt(dosheader[0:], 0); err != nil {
		return nil, err
	}

	var coffHeaderOffset int64
	if dosheader[0] == 'M' && dosheader[1] == 'Z' {
		signoff := int64(binary.LittleEndian.Uint32(dosheader[0x3c:]))
		var sign [4]byte
		r.ReadAt(sign[:], signoff)
		if !(sign[0] == 'P' && sign[1] == 'E' && sign[2] == 0 && sign[3] == 0) {
			return nil, fmt.Errorf("invalid PE COFF file signature: %v", sign)
		}
		coffHeaderOffset = signoff + 4
	}

	p, err := pe.NewFile(r)
	if err != nil {
		return nil, xerrors.Errorf("cannot decode PE binary: %w", err)
	}

	var isPe32Plus bool
	var sizeOfHeaders int64
	var dd []pe.DataDirectory
	switch oh := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sizeOfHeaders = int64(oh.SizeOfHeaders)
		dd = oh.DataDirectory[0:oh.NumberOfRvaAndSizes]
	case *pe.OptionalHeader64:
		isPe32Plus = true
		sizeOfHeaders = int64(oh.SizeOfHeaders)
		dd = oh.DataDirectory[0:oh.NumberOfRvaAndSizes]
	default:
		return nil, errors.New("PE binary doesn't contain an optional header")
	}

	// 1) Load the image header in to memory.
	hr := io.NewSectionReader(r, 0, sizeOfHeaders)

	// 2) Initialize a hash algorithm context.
	h := alg.NewHash()

	// 3) Hash the image header from its base to immediately before the start of the checksum address in the optional header.
	// This includes the DOS header, 4-byte PE signature, COFF header, and the first 64 bytes of the optional header.
	b := make([]byte, int(coffHeaderOffset)+binary.Size(p.FileHeader)+64)
	if _, err := hr.Read(b); err != nil {
		return nil, xerrors.Errorf("cannot read from image to start to checksum: %w", err)
	}
	h.Write(b)

	// 4) Skip over the checksum, which is a 4-byte field.
	hr.Seek(4, io.SeekCurrent)

	var certTable *pe.DataDirectory

	if len(dd) > certTableIndex {
		// 5) Hash everything from the end of the checksum field to immediately before the start of the Certificate Table entry in the
		// optional header data directory.
		// This is 60 bytes for PE32 format binaries, or 76 bytes for PE32+ format binaries.
		sz := 60
		if isPe32Plus {
			sz = 76
		}
		b = make([]byte, sz)
		if _, err := hr.Read(b); err != nil {
			return nil, xerrors.Errorf("cannot read from checksum to certificate table data directory entry: %w", err)
		}
		h.Write(b)

		// 6) Get the Attribute Certificate Table address and size from the Certificate Table entry.
		certTable = &dd[certTableIndex]
	}

	// 7) Exclude the Certificate Table entry from the calculation and hash	everything from the end of the Certificate Table entry
	// to the end of image header, including the Section Table. The Certificate Table entry is 8 bytes long.
	if certTable != nil {
		hr.Seek(8, io.SeekCurrent)
	}

	chunkedHashAll := func(r io.Reader, h hash.Hash) error {
		b := make([]byte, 4096)
		for {
			n, err := r.Read(b)
			h.Write(b[:n])

			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}

	if err := chunkedHashAll(hr, h); err != nil {
		return nil, xerrors.Errorf("cannot hash remainder of headers and section table: %w", err)
	}

	// 8) Create a counter called sumOfBytesHashed, which is not part of the signature. Set this counter to the SizeOfHeaders field.
	sumOfBytesHashed := sizeOfHeaders

	// 9) Build a temporary table of pointers to all of the section headers in the image. Do not include any section headers in the
	// table whose Size field is zero.
	var sections []*pe.SectionHeader
	for _, section := range p.Sections {
		if section.Size == 0 {
			continue
		}
		sections = append(sections, &section.SectionHeader)
	}

	// 10) Using the Offset field in the referenced SectionHeader structure as a key, arrange the table's elements in ascending order.
	// In other words, sort the section headers in ascending order according to the disk-file offset of the sections.
	sort.Slice(sections, func(i, j int) bool { return sections[i].Offset < sections[j].Offset })

	for _, section := range sections {
		// 11) Walk through the sorted table, load the corresponding section into memory, and hash the entire section. Use the
		// Size field in the SectionHeader structure to determine the amount of data to hash.
		sr := io.NewSectionReader(r, int64(section.Offset), int64(section.Size))
		if err := chunkedHashAll(sr, h); err != nil {
			return nil, xerrors.Errorf("cannot hash section %s: %w", section.Name, err)
		}

		// 12) Add the section’s Size value to sumOfBytesHashed.
		sumOfBytesHashed += int64(section.Size)

		// 13) Repeat steps 11 and 12 for all of the sections in the sorted table.
	}

	// 14) Create a value called fileSize, which is not part of the signature. Set this value to the image’s file size. If fileSize is
	// greater than sumOfBytesHashed, the file contains extra data that must be added to the hash. This data begins at the
	// sumOfBytesHashed file offset, and its length is:
	// fileSize – (certTable.Size + sumOfBytesHashed)
	fileSize := r.Size()

	if fileSize > sumOfBytesHashed {
		var certSize int64
		if certTable != nil {
			certSize = int64(certTable.Size)
		}

		if fileSize < (sumOfBytesHashed + certSize) {
			return nil, errors.New("image too short")
		}

		sr := io.NewSectionReader(r, sumOfBytesHashed, fileSize-sumOfBytesHashed-certSize)
		if err := chunkedHashAll(sr, h); err != nil {
			return nil, xerrors.Errorf("cannot hash extra data: %w", err)
		}
	}

	return h.Sum(nil), nil
}

type bootManagerCodePolicyGenBranch struct {
	profile  *PCRProtectionProfile
	branches []*PCRProtectionProfile
}

func (n *bootManagerCodePolicyGenBranch) branch() *bootManagerCodePolicyGenBranch {
	b := &bootManagerCodePolicyGenBranch{profile: NewPCRProtectionProfile()}
	n.branches = append(n.branches, b.profile)
	return b
}

// bmLoadEventAndBranch binds together a EFIImageLoadEvent and the branch that the event needs to be applied to.
type bmLoadEventAndBranch struct {
	event  *EFIImageLoadEvent
	branch *bootManagerCodePolicyGenBranch
}

// EFIBootManagerProfileParams provide the arguments to AddEFIBootManagerProfile.
type EFIBootManagerProfileParams struct {
	// PCRAlgorithm is the algorithm for which to compute PCR digests for. TPMs compliant with the "TCG PC Client Platform TPM Profile
	// (PTP) Specification" Level 00, Revision 01.03 v22, May 22 2017 are required to support tpm2.HashAlgorithmSHA1 and
	// tpm2.HashAlgorithmSHA256. Support for other digest algorithms is optional.
	PCRAlgorithm tpm2.HashAlgorithmId

	// LoadSequences is a list of EFI image load sequences for which to compute PCR digests for.
	LoadSequences []*EFIImageLoadEvent
}

// AddEFIBootManagerProfile adds the UEFI boot manager code and boot attempts profile to the provided PCR protection profile, in order
// to generate a PCR policy that restricts access to a sealed key to a specific set of binaries started from the UEFI boot manager and
// which are measured to PCR 4. Events that are measured to this PCR are detailed in section 2.3.4.5 of the "TCG PC Client Platform
// Firmware Profile Specification".
//
// If the firmware supports executing system preparation applications before the transition to "OS present", events corresponding to
// the launch of these applications will be measured to PCR 4. If the event log indicates that any system preparation applications
// were executed during the current boot, this function will automatically include these binaries in the generated PCR profile. Note
// that it is not possible to pre-compute PCR values for system preparation applications using this function, and so it is not
// possible to update these in a way that is atomic (if any of them are changed, a new PCR profile can only be generated after
// performing a reboot).
//
// The sequences of binaries for which to generate a PCR profile for is supplied via the LoadSequences field of params. Note that
// this function does not use the Source field of EFIImageLoadEvent. Each bootloader stage in each load sequence must perform a
// measurement of any subsequent stage to PCR 4 in the same format as the events measured by the UEFI boot manager.
//
// Section 2.3.4.5 of the "TCG PC Client Platform Firmware Profile Specification" specifies that EFI applications that load additional
// pre-OS environment code must measure this to PCR 4 using the EV_COMPACT_HASH event type. This function does not support EFI
// applications that load additional pre-OS environment code that isn't otherwise authenticated via the secure boot mechanism,
// and will generate PCR profiles that aren't correct for applications that do this.
//
// If the EV_OMIT_BOOT_DEVICE_EVENTS is not recorded to PCR 4, the platform firmware will perform meaurements of all boot attempts,
// even if they fail. The generated PCR policy will not be satisfied if the platform firmware performs boot attempts that fail,
// even if the successful boot attempt is of a sequence of binaries included in this PCR profile.
func AddEFIBootManagerProfile(profile *PCRProtectionProfile, params *EFIBootManagerProfileParams) error {
	// Load event log
	eventLog, err := os.Open(efi.EventLogPath)
	if err != nil {
		return xerrors.Errorf("cannot open TCG event log: %w", err)
	}
	log, err := tcglog.NewLog(eventLog, tcglog.LogOptions{})
	if err != nil {
		return xerrors.Errorf("cannot parse TCG event log header: %w", err)
	}

	if !log.Algorithms.Contains(tcglog.AlgorithmId(params.PCRAlgorithm)) {
		return errors.New("cannot compute secure boot policy digests: the TCG event log does not have the requested algorithm")
	}

	profile.AddPCRValue(params.PCRAlgorithm, bootManagerCodePCR, make(tpm2.Digest, params.PCRAlgorithm.Size()))

	// Replay the event log until we see the transition from "pre-OS" to "OS-present". The event log may contain measurements
	// for system preparation applications, and spec-compliant firmware should measure a EV_EFI_ACTION “Calling EFI Application
	// from Boot Option” event before the EV_SEPARATOR event, but not all firmware does this.
	for {
		event, err := log.NextEvent()
		if err == io.EOF {
			break
		}
		if err != nil {
			return xerrors.Errorf("cannot parse TCG event log: %w", err)
		}

		if event.PCRIndex != bootManagerCodePCR {
			continue
		}

		profile.ExtendPCR(params.PCRAlgorithm, bootManagerCodePCR, tpm2.Digest(event.Digests[tcglog.AlgorithmId(params.PCRAlgorithm)]))
		if event.EventType == tcglog.EventTypeSeparator {
			break
		}
	}

	root := bootManagerCodePolicyGenBranch{profile: profile}
	allBranches := []*bootManagerCodePolicyGenBranch{&root}

	var loadEvents []*bmLoadEventAndBranch
	var nextLoadEvents []*bmLoadEventAndBranch

	if len(params.LoadSequences) == 1 {
		loadEvents = append(loadEvents, &bmLoadEventAndBranch{event: params.LoadSequences[0], branch: &root})
	} else {
		for _, e := range params.LoadSequences {
			branch := root.branch()
			allBranches = append(allBranches, branch)
			loadEvents = append(loadEvents, &bmLoadEventAndBranch{event: e, branch: branch})
		}
	}

	for len(loadEvents) > 0 {
		e := loadEvents[0]
		loadEvents = loadEvents[1:]

		digest, err := computePeImageDigest(params.PCRAlgorithm, e.event.Image)
		if err != nil {
			return err
		}
		e.branch.profile.ExtendPCR(params.PCRAlgorithm, bootManagerCodePCR, digest)

		if len(e.event.Next) == 1 {
			nextLoadEvents = append(nextLoadEvents, &bmLoadEventAndBranch{event: e.event.Next[0], branch: e.branch})
		} else {
			for _, n := range e.event.Next {
				branch := e.branch.branch()
				nextLoadEvents = append(nextLoadEvents, &bmLoadEventAndBranch{event: n, branch: branch})
				allBranches = append(allBranches, branch)
			}
		}

		if len(loadEvents) == 0 {
			loadEvents = nextLoadEvents
			nextLoadEvents = nil
		}
	}

	// Iterate over all of the branch points starting from the root and creates a tree of
	// sub-profiles with AddProfileOR. The ordering doesn't matter here, because each subprofile
	// is already complete
	for _, b := range allBranches {
		if len(b.branches) == 0 {
			continue
		}
		b.profile.AddProfileOR(b.branches...)
	}

	return nil
}
