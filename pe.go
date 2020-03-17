package secboot

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

// readDataDirectories accepts a io.ReadSeeker pointing to data directories in the PE file,
// its size and number of data directories as seen in optional header.
// It parses the given size of bytes and returns given number of data directories.
func readDataDirectories(r io.ReadSeeker, sz uint16, n uint32) ([]pe.DataDirectory, error) {
	ddSz := binary.Size(pe.DataDirectory{})
	if uint32(sz) != n*uint32(ddSz) {
		return nil, fmt.Errorf("size of data directories(%d) is inconsistent with number of data "+
			"directories(%d)", sz, n)
	}

	dd := make([]pe.DataDirectory, n)
	if err := binary.Read(r, binary.LittleEndian, dd); err != nil {
		return nil, fmt.Errorf("failure to read data directories: %v", err)
	}

	return dd, nil
}

// readOptionalHeader accepts a io.ReadSeeker pointing to optional header in the PE file
// and its size as seen in the file header.
// It parses the given size of bytes and returns optional header. It infers whether the
// bytes being parsed refer to 32 bit or 64 bit version of optional header.
func readOptionalHeader(r io.ReadSeeker, sz uint16) (interface{}, error) {
	// If optional header size is 0, return empty optional header.
	if sz == 0 {
		return nil, nil
	}

	var (
		// First couple of bytes in option header state its type.
		// We need to read them first to determine the type and
		// validity of optional header.
		ohMagic   uint16
		ohMagicSz = binary.Size(ohMagic)
	)

	// If optional header size is greater than 0 but less than its magic size, return error.
	if sz < uint16(ohMagicSz) {
		return nil, fmt.Errorf("optional header size is less than optional header magic size")
	}

	// read reads from io.ReadSeeker, r, into data.
	var err error
	read := func(data interface{}) bool {
		err = binary.Read(r, binary.LittleEndian, data)
		return err == nil
	}

	if !read(&ohMagic) {
		return nil, fmt.Errorf("failure to read optional header magic: %v", err)
	}

	switch ohMagic {
	case 0x10b: // PE32
		var (
			oh32 pe.OptionalHeader32
			// There can be 0 or more data directories. So the minimum size of optional
			// header is calculated by substracting oh32.DataDirectory size from oh32 size.
			oh32MinSz = binary.Size(oh32) - binary.Size(oh32.DataDirectory)
		)

		if sz < uint16(oh32MinSz) {
			return nil, fmt.Errorf("optional header size(%d) is less minimum size (%d) of PE32 "+
				"optional header", sz, oh32MinSz)
		}

		// Init oh32 fields
		oh32.Magic = ohMagic
		if !read(&oh32.MajorLinkerVersion) ||
			!read(&oh32.MinorLinkerVersion) ||
			!read(&oh32.SizeOfCode) ||
			!read(&oh32.SizeOfInitializedData) ||
			!read(&oh32.SizeOfUninitializedData) ||
			!read(&oh32.AddressOfEntryPoint) ||
			!read(&oh32.BaseOfCode) ||
			!read(&oh32.BaseOfData) ||
			!read(&oh32.ImageBase) ||
			!read(&oh32.SectionAlignment) ||
			!read(&oh32.FileAlignment) ||
			!read(&oh32.MajorOperatingSystemVersion) ||
			!read(&oh32.MinorOperatingSystemVersion) ||
			!read(&oh32.MajorImageVersion) ||
			!read(&oh32.MinorImageVersion) ||
			!read(&oh32.MajorSubsystemVersion) ||
			!read(&oh32.MinorSubsystemVersion) ||
			!read(&oh32.Win32VersionValue) ||
			!read(&oh32.SizeOfImage) ||
			!read(&oh32.SizeOfHeaders) ||
			!read(&oh32.CheckSum) ||
			!read(&oh32.Subsystem) ||
			!read(&oh32.DllCharacteristics) ||
			!read(&oh32.SizeOfStackReserve) ||
			!read(&oh32.SizeOfStackCommit) ||
			!read(&oh32.SizeOfHeapReserve) ||
			!read(&oh32.SizeOfHeapCommit) ||
			!read(&oh32.LoaderFlags) ||
			!read(&oh32.NumberOfRvaAndSizes) {
			return nil, fmt.Errorf("failure to read PE32 optional header: %v", err)
		}

		dd, err := readDataDirectories(r, sz-uint16(oh32MinSz), oh32.NumberOfRvaAndSizes)
		if err != nil {
			return nil, err
		}

		copy(oh32.DataDirectory[:], dd)

		return &oh32, nil
	case 0x20b: // PE32+
		var (
			oh64 pe.OptionalHeader64
			// There can be 0 or more data directories. So the minimum size of optional
			// header is calculated by substracting oh64.DataDirectory size from oh64 size.
			oh64MinSz = binary.Size(oh64) - binary.Size(oh64.DataDirectory)
		)

		if sz < uint16(oh64MinSz) {
			return nil, fmt.Errorf("optional header size(%d) is less minimum size (%d) for PE32+ "+
				"optional header", sz, oh64MinSz)
		}

		// Init oh64 fields
		oh64.Magic = ohMagic
		if !read(&oh64.MajorLinkerVersion) ||
			!read(&oh64.MinorLinkerVersion) ||
			!read(&oh64.SizeOfCode) ||
			!read(&oh64.SizeOfInitializedData) ||
			!read(&oh64.SizeOfUninitializedData) ||
			!read(&oh64.AddressOfEntryPoint) ||
			!read(&oh64.BaseOfCode) ||
			!read(&oh64.ImageBase) ||
			!read(&oh64.SectionAlignment) ||
			!read(&oh64.FileAlignment) ||
			!read(&oh64.MajorOperatingSystemVersion) ||
			!read(&oh64.MinorOperatingSystemVersion) ||
			!read(&oh64.MajorImageVersion) ||
			!read(&oh64.MinorImageVersion) ||
			!read(&oh64.MajorSubsystemVersion) ||
			!read(&oh64.MinorSubsystemVersion) ||
			!read(&oh64.Win32VersionValue) ||
			!read(&oh64.SizeOfImage) ||
			!read(&oh64.SizeOfHeaders) ||
			!read(&oh64.CheckSum) ||
			!read(&oh64.Subsystem) ||
			!read(&oh64.DllCharacteristics) ||
			!read(&oh64.SizeOfStackReserve) ||
			!read(&oh64.SizeOfStackCommit) ||
			!read(&oh64.SizeOfHeapReserve) ||
			!read(&oh64.SizeOfHeapCommit) ||
			!read(&oh64.LoaderFlags) ||
			!read(&oh64.NumberOfRvaAndSizes) {
			return nil, fmt.Errorf("failure to read PE32+ optional header: %v", err)
		}

		dd, err := readDataDirectories(r, sz-uint16(oh64MinSz), oh64.NumberOfRvaAndSizes)
		if err != nil {
			return nil, err
		}

		copy(oh64.DataDirectory[:], dd)

		return &oh64, nil
	default:
		return nil, fmt.Errorf("optional header has unexpected Magic of 0x%x", ohMagic)
	}
}

func readVariableLengthOptionalHeader(r io.ReaderAt, sz uint16) (interface{}, error) {
	var dosheader [96]byte
	if _, err := r.ReadAt(dosheader[0:], 0); err != nil {
		return nil, err
	}
	var base int64
	if dosheader[0] == 'M' && dosheader[1] == 'Z' {
		signoff := int64(binary.LittleEndian.Uint32(dosheader[0x3c:]))
		var sign [4]byte
		r.ReadAt(sign[:], signoff)
		if !(sign[0] == 'P' && sign[1] == 'E' && sign[2] == 0 && sign[3] == 0) {
			return nil, fmt.Errorf("invalid PE COFF file signature of %v.", sign)
		}
		base = signoff + 4
	} else {
		base = 0
	}

	sr := io.NewSectionReader(r, base+int64(binary.Size(pe.FileHeader{})), int64(sz))
	return readOptionalHeader(sr, sz)
}
