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
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strconv"

	efi "github.com/canonical/go-efilib"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/xerrors"
)

const (
	shimMokListRTName   = "MokListRT"
	shimName            = "Shim"
	shimSbatLevelName   = "SbatLevel"
	shimSbatLevelRTName = "SbatLevelRT"
	shimSbatPolicyName  = "SbatPolicy"
	shimVendorDbName    = "vendor_db"
)

var (
	shimGuid = efi.MakeGUID(0x605dab50, 0xe046, 0x4300, 0xabb6, [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}) // SHIM_LOCK_GUID

	// msKnownSbatLevels are all of the SBAT revocation levels associated with the
	// Microsoft UEFI CA. This is required when upgrading from pre-SBAT to SBAT-capable
	// shim because it isn't possible to determine the current device policy.
	msKnownSbatLevels = [][]byte{
		[]byte("sbat,1,2021030218\n"),
		[]byte("sbat,1,2022052400\ngrub,2\n"),
		[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n")}

	shimIdentVersionRE = regexp.MustCompile(`^\$Version:[[:blank:]]*([[:digit:].]*)[[:blank:]]*\$$`)
	shimVersionRE      = regexp.MustCompile(`^([[:digit:]]+)(?:\.([[:digit:]]+))?$`)
)

// shimSbatPolicy determines which SBAT revocation level that shim will set on the next boot.
type shimSbatPolicy uint8

const (
	shimSbatPolicyLatest   shimSbatPolicy = 1
	shimSbatPolicyPrevious shimSbatPolicy = 2
	shimSbatPolicyReset    shimSbatPolicy = 3
)

// readShimSbatPolicy returns the SBAT policy from the supplied environment.
func readShimSbatPolicy(vars varReader) (shimSbatPolicy, error) {
	data, _, err := vars.ReadVar(shimSbatPolicyName, shimGuid)
	switch {
	case err == efi.ErrVarNotExist:
		// This is the default in shim if the variable doesn't exist
		return shimSbatPolicyPrevious, nil
	case err != nil:
		return 0, err
	default:
		if len(data) != 1 {
			return 0, errors.New("invalid SbatPolicy length")
		}
		sbatPolicy := shimSbatPolicy(data[0])
		switch sbatPolicy {
		case shimSbatPolicyPrevious, shimSbatPolicyLatest, shimSbatPolicyReset:
			return sbatPolicy, nil
		default:
			return 0, errors.New("invalid SbatPolicy value")
		}
	}
}

type shimSbatPolicyLatestOption struct{}

// WithShimSbatPolicyLatest can be supplied to AddPCRProfile to compute the profile
// with the value of the SbatLevel EFI variable set to "latest" (uint(1)), in
// addition to the current value of the variable.
func WithShimSbatPolicyLatest() PCRProfileOption {
	return shimSbatPolicyLatestOption{}
}

func (shimSbatPolicyLatestOption) applyOptionTo(gen *pcrProfileGenerator) {
	gen.varModifiers = append(gen.varModifiers, func(rootVars *rootVarsCollector) error {
		for _, root := range rootVars.PeekAll() {
			if err := root.WriteVar(
				shimSbatPolicyName, shimGuid,
				efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess,
				[]byte{uint8(shimSbatPolicyLatest)}); err != nil {
				return err
			}
		}
		return nil
	})
}

// newestSbatLevel returns the newest SBAT revocation level from one or
// more supplied revocations.
func newestSbatLevel(levels ...[]byte) ([]byte, error) {
	var newestVersion string
	var newestDate string
	var newest []byte

	// Iterate over the first record for each payload.
	for i, level := range levels {
		record, err := csv.NewReader(bytes.NewReader(level)).Read()
		if err != nil {
			return nil, xerrors.Errorf("cannot parse SBAT level %d: %w", i, err)
		}
		if len(record) < 3 {
			return nil, fmt.Errorf("invalid SBAT level at %d", i)
		}

		// Obtain the version and datestamp.
		version := record[1]
		date := record[2]

		switch {
		case newestVersion == "" || version > newestVersion:
			newestVersion = version
			newestDate = date
			newest = level
		case version == newestVersion && date > newestDate:
			newestDate = date
			newest = level
		}
	}

	return newest, nil
}

// shimVersion corresponds to the version of shim.
type shimVersion struct {
	Major uint
	Minor uint
}

// parseShimVersion returns a new shimVersion from the supplied string
func parseShimVersion(version string) (shimVersion, error) {
	m := shimVersionRE.FindStringSubmatch(version)
	if len(m) != 3 {
		return shimVersion{}, errors.New("invalid shim version format")
	}

	major, err := strconv.ParseUint(m[1], 10, 0)
	if err != nil {
		return shimVersion{}, fmt.Errorf("invalid major version \"%s\"", m[1])
	}
	var minor uint64
	if m[2] != "" {
		minor, err = strconv.ParseUint(m[2], 10, 0)
		if err != nil {
			return shimVersion{}, fmt.Errorf("invalid minor version \"%s\"", m[2])
		}
	}
	return shimVersion{Major: uint(major), Minor: uint(minor)}, nil
}

// mustParseShimVersion returns a new shimVersion from the supplied string.
// This will panic if the supplied string is invalid. It is intended for
// parsing a version from compiled in literals.
func mustParseShimVersion(version string) shimVersion {
	ver, err := parseShimVersion(version)
	if err != nil {
		panic(err)
	}
	return ver
}

func parseShimVersionDataIdent(r io.Reader) (shimVersion, error) {
	scanner := bufio.NewScanner(r)

	if !scanner.Scan() {
		return shimVersion{}, errors.New("empty .data.ident section")
	}
	if scanner.Text() != "UEFI SHIM" {
		return shimVersion{}, errors.New("unexpected .data.ident section contents (not shim?)")
	}
	for scanner.Scan() {
		m := shimIdentVersionRE.FindStringSubmatch(scanner.Text())
		if len(m) == 2 {
			return parseShimVersion(m[1])
		}
	}
	if scanner.Err() != nil {
		return shimVersion{}, xerrors.Errorf("cannot decode .data.ident section contents: %w", scanner.Err())
	}
	return shimVersion{}, errors.New("cannot determine version - missing from .data.ident section")
}

// Compare compares 2 shim versions. It returns 0 if a == b, -1 if a < b and 1 if a > b
func (a shimVersion) Compare(b shimVersion) int {
	switch {
	case a.Major > b.Major:
		return 1
	case a.Major < b.Major:
		return -1
	case a.Minor < b.Minor:
		return -1
	case a.Minor > b.Minor:
		return 1
	default:
		return 0
	}
}

func (a shimVersion) String() string {
	return strconv.FormatUint(uint64(a.Major), 10) + "." + strconv.FormatUint(uint64(a.Minor), 10)
}

// shimVendorCertFormat describes the format of the content of shim's .vendor_cert
// section. This is important because it affects the format of measurements in some
// circumstances.
type shimVendorCertFormat int

const (
	// shimVendorCertIsX509 indicates that shim's .vendor_cert section contains
	// a single X.509 certificate.
	shimVendorCertIsX509 shimVendorCertFormat = iota + 1

	// shimVendorCertIsDb indicates that shim's .vendor_cert section contains
	// a signature database consisting of one or more ESLs.
	shimVendorCertIsDb
)

// shimSbatLevel corresponds to the SBAT revocation level payload stored inside
// shim.
type shimSbatLevel [2][]byte

// ForPolicy returns the SBAT revocation level for the specified policy.
func (l shimSbatLevel) ForPolicy(policy shimSbatPolicy) []byte {
	if policy != shimSbatPolicyPrevious && policy != shimSbatPolicyLatest {
		panic("invalid shimSbatPolicy value")
	}
	return l[policy-1]
}

// shimImageHandle provides some utilities for working with a shim image.
type shimImageHandle interface {
	peImageHandle

	// Version returns the shim version.
	Version() (shimVersion, error)

	// ReadVendorDB returns the vendor DB from this shim's .vendor_cert section.
	// It returns an error if the section does not exist.
	ReadVendorDB() (efi.SignatureDatabase, shimVendorCertFormat, error)

	// HasSbatLevelSection determines whether this shim has a .sbatlevel section.
	HasSbatLevelSection() bool

	// ReadSbatLevel returns the SBAT revocation level payload from the shim image.
	// Depending on policy, shim will use this payload to update the revocation
	// level of the device when executed. It will return an error if there is no
	// .sbatlevel section.
	ReadSbatLevel() (shimSbatLevel, error)
}

type shimImageHandleImpl struct {
	peImageHandle
}

// newShimImageHandle returns a new shimImageHandle for the supplied peImageHandle.
var newShimImageHandle = func(image peImageHandle) shimImageHandle {
	return &shimImageHandleImpl{peImageHandle: image}
}

func (h *shimImageHandleImpl) Version() (shimVersion, error) {
	section := h.OpenSection(".data.ident")
	if section == nil {
		return shimVersion{}, errors.New("no .data.ident section")
	}

	return parseShimVersionDataIdent(section)
}

type shimVendorCertTable struct {
	DbSize    uint32
	DbxSize   uint32
	DbOffset  uint32
	DbxOffset uint32
}

func (h *shimImageHandleImpl) ReadVendorDB() (efi.SignatureDatabase, shimVendorCertFormat, error) {
	section := h.OpenSection(".vendor_cert")
	if section == nil {
		return nil, 0, errors.New("no .vendor_cert section")
	}

	// Shim's .vendor_cert section starts with a cert_table struct (see shim.c in the
	// shim source)
	var table shimVendorCertTable
	if err := binary.Read(section, binary.LittleEndian, &table); err != nil {
		return nil, 0, xerrors.Errorf("cannot read vendor certs table: %w", err)
	}

	// A size of zero is valid
	if table.DbSize == 0 {
		return nil, shimVendorCertIsDb, nil
	}

	sr := io.NewSectionReader(section, int64(table.DbOffset), int64(table.DbSize))
	dbData, err := ioutil.ReadAll(sr)
	if err != nil {
		return nil, 0, xerrors.Errorf("cannot read vendor db data: %w", err)
	}

	elem := cryptobyte.String(dbData)
	if elem.ReadASN1Element(&elem, cryptobyte_asn1.SEQUENCE) && len(elem) == len(dbData) {
		// The vendor DB data contains a single X.509 certificate
		return efi.SignatureDatabase{
			{
				Type:       efi.CertX509Guid,
				Signatures: []*efi.SignatureData{{Data: dbData}},
			},
		}, shimVendorCertIsX509, nil
	}

	// The vendor DB data contains one or more ESLs
	db, err := efi.ReadSignatureDatabase(bytes.NewReader(dbData))
	if err != nil {
		return nil, 0, err
	}
	return db, shimVendorCertIsDb, nil
}

func (h *shimImageHandleImpl) HasSbatLevelSection() bool {
	return h.HasSection(".sbatlevel")
}

type shimSbatLevelTable struct {
	PreviousOffset uint32
	LatestOffset   uint32
}

func (h *shimImageHandleImpl) ReadSbatLevel() (shimSbatLevel, error) {
	section := h.OpenSection(".sbatlevel")
	if section == nil {
		return shimSbatLevel{}, errors.New("no .sbatlevel section")
	}

	// The start of the .sbatlevel section is a version number and a table
	// containing 2 offsets to each/ NULL terminated SBAT revocation policy.
	var version uint32
	if err := binary.Read(section, binary.LittleEndian, &version); err != nil {
		return shimSbatLevel{}, xerrors.Errorf("cannot read .sbatlevel version: %w", err)
	}
	if version != 0 {
		return shimSbatLevel{}, errors.New("invalid .sbatlevel version")
	}

	sr := io.NewSectionReader(section, 4, section.Size()-4)

	var table shimSbatLevelTable
	if err := binary.Read(io.NewSectionReader(sr, 0, int64(binary.Size(table))), binary.LittleEndian, &table); err != nil {
		return shimSbatLevel{}, xerrors.Errorf("cannot read .sbatlevel table: %w", err)
	}

	var out shimSbatLevel

	sr.Seek(int64(table.LatestOffset), io.SeekStart)
	level, err := ioutil.ReadAll(newCstringReader(sr))
	if err != nil {
		return shimSbatLevel{}, err
	}
	out[shimSbatPolicyLatest-1] = level

	sr.Seek(int64(table.PreviousOffset), io.SeekStart)
	level, err = ioutil.ReadAll(newCstringReader(sr))
	if err != nil {
		return shimSbatLevel{}, err
	}
	out[shimSbatPolicyPrevious-1] = level

	return out, nil
}
