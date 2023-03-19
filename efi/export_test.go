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
	efi "github.com/canonical/go-efilib"
	"github.com/snapcore/secboot/internal/testutil"
)

// Export constants for testing
const (
	ShimName                                   = shimName
	ShimSbatPolicyLatest                       = shimSbatPolicyLatest
	ShimSbatPolicyPrevious                     = shimSbatPolicyPrevious
	ShimVendorCertIsX509                       = shimVendorCertIsX509
	ShimVendorCertIsDb                         = shimVendorCertIsDb
	SignatureDBUpdateNoFirmwareQuirk           = signatureDBUpdateNoFirmwareQuirk
	SignatureDBUpdateFirmwareDedupIgnoresOwner = signatureDBUpdateFirmwareDedupIgnoresOwner
)

// Export variables and unexported functions for testing
var (
	AppendSignatureDBUpdate   = appendSignatureDBUpdate
	DefaultEnv                = defaultEnv
	MustParseShimVersion      = mustParseShimVersion
	NewestSbatLevel           = newestSbatLevel
	NewRootVarsCollector      = newRootVarsCollector
	NewShimImageHandle        = newShimImageHandle
	OpenPeImage               = openPeImage
	ParseShimVersion          = parseShimVersion
	ParseShimVersionDataIdent = parseShimVersionDataIdent
	ReadShimSbatPolicy        = readShimSbatPolicy
	ShimGuid                  = shimGuid
)

// Alias some unexported types for testing. These are required in order to pass these between functions in tests, or to access
// unexported members of some unexported types.
type ImageLoadParamsSet = imageLoadParamsSet
type LoadParams = loadParams
type PeImageHandle = peImageHandle
type RootVarReaderKey = rootVarReaderKey
type SbatComponent = sbatComponent
type SecureBootAuthority = secureBootAuthority
type SecureBootDB = secureBootDB
type SecureBootPolicyMixin = secureBootPolicyMixin
type ShimImageHandle = shimImageHandle
type ShimSbatLevel = shimSbatLevel
type ShimSbatPolicy = shimSbatPolicy
type ShimVendorCertFormat = shimVendorCertFormat
type ShimVersion = shimVersion
type SignatureDBUpdateFirmwareQuirk = signatureDBUpdateFirmwareQuirk
type VarBranch = varBranch

// Helper functions
func ImageLoadActivityNext(activity ImageLoadActivity) []ImageLoadActivity {
	return activity.next()
}

func ImageLoadActivityParams(activity ImageLoadActivity) imageLoadParamsSet {
	return activity.params()
}

func MockEFIVarsPath(path string) (restore func()) {
	origPath := efiVarsPath
	efiVarsPath = path
	return func() {
		efiVarsPath = origPath
	}
}

func MockEventLogPath(path string) (restore func()) {
	origPath := eventLogPath
	eventLogPath = path
	return func() {
		eventLogPath = origPath
	}
}

func MockReadVar(dir string) (restore func()) {
	origReadVar := readVar
	readVar = func(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
		return testutil.EFIReadVar(dir, name, guid)
	}

	return func() {
		readVar = origReadVar
	}
}

func NewRootVarReader(host HostEnvironment) *rootVarReader {
	return &rootVarReader{
		host:      host,
		overrides: make(map[efi.VariableDescriptor]varContents)}
}

func NewVarUpdate(prev *varUpdate, name efi.VariableDescriptor, attrs efi.VariableAttributes, data []byte) *varUpdate {
	return &varUpdate{
		previous: prev,
		name:     name,
		attrs:    attrs,
		data:     data}
}
