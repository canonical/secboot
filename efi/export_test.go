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
	"github.com/canonical/tcglog-parser"
	"github.com/snapcore/secboot/efi/internal"
)

// Export constants for testing
const (
	GrubChainloaderUsesShimProtocol            = grubChainloaderUsesShimProtocol
	KernelConfigPCR                            = kernelConfigPCR
	ShimFixVariableAuthorityEventsMatchSpec    = shimFixVariableAuthorityEventsMatchSpec
	ShimHasSbatRevocationManagement            = shimHasSbatRevocationManagement
	ShimHasSbatVerification                    = shimHasSbatVerification
	ShimName                                   = shimName
	ShimSbatPolicyLatest                       = shimSbatPolicyLatest
	ShimSbatPolicyPrevious                     = shimSbatPolicyPrevious
	ShimVendorCertContainsDb                   = shimVendorCertContainsDb
	ShimVendorCertIsX509                       = shimVendorCertIsX509
	ShimVendorCertIsDb                         = shimVendorCertIsDb
	SignatureDBUpdateNoFirmwareQuirk           = signatureDBUpdateNoFirmwareQuirk
	SignatureDBUpdateFirmwareDedupIgnoresOwner = signatureDBUpdateFirmwareDedupIgnoresOwner
)

// Export variables and unexported functions for testing
var (
	ApplySignatureDBUpdate                      = applySignatureDBUpdate
	ErrNoHandler                                = errNoHandler
	ImageAlwaysMatches                          = imageAlwaysMatches
	ImageDigestMatches                          = imageDigestMatches
	ImageMatchesAll                             = imageMatchesAll
	ImageMatchesAny                             = imageMatchesAny
	LookupImageLoadHandler                      = lookupImageLoadHandler
	MakeFallbackImageRules                      = makeFallbackImageRules
	MakeImageLoadHandlerMap                     = makeImageLoadHandlerMap
	MakeMicrosoftUEFICASecureBootNamespaceRules = makeMicrosoftUEFICASecureBootNamespaceRules
	MustParseShimVersion                        = mustParseShimVersion
	MakePcrFlags                                = makePcrFlags
	NewestSbatLevel                             = newestSbatLevel
	NewFwLoadHandler                            = newFwLoadHandler
	NewGrubImageHandle                          = newGrubImageHandle
	NewImageLoadHandlerLazyMap                  = newImageLoadHandlerLazyMap
	NewImageRule                                = newImageRule
	NewImageRules                               = newImageRules
	NewPcrImagesMeasurer                        = newPcrImagesMeasurer
	NewPcrProfileGenerator                      = newPcrProfileGenerator
	NewRootPcrBranchCtx                         = newRootPcrBranchCtx
	NewSecureBootNamespaceRules                 = newSecureBootNamespaceRules
	NewShimImageHandle                          = newShimImageHandle
	NewShimLoadHandler                          = newShimLoadHandler
	NewShimLoadHandlerConstructor               = newShimLoadHandlerConstructor
	NewVariableSetCollector                     = newVariableSetCollector
	OpenPeImage                                 = openPeImage
	ParseShimVersion                            = parseShimVersion
	ParseShimVersionDataIdent                   = parseShimVersionDataIdent
	ReadShimSbatPolicy                          = readShimSbatPolicy
	SbatSectionExists                           = sbatSectionExists
	ShimGuid                                    = shimGuid
	ShimVersionIs                               = shimVersionIs
	WithAuthority                               = withAuthority
	WithImageRule                               = withImageRule
	WithImageRuleOnlyForTesting                 = withImageRuleOnlyForTesting
	WithSelfSignedSignerOnlyForTesting          = withSelfSignedSignerOnlyForTesting
)

// Alias some unexported types for testing. These are required in order to pass these between functions in tests, or to access
// unexported members of some unexported types.
type FwContext = fwContext
type GrubFlags = grubFlags
type GrubHasPrefix = grubHasPrefix
type GrubImageHandle = grubImageHandle
type GrubLoadHandler = grubLoadHandler
type ImageLoadHandler = imageLoadHandler
type ImageLoadHandlerMap = imageLoadHandlerMap
type ImageLoadParamsSet = imageLoadParamsSet
type ImageRules = imageRules
type ImageSectionExists = imageSectionExists
type ImageSignedByOrganization = imageSignedByOrganization
type InitialVarReaderKey = initialVarReaderKey
type LoadParams = loadParams
type NullLoadHandler = nullLoadHandler
type PcrBranchContext = pcrBranchContext
type PcrFlags = pcrFlags
type PcrImagesMeasurer = pcrImagesMeasurer
type PcrProfileContext = pcrProfileContext
type PeImageHandle = peImageHandle
type SbatComponent = sbatComponent
type SbatComponentExists = sbatComponentExists
type SecureBootAuthority = secureBootAuthority
type SecureBootDB = secureBootDB
type SecureBootNamespaceRules = secureBootNamespaceRules
type SecureBootPolicyMixin = secureBootPolicyMixin
type ShimContext = shimContext
type ShimFlags = shimFlags
type ShimImageHandle = shimImageHandle
type ShimLoadHandler = shimLoadHandler
type ShimSbatLevel = shimSbatLevel
type ShimSbatPolicy = shimSbatPolicy
type ShimVendorCertFormat = shimVendorCertFormat
type ShimVersion = shimVersion
type SignatureDBUpdateFirmwareQuirk = signatureDBUpdateFirmwareQuirk
type UbuntuCoreUKILoadHandler = ubuntuCoreUKILoadHandler
type VarBranch = varBranch
type VariableSetCollector = variableSetCollector
type VarReadWriter = varReadWriter
type VendorAuthorityGetter = vendorAuthorityGetter

// Helper functions
func ImageLoadActivityNext(activity ImageLoadActivity) []ImageLoadActivity {
	return activity.next()
}

func ImageLoadActivityParams(activity ImageLoadActivity) imageLoadParamsSet {
	return activity.params()
}

func (s *ImageLoadSequences) Images() []ImageLoadActivity {
	return s.images
}

func (s *ImageLoadSequences) Params() imageLoadParamsSet {
	return s.params
}

func MockMakeImageLoadHandlerMap(fn func() imageLoadHandlerMap) (restore func()) {
	orig := makeImageLoadHandlerMap
	makeImageLoadHandlerMap = fn
	return func() {
		makeImageLoadHandlerMap = orig
	}
}

func MockNewFwLoadHandler(fn func(*tcglog.Log) ImageLoadHandler) (restore func()) {
	orig := newFwLoadHandler
	newFwLoadHandler = fn
	return func() {
		newFwLoadHandler = orig
	}
}

func MockNewGrubImageHandle(fn func(peImageHandle) grubImageHandle) (restore func()) {
	orig := newGrubImageHandle
	newGrubImageHandle = fn
	return func() {
		newGrubImageHandle = orig
	}
}

func MockNewShimImageHandle(fn func(peImageHandle) shimImageHandle) (restore func()) {
	orig := newShimImageHandle
	newShimImageHandle = fn
	return func() {
		newShimImageHandle = orig
	}
}

func MockOpenPeImage(fn func(Image) (peImageHandle, error)) (restore func()) {
	orig := openPeImage
	openPeImage = fn
	return func() {
		openPeImage = orig
	}
}

func MockSnapdenvTesting(testing bool) (restore func()) {
	orig := snapdenvTesting
	snapdenvTesting = func() bool { return testing }
	return func() {
		snapdenvTesting = orig
	}
}

func NewInitialVarReader(host HostEnvironment) *initialVarReader {
	return &initialVarReader{
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

type mockInitialVariablesModifierOption internal.InitialVariablesModifier

func (o mockInitialVariablesModifierOption) ApplyOptionTo(visitor internal.PCRProfileOptionVisitor) error {
	visitor.AddInitialVariablesModifier(internal.InitialVariablesModifier(o))
	return nil
}

func WithMockInitialVariablesModifierOption(fn func(internal.VariableSet) error) PCRProfileOption {
	return mockInitialVariablesModifierOption(fn)
}
