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
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	efi "github.com/canonical/go-efilib"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"golang.org/x/xerrors"
)

var (
	// PK is the identity of the Platform Key variable.
	PK = efi.VariableDescriptor{Name: "PK", GUID: efi.GlobalVariable}

	// KEK is the identity of the Key Exchange Key database.
	KEK = efi.VariableDescriptor{Name: "KEK", GUID: efi.GlobalVariable}

	// Db is the identity of the authorized signature database.
	Db = efi.VariableDescriptor{Name: "db", GUID: efi.ImageSecurityDatabaseGuid}

	// Dbx is the identity of the forbidden signature database.
	Dbx = efi.VariableDescriptor{Name: "dbx", GUID: efi.ImageSecurityDatabaseGuid}
)

// SignatureDBUpdate corresponds to an update to a signature database, such as dbx.
type SignatureDBUpdate struct {
	Name efi.VariableDescriptor // The identity of the signature database
	Data []byte                 // The update payload
}

type signatureDBUpdatesOption []*SignatureDBUpdate

func (u signatureDBUpdatesOption) ApplyOptionTo(visitor internal_efi.PCRProfileOptionVisitor) error {
	visitor.AddInitialVariablesModifier(func(vars internal_efi.VariableSet) error {
		for _, quirk := range []signatureDBUpdateFirmwareQuirk{
			signatureDBUpdateNoFirmwareQuirk,
			signatureDBUpdateFirmwareDedupIgnoresOwner} {

			// Create a branch in the variable set
			branch := vars.Clone()

			// This creates an initial variable set for each intermediate state.
			for i, update := range u {
				if err := applySignatureDBUpdate(branch, update, quirk); err != nil {
					return fmt.Errorf("cannot compute signature database update %d: %w", i, err)
				}
			}
		}
		return nil
	})
	return nil
}

// WithSignatureDBUpdates can be supplied to AddPCRProfile to compute the profile
// for each of the supplied signature database updates in turn, in addition to the
// current signature database contents. This should only be supplied once. If a
// profile needs to be computed for more than one signature database update,
// provide them all in a single option.
func WithSignatureDBUpdates(updates ...*SignatureDBUpdate) PCRProfileOption {
	return signatureDBUpdatesOption(updates)
}

// secureBootAuthority describes the CA that authenticates an image.
type secureBootAuthority struct {
	Source    efi.VariableDescriptor
	Signature *efi.SignatureData
}

// secureBootDB describes a secure boot database containing signatures that can be
// used to authenticate an image.
type secureBootDB struct {
	Name     efi.VariableDescriptor
	Contents efi.SignatureDatabase
}

type secureBootPolicyMixin struct{}

// DetermineAuthority returns the CA that will authenticate the specified image using the
// supplied signature databases, in order to determine the verification digest that will
// be measured before the image is loaded.
//
// Where an image has multiple signatures, each signature will be tested against the provided
// databases in the order that they appear in the image.
//
// For each signature in the image, this will iterate over the supplied signature databases
// in the order that they are provided, and the certificates in the order that they appear in
// each database. The first valid CA will be returned.
//
// The behaviour with multiple signatures isn't defined in the UEFI specification, but the
// implementation of this function matches the behaviour of EDK2 and the firmware on the Intel
// NUC.
//
// This only supports images that are verified with an asymmetric signature - it does not
// support images that are authenticated by their image digest.
func (m secureBootPolicyMixin) DetermineAuthority(dbs []*secureBootDB, image peImageHandle) (*secureBootAuthority, error) {
	sigs, err := image.SecureBootSignatures()
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain secure boot signatures: %w", err)
	}

	if len(sigs) == 0 {
		return nil, errors.New("no secure boot signatures")
	}

	var authority *secureBootAuthority
SignatureLoop:
	for _, sig := range sigs {
		for _, db := range dbs {
			// Iterate over ESLs
			for _, l := range db.Contents {
				// Ignore ESLs that aren't X509 certificates
				if l.Type != efi.CertX509Guid {
					continue
				}

				// Shouldn't happen, but just in case...
				if len(l.Signatures) == 0 {
					continue
				}

				ca, err := x509.ParseCertificate(l.Signatures[0].Data)
				if err != nil {
					continue
				}

				if sig.CertLikelyTrustAnchor(ca) {
					authority = &secureBootAuthority{
						Source:    db.Name,
						Signature: l.Signatures[0]}
					break SignatureLoop
				}
			}
		}
	}

	if authority == nil {
		return nil, errors.New("cannot determine authority")
	}
	return authority, nil
}

type signatureDBUpdateFirmwareQuirk int

const (
	signatureDBUpdateNoFirmwareQuirk signatureDBUpdateFirmwareQuirk = iota

	// signatureDBUpdateFirmwareDedupIgnoresOwner enables a mode of computing signature database updates for
	// firmware implementations that consider 2 EFI_SIGNATURE_DATA entries to be duplicates if only their
	// SignatureData fields match, even if they have different SignatureOwner fields. This doesn't match the
	// behaviour in the UEFI spec or the EDK2 implementation, but Dell firmware behaves like this.
	signatureDBUpdateFirmwareDedupIgnoresOwner
)

// applySignatureDBUpdate computes the new signature database contents associated with
// the supplied udpate and base environment, and updates the supplied variable set.
func applySignatureDBUpdate(vars varReadWriter, update *SignatureDBUpdate, quirk signatureDBUpdateFirmwareQuirk) error {
	var updateData []byte
	attrs := efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess | efi.AttributeTimeBasedAuthenticatedWriteAccess

	updateReader := bytes.NewReader(update.Data)

	// Skip over authentication header
	_, err := efi.ReadTimeBasedVariableAuthentication(updateReader)
	if err != nil {
		return xerrors.Errorf("cannot decode EFI_VARIABLE_AUTHENTICATION_2 structure of update: %w", err)
	}

	if update.Name != PK {
		attrs |= efi.AttributeAppendWrite

		data, _, err := vars.ReadVar(update.Name.Name, update.Name.GUID)
		switch {
		case err == efi.ErrVarNotExist:
			// nothing to do
		case err != nil:
			return xerrors.Errorf("cannot read original signature database: %w", err)
		}

		base := bytes.NewReader(data)

		baseDb, err := efi.ReadSignatureDatabase(base)
		if err != nil {
			return xerrors.Errorf("cannot decode base signature database: %w", err)
		}

		updateDb, err := efi.ReadSignatureDatabase(updateReader)
		if err != nil {
			return xerrors.Errorf("cannot decode signature database update: %w", err)
		}

		var filtered efi.SignatureDatabase

		// Filter out signatures in the update that already exist in the base DB.
		for _, ul := range updateDb {
			// For each ESL in this update...
			var newSigs []*efi.SignatureData

			for _, us := range ul.Signatures {
				// For each signature in this ESL, determine if the signature
				// already exists in the base DB
				isNewSig := true

			BaseLoop:
				for _, l := range baseDb {
					if l.Type != ul.Type {
						// Different signature type
						continue
					}

					for _, s := range l.Signatures {
						switch quirk {
						case signatureDBUpdateNoFirmwareQuirk:
							if us.Equal(s) {
								isNewSig = false
							}
						case signatureDBUpdateFirmwareDedupIgnoresOwner:
							if bytes.Equal(us.Data, s.Data) {
								isNewSig = false
							}
						}
						if !isNewSig {
							// The signature already exists in this base ESL
							break BaseLoop
						}
					}
				}

				if isNewSig {
					// Only retain signatures that do not exist in the base DB.
					newSigs = append(newSigs, us)
				}
			}

			if len(newSigs) > 0 {
				// One or more signatures from this update ESL are new, so append the filtered ESL
				filtered = append(filtered, &efi.SignatureList{Type: ul.Type, Header: ul.Header, Signatures: newSigs})
			}
		}

		// Serialize the filtered list of ESLs
		var buf bytes.Buffer
		if err := filtered.Write(&buf); err != nil {
			return xerrors.Errorf("cannot encode filtered signature database update: %w", err)
		}
		updateData = buf.Bytes()
	} else {
		updateData, _ = ioutil.ReadAll(updateReader)
	}

	return vars.WriteVar(update.Name.Name, update.Name.GUID, attrs, updateData)
}

const (
	// allowInsufficientDMAProtectionParamKey is used to allow for the "DMA Protection Disabled"
	// string in PCR7.
	allowInsufficientDMAProtectionParamKey loadParamsKey = "allow_insufficient_dma_protection"

	// includeInsufficientDMAProtectionParamKey is used to signal whether the "DMA Protection Disabled"
	// string should be reflected in the produced PCR profile.
	// this is ignored if allowInsufficientDMAProtection is false, as the presence of the event
	// will lead to an error in that case.
	includeInsufficientDMAProtectionParamKey = "include_insufficient_dma_protection"
)

type allowInsufficientDmaProtectionOption struct{}

func (o allowInsufficientDmaProtectionOption) ApplyOptionTo(visitor internal_efi.PCRProfileOptionVisitor) error {
	visitor.AddImageLoadParams(func(params ...loadParams) []loadParams {
		var out []loadParams
		for _, v := range []bool{false, true} {
			var newParams []loadParams
			for _, p := range params {
				newParams = append(newParams, p.Clone())
			}
			for _, p := range newParams {
				p[allowInsufficientDMAProtectionParamKey] = true
				p[includeInsufficientDMAProtectionParamKey] = v
			}
			out = append(out, newParams...)
		}
		return out
	})
	return nil
}

// WithAllowInsufficientDMAProtection can be supplied to AddPCRProfile to allow for
// PCR7 including the "DMA Protection Disabled" event. While this reduces security,
// it is required on some devices.
// If this string is present in the event log, this option results in a creation of a
// branched PCR profile that has two branches at the Firmware load stage one including
// the event with the string, the another not.
func WithAllowInsufficientDmaProtection() PCRProfileOption {
	return allowInsufficientDmaProtectionOption{}
}
