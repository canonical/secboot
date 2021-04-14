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
	"encoding/base64"
	"encoding/binary"
	"errors"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"
)

const zeroSnapSystemEpoch uint32 = 0

func computeSnapSystemEpochDigest(alg tpm2.HashAlgorithmId, epoch uint32) tpm2.Digest {
	h := alg.NewHash()
	binary.Write(h, binary.LittleEndian, epoch)
	return h.Sum(nil)
}

func computeSnapModelDigest(alg tpm2.HashAlgorithmId, model SnapModel) (tpm2.Digest, error) {
	signKeyId, err := base64.RawURLEncoding.DecodeString(model.SignKeyID())
	if err != nil {
		return nil, xerrors.Errorf("cannot decode signing key ID: %w", err)
	}

	h := alg.NewHash()
	binary.Write(h, binary.LittleEndian, uint16(tpm2.HashAlgorithmSHA384))
	h.Write(signKeyId)
	h.Write([]byte(model.BrandID()))
	digest := h.Sum(nil)

	h = alg.NewHash()
	h.Write(digest)
	h.Write([]byte(model.Model()))
	digest = h.Sum(nil)

	h = alg.NewHash()
	h.Write(digest)
	h.Write([]byte(model.Series()))
	binary.Write(h, binary.LittleEndian, model.Grade().Code())

	return h.Sum(nil), nil
}

// SnapModelProfileParams provides the parameters to AddSnapModelProfile.
type SnapModelProfileParams struct {
	// PCRAlgorithm is the algorithm for which to compute PCR digests for. TPMs compliant with the "TCG PC Client Platform TPM Profile
	// (PTP) Specification" Level 00, Revision 01.03 v22, May 22 2017 are required to support tpm2.HashAlgorithmSHA1 and
	// tpm2.HashAlgorithmSHA256. Support for other digest algorithms is optional.
	PCRAlgorithm tpm2.HashAlgorithmId

	// PCRIndex is the PCR that snap-bootstrap measures the model to.
	PCRIndex int

	// Models is the set of models to add to the PCR profile.
	Models []SnapModel
}

// AddSnapModelProfile adds the snap model profile to the PCR protection profile, as measured by snap-bootstrap, in order to generate
// a PCR policy that is bound to a specific set of device models. It is the responsibility of snap-bootstrap to verify the integrity
// of the model that it has measured.
//
// The profile consists of 2 measurements:
//  digestEpoch
//  digestModel
//
// digestEpoch is currently hardcoded as (where H is the digest algorithm supplied via params.PCRAlgorithm):
//  digestEpoch = H(uint32(0))
//
// A future version of this package may allow another epoch to be supplied.
//
// digestModel is computed as follows (where H is the digest algorithm supplied via params.PCRAlgorithm):
//  digest1 = H(tpm2.HashAlgorithmSHA384 || sign-key-sha3-384 || brand-id)
//  digest2 = H(digest1 || model)
//  digestModel = H(digest2 || series || grade)
// The signing key digest algorithm is encoded in little-endian format, and the sign-key-sha3-384 field is hashed in decoded (binary)
// form. The brand-id, model and series fields are hashed without null terminators. The grade field is encoded as the 32 bits from
// asserts.ModelGrade.Code in little-endian format.
//
// Separate extend operations are used because brand-id, model and series are variable length.
//
// The PCR index that snap-bootstrap measures the model to can be specified via the PCRIndex field of params.
//
// The set of models to add to the PCRProtectionProfile is specified via the Models field of params.
func AddSnapModelProfile(profile *PCRProtectionProfile, params *SnapModelProfileParams) error {
	if params.PCRIndex < 0 {
		return errors.New("invalid PCR index")
	}
	if len(params.Models) == 0 {
		return errors.New("no models provided")
	}

	profile.ExtendPCR(params.PCRAlgorithm, params.PCRIndex, computeSnapSystemEpochDigest(params.PCRAlgorithm, zeroSnapSystemEpoch))

	var subProfiles []*PCRProtectionProfile
	for _, model := range params.Models {
		if model == nil {
			return errors.New("nil model")
		}

		digest, err := computeSnapModelDigest(params.PCRAlgorithm, model)
		if err != nil {
			return err
		}
		subProfiles = append(subProfiles, NewPCRProtectionProfile().ExtendPCR(params.PCRAlgorithm, params.PCRIndex, digest))
	}

	profile.AddProfileOR(subProfiles...)
	return nil
}

func measureSnapPropertyToTPM(tpm *TPMConnection, pcrIndex int, computeDigest func(tpm2.HashAlgorithmId) (tpm2.Digest, error)) error {
	pcrSelection, err := tpm.GetCapabilityPCRs(tpm.HmacSession().IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot determine supported PCR banks: %w", err)
	}

	var digests tpm2.TaggedHashList
	for _, s := range pcrSelection {
		if !s.Hash.Supported() {
			// We can't compute a digest for this algorithm, which is unfortunate. It's unlikely that we'll come across a TPM that supports a
			// digest algorithm that go doesn't have an implementation of, so just skip it to avoid a panic - we can't generate a PCR profile
			// bound to any PCRs in this bank anyway.
			continue
		}

		digest, err := computeDigest(s.Hash)
		if err != nil {
			return xerrors.Errorf("cannot compute digest for algorithm %v: %w", s.Hash, err)
		}

		digests = append(digests, tpm2.TaggedHash{HashAlg: s.Hash, Digest: digest})
	}

	return tpm.PCRExtend(tpm.PCRHandleContext(pcrIndex), digests, tpm.HmacSession())
}

// MeasureSnapSystemEpochToTPM measures a digest of uint32(0) to the specified PCR for all supported PCR banks. See the documentation
// for AddSnapModelProfile for more details.
func MeasureSnapSystemEpochToTPM(tpm *TPMConnection, pcrIndex int) error {
	return measureSnapPropertyToTPM(tpm, pcrIndex, func(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
		return computeSnapSystemEpochDigest(alg, zeroSnapSystemEpoch), nil
	})
}

// MeasureSnapModelToTPM measures a digest of the supplied model assertion to the specified PCR for all supported PCR banks.
// See the documentation for AddSnapModelProfile for details of how the digest of the model is computed.
func MeasureSnapModelToTPM(tpm *TPMConnection, pcrIndex int, model SnapModel) error {
	return measureSnapPropertyToTPM(tpm, pcrIndex, func(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
		return computeSnapModelDigest(alg, model)
	})
}
