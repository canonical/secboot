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
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/snapd/asserts"

	"golang.org/x/xerrors"
)

const (
	modelGradeUnset uint8 = iota
	modelGradeSecured
	modelGradeSigned
	modelGradeDangerous
)

func modelGradeEnum(grade asserts.ModelGrade) (uint8, error) {
	switch grade {
	case asserts.ModelGradeUnset:
		return modelGradeUnset, nil
	case asserts.ModelSecured:
		return modelGradeSecured, nil
	case asserts.ModelSigned:
		return modelGradeSigned, nil
	case asserts.ModelDangerous:
		return modelGradeDangerous, nil
	default:
		return modelGradeUnset, fmt.Errorf("unknown grade: %v", grade)
	}
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
	Models []*asserts.Model
}

// AddSnapModelProfile adds the snap model profile to the PCR protection profile, as measured by snap-bootstrap, in order to generate
// a PCR policy that is bound to a specific set of device models. It is the responsibility of snap-bootstrap to verify the integrity
// of the model that it has measured.
//
// The profile consists of 2 measurements (where H is the digest algorithm supplied via params.PCRAlgorithm):
//  H(uint32(0))
//  digestModel
//
// digestModel is computed as follows:
//  digest1 = H(tpm2.HashAlgorithmSHA384 || sign-key-sha3-384 || brand-id)
//  digest2 = H(digest1 || model)
//  digestModel = H(digest2 || series || grade)
// The signing key digest algorithm is encoded in little-endian format, and the sign-key-sha3-384 field is hashed in decoded (binary)
// form. The brand-id, model and series fields are hashed without null terminators. The grade field is encoded as a single byte with
// the following conversion:
//  "unset":     0
//  "secured":   1
//  "signed":    2
//  "dangerous": 3
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

	h := params.PCRAlgorithm.NewHash()
	binary.Write(h, binary.LittleEndian, uint32(0))
	versionDigest := h.Sum(nil)

	var subProfiles []*PCRProtectionProfile
	for _, model := range params.Models {
		if model == nil {
			return errors.New("nil model")
		}

		subProfile := NewPCRProtectionProfile().ExtendPCR(params.PCRAlgorithm, params.PCRIndex, versionDigest)

		signKeyId, err := base64.RawURLEncoding.DecodeString(model.SignKeyID())
		if err != nil {
			return xerrors.Errorf("cannot decode signing key ID: %w", err)
		}
		h := params.PCRAlgorithm.NewHash()
		binary.Write(h, binary.LittleEndian, uint16(tpm2.HashAlgorithmSHA384))
		h.Write(signKeyId)
		h.Write([]byte(model.BrandID()))
		digest := h.Sum(nil)

		h = params.PCRAlgorithm.NewHash()
		h.Write(digest)
		h.Write([]byte(model.Model()))
		digest = h.Sum(nil)

		grade, err := modelGradeEnum(model.Grade())
		if err != nil {
			return xerrors.Errorf("cannot detemine grade of model: %w", err)
		}
		h = params.PCRAlgorithm.NewHash()
		h.Write(digest)
		h.Write([]byte(model.Series()))
		h.Write([]byte{grade})

		subProfiles = append(subProfiles, subProfile.ExtendPCR(params.PCRAlgorithm, params.PCRIndex, h.Sum(nil)))
	}

	profile.AddProfileOR(subProfiles...)
	return nil
}
