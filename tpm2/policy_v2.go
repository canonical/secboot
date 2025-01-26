// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2021 Canonical Ltd
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

package tpm2

import (
	"github.com/canonical/go-tpm2"
)

func computeV2PcrPolicyCounterAuthPolicies(alg tpm2.HashAlgorithmId, updateKey *tpm2.Public) (tpm2.DigestList, error) {
	return computeV1PcrPolicyCounterAuthPolicies(alg, updateKey)
}

func computeV2PcrPolicyRefFromCounterName(name tpm2.Name) tpm2.Nonce {
	return computeV1PcrPolicyRefFromCounterName(name)
}

// staticPolicyData_v2 represents version 2 of the metadata for executing a
// policy session that never changes for the life of a key. It has the same
// format as version 1.
type staticPolicyData_v2 = staticPolicyData_v1

// pcrPolicyData_v2 represents version 2 of the PCR policy metadata for
// executing a policy session, and can be updated. It has the same format
// as version 1.
type pcrPolicyData_v2 = pcrPolicyData_v1

// keyDataPolicy_v2 represents version 2 of the metadata for executing a
// policy session, and has the same format as version 1.
type keyDataPolicy_v2 = keyDataPolicy_v1
