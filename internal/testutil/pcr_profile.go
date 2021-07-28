// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019,2021 Canonical Ltd
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

package testutil

import (
	"bytes"
	"fmt"

	"github.com/canonical/go-tpm2"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

func FormatPCRValuesFromPCRProtectionProfile(profile *secboot_tpm2.PCRProtectionProfile, tpm *tpm2.TPMContext) string {
	values, err := profile.ComputePCRValues(tpm)
	if err != nil {
		return ""
	}
	var s bytes.Buffer
	fmt.Fprintf(&s, "\n")
	for i, v := range values {
		fmt.Fprintf(&s, "Value %d:\n", i)
		for alg := range v {
			for pcr := range v[alg] {
				fmt.Fprintf(&s, " PCR%d,%v: %x\n", pcr, alg, v[alg][pcr])
			}
		}
	}
	return s.String()
}
