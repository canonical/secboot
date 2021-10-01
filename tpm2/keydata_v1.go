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
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

// keyData_v1 represents version 1 of keyData. Version 1 no longer
// really exists because they are implicitly upgraded to v2.
type keyData_v1 struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	Unused            uint8 // previously AuthModeHint
	StaticPolicyData  *staticPolicyDataRaw_v1
	DynamicPolicyData *dynamicPolicyDataRaw_v0
}

func readKeyDataV1(r io.Reader) (keyData, error) {
	var d *keyData_v1
	if _, err := mu.UnmarshalFromReader(r, &d); err != nil {
		return nil, err
	}

	// Automatically upgrade v1 to v2
	return &keyData_v2{
		KeyPrivate:        d.KeyPrivate,
		KeyPublic:         d.KeyPublic,
		StaticPolicyData:  d.StaticPolicyData,
		DynamicPolicyData: d.DynamicPolicyData}, nil
}
