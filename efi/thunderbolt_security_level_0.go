// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

const (
	// allowThunderboltSecurityLevel0ParamKey is used to allow for the "Security Level is Downgraded to 0"
	// string in PCR7.
	allowThunderboltSecurityLevel0ParamKey loadParamsKey = "allow_thunderbolt_security_level_0"

	// includeThunderboltSecurityLevel0ParamKey is used to signal whether the "Security Level is Downgraded to 0"
	// string should be reflected in the produced PCR profile.
	// this is ignored if allowThunderboltSecurityLevel0 is false, as the presence of the event
	// will lead to an error in that case.
	includeThunderboltSecurityLevel0ParamKey = "include_thunderbolt_security_level_0"
)

type allowThunderboltSecurityLevel0Option struct{}

func (o allowThunderboltSecurityLevel0Option) ApplyOptionTo(visitor internal_efi.PCRProfileOptionVisitor) error {
	visitor.AddImageLoadParams(func(params ...loadParams) []loadParams {
		var out []loadParams
		for _, v := range []bool{false, true} {
			var newParams []loadParams
			for _, p := range params {
				newParams = append(newParams, p.Clone())
			}
			for _, p := range newParams {
				p[allowThunderboltSecurityLevel0ParamKey] = true
				p[includeThunderboltSecurityLevel0ParamKey] = v
			}
			out = append(out, newParams...)
		}
		return out
	})
	return nil
}

// WithAllowThunderboltSecurityLevel0 can be supplied to AddPCRProfile to allow for
// PCR7 including the "Security Level is Downgraded to 0" event. While this reduces security,
// it is required on some devices.
// If this string is present in the event log, this option results in a creation of a
// branched PCR profile that has two branches at the Firmware load stage one including
// the event with the string, the another not.
//
// Rationale and context:
// Some old (2021) BIOS firmware on NUC8v5PNB devices measure an event of type EV_EFI_ACTION
// saying "Security Level is Downgraded to 0" to PCR7.
// By default this event makes secboot raise an error when computing the PCR policy, and this
// is relevant as this event denotes a situation where the platform may have a security issue.
// Moreover, the user who reported this issue said that this could be fixed either by
// configuring the BIOS to the most secure option for Thunderbolt, or by updating the firmware.
// This event should therefore not be allowed by default.
//
// That being said, there may be situations where users have this event and still want to use
// TPM-backed disk encryption. This is why we provide this option.
func WithAllowThunderboltSecurityLevel0() PCRProfileOption {
	return allowThunderboltSecurityLevel0Option{}
}
