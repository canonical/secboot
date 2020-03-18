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
	"bytes"
	"errors"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"

	"golang.org/x/xerrors"
)

// SystemdEFIStubProfileParams provides the parameters to AddSystemdEFIStubProfile.
type SystemdEFIStubProfileParams struct {
	PCRAlgorithm   tpm2.HashAlgorithmId
	PCRIndex       int      // The PCR that the systemd EFI stub measures the kernel commandline to
	KernelCmdlines []string // The set of kernel commandlines to generate PCR digests for
}

// AddSystemdEFIStubProfile adds the systemd EFI linux loader stub profile to the PCR protection profile, in order to generate a
// PCR policy that restricts access to a key to a defined set of kernel commandlines when booting a linux kernel using the systemd
// EFI stub.
//
// The PCR index that the EFI stub measures the kernel commandline too can be specified via the PCRIndex field of params.
//
// The permitted set of kernel commandlines can be specified via the KernelCmdlines field of params.
func AddSystemdEFIStubProfile(profile *PCRProtectionProfile, params *SystemdEFIStubProfileParams) error {
	if profile == nil {
		return errors.New("no profile supported")
	}
	if params == nil {
		return errors.New("no params provided")
	}

	if len(params.KernelCmdlines) == 0 {
		return errors.New("no kernel commandlines specified")
	}

	var subProfiles []*PCRProtectionProfile
	for _, cmdline := range params.KernelCmdlines {
		event := tcglog.SystemdEFIStubEventData{Str: cmdline}
		var buf bytes.Buffer
		if err := event.EncodeMeasuredBytes(&buf); err != nil {
			return xerrors.Errorf("cannot encode kernel commandline event: %w", err)
		}

		h := params.PCRAlgorithm.NewHash()
		buf.WriteTo(h)

		subProfiles = append(subProfiles, NewPCRProtectionProfile().ExtendPCR(params.PCRAlgorithm, params.PCRIndex, h.Sum(nil)))
	}

	profile.AddProfileOR(subProfiles...)
	return nil
}
