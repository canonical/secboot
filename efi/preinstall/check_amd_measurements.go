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
 */

package preinstall

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

func checkAMDTSMEConfigEvent(ev *tcglog.Event, pcrAlg tpm2.HashAlgorithmId, config *amdPreOSMeasurementConfig, seen *bool) (bool, error) {
	if !internal_efi.IsAMDTSMEConfigEvent(ev) {
		return false, nil
	}
	if config == nil {
		return true, errors.New("encountered AMD TSME configuration event without independently detected platform configuration")
	}
	if *seen {
		return true, errors.New("encountered duplicate AMD TSME configuration event")
	}

	expectedData := internal_efi.AMDTSMEConfigEventData(config.TSMEEnabled)
	if !bytes.Equal(ev.Data.Bytes(), expectedData) {
		return true, fmt.Errorf("AMD TSME configuration event data does not match detected TSME status (expected %#x, got %#x)", expectedData, ev.Data.Bytes())
	}
	expectedDigest := tcglog.ComputeEventDigest(pcrAlg.GetHash(), expectedData)
	if !bytes.Equal(ev.Digests[pcrAlg], expectedDigest) {
		return true, errors.New("invalid digest for AMD TSME configuration event")
	}

	*seen = true
	return true, nil
}
