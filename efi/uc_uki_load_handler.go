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
	"errors"
	"fmt"

	"github.com/canonical/tcglog-parser"
	"github.com/snapcore/secboot/tpm2"
)

type ubuntuCoreUKILoadHandler struct{}

func newUbuntuCoreUKILoadHandler(_ peImageHandle) (imageLoadHandler, error) {
	return new(ubuntuCoreUKILoadHandler), nil
}

func (h *ubuntuCoreUKILoadHandler) MeasureImageStart(ctx pcrBranchContext) error {
	// TODO: maybe handle the kernel boot PCR (11) in the future because this
	// also contains the boot phase, which could replace the additional measurement
	// we make to PCR12. This does also contain the kernel digest, although this is
	// less interesting for us. Note that this would require some additional work
	// because the systemd-pcrphase is disabled at the moment.

	if ctx.PCRs().Contains(kernelConfigPCR) {
		// the stub doesn't measure anything if the commandline is empty
		if ctx.Params().KernelCommandline != "" {
			ctx.ExtendPCR(kernelConfigPCR,
				tcglog.ComputeSystemdEFIStubCommandlineDigest(ctx.PCRAlg().GetHash(), ctx.Params().KernelCommandline))
		}

		// TODO: handle credentials, confexts and commandline addons if we need
		// then in the future. These all go into kernelConfigPCR
	}

	// TODO: handle sysexts if we need them in the future, which go to the sysext PCR (13).

	if ctx.PCRs().Contains(kernelConfigPCR) {
		if ctx.Params().SnapModel == nil {
			return errors.New("snap model must be set using SnapModelParams")
		}
		ctx.ExtendPCR(kernelConfigPCR, tpm2.ComputeSnapSystemEpochDigest(ctx.PCRAlg(), 0))
		modelDigest, err := tpm2.ComputeSnapModelDigest(ctx.PCRAlg(), ctx.Params().SnapModel)
		if err != nil {
			return fmt.Errorf("cannot compute model digest: %w", err)
		}
		ctx.ExtendPCR(kernelConfigPCR, modelDigest)
	}

	return nil
}

func (h *ubuntuCoreUKILoadHandler) MeasureImageLoad(_ pcrBranchContext, _ peImageHandle) (imageLoadHandler, error) {
	return nil, errors.New("kernel is a leaf image")
}
