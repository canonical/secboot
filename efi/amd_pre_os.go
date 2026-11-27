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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package efi

import internal_efi "github.com/snapcore/secboot/internal/efi"

const (
	amdTSMEEnabledParamKey            loadParamsKey = "amd_tsme_enabled"
	includeHPPreBootDMAConfigParamKey loadParamsKey = "include_hp_pre_boot_dma_config"
)

type amdPreOSMeasurementsOption struct {
	tsmeEnabled               bool
	includeHPPreBootDMAConfig bool
}

func (o *amdPreOSMeasurementsOption) ApplyOptionTo(visitor internal_efi.PCRProfileOptionVisitor) error {
	visitor.AddImageLoadParams(func(params ...loadParams) []loadParams {
		out := make([]loadParams, 0, len(params))
		for _, p := range params {
			p = p.Clone()
			p[amdTSMEEnabledParamKey] = o.tsmeEnabled
			p[includeHPPreBootDMAConfigParamKey] = o.includeHPPreBootDMAConfig
			out = append(out, p)
		}
		return out
	})
	return nil
}

// WithAMDPreOSMeasurements supplies independently detected AMD platform
// configuration that affects pre-OS measurements. tsmeEnabled controls the
// expected payload if AMD's vendor-defined TSME event is present. If
// includeHPPreBootDMAConfig is true, the PCR7 profile includes HP's enabled
// SVM and DMA protection configuration event.
func WithAMDPreOSMeasurements(tsmeEnabled, includeHPPreBootDMAConfig bool) PCRProfileOption {
	return &amdPreOSMeasurementsOption{
		tsmeEnabled:               tsmeEnabled,
		includeHPPreBootDMAConfig: includeHPPreBootDMAConfig,
	}
}
