// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package preinstall

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	secboot_efi "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

type authorityTrust int

const (
	authorityTrustBootCode authorityTrust = 1 << iota // authority is trusted to load boot code (we don't need PCR4)
	authorityTrustDrivers                             // authority is trusted to load drivers (we may not need PCR2)
)

type authorityTrustDataSet []authorityTrustData

func (s authorityTrustDataSet) determineTrust(certs []*x509.Certificate) authorityTrust {
	trust := authorityTrustBootCode | authorityTrustDrivers
	for _, cert := range certs {
		var certTrust authorityTrust
		for _, auth := range s {
			if !bytes.Equal(auth.Authority.Subject, cert.RawSubject) {
				continue
			}
			if !bytes.Equal(auth.Authority.SubjectKeyId, cert.SubjectKeyId) {
				continue
			}
			if auth.Authority.PublicKeyAlgorithm != cert.PublicKeyAlgorithm {
				continue
			}
			certTrust = auth.Trust
			break
		}
		trust &= certTrust
	}

	return trust
}

func (s authorityTrustDataSet) trustedForBootManager(certs []*x509.Certificate) bool {
	return s.determineTrust(certs)&authorityTrustBootCode > 0
}

func (s authorityTrustDataSet) trustedForDrivers(certs []*x509.Certificate) bool {
	return s.determineTrust(certs)&authorityTrustDrivers > 0
}

type authorityTrustData struct {
	Authority *internal_efi.SecureBootAuthorityIdentity
	Trust     authorityTrust
}

var (
	knownCAs = authorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, 0}, // be conservative here for now, but will we be able to set the authorityTrustDrivers flag for the MS2023 CA?
	}
)

// PCRProfileOptionsFlags provides a way to customize [WithAutoPCRProfile].
type PCRProfileOptionsFlags uint32

const (
	// PCRProfileOptionsDefault is the default PCR configuration
	PCRProfileOptionsDefault PCRProfileOptionsFlags = 0

	// PCRProfileOptionMostSecure is the most secure configuration by
	// including all relevant TCG defined PCRs supported by the efi package
	// (PCRs 0, 1, 2, 3, 4, 5 and 7).
	//
	// Note that this option will currently not work because the efi package
	// does not support PCRs 1, 3 and 5, but will do in the future.
	PCRProfileOptionMostSecure PCRProfileOptionsFlags = 1 << iota

	// PCRProfileOptionTrustCAsForBootCode can omit PCR4 if CAs in the authorized
	// signature database that were used to authenticate code on the current boot
	// are not directly trusted to sign boot code, but a system administrator makes
	// an explicit decision to trust these CAs. This might be because it uses custom
	// CAs that are unrecognized for trust by this package.
	PCRProfileOptionTrustCAsForBootCode

	// PCRProfileOptionTrustCAsForVARSuppliedDrivers can omit PCR2 if the CAs in the
	// authorized signature database that were used to authenticate code on the current
	// boot are not directly trusted to sign UEFI drivers, but a system administrator
	// makes an explicit decision to trust these CAs. This might be because it uses
	// custom CAs that are unrecognized for trust by this package.
	PCRProfileOptionTrustCAsForVARSuppliedDrivers

	// PCRProfileOptionDistrustVARSuppliedNonHostCode can be used to include PCR2 if a
	// system administrator makes an explicit decision to not trust non host code running
	// on attached embedded controllers in value-added-retailer components - this is code
	// that is not part of the host's trust chain but may still affect trust in the platform.
	PCRProfileOptionDistrustVARSuppliedNonHostCode

	// PCRProfileOptionNoDiscreteTPMResetMitigation can be used to omit PCR0 from the
	// profile on platforms that have a discrete TPM and where including PCR0 can provide
	// limited mitigation of TPM reset attacks by preventing the PCR values from being
	// reconstructed from software. This should only be used if a system administrator makes
	// an explicit decision that they don't want the additional PCR fragility caused by this
	// mitigation, perhaps because they consider that discrete TPMs still have other
	// weaknesses to anyone with physical access to the device without any of their own
	// mitigations. See the DiscreteTPMDetected CheckResultFlags flag description for more
	// information.
	PCRProfileOptionNoDiscreteTPMResetMitigation
)

// PCRProfileAutoEnablePCRsOption is an option for AddPCRProfile that adds one or more PCRs
// based on a set of tests done at some point in the past.
type PCRProfileAutoEnablePCRsOption interface {
	secboot_efi.PCRProfileEnablePCRsOption

	// Options returns a new PCRProfileAutoEnablePCRsOption instance with
	// the specified options applied.
	Options(opts PCRProfileOptionsFlags) PCRProfileAutoEnablePCRsOption
}

type pcrProfileAutoSetPcrsOption struct {
	secboot_efi.PCRProfileEnablePCRsOption

	result *CheckResult
	opts   PCRProfileOptionsFlags
}

// WithAutoPCRProfile returns a profile for the TCG defined PCRs based on the supplied result
// of [RunChecks] and the specified options.
func WithAutoPCRProfile(r *CheckResult, opts PCRProfileOptionsFlags) PCRProfileAutoEnablePCRsOption {
	out := &pcrProfileAutoSetPcrsOption{
		result: r,
		opts:   opts,
	}
	out.PCRProfileEnablePCRsOption = out
	return out
}

func (o *pcrProfileAutoSetPcrsOption) options() ([]secboot_efi.PCRProfileEnablePCRsOption, error) {
	switch {
	case o.opts&PCRProfileOptionMostSecure > 0:
		if o.opts != PCRProfileOptionMostSecure {
			return nil, errors.New("PCRProfileOptionMostSecure can only be used on its own")
		}
		const mask = NoPlatformFirmwareProfileSupport |
			NoPlatformConfigProfileSupport |
			NoDriversAndAppsProfileSupport |
			NoDriversAndAppsConfigProfileSupport |
			NoBootManagerCodeProfileSupport |
			NoBootManagerConfigProfileSupport |
			NoSecureBootPolicyProfileSupport
		if o.result.Flags&mask > 0 {
			return nil, errors.New("PCRProfileOptionMostSecure does not work because of one or more of PCRs 0, 1, 2, 3, 4, 5 or 7 failed earlier checks")
		}

		return nil, errors.New("PCRProfileOptionMostSecure is currently unsupported")
		//		return []secboot_efi.PCRProfileEnablePCRsOption{
		//			secboot_efi.WithPlatformFirmwareProfile(),
		//			//secboot_efi.WithPlatformConfigProfile(), // TODO: implement in efi package
		//			secboot_efi.WithDriversAndAppsProfile(),
		//			//secboot_efi.WithDriversAndAppsConfigProfile() // TODO: implement in efi package
		//			secboot_efi.WithBootManagerCodeProfile(),
		//			//secboot_efi.WithBootManagerConfigProfile(), // TODO: implement in efi package
		//			efi.WithSecureBootPolicyProfile(),
		//		}, nil
	default:
		var opts []secboot_efi.PCRProfileEnablePCRsOption
		if o.result.Flags&NoSecureBootPolicyProfileSupport == 0 {
			// If PCR7 usage is ok, always include it
			opts = append(opts, secboot_efi.WithSecureBootPolicyProfile())

			if !knownCAs.trustedForBootManager(o.result.UsedSecureBootCAs) && o.opts&PCRProfileOptionTrustCAsForBootCode == 0 {
				// We need to include PCR4 if any CAs used for verification are not generally trusted to sign boot applications
				// (ie, they may have signed code in the past that can defeat our security model, such as versions of shim that
				// don't extend anything to the TPM, breaking the root-of-trust. This is true of the Microsoft UEFI CA 2011,
				// and for now, we assume to be true of the 2023 UEFI CA unless Microsoft are more transparent about what is
				// signed under this CA). It's also assumed to be true for any unrecognized CAs.
				// This can be overridden with PCRProfileOptionsTrustCAsForBootCode.
				if o.result.Flags&NoBootManagerCodeProfileSupport > 0 {
					return nil, errors.New("one or more CAs used for secure boot verification are not trusted to authenticate boot code " +
						"and the PCRProfileOptionTrustCAsForBootCode option was not supplied, so PCR 4 is required, but PCR 4 failed earlier checks")
				}
				opts = append(opts, secboot_efi.WithBootManagerCodeProfile())
			}

			isPcr2Supported := o.result.Flags&NoDriversAndAppsProfileSupport == 0

			includePcr2 := o.opts&PCRProfileOptionDistrustVARSuppliedNonHostCode > 0
			if includePcr2 && !isPcr2Supported {
				// Include PCR2 if the user explicitly distrusts non-host code running
				// in attached embedded controllers.
				return nil, errors.New("options include PCRProfileOptionDistrustVARSuppliedNonHostCode, so PCR 2 is required, but PCR2 failed earlier checks")
			}
			if !knownCAs.trustedForDrivers(o.result.UsedSecureBootCAs) && o.opts&PCRProfileOptionTrustCAsForVARSuppliedDrivers == 0 {
				// We need to include PCR2 if any CAs used for verification are not generally trusted to sign UEFI drivers
				// (ie, they may have signed code in the past that can defeat our security model. This is true of the Microsoft
				// UEFI CA 2011, and for now, we assume to be true of the 2023 UEFI CA unless Microsoft are more transparent about
				// what they sign under this CA). It's also assumed to be true for any unrecognized CAs.
				// This can be overridden with PCRProfileOptionsTrustCAsForVARSuppliedDrivers.
				includePcr2 = true
				if !isPcr2Supported {
					return nil, fmt.Errorf("one or more CAs used for secure boot verification are not trusted to authenticate value-added-retailer supplied drivers " +
						"and the PCRProfileOptionTrustCAsForVARSuppliedDrivers option was not supplied, so PCR 2 is required, but PCR 2 failed earlier checks")
				}
			}
			if includePcr2 {
				opts = append(opts, secboot_efi.WithDriversAndAppsProfile())
			}
		} else {
			// We can't use PCR7, so we must include PCRs 1, 2, 3, 4 and 5. These can't be omitted. PCR1 is required
			// because we have to depend on platform firmware config rather relying on security-relevant firmware settings
			// such as DMA protection changing the value of PCR7. PCR3 is required for the same reason, as firmware running
			// in value-added-retailer components may measure configuration there. PCR5 is required for the same reason - boot
			// manager configuration can be measured there, but anything that is security relevant should change the value of
			// PCR7.
			const mask = NoPlatformConfigProfileSupport |
				NoDriversAndAppsProfileSupport |
				NoDriversAndAppsConfigProfileSupport |
				NoBootManagerCodeProfileSupport |
				NoBootManagerConfigProfileSupport
			if o.result.Flags&mask > 0 {
				return nil, errors.New("PCR 7 failed earlier checks making PCRs 1, 2, 3, 4 and 5 mandatory, but one or more of these failed earlier checks")
			}

			return nil, errors.New("configurations without PCR 7 are currently unsupported")
			//			opts = append(opts,
			//				//secboot_efi.WithPlatformConfigProfile(), // TODO: implement in efi package
			//				secboot_efi.WithDriversAndAppsProfile(),
			//				//secboot_efi.WithDriversAndAppsConfigProfile(), // TODO: implement in efi package
			//				secboot_efi.WithBootManagerCodeProfile(),
			//				//secboot_efi.WithBootManagerConfigProfile(), // TODO: implement in efi package
			//			)

		}
		if o.opts&PCRProfileOptionNoDiscreteTPMResetMitigation == 0 {
			const mask = DiscreteTPMDetected | StartupLocalityNotProtected
			if o.result.Flags&mask == DiscreteTPMDetected {
				// Enable reset attack mitigations by including PCR0, because the startup locality
				// is protected making it impossible to reconstruct PCR0 from software if the TPM is
				// reset indepdendently of the host platform. Note that it is still possible for an
				// adversary with physical access to reconstruct PCR0 by manipulating the bus between
				// the host CPU and the discrete TPM directly, as this will allow them access to all
				// localities.
				if o.result.Flags&NoPlatformFirmwareProfileSupport > 0 {
					return nil, errors.New("it was decided to enable a discrete TPM reset attack mitigation and the PCRProfileOptionNoDiscreteTPMResetMitigation option was not supplied, so PCR 0 is required, but PCR 0 failed earlier checks")
				}
				opts = append(opts, secboot_efi.WithPlatformFirmwareProfile())
			}
		}
		return opts, nil
	}
}

// ApplyOptionTo implements [secboot_efi.PCRProfileOption].
func (o *pcrProfileAutoSetPcrsOption) ApplyOptionTo(visitor internal_efi.PCRProfileOptionVisitor) error {
	opts, err := o.options()
	if err != nil {
		return fmt.Errorf("cannot select an appropriate set of TCG defined PCRs with the current options: %w", err)
	}
	for i, opt := range opts {
		if err := opt.ApplyOptionTo(visitor); err != nil {
			return fmt.Errorf("cannot add PCR profile option %d: %w", i, err)
		}
	}
	return nil
}

func (o *pcrProfileAutoSetPcrsOption) Options(opts PCRProfileOptionsFlags) PCRProfileAutoEnablePCRsOption {
	return WithAutoPCRProfile(o.result, opts)
}

// PCRs implements [secboot_efi.PCRProfileEnablePCRsOption.PCRs].
func (o *pcrProfileAutoSetPcrsOption) PCRs() (tpm2.HandleList, error) {
	opts, err := o.options()
	if err != nil {
		return nil, fmt.Errorf("cannot select an appropriate set of TCG defined PCRs with the current options: %w", err)
	}

	var out tpm2.HandleList
	for i, opt := range opts {
		pcrs, err := opt.PCRs()
		if err != nil {
			return nil, fmt.Errorf("cannot add PCRs from profile option %d: %w", i, err)
		}
		out = append(out, pcrs...)
	}
	return out, nil
}
