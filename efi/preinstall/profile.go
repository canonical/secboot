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

func (s authorityTrustDataSet) determineTrust(certs []*X509CertificateID) authorityTrust {
	trust := authorityTrustBootCode | authorityTrustDrivers
	for _, cert := range certs {
		var certTrust authorityTrust
		for _, auth := range s {
			if !bytes.Equal(auth.Authority.Subject, cert.RawSubject()) {
				continue
			}
			if !bytes.Equal(auth.Authority.SubjectKeyId, cert.SubjectKeyId()) {
				continue
			}
			if auth.Authority.PublicKeyAlgorithm != cert.PublicKeyAlgorithm() {
				continue
			}
			if !bytes.Equal(auth.Authority.Issuer, cert.RawIssuer()) {
				continue
			}
			if !bytes.Equal(auth.Authority.AuthorityKeyId, cert.AuthorityKeyId()) {
				continue
			}
			if auth.Authority.SignatureAlgorithm != cert.SignatureAlgorithm() {
				continue
			}
			certTrust = auth.Trust
			break
		}
		trust &= certTrust
	}

	return trust
}

func (s authorityTrustDataSet) trustedForBootManager(certs []*X509CertificateID) bool {
	return s.determineTrust(certs)&authorityTrustBootCode > 0
}

func (s authorityTrustDataSet) trustedForDrivers(certs []*X509CertificateID) bool {
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

// PCRProfileOptionsFlags provides a way to customize [WithAutoTCGPCRProfile].
type PCRProfileOptionsFlags uint32

const (
	// PCRProfileOptionsDefault is the default PCR configuration. WithAutoTCGPCRProfile
	// will select the most appropriate configuration depending on the CheckResult.
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

	// PCRProfileOptionPermitNoSecureBootPolicyProfle can be used to permit a fallback to
	// a configuration without the secure boot policy included if the supplied CheckResult
	// indicates that PCR7 cannot be used.
	PCRProfileOptionPermitNoSecureBootPolicyProfile

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

// WithAutoTCGPCRProfile returns a profile for the TCG defined PCRs based on the supplied result
// of [RunChecks] and the specified user options.
func WithAutoTCGPCRProfile(r *CheckResult, opts PCRProfileOptionsFlags) PCRProfileAutoEnablePCRsOption {
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
			return nil, fmt.Errorf("PCRProfileOptionMostSecure cannot be used: %w", newUnsupportedRequiredPCRsError(tpm2.HandleList{0, 1, 2, 3, 4, 5, 7}, o.result.Flags))
		}

		// TODO: remove this once the secboot_efi package implements support for the remaining PCRs
		return nil, fmt.Errorf("PCRProfileOptionMostSecure cannot be used because it is currently unsupported: %w",
			newUnsupportedRequiredPCRsError(tpm2.HandleList{0, 1, 2, 3, 4, 5, 7}, NoPlatformConfigProfileSupport|NoDriversAndAppsConfigProfileSupport|NoBootManagerConfigProfileSupport))
		//		return []secboot_efi.PCRProfileEnablePCRsOption{
		//			secboot_efi.WithPlatformFirmwareProfile(),
		//			//secboot_efi.WithPlatformConfigProfile(), // TODO: implement in secboot_efi package
		//			secboot_efi.WithDriversAndAppsProfile(),
		//			//secboot_efi.WithDriversAndAppsConfigProfile() // TODO: implement in secboot_efi package
		//			secboot_efi.WithBootManagerCodeProfile(),
		//			//secboot_efi.WithBootManagerConfigProfile(), // TODO: implement in secboot_efi package
		//			efi.WithSecureBootPolicyProfile(),
		//		}, nil
	default:
		var opts []secboot_efi.PCRProfileEnablePCRsOption
		switch {
		case o.result.Flags&NoSecureBootPolicyProfileSupport == 0:
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
					return nil, fmt.Errorf("cannot create a valid secure boot configuration: one or more CAs used for secure boot "+
						"verification are not trusted to authenticate boot code and the PCRProfileOptionTrustCAsForBootCode "+
						"option was not supplied: %w", newUnsupportedRequiredPCRsError(tpm2.HandleList{4}, o.result.Flags))
				}
				opts = append(opts, secboot_efi.WithBootManagerCodeProfile())
			}

			isPcr2Supported := o.result.Flags&NoDriversAndAppsProfileSupport == 0

			includePcr2 := o.opts&PCRProfileOptionDistrustVARSuppliedNonHostCode > 0
			if includePcr2 && !isPcr2Supported {
				// Include PCR2 if the user explicitly distrusts non-host code running
				// in attached embedded controllers.
				return nil, fmt.Errorf("PCRProfileOptionDistrustVARSuppliedNonHostCode cannot be used: %w", newUnsupportedRequiredPCRsError(tpm2.HandleList{2}, o.result.Flags))
			}
			if !knownCAs.trustedForDrivers(o.result.UsedSecureBootCAs) && o.opts&PCRProfileOptionTrustCAsForVARSuppliedDrivers == 0 {
				// We need to include PCR2 if any CAs used for verification are not generally trusted to sign UEFI drivers
				// (ie, they may have signed code in the past that can defeat our security model. This is true of the Microsoft
				// UEFI CA 2011, and for now, we assume to be true of the 2023 UEFI CA unless Microsoft are more transparent about
				// what they sign under this CA). It's also assumed to be true for any unrecognized CAs.
				// This can be overridden with PCRProfileOptionsTrustCAsForVARSuppliedDrivers.
				includePcr2 = true
				if !isPcr2Supported {
					return nil, fmt.Errorf("cannot create a valid secure boot configuration: one or more CAs used for secure boot "+
						"verification are not trusted to authenticate value-added-retailer suppled drivers and the "+
						"PCRProfileOptionTrustCAsForVARSuppliedDrivers option was not supplied: %w",
						newUnsupportedRequiredPCRsError(tpm2.HandleList{2}, o.result.Flags))
				}
			}
			if includePcr2 {
				opts = append(opts, secboot_efi.WithDriversAndAppsProfile())
			}
		case o.opts&PCRProfileOptionPermitNoSecureBootPolicyProfile == 0:
			// PCR 7 usage is not ok and the user hasn't opted into permitting configurations without it
			return nil, fmt.Errorf("cannot create a valid configuration without secure boot policy and the "+
				"PCRProfileOptionPermitNoSecureBootPolicyProfile option was not supplied: %w",
				newUnsupportedRequiredPCRsError(tpm2.HandleList{7}, o.result.Flags))
		default:
			// PCR 7 usage is not ok and the user has opted into permitting configutations without it. We must include PCRs
			// 1, 2, 3, 4 and 5 - none of these can be omitted.
			// - PCR1 is required because we have to depend on platform config rather relying on security-relevant firmware
			//   setting such as DMA protection changing the value of PCR7.
			// - PCR2 is required to include all non-platform value-added-retailer supplied drivers that execute.
			// - PCR3 is required for the same reason as PCR1, but for value-added-retailer driver configuration.
			// - PCR4 is required for all system preparation applications and boot manager code that execute.
			// - PCR5 is required for the same reason as PCR1, but for boot manager configuration.
			const mask = NoPlatformConfigProfileSupport |
				NoDriversAndAppsProfileSupport |
				NoDriversAndAppsConfigProfileSupport |
				NoBootManagerCodeProfileSupport |
				NoBootManagerConfigProfileSupport
			if o.result.Flags&mask > 0 {
				return nil, fmt.Errorf("cannot create a valid configuration without secure boot policy: %w", newUnsupportedRequiredPCRsError(tpm2.HandleList{1, 2, 3, 4, 5}, o.result.Flags))
			}

			// TODO: remove this once the secboot_efi package implements support for the remaining PCRs
			return nil, fmt.Errorf("cannot create a configuration without secure boot policy because this is currently unsupported: %w",
				newUnsupportedRequiredPCRsError(tpm2.HandleList{1, 2, 3, 4, 5}, NoPlatformConfigProfileSupport|NoDriversAndAppsConfigProfileSupport|NoBootManagerConfigProfileSupport))
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
					return nil, fmt.Errorf("cannot enable a discrete TPM reset attack mitigation and the "+
						"PCRProfileOptionNoDiscreteTPMResetMitigation was not supplied: %w", newUnsupportedRequiredPCRsError(tpm2.HandleList{0}, o.result.Flags))
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
	return WithAutoTCGPCRProfile(o.result, opts)
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
