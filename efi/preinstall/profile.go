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
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"

	"github.com/canonical/go-tpm2"
	secboot_efi "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

type authorityTrustFlags int

const (
	authorityTrustBootCode authorityTrustFlags = 1 << iota // authority is trusted to load boot code (we don't need PCR4)
	authorityTrustDrivers                                  // authority is trusted to load drivers (we may not need PCR2)
)

type authoritiesTrustLevel int

const (
	authoritiesTrustUnknown authoritiesTrustLevel = iota
	authoritiesNotTrusted
	authoritiesTrusted
)

type authorityTrustDataSet []authorityTrustData

func (s authorityTrustDataSet) trustedFor(certs []*X509CertificateID, flags authorityTrustFlags) authoritiesTrustLevel {
	for _, cert := range certs {
		var authFound bool
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

			if flags&auth.Trust != flags {
				return authoritiesNotTrusted
			}
			authFound = true
			break
		}
		if !authFound {
			// We have no information about this certificate because it isn't in our dataset.
			return authoritiesTrustUnknown
		}
	}

	return authoritiesTrusted
}

func (s authorityTrustDataSet) trustedForBootManager(certs []*X509CertificateID) authoritiesTrustLevel {
	return s.trustedFor(certs, authorityTrustBootCode)
}

func (s authorityTrustDataSet) trustedForDrivers(certs []*X509CertificateID) authoritiesTrustLevel {
	return s.trustedFor(certs, authorityTrustDrivers)
}

type authorityTrustData struct {
	Authority *internal_efi.SecureBootAuthorityIdentity
	Trust     authorityTrustFlags
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
	// PCRProfileOptionLockToPlatformFirmware is used to lock the PCR
	// profile to the platform firmware PCR using
	// secboot_efi.WithPlatformFirmwareProfile.
	PCRProfileOptionLockToPlatformFirmware PCRProfileOptionsFlags = 1 << iota

	// PCRProfileOptionLockToPlatformConfig is used to lock the PCR
	// profile to the platform config PCR.
	//
	// This option is currently unsupported and will result in an error.
	PCRProfileOptionLockToPlatformConfig

	// PCRProfileOptionLockToDriversAndApps is used to lock the PCR
	// profile to the drivers and apps PCR using
	// secboot_efi.WithDriversAndAppsProfile.
	PCRProfileOptionLockToDriversAndApps

	// PCRProfileOptionLockToDriversAndAppsConfig is used to lock the PCR
	// profile to the drivers and apps config PCR.
	//
	// This option is currently unsupported and will result in an error.
	PCRProfileOptionLockToDriversAndAppsConfig

	// PCRProfileOptionLockToBootManagerCode is used to lock the PCR
	// profile to the boot manager code PCR using
	// secboot_efi.WithBootManagerCodeProfile.
	PCRProfileOptionLockToBootManagerCode

	// PCRProfileOptionLockToBootManagerConfig is used to lock the PCR
	// profile to the boot manager config PCR.
	//
	// This option is currently unsupported and will result in an error.
	PCRProfileOptionLockToBootManagerConfig

	// PCRProfileOptionTrustSecureBootAuthoritiesForBootCode can omit the boot
	// manager code PCR if CAs in the authorized signature database that were used
	// to authenticate code on the current boot are not recognized, but a system
	// administrator makes an explicit decision to trust these CAs to sign boot
	// code.
	PCRProfileOptionTrustSecureBootAuthoritiesForBootCode

	// PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers can omit the
	// drivers and apps PCR if the CAs in the authorized signature database that were
	// used to authenticate code on the current boot are not recognized, but a system
	// administrator makes an explicit decision to trust these CAs to sign addon
	// drivers.
	PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers

	// PCRProfileOptionPermitNoSecureBootPolicyProfle can be used to permit a fallback
	// to a configuration without the secure boot policy profile included if the supplied
	// CheckResult indicates that it cannot be used.
	PCRProfileOptionPermitNoSecureBootPolicyProfile

	// PCRProfileOptionNoPartialDiscreteTPMResetAttackMitigation can be used to omit the
	// platform firmware PCR from the profile on platforms that have a discrete TPM and
	// where including PCR0 can provide limited mitigation of TPM reset attacks by preventing
	// the PCR values from being reconstructed from software. This should only be used if a
	// system administrator makes an explicit decision that they don't want the additional PCR
	// fragility caused by this mitigation, perhaps because they consider that discrete TPMs
	// still have other weaknesses to anyone with physical access to the device without any of
	// their own mitigations. See the RequestPartialDiscreteTPMResetAttackMitigation
	// CheckResultFlags flag description for more information.
	PCRProfileOptionNoPartialDiscreteTPMResetAttackMitigation

	// PCRProfileOptionsDefault is the default PCR configuration. WithAutoTCGPCRProfile
	// will select the most appropriate configuration depending on the CheckResult.
	PCRProfileOptionsDefault PCRProfileOptionsFlags = 0

	// PCRProfileOptionMostSecure is the most secure configuration by including all relevant
	// TCG defined PCRs supported by the efi package.
	//
	// This option is currently unsupported and will result in an error.
	PCRProfileOptionMostSecure = PCRProfileOptionLockToPlatformFirmware | PCRProfileOptionLockToPlatformConfig | PCRProfileOptionLockToDriversAndApps | PCRProfileOptionLockToDriversAndAppsConfig | PCRProfileOptionLockToBootManagerCode | PCRProfileOptionLockToBootManagerConfig
)

func (o PCRProfileOptionsFlags) toStringSlice() []string {
	out := make([]string, 0, bits.OnesCount32(uint32(o)))
	for i := 0; i < 32; i++ {
		flag := PCRProfileOptionsFlags(1 << i)
		if o&flag == 0 {
			continue
		}

		var str string
		switch flag {
		case PCRProfileOptionLockToPlatformFirmware:
			str = "lock-platform-firmware"
		case PCRProfileOptionLockToPlatformConfig:
			str = "lock-platform-config"
		case PCRProfileOptionLockToDriversAndApps:
			str = "lock-drivers-and-apps"
		case PCRProfileOptionLockToDriversAndAppsConfig:
			str = "lock-drivers-and-apps-config"
		case PCRProfileOptionLockToBootManagerCode:
			str = "lock-boot-manager-code"
		case PCRProfileOptionLockToBootManagerConfig:
			str = "lock-boot-manager-config"
		case PCRProfileOptionTrustSecureBootAuthoritiesForBootCode:
			str = "trust-authorities-for-boot-code"
		case PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers:
			str = "trust-authorities-for-addon-drivers"
		case PCRProfileOptionPermitNoSecureBootPolicyProfile:
			str = "permit-no-secure-boot-policy-profile"
		case PCRProfileOptionNoPartialDiscreteTPMResetAttackMitigation:
			str = "no-partial-dtpm-reset-attack-mitigation"
		default:
			str = fmt.Sprintf("%#08x", uint32(flag))
		}

		out = append(out, str)
	}

	return out
}

// MarshalJSON implements [json.Marshaler].
func (o PCRProfileOptionsFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.toStringSlice())
}

// UnmarshalJSON implements [json.Unmarshaler].
func (o *PCRProfileOptionsFlags) UnmarshalJSON(data []byte) error {
	var flags []string
	if err := json.Unmarshal(data, &flags); err != nil {
		return err
	}

	var out PCRProfileOptionsFlags
	for _, flag := range flags {
		var val PCRProfileOptionsFlags

		switch flag {
		case "lock-platform-firmware":
			val = PCRProfileOptionLockToPlatformFirmware
		case "lock-platform-config":
			val = PCRProfileOptionLockToPlatformConfig
		case "lock-drivers-and-apps":
			val = PCRProfileOptionLockToDriversAndApps
		case "lock-drivers-and-apps-config":
			val = PCRProfileOptionLockToDriversAndAppsConfig
		case "lock-boot-manager-code":
			val = PCRProfileOptionLockToBootManagerCode
		case "lock-boot-manager-config":
			val = PCRProfileOptionLockToBootManagerConfig
		case "trust-authorities-for-boot-code":
			val = PCRProfileOptionTrustSecureBootAuthoritiesForBootCode
		case "trust-authorities-for-addon-drivers":
			val = PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers
		case "permit-no-secure-boot-policy-profile":
			val = PCRProfileOptionPermitNoSecureBootPolicyProfile
		case "no-partial-dtpm-reset-attack-mitigation":
			val = PCRProfileOptionNoPartialDiscreteTPMResetAttackMitigation
		default:
			v, err := strconv.ParseUint(flag, 0, 32)
			switch {
			case errors.Is(err, strconv.ErrSyntax) || errors.Is(err, strconv.ErrRange):
				return fmt.Errorf("unrecognized flag %q", flag)
			case err != nil:
				return err
			}
			val = PCRProfileOptionsFlags(v)
		}

		out |= val
	}

	*o = out
	return nil
}

func (o PCRProfileOptionsFlags) String() string {
	return strings.Join(o.toStringSlice(), ",")
}

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

func (o *pcrProfileAutoSetPcrsOption) pcrOptions() ([]secboot_efi.PCRProfileEnablePCRsOption, error) {
	pcrs := make(map[tpm2.Handle]bool)
	switch {
	case o.result.Flags&NoSecureBootPolicyProfileSupport == 0 || o.opts&PCRProfileOptionPermitNoSecureBootPolicyProfile == 0:
		// Always include secure boot policy when it is supported. We also
		// run this branch if it isn't supported and the user hasn't opted
		// in to allowing profiles without it. We'll eventually return an
		// error with the appropriate set of required but unsupported PCRs.
		pcrs[internal_efi.SecureBootPolicyPCR] = true

		if o.opts&PCRProfileOptionLockToPlatformFirmware > 0 {
			pcrs[internal_efi.PlatformFirmwarePCR] = true
		}
		if o.opts&PCRProfileOptionLockToPlatformConfig > 0 {
			pcrs[internal_efi.PlatformConfigPCR] = true
		}

		lockToDriversAndApps := o.opts&PCRProfileOptionLockToDriversAndApps > 0
		trustCAsForDrivers := o.opts&PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers > 0
		trustLevelForDrivers := knownCAs.trustedForDrivers(o.result.UsedSecureBootCAs)
		switch {
		case lockToDriversAndApps && trustCAsForDrivers:
			// Invalid options.
			return nil, fmt.Errorf("%q option is incompatible with %q option", PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers, PCRProfileOptionLockToDriversAndApps)
		case lockToDriversAndApps:
			// User opted to lock to PCR2.
			pcrs[internal_efi.DriversAndAppsPCR] = true
		case trustCAsForDrivers && trustLevelForDrivers == authoritiesNotTrusted:
			// User opted to trust the active secure boot CAs for signing addon
			// drivers but the active CAs are explicitly distrusted.
			return nil, fmt.Errorf("%q option cannot be used when secure boot CAs that are explicitly distrusted for authenticating addon drivers are active", PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers)
		case trustCAsForDrivers:
			// User opted to trust unknown active secure boot CAs for signing
			// addon drivers.
		case trustLevelForDrivers == authoritiesTrusted:
			// Active secure boot CAs are trusted for signing addon drivers.
		default:
			// Active secure boot CAs are not trusted for signing addon drivers.
			pcrs[internal_efi.DriversAndAppsPCR] = true
		}

		if o.opts&PCRProfileOptionLockToDriversAndAppsConfig > 0 {
			pcrs[internal_efi.DriversAndAppsConfigPCR] = true
		}

		lockToBootCode := o.opts&PCRProfileOptionLockToBootManagerCode > 0
		trustCAsForBootCode := o.opts&PCRProfileOptionTrustSecureBootAuthoritiesForBootCode > 0
		trustLevelForBootCode := knownCAs.trustedForBootManager(o.result.UsedSecureBootCAs)
		switch {
		case lockToBootCode && trustCAsForBootCode:
			// Invalid options.
			return nil, fmt.Errorf("%q option is incompatible with %q option", PCRProfileOptionTrustSecureBootAuthoritiesForBootCode, PCRProfileOptionLockToBootManagerCode)
		case lockToBootCode:
			// User opted to lock to PCR2.
			pcrs[internal_efi.BootManagerCodePCR] = true
		case trustCAsForBootCode && trustLevelForBootCode == authoritiesNotTrusted:
			// User opted to trust the active secure boot CAs for signing boot
			// code but the active CAs are explicitly distrusted.
			return nil, fmt.Errorf("%q option cannot be used when secure boot CAs that are explicitly distrusted for authenticating boot code are active", PCRProfileOptionTrustSecureBootAuthoritiesForBootCode)
		case trustCAsForBootCode:
			// User opted to trust unknown active secure boot CAs for signing
			// boot code.
		case trustLevelForBootCode == authoritiesTrusted:
			// Active secure boot CAs are trusted for signing boot code.
		default:
			// Active secure boot CAs are not trusted for signing boot code.
			pcrs[internal_efi.BootManagerCodePCR] = true
		}

		if o.opts&PCRProfileOptionLockToBootManagerConfig > 0 {
			pcrs[internal_efi.BootManagerConfigPCR] = true
		}

	default:
		// Secure boot policy is not supported and the user opted in to
		// allowing profiles without it. Include all other PCRs in this case:
		// - PCR1 is required because we have to depend on platform config rather relying on security-relevant firmware
		//   setting such as DMA protection changing the value of PCR7.
		// - PCR2 is required to include all non-platform value-added-retailer supplied drivers that execute.
		// - PCR3 is required for the same reason as PCR1, but for value-added-retailer driver configuration.
		// - PCR4 is required for all system preparation applications and boot manager code that execute.
		// - PCR5 is required for the same reason as PCR1, but for boot manager configuration.
		pcrs[internal_efi.PlatformFirmwarePCR] = true
		pcrs[internal_efi.PlatformConfigPCR] = true
		pcrs[internal_efi.DriversAndAppsPCR] = true
		pcrs[internal_efi.DriversAndAppsConfigPCR] = true
		pcrs[internal_efi.BootManagerCodePCR] = true
		pcrs[internal_efi.BootManagerConfigPCR] = true

		if o.opts&PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers > 0 {
			return nil, fmt.Errorf("%q option cannot be used when the secure boot policy profile isn't available", PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers)
		}
		if o.opts&PCRProfileOptionTrustSecureBootAuthoritiesForBootCode > 0 {
			return nil, fmt.Errorf("%q option cannot be used when the secure boot policy profile isn't available", PCRProfileOptionTrustSecureBootAuthoritiesForBootCode)
		}
	}

	if o.opts&PCRProfileOptionNoPartialDiscreteTPMResetAttackMitigation == 0 && o.result.Flags&RequestPartialDiscreteTPMResetAttackMitigation > 0 {
		// Enable reset attack mitigations by including PCR0, because the startup locality
		// is protected making it impossible to reconstruct PCR0 from software if the TPM is
		// reset indepdendently of the host platform. Note that it is still possible for an
		// adversary with physical access to reconstruct PCR0 by manipulating the bus between
		// the host CPU and the discrete TPM directly, as this will allow them access to all
		// localities.
		pcrs[internal_efi.PlatformFirmwarePCR] = true
	}

	var (
		mask        CheckResultFlags                         // the set of flags that must not be in the results.
		resultFlags = o.result.Flags                         // save this locally because it can be modified below.
		opts        []secboot_efi.PCRProfileEnablePCRsOption // the set of PCR options.
		pcrHandles  tpm2.HandleList                          // the required PCRs.
	)
	for _, data := range []struct {
		pcr             tpm2.Handle
		unsupportedFlag CheckResultFlags
		opt             func() secboot_efi.PCRProfileEnablePCRsOption
	}{
		{pcr: internal_efi.PlatformFirmwarePCR, unsupportedFlag: NoPlatformFirmwareProfileSupport, opt: secboot_efi.WithPlatformFirmwareProfile},
		{pcr: internal_efi.PlatformConfigPCR, unsupportedFlag: NoPlatformConfigProfileSupport},
		{pcr: internal_efi.DriversAndAppsPCR, unsupportedFlag: NoDriversAndAppsProfileSupport, opt: secboot_efi.WithDriversAndAppsProfile},
		{pcr: internal_efi.DriversAndAppsConfigPCR, unsupportedFlag: NoDriversAndAppsConfigProfileSupport},
		{pcr: internal_efi.BootManagerCodePCR, unsupportedFlag: NoBootManagerCodeProfileSupport, opt: secboot_efi.WithBootManagerCodeProfile},
		{pcr: internal_efi.BootManagerConfigPCR, unsupportedFlag: NoBootManagerConfigProfileSupport},
		{pcr: internal_efi.SecureBootPolicyPCR, unsupportedFlag: NoSecureBootPolicyProfileSupport, opt: secboot_efi.WithSecureBootPolicyProfile},
	} {
		if _, required := pcrs[data.pcr]; required {
			mask |= data.unsupportedFlag
			if data.opt != nil {
				opts = append(opts, data.opt())
			} else {
				// This flag should already be in the results, but make sure it's there
				// just in case.
				resultFlags |= data.unsupportedFlag
			}
			pcrHandles = append(pcrHandles, data.pcr)
		}
	}
	if resultFlags&mask > 0 {
		return nil, newUnsupportedRequiredPCRsError(pcrHandles, resultFlags)
	}

	return opts, nil
}

// ApplyOptionTo implements [secboot_efi.PCRProfileOption].
func (o *pcrProfileAutoSetPcrsOption) ApplyOptionTo(visitor internal_efi.PCRProfileOptionVisitor) error {
	pcrOpts, err := o.pcrOptions()
	if err != nil {
		return fmt.Errorf("cannot select an appropriate set of TCG defined PCRs with the current options: %w", err)
	}
	for i, pcrOpt := range pcrOpts {
		if err := pcrOpt.ApplyOptionTo(visitor); err != nil {
			return fmt.Errorf("cannot add PCR profile option %d: %w", i, err)
		}
	}
	if _, permitted := o.result.AcceptedErrors[ErrorKindInsufficientDMAProtection]; permitted {
		if err := secboot_efi.WithAllowInsufficientDmaProtection().ApplyOptionTo(visitor); err != nil {
			return fmt.Errorf("cannot add DMA allow insufficient protection profile option: %w", err)
		}
	}
	return nil
}

func (o *pcrProfileAutoSetPcrsOption) Options(opts PCRProfileOptionsFlags) PCRProfileAutoEnablePCRsOption {
	return WithAutoTCGPCRProfile(o.result, opts)
}

// PCRs implements [secboot_efi.PCRProfileEnablePCRsOption.PCRs].
func (o *pcrProfileAutoSetPcrsOption) PCRs() (tpm2.HandleList, error) {
	pcrOpts, err := o.pcrOptions()
	if err != nil {
		return nil, fmt.Errorf("cannot select an appropriate set of TCG defined PCRs with the current options: %w", err)
	}

	var out tpm2.HandleList
	for i, pcrOpt := range pcrOpts {
		pcrs, err := pcrOpt.PCRs()
		if err != nil {
			return nil, fmt.Errorf("cannot add PCRs from profile option %d: %w", i, err)
		}
		out = append(out, pcrs...)
	}
	return out, nil
}
