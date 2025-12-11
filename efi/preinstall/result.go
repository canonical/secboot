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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"strconv"
	"strings"

	"github.com/canonical/go-tpm2"
)

// CheckResultFlags is returned from [RunChecks].
type CheckResultFlags uint64

const (
	// NoPlatformFirmwareProfileSupport means that efi.WithPlatformFirmwareProfile can't
	// be used to add the PCR0 profile to a policy.
	NoPlatformFirmwareProfileSupport CheckResultFlags = 1 << iota

	// NoPlatformConfigProfileSupport means that a PCR1 profile cannot be added to a
	// policy.
	//
	// Note that this will always be set because the efi package does not implement
	// support for this PCR yet.
	NoPlatformConfigProfileSupport

	// NoDriversAndAppsProfileSupport means that efi.WithDriversAndAppsProfile can't be used
	// to add the PCR2 profile to a policy.
	NoDriversAndAppsProfileSupport

	// NoDriversAndAppsConfigProfileSupport means that a PCR3 profile cannot be added to a
	// policy.
	//
	// Note that this will always be set because the efi package does not implement
	// support for this PCR yet.
	NoDriversAndAppsConfigProfileSupport

	// NoBootManagerCodeProfileSupport means that efi.WithBootManagerCodeProfile can't be
	// used to add the PCR4 profile to a policy.
	NoBootManagerCodeProfileSupport

	// NoBootManagerConfigProfileSupport means that a PCR5 profile cannot be added to a
	// policy.
	//
	// Note that this will always be set because the efi package does not implement
	// support for this PCR yet.
	NoBootManagerConfigProfileSupport

	// NoSecureBootPolicyProfileSupport means that efi.WithSecureBootPolicyProfile can't
	// be used to add the PCR7 profile to a policy.
	NoSecureBootPolicyProfileSupport

	// RequestPartialDiscreteTPMResetAttackMitigation indicates that a partial mitigation against discrete
	// TPM reset attacks should be enabled.
	//
	// Discrete TPMs on some platforms may be vulnerable to a class of attack where the TPM can be reset
	// independently of the host platform, contrary to the requirements of the TCG PC Client Platform
	// Firmware Profile specification, breaking measured boot. This flag will be set on these platforms
	// if a partial mitigation is available.
	//
	// The locality from which TPM2_Startup is called from affects the starting value of PCR0. If access
	// to the startup locality is restricted by the hardware root-of-trust, then it's possible to
	// enable a partial mitigation against discrete TPM reset attacks by binding policies to PCR0,
	// which ensures that PCR0 cannot be reconstructed from the OS.
	//
	// This is only a partial mitigation becuase discrete TPMs may be vulnerable to several classes of
	// attacks. This doesn't mitigate active interposer attacks (where an adversary can modify communication
	// between the host CPU and TPM - this would require measures such as end-to-end integrity protection
	// of PCR extends and other critical commands throughout the entire chain of trust, and the use of
	// TPM2_EncryptDecrypt2 rather than TPM2_Unseal to prevent modification of session attributes to remove
	// the response encryption flag), nor other types of attacks where the TPM can be physically detached
	// in order to spoof the host platform. Even on platforms where the discrete TPM can't be reset
	// independently of the host CPU, it may still be possible for an adversary to reset it independently by
	// lifting pins.
	RequestPartialDiscreteTPMResetAttackMitigation

	// InsufficientDMAProtectionDetected indicates that DMA remapping was disabled in the pre-OS environment.
	// This weakens security because it allows pre-OS DMA attacks to compromise system integrity.
	// Support for this has to be opted into with the PermitInsufficientDMAProtection flag to RunChecks.
	// This check may not run if the NoSecureBootPolicyProfileSupport flag is set.
	InsufficientDMAProtectionDetected

	discreteTPMDetected
	startupLocalityNotProtected
)

func (f CheckResultFlags) toStringSlice() []string {
	out := make([]string, 0, bits.OnesCount64(uint64(f)))
	for i := 0; i < 64; i++ {
		flag := CheckResultFlags(1 << i)
		if f&flag == 0 {
			continue
		}

		var str string
		switch flag {
		case NoPlatformFirmwareProfileSupport:
			str = "no-platform-firmware-profile-support"
		case NoPlatformConfigProfileSupport:
			str = "no-platform-config-profile-support"
		case NoDriversAndAppsProfileSupport:
			str = "no-drivers-and-apps-profile-support"
		case NoDriversAndAppsConfigProfileSupport:
			str = "no-drivers-and-apps-config-profile-support"
		case NoBootManagerCodeProfileSupport:
			str = "no-boot-manager-code-profile-support"
		case NoBootManagerConfigProfileSupport:
			str = "no-boot-manager-config-profile-support"
		case NoSecureBootPolicyProfileSupport:
			str = "no-secure-boot-policy-profile-support"
		case RequestPartialDiscreteTPMResetAttackMitigation:
			str = "request-partial-dtpm-reset-attack-mitigation"
		case InsufficientDMAProtectionDetected:
			str = "insufficient-dma-protection-detected"
		default:
			str = fmt.Sprintf("%#08x", uint32(flag))
		}

		out = append(out, str)
	}

	return out

}

// MarshalJSON implements [json.Marshaler].
func (f CheckResultFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.toStringSlice())
}

// UnmarshalJSON implements [json.Unmarshaler].
func (f *CheckResultFlags) UnmarshalJSON(data []byte) error {
	var flags []string
	if err := json.Unmarshal(data, &flags); err != nil {
		return err
	}

	var out CheckResultFlags
	for _, flag := range flags {
		var val CheckResultFlags

		switch flag {
		case "no-platform-firmware-profile-support":
			val = NoPlatformFirmwareProfileSupport
		case "no-platform-config-profile-support":
			val = NoPlatformConfigProfileSupport
		case "no-drivers-and-apps-profile-support":
			val = NoDriversAndAppsProfileSupport
		case "no-drivers-and-apps-config-profile-support":
			val = NoDriversAndAppsConfigProfileSupport
		case "no-boot-manager-code-profile-support":
			val = NoBootManagerCodeProfileSupport
		case "no-boot-manager-config-profile-support":
			val = NoBootManagerConfigProfileSupport
		case "no-secure-boot-policy-profile-support":
			val = NoSecureBootPolicyProfileSupport
		case "request-partial-dtpm-reset-attack-mitigation":
			val = RequestPartialDiscreteTPMResetAttackMitigation
		case "insufficient-dma-protection-detected":
			val = InsufficientDMAProtectionDetected
		case "discrete-tpm-detected":
			val = discreteTPMDetected
		case "startup-locality-not-protected":
			val = startupLocalityNotProtected
		default:
			v, err := strconv.ParseUint(flag, 0, 32)
			switch {
			case errors.Is(err, strconv.ErrSyntax) || errors.Is(err, strconv.ErrRange):
				return fmt.Errorf("unrecognized flag %q", flag)
			case err != nil:
				return err
			}
			val = CheckResultFlags(v)
		}

		out |= val
	}

	if out&(discreteTPMDetected|startupLocalityNotProtected) == discreteTPMDetected {
		out |= RequestPartialDiscreteTPMResetAttackMitigation
	}
	out &^= (discreteTPMDetected | startupLocalityNotProtected)

	*f = out
	return nil
}

// String implements [fmt.Stringer].
func (f CheckResultFlags) String() string {
	return strings.Join(f.toStringSlice(), ",")
}

type checkResultJSON struct {
	PCRAlg            hashAlgorithmId      `json:"pcr-alg"`
	UsedSecureBootCAs []*X509CertificateID `json:"used-secure-boot-cas"`
	Flags             CheckResultFlags     `json:"flags"`
}

// CheckResult is returned from [RunChecks] when it completes successfully.
// It is JSON serializable, although some flags and fields are omitted.
type CheckResult struct {
	PCRAlg tpm2.HashAlgorithmId // The optimum PCR algorithm.

	// UsedSecureBootCAs indicates the CAs included in the firmware's authorized
	// signature database that were used to authenticate code running on this device,
	// so an experienced user can use this to manually express various levels of trust
	// in these in order to customize the Options field.
	UsedSecureBootCAs []*X509CertificateID

	// Flags contains a set of result flags
	Flags CheckResultFlags

	// Warnings contains any non-fatal errors that were detected when running the tests
	// on the current platform with the specified configuration. Note that this field is
	// not serialized.
	Warnings CompoundError
}

// MarshalJSON implements [json.Marshaler].
func (r CheckResult) MarshalJSON() ([]byte, error) {
	res := &checkResultJSON{
		PCRAlg:            hashAlgorithmId(r.PCRAlg),
		UsedSecureBootCAs: r.UsedSecureBootCAs,
		Flags:             r.Flags,
	}
	return json.Marshal(res)
}

// UnmarshalJSON implements [json.Unmarshaler].
func (r *CheckResult) UnmarshalJSON(data []byte) error {
	var res *checkResultJSON
	if err := json.Unmarshal(data, &res); err != nil {
		return err
	}

	*r = CheckResult{
		PCRAlg:            tpm2.HashAlgorithmId(res.PCRAlg),
		UsedSecureBootCAs: res.UsedSecureBootCAs,
		Flags:             res.Flags,
	}
	return nil
}

// String implements [fmt.Stringer].
func (r CheckResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nEFI based TPM protected FDE test support results:\n")
	io.WriteString(&b, makeIndentedListItem(0, "-", fmt.Sprintf("Best PCR algorithm: %v\n", r.PCRAlg)))
	io.WriteString(&b, makeIndentedListItem(0, "-", fmt.Sprintf("Secure boot CAs used for verification:\n")))
	for i, ca := range r.UsedSecureBootCAs {
		io.WriteString(&b, makeIndentedListItem(2, strconv.Itoa(i+1)+":", fmt.Sprintf("subject=%v, SKID=%#x, pubkeyAlg=%v, issuer=%v, AKID=%#x, sigAlg=%v\n",
			ca.Subject(), ca.SubjectKeyId(), ca.PublicKeyAlgorithm(), ca.Issuer(), ca.AuthorityKeyId(), ca.SignatureAlgorithm())))
	}
	io.WriteString(&b, makeIndentedListItem(0, "-", fmt.Sprintf("Flags: %s\n", r.Flags)))
	if r.Warnings != nil {
		warnings := r.Warnings.Unwrap()
		io.WriteString(&b, makeIndentedListItem(0, "-", "Warnings:\n"))
		for _, warning := range warnings {
			io.WriteString(&b, makeIndentedListItem(2, "-", fmt.Sprintf("%v\n", warning)))
		}
	}
	return b.String()
}
