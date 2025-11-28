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
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot"
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

	// DiscreteTPMDetected indicates that a discrete TPM was detected. Discrete TPMs suffer from
	// some well known attacks against the bus that it uses to communicate with the host chipset if
	// an adversary has physical access, such as passive interposer attacks (which are mitigated
	// against in Ubuntu by using response encryption with TPM2_Unseal), active interposer attacks
	// where an adversary can modify communications as well as monitor them (for which there are no
	// OS-level mitigations - whilst this can be mitigated by end-to-end integrity protection of PCR
	// extends and other critical commands, and the use of TPM2_EncryptDecrypt2 rather than TPM2_Unseal
	// in order to prevent the ability to modify session attributes and remove response encryption flag,
	// the mitigations are required throughout the entire trust chain including the firmware, which is
	// not the case today) and the ability to just desolder the device and attach it to a malicious host
	// platform, for which there are obviously no software mitigations. Firmware based TPMs such as Intel
	// PTT or those which run in a TEE are generally considered more secure as long as the persistent
	// storage is adequately protected from reading sensitive data, modification and rollback.
	//
	// They also potentially suffer from reset attacks. Whilst the TCG PC Client Platform Firmware
	// Profile Specification requires that the TPM and host platform cannot be reset independently, some
	// platforms permit the TPM to be reset without resetting the host platform, breaking measured boot
	// because it may be possible to reconstruct PCR values from software. This type of issue is a
	// hardware integration bug. Even if resetting the TPM correctly resets the host platform, it may be
	// possible for an adversary with physical access to lift the reset pin of the TPM in order to reset
	// it independently, depending on what type of package is used - eg, this is significantly harder for
	// TPMs in a QFN package than it is for TPMs in a TSSOP package - both of which are permitted as
	// described in the TCG PC Client Platform TPM Profile Specification for TPM 2.0, although the QFN
	// package is more likely to be found in laptops and other small computing devices. Note that it may
	// be possible to provide some mitigation against reset attacks if the TPM's startup locality is not
	// accessible from ring 0 code (platform firmware and privileged OS code). This is because the startup
	// locality changes the initial value of PCR 0, and so a startup locality other than 0 will make it
	// impossible to reconstruct the same PCR values from software as long as the startup locality cannot
	// be accessed from software by the adversary. Note that this type of mitigation offers no protection
	// from an adversary performing an active interposer attack as described before, as if they can control
	// bus communications then they can access any locality in order to replay PCR values, so any mitigation
	// provided is limited.
	DiscreteTPMDetected

	// StartupLocalityNotProtected indicates that the TPM's startup locality can most likely be accessed
	// from any code running at ring 0 (platform firmware and privileged OS code). This won't be set if
	// DiscreteTPMDetected isn't also set. If this is set, then it is not possible to offer any mitigation
	// against replaying PCR values from software as part of a reset attack. Support for not offering any
	// reset attack mitigation has to be opted into with the PermitNoDiscreteTPMResetMitigation flag to
	// RunChecks.
	StartupLocalityNotProtected

	// InsufficientDMAProtectionDetected indicates that DMA remapping was disabled in the pre-OS environment.
	// This weakens security because it allows pre-OS DMA attacks to compromise system integrity.
	// Support for this has to be opted into with the PermitInsufficientDMAProtection flag to RunChecks.
	// This check may not run if the NoSecureBootPolicyProfileSupport flag is set.
	InsufficientDMAProtectionDetected
)

func (f CheckResultFlags) toStringSlice() []string {
	out := make([]string, 0)
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
		case DiscreteTPMDetected:
			str = "discrete-tpm-detected"
		case StartupLocalityNotProtected:
			str = "startup-locality-not-protected"
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
		case "discrete-tpm-detected":
			val = DiscreteTPMDetected
		case "startup-locality-not-protected":
			val = StartupLocalityNotProtected
		case "insufficient-dma-protection-detected":
			val = InsufficientDMAProtectionDetected
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

	*f = out
	return nil
}

// String implements [fmt.Stringer].
func (f CheckResultFlags) String() string {
	return strings.Join(f.toStringSlice(), ",")
}

type checkResultJSON struct {
	PCRAlg            secboot.HashAlg      `json:"pcr-alg"`
	UsedSecureBootCAs []*X509CertificateID `json:"used-secure-boot-cas"`
	Flags             CheckResultFlags     `json:"flags"`
}

func newCheckResultJSON(r *CheckResult) (*checkResultJSON, error) {
	out := &checkResultJSON{
		UsedSecureBootCAs: r.UsedSecureBootCAs,
		Flags:             r.Flags,
	}
	out.PCRAlg = secboot.HashAlg(r.PCRAlg.GetHash())
	if out.PCRAlg == secboot.HashAlg(0) {
		return nil, errors.New("invalid PCR algorithm")
	}

	return out, nil
}

func (r checkResultJSON) toPublic() (*CheckResult, error) {
	out := &CheckResult{
		UsedSecureBootCAs: r.UsedSecureBootCAs,
		Flags:             r.Flags,
	}

	switch crypto.Hash(r.PCRAlg) {
	case crypto.SHA1:
		out.PCRAlg = tpm2.HashAlgorithmSHA1
	case crypto.SHA256:
		out.PCRAlg = tpm2.HashAlgorithmSHA256
	case crypto.SHA384:
		out.PCRAlg = tpm2.HashAlgorithmSHA384
	case crypto.SHA512:
		out.PCRAlg = tpm2.HashAlgorithmSHA512
	default:
		return nil, errors.New("unrecognized PCR algorithm")
	}

	return out, nil
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

// MarshalJSON implements [json.Marshaler].
func (r CheckResult) MarshalJSON() ([]byte, error) {
	j, err := newCheckResultJSON(&r)
	if err != nil {
		return nil, fmt.Errorf("cannot encode CheckResult: %w", err)
	}
	return json.Marshal(j)
}

// UnmarshalJSON implements [json.Unmarshaler].
func (r *CheckResult) UnmarshalJSON(data []byte) error {
	var j *checkResultJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	pub, err := j.toPublic()
	if err != nil {
		return fmt.Errorf("cannot decode CheckResult: %w", err)
	}

	*r = *pub
	return nil
}
