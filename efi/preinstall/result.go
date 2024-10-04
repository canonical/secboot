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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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
	// be possible to mitigate reset attacks if the TPM's startup locality is not accessible from ring 0
	// code. This is because the startup locality changes the initial value of PCR 0, and so a startup
	// locality other than 0 will make it impossible to reconstruct the same PCR values from software as
	// long as the startup locality cannot be accessed from software by the adversary. Note that this
	// offers no protection from an adversary performing an active interposer attack as described before,
	// as they can access any locality.
	DiscreteTPMDetected

	// StartupLocalityNotProtected indicates that the TPM's startup locality can most likely be accessed
	// from any code running at ring 0. This won't be set if DiscreteTPMDetected isn't also set. If this
	// is set, then it is not possible to offer any mitigation against replaying PCR values from software
	// as part of a reset attack. Support for not offering any reset attack mitigation has to be opted
	// into with the PermitNoDiscreteTPMResetMitigation flag to RunChecks.
	StartupLocalityNotProtected

	// VARDriversPresent indicates that value-added-retailer drivers were present, either
	// because there are Driver#### load options and/or DriverOrder global variable, or
	// because one or more was loaded from an option ROM contained on a PCI device. These
	// are included in a PCR policy when using efi.WithDriversAndAppsProfile. Support for
	// including value-added-retailer drivers has to be opted into with the
	// PermitVARSuppliedDrivers flag to RunChecks.
	// This check may not run if the NoDriversAndAppsProfileSupport flag is set.
	//
	// Note that this flag is not persisted when serializing the results.
	VARDriversPresent

	// SysPrepApplicationsPresent indicates that system preparation applications were
	// running as part of the pre-OS environment because there are SysPrep#### and
	// SysPrepOrder global variables defined. As these aren't under the control of the OS,
	// these can increase the fragility of profiles that include efi.WithBootManagerCodeProfile.
	// Support for including system preparation applications has to be opted into with the
	// PermitSysPrepApplications flag to RunChecks.
	// This check may not run if the NoBootManagerCodeProfileSupport flag is set.
	//
	// Note that this flag is not persisted when serializing the results.
	SysPrepApplicationsPresent

	// AbsoluteComputeActive indicates that the platform firmware is executing an endpoint
	// management application called "Absolute" using the LoadImage API. If it is, this is
	// measured to PCR4 as part of the OS-present environment before the OS is loaded.
	// As this is a firmware component, this increases the fragility of profiles that include
	// efi.WithBootManagerCodeProfile. Where possible, this firmware should be disabled. Support
	// for including Absolute has to be opted into with the PermitAbsoluteComputrace flag to
	// RunChecks.
	// This check may not run if the NoBootManagerCodeProfileSupport flag is set.
	//
	// Note that this flag is not persisted when serializing the results.
	AbsoluteComputraceActive

	// NotAllBootManagerCodeDigestsVerified indicates that the checks for efi.WithBootManagerCodeProfile
	// was not able to verify all of the EV_EFI_BOOT_SERVICES_APPLICATION digests that appear in the
	// log to ensure that they contain an Authenticode digest that matches a boot component used during
	// the current boot. If this is set, it means that not all boot components were supplied to RunChecks.
	// Support for not verifying all EV_EFI_BOOT_SERVICES_APPLICATION digests has to opted into with the
	// PermitNotVerifyingAllBootManagerCodeDigests flag to RunChecks.
	// This check may not run if the NoBootManagerCodeProfileSupport flag is set.
	//
	// Note that this flag is not persisted when serializing the results.
	NotAllBootManagerCodeDigestsVerified

	// RunningInVirtualMachine indicates that the OS is running in a virtual machine. As parts
	// of the TCB, such as the initial firmware code and the vTPM are under the control of the host
	// environment, this configuration offers little benefit other than for testing - particularly
	// in CI environments. If this is set, no checks for platform firmware protections were
	// performed. Support for virtual machines has to be opted into with the PermitVirtualMachine flag
	// to RunChecks.
	//
	// Note that this flag is not persisted when serializing the results.
	RunningInVirtualMachine

	// WeakSecureBootAlgorithms indicates that weak algorithms were detected during secure boot verification,
	// such as authenticating a pre-OS binary with SHA1, or with a CA with a 1024-bit RSA public key, or because
	// the signing key used to sign the initial boot loader uses a 1024-bit RSA key. This does have some
	// limitations because the TCG log doesn't indicate the properties of the actual signing certificate of
	// the algorithms used to sign each binary, so it's not possible to verify the signing keys for components
	// outside of the OS control. Support for weak secure boot algorithms has to be opted into with the
	// PermitWeakSecureBootAlgorithms flag to RunChecks.
	// This check may not run if the NoSecureBootPolicyProfileSupport flag is set.
	//
	// Note that this flag is not persisted when serializing the results.
	WeakSecureBootAlgorithmsDetected

	// PreOSVerificationUsingDigestDetected indicates that pre-OS components were verified by the
	// use of a digest hardcoded in the authorized signature database as opposed to a X.509 certificate.
	// Support for this has to be opted into with the PermitPreOSVerificationUsingDigests flag to
	// RunChecks, as it implies that db has to change with each update to certain firmware components.
	// This check may not run if the NoSecureBootPolicyProfileSupport flag is set.
	//
	// Note that this flag is not persisted when serializing the results.
	PreOSVerificationUsingDigestsDetected
)

var checkResultFlagToIDStringMap = map[CheckResultFlags]string{
	NoPlatformFirmwareProfileSupport:     "no-platform-firmware-profile-support",
	NoPlatformConfigProfileSupport:       "no-platform-config-profile-support",
	NoDriversAndAppsProfileSupport:       "no-drivers-and-apps-profile-support",
	NoDriversAndAppsConfigProfileSupport: "no-drivers-and-apps-config-profile-support",
	NoBootManagerCodeProfileSupport:      "no-boot-manager-code-profile-support",
	NoBootManagerConfigProfileSupport:    "no-boot-manager-config-profile-support",
	NoSecureBootPolicyProfileSupport:     "no-secure-boot-policy-profile-support",
	DiscreteTPMDetected:                  "discrete-tpm-detected",
	StartupLocalityNotProtected:          "startup-locality-not-protected",
}

var checkNonPersistentResultFlagToIDStringMap = map[CheckResultFlags]string{
	VARDriversPresent:                     "var-drivers-present",
	SysPrepApplicationsPresent:            "sysprep-apps-present",
	AbsoluteComputraceActive:              "absolute-active",
	NotAllBootManagerCodeDigestsVerified:  "not-all-boot-manager-code-digests-verified",
	RunningInVirtualMachine:               "running-in-vm",
	WeakSecureBootAlgorithmsDetected:      "weak-secure-boot-algs-detected",
	PreOSVerificationUsingDigestsDetected: "pre-os-verification-using-digests-detected",
}

var checkResultFlagFromIDStringMap = map[string]CheckResultFlags{
	"no-platform-firmware-profile-support":       NoPlatformFirmwareProfileSupport,
	"no-platform-config-profile-support":         NoPlatformConfigProfileSupport,
	"no-drivers-and-apps-profile-support":        NoDriversAndAppsProfileSupport,
	"no-drivers-and-apps-config-profile-support": NoDriversAndAppsConfigProfileSupport,
	"no-boot-manager-code-profile-support":       NoBootManagerCodeProfileSupport,
	"no-boot-manager-config-profile-support":     NoBootManagerConfigProfileSupport,
	"no-secure-boot-policy-profile-support":      NoSecureBootPolicyProfileSupport,
	"discrete-tpm-detected":                      DiscreteTPMDetected,
	"startup-locality-not-protected":             StartupLocalityNotProtected,
}

type checkResultJSON struct {
	PCRAlg            secboot.HashAlg `json:"pcr-alg"`
	UsedSecureBootCAs [][]byte        `json:"used-secure-boot-cas"`
	Flags             []string        `json:"flags"`
}

func newCheckResultJSON(r *CheckResult) *checkResultJSON {
	out := new(checkResultJSON)
	out.PCRAlg = secboot.HashAlg(r.PCRAlg.GetHash())
	for _, ca := range r.UsedSecureBootCAs {
		out.UsedSecureBootCAs = append(out.UsedSecureBootCAs, ca.Raw)
	}
	for i := 0; i < 64; i++ {
		if r.Flags&CheckResultFlags(1<<i) > 0 {
			if str, exists := checkResultFlagToIDStringMap[CheckResultFlags(1<<i)]; exists {
				out.Flags = append(out.Flags, str)
			}
		}
	}
	return out
}

func (r checkResultJSON) toPublic() (*CheckResult, error) {
	out := new(CheckResult)

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

	for i, ca := range r.UsedSecureBootCAs {
		cert, err := x509.ParseCertificate(ca)
		if err != nil {
			return nil, fmt.Errorf("cannot parse certificate at index %d: %w", i, err)
		}
		out.UsedSecureBootCAs = append(out.UsedSecureBootCAs, cert)
	}

	for _, flag := range r.Flags {
		val, exists := checkResultFlagFromIDStringMap[flag]
		if !exists {
			return nil, fmt.Errorf("unrecognized flag %q", flag)
		}
		out.Flags |= val
	}

	return out, nil
}

// CheckResult is returned from [RunChecks] when it completes successfully.
type CheckResult struct {
	PCRAlg tpm2.HashAlgorithmId // The optimum PCR algorithm.

	// UsedSecureBootCAs indicates the CAs included in the firmware's authorized
	// signature database that were used to authenticate code running on this device,
	// so an experienced user can use this to manually express various levels of trust
	// in these in order to customize the Options field.
	UsedSecureBootCAs []*x509.Certificate

	// Flags contains a set of result flags
	Flags CheckResultFlags
}

// String implements [fmt.Stringer].
func (r CheckResult) String() string {
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "\nEFI based TPM protected FDE test support results:\n")
	fmt.Fprintf(w, "- Best PCR algorithm: %v\n", r.PCRAlg)
	fmt.Fprintf(w, "- Secure boot CAs used for verification:\n")
	for i, ca := range r.UsedSecureBootCAs {
		fmt.Fprintf(w, "  %d: subject=%v, SKID=%#x, pubkeyAlg=%v\n", i+1, ca.Subject, ca.SubjectKeyId, ca.PublicKeyAlgorithm)
	}
	var flags []string
	for i := 0; i < 64; i++ {
		if r.Flags&CheckResultFlags(1<<i) > 0 {
			str, exists := checkResultFlagToIDStringMap[CheckResultFlags(1<<i)]
			if !exists {
				str, exists = checkNonPersistentResultFlagToIDStringMap[CheckResultFlags(1<<i)]
			}
			if !exists {
				str = fmt.Sprintf("%016x", 1<<i)
			}
			flags = append(flags, str)
		}
	}
	fmt.Fprintf(w, "- Flags: %s\n", strings.Join(flags, ","))
	return w.String()
}

// MarshalJSON implements [json.Marshaler].
func (r CheckResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(newCheckResultJSON(&r))
}

// UnmarshalJSON implements [json.Unmarshaler].
func (r *CheckResult) UnmarshalJSON(data []byte) error {
	var j *checkResultJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	pub, err := j.toPublic()
	if err != nil {
		return err
	}

	*r = *pub
	return nil
}
