//go:build amd64

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
	"bufio"
	"errors"
	"fmt"

	"github.com/canonical/cpuid"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

type (
	hfsts1 uint32
	hfsts2 uint32
	hfsts3 uint32
	hfsts4 uint32
	hfsts5 uint32
	hfsts6 uint32

	meOperationMode        uint8
	errorEnforcementPolicy uint8
)

func (reg hfsts1) operationMode() meOperationMode {
	return meOperationMode(reg & hfsts1OperationMode >> 16)
}

func (reg hfsts6) errorEnforcementPolicy() errorEnforcementPolicy {
	return errorEnforcementPolicy(reg & hfsts6ErrorEnforcementPolicy >> 6)
}

const (
	hfsts1MfgMode       hfsts1 = 1 << 4
	hfsts1OperationMode hfsts1 = 0xf0000

	hfsts6ForceBootGuardACM      hfsts6 = 1 << 0
	hfsts6CpuDebugDisable        hfsts6 = 1 << 1
	hfsts6ProtectBIOSEnv         hfsts6 = 1 << 3
	hfsts6ErrorEnforcementPolicy hfsts6 = 0xc0
	hfsts6MeasuredBoot           hfsts6 = 1 << 8
	hfsts6VerifiedBoot           hfsts6 = 1 << 9
	hfsts6BootGuardDisable       hfsts6 = 1 << 28
	hfsts6FPFSOCLock             hfsts6 = 1 << 30

	meOperationModeNormal         meOperationMode = 0
	meOperationModeDebug          meOperationMode = 2
	meOperationModeDisabled       meOperationMode = 3
	meOperationModeOverrideJumper meOperationMode = 4
	meOperationModeOverrideMei    meOperationMode = 5
	meOperationModeMaybeSps       meOperationMode = 7

	errorEnforcementPolicyNothing        errorEnforcementPolicy = 0
	errorEnforcementPolicyShutdown30Mins errorEnforcementPolicy = 1
	errorEnforcementPolicyShutdownNow    errorEnforcementPolicy = 3
)

type meFamily uint8

const (
	meFamilyUnknown meFamily = iota
	meFamilySps
	meFamilyTxe
	meFamilyMe
	meFamilyCsme
)

func readIntelHFSTSRegistersFromMEISysfs(device internal_efi.SysfsDevice, regs [6]*uint32) error {
	rc, err := device.AttributeReader("fw_status")
	if err != nil {
		return err
	}
	defer rc.Close()

	i := 0
	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		if i > len(regs)-1 {
			return errors.New("invalid fw_status format: too many entries")
		}

		str := scanner.Text()
		if len(str) != 8 {
			return fmt.Errorf("invalid fw_status format: unexpected line length for line %d (%d chars)", i, len(str))
		}

		n, err := fmt.Sscanf(str, "%08x", regs[i])
		if err != nil {
			return fmt.Errorf("invalid fw_status format: cannot scan line %d: %w", i, err)
		}
		if n != 1 {
			return fmt.Errorf("invalid fw_status format: unexpected number of arguments scanned for line %d", i)
		}

		i += 1
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error when scanning fw_status: %w", err)
	}
	if i != 6 {
		return errors.New("invalid fw_status format: not enough entries")
	}

	return nil
}

type meVersion struct {
	Platform uint8
	Major    uint8
	Minor    uint8
	Hotfix   uint8
	Buildno  uint16
}

func decodeMeVersion(str string) (out meVersion, err error) {
	n, err := fmt.Sscanf(str, "%d:%d.%d.%d.%d", &out.Platform, &out.Major, &out.Minor, &out.Hotfix, &out.Buildno)
	if err != nil {
		return meVersion{}, err
	}
	if n != 5 {
		return meVersion{}, errors.New("unexpected number of arguments scanned")
	}
	return out, nil
}

func (v meVersion) String() string {
	return fmt.Sprintf("%d:%d.%d.%d.%d", v.Platform, v.Major, v.Minor, v.Hotfix, v.Buildno)
}

func readIntelMEVersionFromMEISysfs(device internal_efi.SysfsDevice) (meVersion, error) {
	rc, err := device.AttributeReader("fw_ver")
	if err != nil {
		return meVersion{}, err
	}
	defer rc.Close()

	var vers meVersion
	scanner := bufio.NewScanner(rc)
	// Only care about the first line
	if scanner.Scan() {
		vers, err = decodeMeVersion(scanner.Text())
		if err != nil {
			return meVersion{}, fmt.Errorf("invalid fw_ver: %w", err)
		}
	} else {
		return meVersion{}, errors.New("invalid fw_ver: nothing to scan")
	}

	if err := scanner.Err(); err != nil {
		return meVersion{}, fmt.Errorf("error when scanning fw_ver: %w", err)
	}

	return vers, nil
}

func calculateIntelMEFamily(vers meVersion, hfsts1Reg hfsts1) meFamily {
	switch vers.Major {
	case 0:
		return meFamilyUnknown
	case 1, 2, 3, 4:
		if hfsts1Reg.operationMode() == 0xf {
			return meFamilySps
		}
		return meFamilyTxe
	case 5:
		return meFamilyTxe
	case 6, 7, 8, 9, 10:
		return meFamilyMe
	default:
		return meFamilyCsme
	}
}

func checkPlatformFirmwareProtectionsIntelMEI(env internal_efi.HostEnvironment) error {
	devices, err := env.DevicesForClass("mei")
	if err != nil {
		return fmt.Errorf("cannot obtain devices with \"mei\" class: %w", err)
	}
	if len(devices) == 0 {
		return fmt.Errorf("no MEI device available")
	}
	device := devices[0]

	var (
		// Host Firmware Status Registers provided by the ME. The meaning of the
		// bits of these registers is not described in the datasheet for the PCH.
		// Thankfully, others have done most of the leg work here to figure out
		// what most bits mean, and we're only interested in a few of them anyway.
		hfsts1Reg hfsts1
		hfsts2Reg hfsts2
		hfsts3Reg hfsts3
		hfsts4Reg hfsts4
		hfsts5Reg hfsts5
		hfsts6Reg hfsts6
	)

	if err := readIntelHFSTSRegistersFromMEISysfs(device, [6]*uint32{
		(*uint32)(&hfsts1Reg),
		(*uint32)(&hfsts2Reg),
		(*uint32)(&hfsts3Reg),
		(*uint32)(&hfsts4Reg),
		(*uint32)(&hfsts5Reg),
		(*uint32)(&hfsts6Reg),
	}); err != nil {
		return fmt.Errorf("cannot read HFSTS registers from sysfs: %w", err)
	}

	vers, err := readIntelMEVersionFromMEISysfs(device)
	if err != nil {
		return fmt.Errorf("cannot obtain ME version from sysfs: %w", err)
	}

	// From here, these checks are based on the HSI checks performed in the pci-mei
	// plugin in fwupd.
	family := calculateIntelMEFamily(vers, hfsts1Reg)
	if family == meFamilyUnknown {
		return fmt.Errorf("cannot determine ME family: %w", err)
	}

	// Check manufacturing mode is not enabled.
	if hfsts1Reg&hfsts1MfgMode > 0 {
		return &NoHardwareRootOfTrustError{errors.New("ME is in manufacturing mode: no firmware protections are enabled")}
	}

	// Check operation mode
	switch hfsts1Reg.operationMode() {
	case meOperationModeOverrideJumper:
		return &NoHardwareRootOfTrustError{errors.New("invalid ME operation mode: checks for software tampering may be disabled")}
	default:
		// ok
	}

	// Check BootGuard profile - BootGuard must be force enabled. As it's an ACM, it's signed
	// by Intel and authenticated by a key that's rooted in the CPU microcode (which itself is
	// authenticated), it's essentially part of the TCB and the hardware root of trust. It
	// must be configured at least in verified boot mode (where it indirectly verifies that the
	// IBB has a valid OEM supplied signature before allowing it to execute it, via a hierarchy
	// of keys), with measured boot mode optional. Note that it's not clear if measured boot mode
	// without verified boot mode is a valid configuration, and it's not supported here yet. In
	// order to support it, we would need to be sure that for discrete TPMs, the GPIO configuration
	// is locked before the platform firmware executes.
	//
	// It must have an appropriate error enforcement policy if it fails to execute. The "Protect
	// BIOS Environment" feauture muse be enabled. The FPFs that control the profile and contain
	// the hash of the OEM key must be locked.

	// First check we have an appropriate ME family.
	switch family {
	case meFamilyUnknown:
		return &NoHardwareRootOfTrustError{errors.New("BootGuard unsupported on unknown ME family")}
	case meFamilyTxe:
		return &NoHardwareRootOfTrustError{errors.New("BootGuard unsupported on TXE ME family")}
	}

	if hfsts6Reg&hfsts6BootGuardDisable > 0 {
		// This isn't a good start
		return &NoHardwareRootOfTrustError{errors.New("BootGuard is disabled")}
	}

	// Verify the BootGuard profile
	if hfsts6Reg&hfsts6ForceBootGuardACM == 0 {
		return &NoHardwareRootOfTrustError{errors.New("the BootGuard ACM is not forced to execute - the CPU can execute arbitrary code from the legacy reset vector if BootGuard cannot be successfully loaded")}
	}
	if hfsts6Reg&hfsts6VerifiedBoot == 0 {
		return &NoHardwareRootOfTrustError{errors.New("BootGuard verified boot mode is not enabled - this allows arbitrary firmware that doesn't have a valid signature to be executed")}
	}
	if hfsts6Reg.errorEnforcementPolicy() != errorEnforcementPolicyShutdownNow {
		return &NoHardwareRootOfTrustError{errors.New("BootGuard does not have an appropriate error enforcement policy")}
	}
	if hfsts6Reg&hfsts6ProtectBIOSEnv == 0 {
		return &NoHardwareRootOfTrustError{errors.New("the \"Protect BIOS Environment\" feature is not enabled")}
	}

	// Make sure that the FPFs are locked.
	if hfsts6Reg&hfsts6FPFSOCLock == 0 {
		return &NoHardwareRootOfTrustError{errors.New("BootGuard OTP fuses are not locked")}
	}

	// Everything is ok
	return nil
}

const (
	ia32DebugInterfaceMSR = 0xc80

	ia32DebugEnable uint64 = 1 << 0
	ia32DebugLock   uint64 = 1 << 30
)

func checkCPUDebuggingLockedMSR(env internal_efi.HostEnvironmentAMD64) error {
	// Check for "Silicon Debug Interface", returned in bit 11 of %ecx when calling
	// cpuid with %eax=1.
	debugSupported := env.HasCPUIDFeature(cpuid.SDBG)
	if !debugSupported {
		return nil
	}

	vals, err := env.ReadMSRs(ia32DebugInterfaceMSR)
	if err != nil {
		return err
	}
	if len(vals) == 0 {
		return errors.New("no MSR values returned")
	}

	for _, val := range vals {
		if val&ia32DebugEnable > 0 || val&ia32DebugLock == 0 {
			return ErrCPUDebuggingNotLocked
		}
	}

	return nil
}
