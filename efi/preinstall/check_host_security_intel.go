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

	// meOperationMode is the ME operation mode.
	meOperationMode uint8

	hfstsRegisters struct {
		Hfsts1 hfsts1
		Hfsts2 hfsts2
		Hfsts3 hfsts3
		Hfsts4 hfsts4
		Hfsts5 hfsts5
		Hfsts6 hfsts6
	}

	// btgProfile is the BootGuard profile.
	btgProfile uint8
)

func (reg hfsts1) operationMode() meOperationMode {
	return meOperationMode(reg & hfsts1OperationMode >> 16)
}

const (
	// hfsts1MfgMode indicates that the ME is in manufacturing mode. Fwupd refers to this
	// as manufacturing mode for CSME #11 and SPI protection mode for CSME #18. Slimbootloader
	// refers to this as the latter for everything other than Comet Lake.
	hfsts1MfgMode hfsts1 = 1 << 4

	// hfsts1OperationMode is the ME operation mode bitmask, from fwupd and slimbootloader.
	hfsts1OperationMode hfsts1 = 0xf0000

	hfsts5BtgAcmActive hfsts5 = 1 << 0
	hfsts5BtgAcmDone   hfsts5 = 1 << 8

	hfsts6FPFSOCLock hfsts6 = 1 << 30

	meOperationModeNormal         meOperationMode = 0x0
	meOperationModeDebug          meOperationMode = 0x2
	meOperationModeDisabled       meOperationMode = 0x3
	meOperationModeOverrideJumper meOperationMode = 0x4
	meOperationModeOverrideMei    meOperationMode = 0x5
	meOperationModeSps            meOperationMode = 0xf

	// btgProfileNoVFME indicates that BootGuard will execute without verified or
	// measured boot.
	btgProfileNoFVME btgProfile = 0

	// btgProfileVM indicates that BootGuard will execute with verified and measured
	// boot but the platform will continue booting if verification fails.
	btgProfileVM btgProfile = 3

	// btgProfileFVE indicates that BootGuard will execute with verified boot.
	// BootGuard is forced to execute and verification failures result in immediate
	// shutdown.
	btgProfileFVE btgProfile = 4

	// btgProfileFVME indicates that BootGuard will execute with verified and
	// measured boot. BootGuard is forced to execute and verification failures result
	// in immediate shutdown.
	btgProfileFVME btgProfile = 5
)

type meFamily uint8

const (
	meFamilyUnknown meFamily = iota
	meFamilySps
	meFamilyTxe
	meFamilyMe
	meFamilyCsme
)

func (f meFamily) String() string {
	switch f {
	case meFamilySps:
		return "SPS"
	case meFamilyTxe:
		return "TXE"
	case meFamilyMe:
		return "ME"
	case meFamilyCsme:
		return "CSME"
	default:
		return "unknown"
	}
}

func readIntelHFSTSRegistersFromMEISysfs(device internal_efi.SysfsDevice) (regs hfstsRegisters, err error) {
	rc, err := device.AttributeReader("fw_status")
	if err != nil {
		return hfstsRegisters{}, err
	}
	defer rc.Close()

	regs32 := [...]*uint32{
		(*uint32)(&regs.Hfsts1),
		(*uint32)(&regs.Hfsts2),
		(*uint32)(&regs.Hfsts3),
		(*uint32)(&regs.Hfsts4),
		(*uint32)(&regs.Hfsts5),
		(*uint32)(&regs.Hfsts6),
	}

	i := 0
	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		if i > len(regs32)-1 {
			return hfstsRegisters{}, errors.New("invalid fw_status format: too many entries")
		}

		str := scanner.Text()
		if len(str) != 8 {
			return hfstsRegisters{}, fmt.Errorf("invalid fw_status format: unexpected line length for line %d (%d chars)", i, len(str))
		}

		n, err := fmt.Sscanf(str, "%08x", regs32[i])
		if err != nil {
			return hfstsRegisters{}, fmt.Errorf("invalid fw_status format: cannot scan line %d: %w", i, err)
		}
		if n != 1 {
			return hfstsRegisters{}, fmt.Errorf("invalid fw_status format: unexpected number of arguments scanned for line %d", i)
		}

		i += 1
	}
	if err := scanner.Err(); err != nil {
		return hfstsRegisters{}, fmt.Errorf("error when scanning fw_status: %w", err)
	}
	if i != len(regs32) {
		return hfstsRegisters{}, errors.New("invalid fw_status format: not enough entries")
	}

	return regs, nil
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
		if hfsts1Reg.operationMode() == meOperationModeSps {
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

func checkHostSecurityIntelBootGuard(env internal_efi.HostEnvironment) error {
	devices, err := env.DevicesForClass("mei")
	if err != nil {
		return fmt.Errorf("cannot obtain devices with \"mei\" class: %w", err)
	}
	if len(devices) == 0 {
		return MissingKernelModuleError("mei_me")
	}
	device := devices[0]

	vers, err := readIntelMEVersionFromMEISysfs(device)
	if err != nil {
		return fmt.Errorf("cannot obtain ME version from sysfs: %w", err)
	}

	regs, err := readIntelHFSTSRegistersFromMEISysfs(device)
	if err != nil {
		return fmt.Errorf("cannot read HFSTS registers from sysfs: %w", err)
	}

	// Only support CSME.
	if calculateIntelMEFamily(vers, regs.Hfsts1) != meFamilyCsme {
		return &UnsupportedPlatformError{errors.New("unsupported ME family")}
	}

	// Check that operation mode is normal.
	if regs.Hfsts1.operationMode() != meOperationModeNormal {
		return &NoHardwareRootOfTrustError{errors.New("invalid ME operation mode")}
	}

	// Check manufacturing mode is not enabled.
	if regs.Hfsts1&hfsts1MfgMode > 0 {
		return &NoHardwareRootOfTrustError{errors.New("ME is in manufacturing mode")}
	}

	// Check that the BootGuard ACM is active. Fwupd only checks this for CSME #18, but it
	// appears that the same bits are defined for both versions.
	if regs.Hfsts5&(hfsts5BtgAcmActive|hfsts5BtgAcmDone) != hfsts5BtgAcmActive|hfsts5BtgAcmDone {
		return &NoHardwareRootOfTrustError{errors.New("BootGuard ACM is not active")}
	}

	// Check that the FPFs are locked.
	if regs.Hfsts6&hfsts6FPFSOCLock == 0 {
		return &NoHardwareRootOfTrustError{errors.New("BootGuard OTP fuses are not locked")}
	}

	if vers.Major < 18 {
		return checkHostSecurityIntelBootGuardCSME11(toHfstsRegistersCsme11(regs))
	}

	return checkHostSecurityIntelBootGuardCSME18(toHfstsRegistersCsme18(regs))
}

const (
	ia32DebugInterfaceMSR = 0xc80

	ia32DebugEnable uint64 = 1 << 0
	ia32DebugLock   uint64 = 1 << 30
)

func checkHostSecurityIntelCPUDebuggingLocked(env internal_efi.HostEnvironmentAMD64) error {
	// Check for "Silicon Debug Interface", returned in bit 11 of %ecx when calling
	// cpuid with %eax=1.
	debugSupported := env.HasCPUIDFeature(cpuid.SDBG)
	if !debugSupported {
		return nil
	}

	vals, err := env.ReadMSRs(ia32DebugInterfaceMSR)
	switch {
	case errors.Is(err, internal_efi.ErrNoKernelMSRSupport):
		return MissingKernelModuleError("msr")
	case err != nil:
		return fmt.Errorf("cannot read MSRs: %w", err)
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
