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
	"fmt"

	"github.com/canonical/go-tpm2"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

const (
	pcClientClass uint32 = 0x00000001
)

// checkTPM2DeviceFlags are passed to openAndCheckTPM2Device
type checkTPM2DeviceFlags int

const (
	// checkTPM2DeviceInVM indicates that the current environment is a
	// virtual machine.
	checkTPM2DeviceInVM checkTPM2DeviceFlags = 1 << iota

	// checkTPM2DevicePostInstall indicates that this function is being
	// executed post-install as opposed to pre-install.
	checkTPM2DevicePostInstall
)

// openAndCheckTPM2Device opens the default TPM device for the associated environment and
// performs some checks on it. It returns an open TPMContext and whether the TPM is a discrete
// TPM if these checks are successful. This may return some errors immediately, where those
// errors can't be resolved or prevent further use of the TPM. For errors that can be resolved
// and don't prevent further use of the TPM, the errors will be returned wrapped in [joinError].
func openAndCheckTPM2Device(env internal_efi.HostEnvironment, flags checkTPM2DeviceFlags) (tpm *tpm2.TPMContext, discreteTPM bool, err error) {
	// Get a device from the supplied environment
	device, err := env.TPMDevice()
	if err != nil {
		return nil, false, err
	}

	// Open it!
	tpm, err = tpm2.OpenTPMDevice(device)
	if err != nil {
		return nil, false, fmt.Errorf("cannot open TPM device: %w", err)
	}
	savedTpm := tpm
	defer func() {
		// Make sure it gets closed again if we return an error
		if err == nil {
			return
		}
		savedTpm.Close()
	}()

	// Make sure that the TPM is not in failure mode, else the following GetCapability calls
	// will fail due to the wrong property being returned (TPM2_GetCapability is usable in
	// failure mode, but only to fetch information about the manufacturer, firmware version
	// and vendor information, and it may round up the supplied property to match one of these).
	// In addition to using TPM2_GetCapability to fetch this limited set of properties, only
	// the TPM2_GetTestResult command is usable when the TPM is in failure mode.
	// Trigger a self test of untested functionality (note that the platform firmware might
	// have already done this, which is good because it will mean there's nothing to test).
	//
	// The reference library spec says that TPM2_SelfTest implementations can either run tests
	// synchronously - returning the result directly, or can run tests in the background after the
	// command completes, with the results having to be fetched with TPM2_GetTestResult. It does
	// say that there are no PC-Client devices that implements TPM2_SelfTest(YES) using background
	// testing - the important detail is that this statement only applies to full self-tests, which
	// we aren't requesting here (and don't want to - we only want to test functionality that hasn't
	// been tested yet). For now, we'll assume that the same statement applies also to
	// TPM2_SelfTest(NO) (there's no good reason why an implementation would implement both cases
	// differently) and only support the case where it runs the tests synchronously - we can
	// uncomment the other path later on if we come across implementations that need it, perhaps
	// with some sort of timeout.
	err = tpm.SelfTest(false)
	switch {
	//case tpm2.IsTPMWarning(err, tpm2.WarningTesting, tpm2.CommandSelfTest):
	// This is an implementation that performs the remaining self tests after the
	// command completes. We need to wait around to get a test result. Poll it every
	// 100ms.
	// XXX(chrisccoulson): Uncomment this code path if needed, and the corresponding
	// tests:
	// - tpmSuite.TestOpenAndCheckTPM2DeviceGoodPreInstallNoVMInfiniteCountersDiscreteTPMWithBackgroundSelfTest
	// - tpmSuite.TestOpenAndCheckTPM2DeviceFailureModeBackgroundTest
	// ... and remove this test:
	// - tpmSuite.TestOpenAndCheckTPM2DeviceWithBackgroundSelfTest
	//tick := time.NewTicker(100 * time.Millisecond)
	//for {
	//	_, rc, err := tpm.GetTestResult()
	//	if err != nil {
	//		return nil, false, fmt.Errorf("cannot obtain self test results: %w", err)
	//	}
	//	if rc == tpm2.ResponseSuccess {
	//		// All executed tests completed successfully.
	//		break
	//	}
	//	switch rc {
	//	case tpm2.ResponseFailure:
	//		// One or more tests failed and the TPM is now in failure mode.
	//		return nil, false, ErrTPMFailure
	//	case tpm2.ResponseTesting:
	//		// The tests are still running. We need to wait for a bit and
	//		// then try again.
	//	default:
	//		return nil, false, fmt.Errorf("unexpected self test result: %#x", rc)
	//	}
	//	<-tick.C
	//}
	case tpm2.IsTPMError(err, tpm2.ErrorFailure, tpm2.CommandSelfTest):
		// Either previously executed tests failed, or this is an implementation that
		// runs the remaining self tests before the command completes, and one or more
		// of them failed. In any case, the TPM is in failure mode.
		return nil, false, ErrTPMFailure
	case err != nil:
		return nil, false, fmt.Errorf("cannot perform partial self test: %w", err)
	default:
		// This is either an implementation that performs the self tests before the
		// command completes, and everything tested is ok, or all tests have already
		// been performed successfully.
	}

	// Make sure that the TPM is enabled. The firmware disables the TPM by disabling the
	// storage and endorsement hierarchies. Of course, user-space can do this as well, although
	// it requires a TPM reset to restore them anyway.
	sc, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyStartupClear)
	if err != nil {
		return nil, false, fmt.Errorf("cannot obtain value for TPM_PT_STARTUP_CLEAR: %w", err)
	}
	const enabledMask = tpm2.AttrShEnable | tpm2.AttrEhEnable
	if tpm2.StartupClearAttributes(sc)&enabledMask != enabledMask {
		return nil, true, ErrTPMDisabled
	}

	// Check TPM2 device class. The class is associated with a TPM Profile (PTP) spec
	// which says a lot about the TPM such as mandatory commands, algorithms, PCR banks
	// and the minimum number of PCRs. In all honesty, we're only ever likely to see
	// PC-Client devices here because that's basically all that exists, but check anyway
	// just in case.
	psFamily, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyPSFamilyIndicator)
	if err != nil {
		return nil, false, fmt.Errorf("cannot obtain value for TPM_PT_PS_FAMILY_INDICATOR: %w", err)
	}
	if psFamily != pcClientClass {
		// swtpm sets TPM_PT_PS_FAMILY_INDICATOR to the same value as TPM_PT_FAMILY_INDICATOR,
		// which is incorrect - the latter is "2.0" in ASCII with a NULL terminator and is used
		// to indicate the major version of the TCG reference library supported by the TPM. The
		// former indicates the class, as described earlier, and is 0 in the reference
		// implementation and should be 1 for PC-Client. Permit this bug if we are running in a VM.
		if flags&checkTPM2DeviceInVM == 0 {
			// We're not in a VM, so expect the proper PC-Client value.
			return nil, false, ErrNoPCClientTPM
		}
		// In a VM, make sure that the value of TPM_PT_PS_FAMILY_INDICATOR == TPM_PT_FAMILY_INDICATOR.
		// I think that this is always the case, but we might need to add additional VM-specific quirks here.
		family, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyFamilyIndicator)
		if err != nil {
			return nil, false, fmt.Errorf("cannot obtain value for TPM_PT_FAMILY_INDICATOR: %w", err)
		}
		if family != psFamily {
			// This doesn't have the swtpm quirk, so we have no idea what sort of vTPM we have
			// at this point - just return an error because we aren't going to check for every
			// individual TPM feature.
			return nil, false, ErrNoPCClientTPM
		}
	}

	// Determine whether we have a discrete TPM.
	// This isn't exposed via the TPM device itself, but instead platforms seem to expose
	// this in a vendor specific manner.
	switch {
	case flags&checkTPM2DeviceInVM > 0:
		// We're in a VM. A vTPM is not discrete
		discreteTPM = false
	default:
		// On a physical device, by default we assume the TPM is discrete unless proven otherwise.
		amd64Env, err := env.AMD64()
		if err != nil {
			return nil, false, err
		}
		cpuVendor, err := determineCPUVendor(amd64Env)
		if err != nil {
			return nil, false, err
		}
		switch cpuVendor {
		case cpuVendorIntel:
			discreteTPM, err = checkIsTpmDiscreteIntel(amd64Env)
			if err != nil {
				return nil, false, err
			}
		default:
			return nil, false, fmt.Errorf("cannot determine TPM discreteness for CPU vendor %v", cpuVendor)
		}
	}

	if flags&checkTPM2DevicePostInstall == 0 {
		var errs []error

		// Perform some checks only during pre-install.
		perm, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
		if err != nil {
			return nil, false, fmt.Errorf("cannot obtain value for TPM_PT_PERMANENT: %w", err)
		}

		// First of all, make sure that the TPM isn't owned.
		ownedErr := new(TPM2OwnedHierarchiesError)

		// Make sure the lockout hierarchy auth value is not set.
		if tpm2.PermanentAttributes(perm)&tpm2.AttrLockoutAuthSet > 0 {
			ownedErr.addAuthValue(tpm2.HandleLockout)
		}

		// Make sure the owner hierarchy authorization value is not set.
		if tpm2.PermanentAttributes(perm)&(tpm2.AttrOwnerAuthSet) > 0 {
			ownedErr.addAuthValue(tpm2.HandleOwner)
		}

		// Make sure the endorsement hierarchy authorization value is not set.
		if tpm2.PermanentAttributes(perm)&(tpm2.AttrEndorsementAuthSet) > 0 {
			ownedErr.addAuthValue(tpm2.HandleEndorsement)
		}

		// Make sure that none of the hierarchies have an authorization policy.
		for _, handle := range []tpm2.Handle{tpm2.HandleLockout, tpm2.HandleOwner, tpm2.HandleEndorsement} {
			ta, err := tpm.GetCapabilityAuthPolicy(handle)
			if err != nil {
				return nil, false, fmt.Errorf("cannot determine if %v hierarchy has an authorization policy: %w", handle, err)
			}
			if ta.HashAlg != tpm2.HashAlgorithmNull {
				ownedErr.addAuthPolicy(handle)
			}
		}

		if !ownedErr.isEmpty() {
			errs = append(errs, ownedErr)
		}

		// Make sure that the DA lockout mode is not activated. This is easy to fix if the
		// authorization value for the lockout hierarchy is empty.
		if tpm2.PermanentAttributes(perm)&tpm2.AttrInLockout > 0 {
			errs = append(errs, ErrTPMLockout)
		}

		// Make sure we have enough NV counters for PCR policy revocation. We need at least 2
		// (1 normally, and an extra 1 during reprovision). The platform firmware may use up
		// some of the allocation.
		nvCountersMax, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyNVCountersMax)
		if err != nil {
			return nil, false, fmt.Errorf("cannot obtain value for TPM_NV_COUNTERS_MAX: %w", err)
		}
		if nvCountersMax > 0 {
			// If the TPM returns 0, there are no limits to the number of counters other than
			// available NV storage. If there are a finite number of counters, obtain the number
			// of active counters.
			nvCounters, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyNVCounters)
			if err != nil {
				return nil, false, fmt.Errorf("cannot obtain value for TPM_NV_COUNTERS_MAX: %w", err)
			}
			if (nvCountersMax - nvCounters) < 2 {
				errs = append(errs, ErrTPMInsufficientNVCounters)
			}
		}

		if len(errs) > 0 {
			return tpm, discreteTPM, joinErrors(errs...)
		}
	}

	return tpm, discreteTPM, nil
}
