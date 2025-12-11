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
	"fmt"

	"github.com/canonical/go-tpm2"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

const (
	pcClientClass uint32 = 0x00000001
)

func checkTPM2ForRequiredPCClientFeatures(tpm *tpm2.TPMContext) (ok bool, err error) {
	// Check permanent properties.
	type cmpFn func(x, y uint32) bool
	var (
		cmpGE       = func(x, y uint32) bool { return x >= y }
		cmpGEOrZero = func(x, y uint32) bool {
			if x == 0 {
				return true
			}
			return x >= y
		}
	)

	for _, data := range [...]struct {
		prop     tpm2.Property
		expected uint32
		cmp      cmpFn
	}{
		{prop: tpm2.PropertyHRTransientMin, expected: 3, cmp: cmpGE},  // We use transient objects, so expect the PC-Client minimum
		{prop: tpm2.PropertyHRPersistentMin, expected: 7, cmp: cmpGE}, // We store persistent objects, so expect the PC-Client minimum
		{prop: tpm2.PropertyHRLoadedMin, expected: 3, cmp: cmpGE},     // We make use of multiple loaded sessions, so expect the PC-Client minimum
		{prop: tpm2.PropertyPCRCount, expected: 24, cmp: cmpGE},
		// If TPM2_PT_NV_COUNTERS_MAX is zero, then the either the number of NV
		// counters is only limited by the amount of NV storage space available,
		// or no NV counters are supported. In the latter case, this should be
		// caught by missing support for TPM_CC_NV_INCREMENT.
		{prop: tpm2.PropertyNVCountersMax, expected: 6, cmp: cmpGEOrZero},
	} {
		switch val, err := tpm.GetCapabilityTPMProperty(data.prop); {
		case err != nil:
			return false, fmt.Errorf("cannot obtain value of %v: %w", data.prop, err)
		case !data.cmp(val, data.expected):
			return false, nil
		}
	}

	// Check algorithms.
	for _, alg := range [...]tpm2.AlgorithmId{
		tpm2.AlgorithmRSA,            // Required for primary keys.
		tpm2.AlgorithmAES,            // Required for primary keys and parameter encryption.
		tpm2.AlgorithmKeyedHash,      // Required for sealed objects.
		tpm2.AlgorithmSHA256,         // Required for name algorithm and PCR banks.
		tpm2.AlgorithmOAEP,           // Required for parameter encryption.
		tpm2.AlgorithmECDSA,          // Required for PCR policy signatures.
		tpm2.AlgorithmKDF1_SP800_108, // Required for deriving session keys.
		tpm2.AlgorithmECC,            // Required for PCR policy signing keys.
		tpm2.AlgorithmCFB,            // Required for primary keys and parameter encryption.
	} {
		if !tpm.IsAlgorithmSupported(alg) {
			return false, nil
		}
	}

	// Check elliptic curves.
	if !tpm.IsECCCurveSupported(tpm2.ECCCurveNIST_P256) {
		return false, nil
	}

	// Check PCR attributes.
	for _, data := range []struct {
		prop     tpm2.PropertyPCR
		expected tpm2.PCRSelect
		required bool
	}{
		// All S-RTM PCRs should be saved on TPM2_Shutdown(STATE) so they can be restored on resume.
		{prop: tpm2.PropertyPCRSave, expected: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, required: true},

		// All S-RTM PCRs are extendable from locality 0.
		{prop: tpm2.PropertyPCRExtendL0, expected: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}, // won't be present if localities aren't supported.

		// No S-RTM PCRs are resettable from any locality.
		{prop: tpm2.PropertyPCRResetL0, expected: []int{}},   // won't be present if localities aren't supported.
		{prop: tpm2.PropertyPCRResetL1, expected: []int{}},   // won't be present if localities aren't supported.
		{prop: tpm2.PropertyPCRResetL2, expected: []int{}},   // won't be present if localities aren't supported.
		{prop: tpm2.PropertyPCRResetL3, expected: []int{}},   // won't be present if localities aren't supported.
		{prop: tpm2.PropertyPCRResetL4, expected: []int{}},   // won't be present if localities aren't supported.
		{prop: tpm2.PropertyPCRDRTMReset, expected: []int{}}, // optional feature.

		// Extending any S-RTM increments the PCR update counter.
		{prop: tpm2.PropertyPCRNoIncrement, expected: []int{}}, // optional feature.

		// No S-RTM PCR is part of a policy or auth group.
		{prop: tpm2.PropertyPCRPolicy, expected: []int{}}, // optional feature.
		{prop: tpm2.PropertyPCRAuth, expected: []int{}},   // optional feature.
	} {
		// XXX: TPMContext should have a GetCapabilityPCRProperty method (equivalent to
		// GetCapabilityTPMProperty, used above) which simplifies things here.
		switch props, err := tpm.GetCapabilityPCRProperties(data.prop, 1); {
		case err != nil:
			return false, fmt.Errorf("cannot obtain value of %v: %w", data.prop, err)
		case (len(props) < 1 || props[0].Tag != data.prop) && data.required:
			return false, fmt.Errorf("cannot obtain value of %v: missing property", data.prop)
		case len(props) < 1 || props[0].Tag != data.prop:
			// ok
		default:
			// Filter out PCRs not associated with the S-RTM from the result.
			var pcrs tpm2.PCRSelect
			for _, pcr := range props[0].Select {
				if pcr > 15 {
					continue
				}
				pcrs = append(pcrs, pcr)
			}

			expectedBitmap, err := data.expected.ToBitmap(0)
			if err != nil {
				// The PCR selection is hard-coded.
				panic(err)
			}
			bitmap, err := pcrs.ToBitmap(0)
			if err != nil {
				// This value was unmarshaled from a PCRSelectBitmap by
				// go-tpm2 and we've also pruned the PCRs so there's no
				// way this can fail.
				panic(err)
			}
			if !bytes.Equal(bitmap.Bytes, expectedBitmap.Bytes) {
				return false, nil
			}
		}
	}

	// Check commands.
	for _, command := range []tpm2.CommandCode{
		tpm2.CommandSelfTest,
		tpm2.CommandGetTestResult,
		tpm2.CommandStartAuthSession,
		tpm2.CommandCreate,
		tpm2.CommandLoad,
		tpm2.CommandLoadExternal,
		tpm2.CommandReadPublic,
		tpm2.CommandUnseal,
		tpm2.CommandObjectChangeAuth,
		tpm2.CommandImport,
		tpm2.CommandHashSequenceStart,
		tpm2.CommandSequenceUpdate,
		tpm2.CommandEventSequenceComplete,
		tpm2.CommandVerifySignature,
		tpm2.CommandPCRRead,
		tpm2.CommandPolicySigned,
		tpm2.CommandPolicySecret,
		tpm2.CommandPolicyOR,
		tpm2.CommandPolicyPCR,
		tpm2.CommandPolicyNV,
		tpm2.CommandPolicyCommandCode,
		tpm2.CommandPolicyAuthorize,
		tpm2.CommandPolicyAuthValue,
		tpm2.CommandPolicyGetDigest,
		tpm2.CommandPolicyNvWritten,
		tpm2.CommandCreatePrimary,
		tpm2.CommandClear,
		tpm2.CommandClearControl,
		tpm2.CommandHierarchyChangeAuth,
		tpm2.CommandDictionaryAttackLockReset,
		tpm2.CommandDictionaryAttackParameters,
		tpm2.CommandContextSave,
		tpm2.CommandContextLoad,
		tpm2.CommandFlushContext,
		tpm2.CommandEvictControl,
		tpm2.CommandGetCapability,
		tpm2.CommandNVDefineSpace,
		tpm2.CommandNVUndefineSpace,
		tpm2.CommandNVReadPublic,
		tpm2.CommandNVWrite,
		tpm2.CommandNVIncrement,
		tpm2.CommandNVWriteLock,
		tpm2.CommandNVRead,
	} {
		if !tpm.IsCommandSupported(command) {
			return false, nil
		}
	}

	// XXX: We can't check NV storage size, but we don't check that in the normal case either.
	return true, nil
}

// checkTPM2DeviceFlags are passed to openAndCheckTPM2Device
type checkTPM2DeviceFlags int

const (
	// checkTPM2DevicePostInstall indicates that this function is being
	// executed post-install as opposed to pre-install.
	checkTPM2DevicePostInstall = 1 << iota
)

// openAndCheckTPM2Device opens the default TPM device for the associated environment and
// performs some checks on it. It returns an open TPMContext and whether the TPM is a discrete
// TPM if these checks are successful. This may return some errors immediately, where those
// errors can't be resolved or prevent further use of the TPM. For errors that can be resolved
// and don't prevent further use of the TPM, the errors will be returned wrapped in a type
// that implements [CompoundError].
func openAndCheckTPM2Device(env internal_efi.HostEnvironment, flags checkTPM2DeviceFlags) (tpm *tpm2.TPMContext, err error) {
	// Open the device from the supplied environment.
	tpm, err = openTPMDevice(env)
	if err != nil {
		return nil, fmt.Errorf("cannot open TPM device: %w", err)
	}
	savedTpm := tpm
	defer func() {
		// Make sure it gets closed again if we return an error and no TPM context.
		if tpm != nil {
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
		return nil, ErrTPMFailure
	case err != nil:
		return nil, fmt.Errorf("cannot perform partial self test: %w", err)
	default:
		// This is either an implementation that performs the self tests before the
		// command completes, and everything tested is ok, or all tests have already
		// been performed successfully.
	}

	// Check that the TPM2 device class is TPM_PS_PC (0x1). We can then make assumptions about
	// the supported features (such as mandatory commands, algorithms, PCR banks etc) based on
	// the TPM PC Client Platform TPM Profile (PTP) spec. In all honesty, we're only ever likely
	// to see PC-Client devices here because that's basically all that exists, but check anyway
	// just in case.
	switch psFamily, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyPSFamilyIndicator); {
	case err != nil:
		return nil, fmt.Errorf("cannot obtain value for TPM_PT_PS_FAMILY_INDICATOR: %w", err)
	case psFamily != pcClientClass:
		// Some devices return TPM_PS_PDA (0x2) here, and there doesn't seem to be a corresponding
		// PTP spec. Also, swtpm sets TPM_PT_PS_FAMILY_INDICATOR to the same value as
		// TPM_PT_FAMILY_INDICATOR, which is the major version of the TCG reference library
		// supported by the TPM ("2.0"). For these cases, perform feature detection instead.
		switch ok, err := checkTPM2ForRequiredPCClientFeatures(tpm); {
		case err != nil:
			return nil, fmt.Errorf("cannot check TPM2 device for required PC-Client features: %w", err)
		case !ok:
			return nil, ErrNoPCClientTPM
		default:
			// This TPM has the required features.
		}
	default:
		// This is a PC-Client TPM.
	}

	// Make sure that the TPM is enabled. The firmware disables the TPM by disabling the
	// storage and endorsement hierarchies. Of course, user-space can do this as well, although
	// it requires a TPM reset to restore them anyway.
	sc, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyStartupClear)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain value for TPM_PT_STARTUP_CLEAR: %w", err)
	}
	const enabledMask = tpm2.AttrShEnable | tpm2.AttrEhEnable
	if tpm2.StartupClearAttributes(sc)&enabledMask != enabledMask {
		return nil, ErrTPMDisabled
	}

	// Some errors from this point may be collected and returned together.
	var errs []error

	// Obtain the permanent attributes from the TPM.
	perm, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain value for TPM_PT_PERMANENT: %w", err)
	}

	switch {
	case tpm2.PermanentAttributes(perm)&tpm2.AttrLockoutAuthSet == 0:
		// If the lockout hierarchy has no authorization value, check if it is available. We do
		// this by attempting to use it with an empty authorization value. There is no other way to
		// figure this out other than by using it.
		//
		// As we test the lockout hierarchy with TPM2_DictionaryAttackLockReset, this may have the
		// side effect of clearing a DA lockout.
		tpm.LockoutHandleContext().SetAuthValue(nil)
		err := tpm.DictionaryAttackLockReset(tpm.LockoutHandleContext(), nil)
		switch {
		case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandDictionaryAttackLockReset):
			// The lockout hierarchy is unavailable because it is locked out, either for what is
			// remaining of the pre-programmed lockoutRecovery time, or until the TPM is cleared
			// using the platform auth.
			errs = append(errs, ErrTPMLockoutLockedOut)
		case err != nil:
			return nil, fmt.Errorf("cannot test usage of TPM_RH_LOCKOUT: %w", err)
		case tpm2.PermanentAttributes(perm)&tpm2.AttrInLockout > 0:
			// The lockout hierarchy is available and TPM2_DictionaryAttackLockReset completed
			// successfully. As the DA lockout had previously been activated, obtain the
			// permanent attributes from the TPM again in case it has been cleared. It may not
			// have been cleared in the case where the maxTries DA setting is zero.
			perm, err = tpm.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
			if err != nil {
				return nil, fmt.Errorf("cannot refresh value for TPM_PT_PERMANENT: %w", err)
			}
		default:
			// The lockout hierarchy is available and TPM2_DictionaryAttackLockReset completed
			// successfully. There was no DA lockout previously activated, so there's nothing
			// else to do.
		}
	default:
		// The lockout hierarchy has an authorization value set, so add an error indicating that
		// we couldn't test if the hierarchy is available.
		// TODO: Update the public API to accept the authorization value for post-install tests.
		errs = append(errs, ErrTPMLockoutAvailabilityNotChecked)
	}

	// Make sure that the DA lockout mode is not activated.
	if tpm2.PermanentAttributes(perm)&tpm2.AttrInLockout > 0 {
		errs = append(errs, ErrTPMLockout)
	}

	if flags&checkTPM2DevicePostInstall == 0 {
		// Perform some checks only during pre-install.

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
				return nil, fmt.Errorf("cannot determine if %v hierarchy has an authorization policy: %w", handle, err)
			}
			if ta.HashAlg != tpm2.HashAlgorithmNull {
				ownedErr.addAuthPolicy(handle)
			}
		}

		if !ownedErr.isEmpty() {
			errs = append(errs, ownedErr)
		}

		// Make sure we have enough NV counters for PCR policy revocation. We need at least 2
		// (1 normally, and an extra 1 during reprovision). The platform firmware may use up
		// some of the allocation.
		nvCountersMax, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyNVCountersMax)
		if err != nil {
			return nil, fmt.Errorf("cannot obtain value for TPM_NV_COUNTERS_MAX: %w", err)
		}
		if nvCountersMax > 0 {
			// If the TPM returns 0, there are no limits to the number of counters other than
			// available NV storage. If there are a finite number of counters, obtain the number
			// of active counters.
			nvCounters, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyNVCounters)
			if err != nil {
				return nil, fmt.Errorf("cannot obtain value for TPM_NV_COUNTERS_MAX: %w", err)
			}
			if (nvCountersMax - nvCounters) < 2 {
				errs = append(errs, ErrTPMInsufficientNVCounters)
			}
		}
	}

	if len(errs) > 0 {
		return tpm, joinErrors(errs...)
	}

	return tpm, nil
}
