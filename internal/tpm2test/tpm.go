// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2021 Canonical Ltd
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

package tpm2test

import (
	"testing"

	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/tcti"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

const (
	// TPMFeatureOwnerHierarchy indicates that the test requires the use of the storage hierarchy. The
	// authorization value should be empty at the start of the test.
	TPMFeatureOwnerHierarchy       = tpm2_testutil.TPMFeatureOwnerHierarchy

	// TPMFeatureEndorsementHierarchy indicates that the test requires the use of the endorsement hierarchy.
	// The authorization value should be empty at the start of the test.
	TPMFeatureEndorsementHierarchy = tpm2_testutil.TPMFeatureEndorsementHierarchy

	// TPMFeatureLockoutHierarchy indicates that the test requires the use of the lockout hierarchy. The
	// authorization value should be empty at the start of the test.
	TPMFeatureLockoutHierarchy     = tpm2_testutil.TPMFeatureLockoutHierarchy

	// TPMFeaturePlatformHierarchy indicates that the test requires the use of the platform hierarchy. The
	// authorization value should be empty at the start of the test.
	// In order to maximize the number of tests that can run on a real TPM, this should be used
	// sparingly as the platform hierarchy should not normally be available - it may be needed in some
	// cases just to make the test fixture happy, but these tests will generally only run on a simulator.
	TPMFeaturePlatformHierarchy    = tpm2_testutil.TPMFeaturePlatformHierarchy

	// TPMFeaturePCR indicates that the test requires the use of a PCR. This is only required for
	// commands that require authorization - ie, it is not required for TPM2_PCR_Read.
	// Tests that use this should only use it for PCR16 or PCR23 - defined as debug /
	// application-specific and resettable on PC-Client TPMs, and should avoid using it for any
	// other PCR.
	TPMFeaturePCR                  = tpm2_testutil.TPMFeaturePCR

	//TPMFeatureStClearChange = tpm2_testutil.TPMFeatureStClearChange
	//TPMFeatureSetCommandCodeAuditStatus = tpm2_testutil.TPMFeatureSetCommandCodeAuditStatus

	// TPMFeatureClear indicates that the test uses the TPM2_Clear command. This also requires either
	// TPMFeatureLockoutHierarchy or TPMFeaturePlatformHierarchy. This implies TPMFeatureNV for the
	// TPM2_Clear command.
	// In order to maximize the number of tests that are suitable for running on a real TPM, it
	// should be used sparingly.
	TPMFeatureClear = tpm2_testutil.TPMFeatureClear

	//TPMFeatureClearControl = tpm2_testutil.TPMFeatureClearControl
	//TPMFeatureShutdown = tpm2_testutil.TPMFeatureShutdown
	//TPMFeatureNVGlobalWriteLock = tpm2_testutil.TPMFeatureNVGlobalWriteLock
	//TPMFeatureDAProtectedCapability = tpm2_testutil.TPMFeatureDAProtectedCapability

	// TPMFeatureNV indicates that the test makes use of a command that may write to NV. Physical
	// TPMs may employ rate limiting on these commands.
	TPMFeatureNV                    = tpm2_testutil.TPMFeatureNV

	//TPMFeaturePersistent		= tpm2_testutil.TPMFeaturePersistent
)

// MockOpenDefaultTctiFn overrides the tcti.OpenDefault function, used
// to create a connection to the default TPM.
func MockOpenDefaultTctiFn(fn func() (tpm2.TCTI, error)) (restore func()) {
	origFn := tcti.OpenDefault
	tcti.OpenDefault = fn
	return func() {
		tcti.OpenDefault = origFn
	}
}

// MockEKTemplate overrides the tcg.EKTemplate variable, used to define
// the standard EK template.
func MockEKTemplate(mock *tpm2.Public) (restore func()) {
	orig := tcg.EKTemplate
	tcg.EKTemplate = mock
	return func() {
		tcg.EKTemplate = orig
	}
}

// OpenTPMSimulatorConnection returns a new TPM connection to the TPM simulator on
// the port specified by tpm2_testutil.MssimPort. If tpm2_testutil.TPMBackend is
// not TPMBackendMssim then the test will be skipped.
//
// The returned connection must be closed when it is no longer required.
func OpenTPMSimulatorConnection(c *C) (tpm *secboot_tpm2.Connection, tcti *TCTI) {
	tcti = WrapTCTI(tpm2_testutil.NewSimulatorTCTI(c))

	restore := MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return tcti, nil
	})
	defer restore()

	tpm, err := secboot_tpm2.ConnectToTPM()
	c.Assert(err, IsNil)

	return tpm, tcti
}

// OpenTPMSimulatorConnectionT returns a new TPM connection to the TPM simulator
// on the port specified by tpm2_testutil.MssimPort. If tpm2_testutil.TPMBackend is
// not TPMBackendMssim then the test will be skipped.
//
// The returned connection must be closed when it is no longer required. This can
// be done with the returned close callback, which will cause the test to fail if
// closing doesn't succeed.
func OpenTPMSimulatorConnectionT(t *testing.T) (tpm *secboot_tpm2.Connection, tcti *TCTI, close func()) {
	tcti = WrapTCTI(tpm2_testutil.NewSimulatorTCTIT(t))

	restore := MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return tcti, nil
	})
	defer restore()

	tpm, err := secboot_tpm2.ConnectToTPM()
	if err != nil {
		t.Fatalf("%v", err)
	}

	return tpm, tcti, func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("close failed: %v", err)
		}
	}
}

// OpenTPMConnection returns a new TPM connection for testing. If tpm2_testutil.TPMBackend
// is TPMBackendNone then the current test will be skipped. If tpm2_testutil.TPMBackend
// is TPMBackendMssim, the returned context will correspond to a connection to the TPM
// simulator on the port specified by the tpm2_testutil.MssimPort variable. If
// tpm2_testutil.TPMBackend is TPMBackendDevice, a TPM connection will be returned if
// the requested features are permitted, as defined by the tpm2_testutil.PermittedTPMFeatures
// variable. In this case, the connection will correspond to a connection to the Linux
// character device at the path specified by the tpm2_testutil.TPMDevicePath variable.
// If the test requires features that are not permitted, the test will be skipped.
//
// The returned connection must be closed when it is no longer required.
func OpenTPMConnection(c *C, features tpm2_testutil.TPMFeatureFlags) (tpm *secboot_tpm2.Connection, tcti *TCTI) {
	tcti = WrapTCTI(tpm2_testutil.NewTCTI(c, features))

	restore := MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return tcti, nil
	})
	defer restore()

	tpm, err := secboot_tpm2.ConnectToTPM()
	c.Assert(err, IsNil)

	return tpm, tcti
}

// OpenTPMConnectionT returns a new TPM connection for testing. If tpm2_testutil.TPMBackend
// is TPMBackendNone then the current test will be skipped. If tpm2_testutil.TPMBackend
// is TPMBackendMssim, the returned context will correspond to a connection to the TPM
// simulator on the port specified by the tpm2_testutil.MssimPort variable. If
// tpm2_testutil.TPMBackend is TPMBackendDevice, a TPM connection will be returned if
// the requested features are permitted, as defined by the tpm2_testutil.PermittedTPMFeatures
// variable. In this case, the connection will correspond to a connection to the Linux
// character device at the path specified by the tpm2_testutil.TPMDevicePath variable.
// If the test requires features that are not permitted, the test will be skipped.
//
// The returned connection must be closed when it is no longer required. This can be
// done with the returned close callback, which will cause the test to fail if closing
// doesn't succeed.
func OpenTPMConnectionT(t *testing.T, features tpm2_testutil.TPMFeatureFlags) (tpm *secboot_tpm2.Connection, tcti *TCTI, close func()) {
	tcti = WrapTCTI(tpm2_testutil.NewTCTIT(t, features))

	restore := MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return tcti, nil
	})
	defer restore()

	tpm, err := secboot_tpm2.ConnectToTPM()
	if err != nil {
		t.Fatalf("%v", err)
	}

	return tpm, tcti, func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("close failed: %v", err)
		}
	}
}

func newTPMConnectionFromExisting(tpm *secboot_tpm2.Connection, tcti *TCTI) (*secboot_tpm2.Connection, *TCTI, error) {
	if tpm != nil {
		// Pretend to close the existing connection, which flushes
		// the HMAC session associated with it.
		tcti.SetKeepOpen(true)

		if err := tpm.Close(); err != nil {
			return nil, nil, err
		}
	}

	// Create a new tcti, using the same underlyinhg connection.
	tcti = WrapTCTI(tcti.Unwrap().(*tpm2_testutil.TCTI))

	restore := MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return tcti, nil
	})
	defer restore()

	// Create a new connection.
	tpm, err := secboot_tpm2.ConnectToTPM()
	if err != nil {
		tcti.Close()
	}
	return tpm, tcti, err
}

// NewTPMConnectionFromExistingT creates a new connection and TCTI from the
// supplied ones. This is useful in scenarios where test fixture setup and
// test execution require a different connection. The returned connection
// uses the same underlying connection as the one supplied. The supplied
// source connection does not need to be closed afterwards.
func NewTPMConnectionFromExistingT(t *testing.T, tpm *secboot_tpm2.Connection, tcti *TCTI) (newTpm *secboot_tpm2.Connection, newTcti *TCTI, close func()) {
	tpm, tcti, err := newTPMConnectionFromExisting(tpm, tcti)
	if err != nil {
		t.Fatal(err)
	}
	return tpm, tcti, func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("close failed: %v", err)
		}
	}
}

// ResetTPMSimulatorT issues a Shutdown -> Reset -> Startup cycle of the TPM
// simulator and returns a newly initialized TPM connection. The supplied
// source connection does not need to be closed afterwards.
func ResetTPMSimulatorT(t *testing.T, tpm *secboot_tpm2.Connection, tcti *TCTI) (newTpm *secboot_tpm2.Connection, newTcti *TCTI, close func()) {
	tpm2_testutil.ResetTPMSimulatorT(t, tpm.TPMContext, tcti.Unwrap().(*tpm2_testutil.TCTI))
	return NewTPMConnectionFromExistingT(t, tpm, tcti)
}
