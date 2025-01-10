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
	"errors"
	"testing"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/ppi"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2_device"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

const (
	// TPMFeatureOwnerHierarchy indicates that the test requires the use of the storage hierarchy. The
	// authorization value should be empty at the start of the test.
	TPMFeatureOwnerHierarchy = tpm2_testutil.TPMFeatureOwnerHierarchy

	// TPMFeatureEndorsementHierarchy indicates that the test requires the use of the endorsement hierarchy.
	// The authorization value should be empty at the start of the test.
	TPMFeatureEndorsementHierarchy = tpm2_testutil.TPMFeatureEndorsementHierarchy

	// TPMFeatureLockoutHierarchy indicates that the test requires the use of the lockout hierarchy. The
	// authorization value should be empty at the start of the test.
	TPMFeatureLockoutHierarchy = tpm2_testutil.TPMFeatureLockoutHierarchy

	// TPMFeaturePlatformHierarchy indicates that the test requires the use of the platform hierarchy. The
	// authorization value should be empty at the start of the test.
	// In order to maximize the number of tests that can run on a real TPM, this should be used
	// sparingly as the platform hierarchy should not normally be available - it may be needed in some
	// cases just to make the test fixture happy, but these tests will generally only run on a simulator.
	TPMFeaturePlatformHierarchy = tpm2_testutil.TPMFeaturePlatformHierarchy

	// TPMFeaturePCR indicates that the test requires the use of a PCR. This is only required for
	// commands that require authorization - ie, it is not required for TPM2_PCR_Read.
	// Tests that use this should only use it for PCR16 or PCR23 - defined as debug /
	// application-specific and resettable on PC-Client TPMs, and should avoid using it for any
	// other PCR.
	TPMFeaturePCR = tpm2_testutil.TPMFeaturePCR

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
	TPMFeatureNV = tpm2_testutil.TPMFeatureNV

	//TPMFeaturePersistent		= tpm2_testutil.TPMFeaturePersistent
)

// MockDefaultDeviceFn overrides the tpm2_device.DefaultDevice function, used
// to obtain the default TPM device.
func MockDefaultDeviceFn(fn func(tpm2_device.DeviceMode) (tpm2_device.TPMDevice, error)) (restore func()) {
	orig := tpm2_device.DefaultDevice
	tpm2_device.DefaultDevice = fn
	return func() {
		tpm2_device.DefaultDevice = orig
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

type testTpmDevice struct {
	tpm2.TPMDevice
}

func newTestTpmDevice(dev tpm2.TPMDevice) *testTpmDevice {
	return &testTpmDevice{TPMDevice: dev}
}

func (d *testTpmDevice) Open() (tpm2.Transport, error) {
	transport, err := d.TPMDevice.Open()
	if err != nil {
		return nil, err
	}
	testTransport, ok := transport.(*tpm2_testutil.Transport)
	if !ok {
		return nil, errors.New("expected a tpm2_testutil.Transport")
	}
	return WrapTransport(testTransport), nil
}

type tpmDevice struct {
	tpm2.TPMDevice
	mode   tpm2_device.DeviceMode
	ppi    ppi.PPI
	ppiErr error
}

func newTpmDevice(dev tpm2.TPMDevice, mode tpm2_device.DeviceMode, ppi ppi.PPI, ppiErr error) *tpmDevice {
	return &tpmDevice{
		TPMDevice: dev,
		mode:      mode,
		ppi:       ppi,
		ppiErr:    ppiErr,
	}
}

func (d *tpmDevice) Mode() tpm2_device.DeviceMode {
	return d.mode
}

func (d *tpmDevice) PPI() (ppi.PPI, error) {
	return d.ppi, d.ppiErr
}

func openTPMDevice(dev tpm2.TPMDevice, ppi ppi.PPI, ppiErr error) (tpm *secboot_tpm2.Connection, err error) {
	restore := MockDefaultDeviceFn(func(mode tpm2_device.DeviceMode) (tpm2_device.TPMDevice, error) {
		if mode != tpm2_device.DeviceModeDirect {
			// TODO: Support other modes here
			return nil, errors.New("unexpected mode")
		}
		if ppi == nil && ppiErr == nil {
			ppiErr = tpm2_device.ErrNoPPI
		}
		return newTpmDevice(newTestTpmDevice(dev), mode, ppi, ppiErr), nil
	})
	defer restore()

	tpm, err = secboot_tpm2.ConnectToDefaultTPM()
	if err != nil {
		return nil, err
	}

	return tpm, nil
}

func OpenTPMDevice(c *C, dev tpm2.TPMDevice, ppi ppi.PPI, ppiErr error) (tpm *secboot_tpm2.Connection, transport *Transport) {
	tpm, err := openTPMDevice(dev, ppi, ppiErr)
	if errors.Is(err, tpm2_testutil.ErrSkipNoTPM) {
		c.Skip("no TPM available for the test")
	}
	c.Assert(err, IsNil)
	c.Assert(tpm.Transport(), testutil.ConvertibleTo, &Transport{})

	return tpm, tpm.Transport().(*Transport)
}

func OpenTPMDeviceT(t *testing.T, dev tpm2.TPMDevice, ppi ppi.PPI, ppiErr error) (tpm *secboot_tpm2.Connection, transport *Transport, close func()) {
	tpm, err := openTPMDevice(dev, ppi, ppiErr)
	if errors.Is(err, tpm2_testutil.ErrSkipNoTPM) {
		t.SkipNow()
	}
	if err != nil {
		t.Fatalf("%v", err)
	}

	transport, ok := tpm.Transport().(*Transport)
	if !ok {
		t.Fatal("unexpected transport type")
	}

	return tpm, transport, func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("close failed: %v", err)
		}
	}
}

// OpenDefaultTPMSimulatorConnection returns a new TPM connection to the TPM simulator on
// the port specified by tpm2_testutil.MssimPort. If tpm2_testutil.TPMBackend is
// not TPMBackendMssim then the test will be skipped.
//
// The returned connection must be closed when it is no longer required.
func OpenDefaultTPMSimulatorConnection(c *C) (tpm *secboot_tpm2.Connection, transport *Transport) {
	// TODO: Support supplying a ppi.PPI implementation that can be tested.
	return OpenTPMDevice(c, tpm2_testutil.NewSimulatorDevice(), nil, nil)
}

// OpenDefaultTPMSimulatorConnectionT returns a new TPM connection to the TPM simulator
// on the port specified by tpm2_testutil.MssimPort. If tpm2_testutil.TPMBackend is
// not TPMBackendMssim then the test will be skipped.
//
// The returned connection must be closed when it is no longer required. This can
// be done with the returned close callback, which will cause the test to fail if
// closing doesn't succeed.
func OpenDefaultTPMSimulatorConnectionT(t *testing.T) (tpm *secboot_tpm2.Connection, transport *Transport, close func()) {
	// TODO: Support supplying a ppi.PPI implementation that can be tested.
	return OpenTPMDeviceT(t, tpm2_testutil.NewSimulatorDevice(), nil, nil)
}

// OpenDefaultTPMConnection returns a new TPM connection for testing. If tpm2_testutil.TPMBackend
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
func OpenDefaultTPMConnection(c *C, features tpm2_testutil.TPMFeatureFlags) (tpm *secboot_tpm2.Connection, transport *Transport) {
	// TODO: Support supplying a ppi.PPI implementation that can be tested.
	return OpenTPMDevice(c, tpm2_testutil.NewDevice(c, features), nil, nil)
}

// OpenDefaultTPMConnectionT returns a new TPM connection for testing. If tpm2_testutil.TPMBackend
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
func OpenDefaultTPMConnectionT(t *testing.T, features tpm2_testutil.TPMFeatureFlags) (tpm *secboot_tpm2.Connection, transport *Transport, close func()) {
	// TODO: Support supplying a ppi.PPI implementation that can be tested.
	return OpenTPMDeviceT(t, tpm2_testutil.NewDeviceT(t, features), nil, nil)
}

func newTPMConnectionFromExistingTransport(tpm *secboot_tpm2.Connection, transport *Transport) (*secboot_tpm2.Connection, *Transport, error) {
	// Wrap the supplied transport in a TPMDevice.
	dev := tpm2_testutil.NewTransportPassthroughDevice(transport.Unwrap())

	if tpm != nil {
		// A TPM Connection was supplied. Pretend to close the existing connection,
		// which flushes the HMAC session associated with it. This will close the
		// test transport, but we keep the underlying transport open.
		if transport != tpm.Transport() {
			return nil, nil, errors.New("invalid transport")
		}
		// Pretend to close the existing connection, which flushes
		// the HMAC session associated with it.
		transport.SetKeepOpen(true)

		if err := tpm.Close(); err != nil {
			return nil, nil, err
		}

		// Create another device based on the same underlying transport.
		dev = tpm2_testutil.NewTransportPassthroughDevice(transport.Unwrap())
	}

	restore := MockDefaultDeviceFn(func(mode tpm2_device.DeviceMode) (tpm2_device.TPMDevice, error) {
		return newTpmDevice(newTestTpmDevice(dev), mode, nil, tpm2_device.ErrNoPPI), nil
	})
	defer restore()

	// Create a new connection using the existing transport.
	tpm, err := secboot_tpm2.ConnectToDefaultTPM()
	if err != nil {
		transport.Close()
	}
	return tpm, tpm.Transport().(*Transport), err
}

// NewTPMConnectionFromExistingT creates a new connection and TCTI from the
// supplied ones. This is useful in scenarios where test fixture setup and
// test execution require a different connection. The returned connection
// uses the same underlying connection as the one supplied. The supplied
// source connection does not need to be closed afterwards.
func NewTPMConnectionFromExistingTransportT(t *testing.T, tpm *secboot_tpm2.Connection, transport *Transport) (newTpm *secboot_tpm2.Connection, newTransport *Transport, close func()) {
	newTpm, newTransport, err := newTPMConnectionFromExistingTransport(tpm, transport)
	if err != nil {
		t.Fatal(err)
	}
	return newTpm, newTransport, func() {
		if err := newTpm.Close(); err != nil {
			t.Errorf("close failed: %v", err)
		}
	}
}

// ResetTPMSimulatorT issues a Shutdown -> Reset -> Startup cycle of the TPM
// simulator and returns a newly initialized TPM connection. The supplied
// source connection does not need to be closed afterwards.
func ResetTPMSimulatorT(t *testing.T, tpm *secboot_tpm2.Connection, transport *Transport) (newTpm *secboot_tpm2.Connection, newTransport *Transport, close func()) {
	tpm2_testutil.ResetTPMSimulatorT(t, tpm.TPMContext, transport.Unwrap().(*tpm2_testutil.Transport))
	return NewTPMConnectionFromExistingTransportT(t, tpm, transport)
}
