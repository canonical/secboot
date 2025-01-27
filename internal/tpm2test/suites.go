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
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tpm2_device"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

type tpmTestMixin struct {
	TPM            *secboot_tpm2.Connection
	Transport      *Transport
	mockConnection *secboot_tpm2.Connection // Unit tests always consume a connection, although this can be temporarily closed
}

func (m *tpmTestMixin) setUpTest(c *C, suite *tpm2_testutil.TPMTest, open func() (*secboot_tpm2.Connection, *Transport)) (cleanup func(*C)) {
	switch {
	case m.TPM != nil:
		// Allow the test to supply a secboot_tpm2.Connection via SetConnection
		c.Assert(m.Transport, NotNil)
		suite.TPM = m.TPM.TPMContext                                      // Copy the tpm2.TPMContext to the TPMTest suite
		suite.Transport = m.Transport.Unwrap().(*tpm2_testutil.Transport) // Copy the tpm2_testutil.Transport to the TPMTest suite
	case m.Transport != nil:
		// Allow the test to supply an existing transport, and create a connection from it
		tpm, _, err := newTPMConnectionFromExistingTransport(nil, m.Transport)
		c.Assert(err, IsNil)
		m.TPM = tpm
		suite.TPM = m.TPM.TPMContext                                      // Copy the tpm2.TPMContext to the TPMTest suite
		suite.Transport = m.Transport.Unwrap().(*tpm2_testutil.Transport) // Copy the tpm2_testutil.Transport to the TPMTest suite
	case suite.Device != nil:
		// Allow the test to supply a device, and create a connection from it
		tpm, transport := OpenTPMDevice(c, suite.Device, nil, nil)
		m.TPM = tpm
		m.Transport = transport
		suite.TPM = m.TPM.TPMContext                                      // Copy the tpm2.TPMContext to the TPMTest suite
		suite.Transport = m.Transport.Unwrap().(*tpm2_testutil.Transport) // Copy the tpm2_testutil.Transport to the TPMTest suite
	default:
		// The default case - open a default connection
		tpm, transport := open()
		m.TPM = tpm
		m.Transport = transport
		suite.TPM = m.TPM.TPMContext                                      // Copy the tpm2.TPMContext to the TPMTest suite
		suite.Transport = m.Transport.Unwrap().(*tpm2_testutil.Transport) // Copy the tpm2_testutil.Transport to the TPMTest suite
	}

	// Some tests execute code which calls secboot_tpm2.ConnectToDefaultTPM.
	// Allow this code to get a new secboot_tpm2.Connection using the
	// tests existing underlying connection, but don't allow the code
	// to fully close the connection - leave this to the test fixture.
	// TODO: Support resource managed device concepts in tests.
	internalDev := newTpmDevice(tpm2_testutil.NewTransportBackedDevice(suite.Transport, false, 1), tpm2_device.DeviceModeDirect, nil, tpm2_device.ErrNoPPI)
	restoreDefaultDeviceFn := MockDefaultDeviceFn(func(mode tpm2_device.DeviceMode) (tpm2_device.TPMDevice, error) {
		c.Assert(mode, Equals, tpm2_device.DeviceModeDirect)
		return internalDev, nil
	})

	// Unit tests always consume a connection
	mockConn, err := secboot_tpm2.ConnectToDefaultTPM()
	c.Assert(err, IsNil)
	m.mockConnection = mockConn
	// This connection isn't going to be used, so don't take up a loaded session slot
	m.mockConnection.FlushContext(m.mockConnection.HmacSession())

	return func(c *C) {
		if m.mockConnection != nil {
			c.Check(m.mockConnection.Close(), IsNil)
		}
		restoreDefaultDeviceFn()
		c.Check(internalDev.TPMDevice.(*tpm2_testutil.TransportBackedDevice).NumberOpen(), Equals, 0)
		c.Check(m.TPM.Close(), IsNil)
		m.TPM = nil
		m.Transport = nil
	}
}

// CloseMockConnection closes a mock connection that is opened automatically in test
// setup via the mock device, but not exposed for use by testing. The connection mocks
// the behaviour of having already called ConnectToDefaultTPM for testing APIs that
// accept an already open connection. In order to test APIs that don't already accept
// an open connection, and open their own connection instead, the test should call this
// API to temporarily close the internal mock connection.
//
// This also context saves the HMAC session associated with the connection accessible
// via the TPM() accessor.
//
// It returns a callback to re-open the mock connection again, and restore the HMAC
// session that was context saved.
func (m *tpmTestMixin) CloseMockConnection(c *C) (restore func()) {
	c.Assert(m.mockConnection, NotNil)
	c.Check(m.mockConnection.Close(), IsNil)
	m.mockConnection = nil

	hmacSessionContext, err := m.TPM.ContextSave(m.TPM.HmacSession())
	c.Assert(err, IsNil)

	return func() {
		_, err := m.TPM.ContextLoad(hmacSessionContext)
		c.Assert(err, IsNil)

		mockConn, err := secboot_tpm2.ConnectToDefaultTPM()
		c.Assert(err, IsNil)
		m.mockConnection = mockConn
		// This connection isn't going to be used, so don't take up a loaded session slot
		m.mockConnection.FlushContext(m.mockConnection.HmacSession())
	}
}

func (m *tpmTestMixin) reinitTPMConnectionFromExisting(c *C, suite *tpm2_testutil.TPMTest) {
	tpm, transport, err := newTPMConnectionFromExistingTransport(m.TPM, m.Transport)
	c.Assert(err, IsNil)
	m.TPM = tpm
	m.Transport = transport
	suite.TPM = m.TPM.TPMContext                                      // Copy the tpm2.TPMContext to the TPMTest suite
	suite.Transport = m.Transport.Unwrap().(*tpm2_testutil.Transport) // Copy the tpm2_testutil.Transport to the TPMTest suite
	suite.TCTI = suite.Transport                                      // Fill the legacy member (this normally happens in tpm2_testutil.TPMTest.SetUpTest)
}

// TPMTest is a base test suite for all tests that require a TPM and are able to
// execute on a real TPM or a simulator. This test suite makes use of the test
// fixture from go-tpm2 which restores TPM state when the connection is closed
// at the end of a test.
type TPMTest struct {
	tpm2_testutil.TPMTest
	tpmTestMixin
}

// SetUpTest is called to set up the test fixture before each test. If
// SetConnection has not been called before this is called, a TPM connection will
// be created automatically. In this case, the TPMFeatures member should be set prior
// to calling SetUpTest in order to declare the features that the test will require.
// If the test requires any features that are not included in
// tpm2_testutil.PermittedTPMFeatures, the test will be skipped.
// If tpm2_testutil.TPMBackend is TPMBackendNone, then the test will be skipped.
//
// If SetConnection is called prior to calling SetUpTest, the supplied TPM connection
// will be used for the test.
//
// If the Device member is set prior to calling SetUpTest, a TPM connection and
// TPMContext is created using this.
//
// The TPM connection closed automatically when TearDownTest is called.
func (b *TPMTest) SetUpTest(c *C) {
	// Don't support setting these directly as it makes things
	// complicated.
	c.Assert(b.TPMTest.TPM, IsNil)
	c.Assert(b.TPMTest.Transport, IsNil)
	c.Assert(b.TPMTest.TCTI, IsNil)

	cleanup := b.setUpTest(c, &b.TPMTest, func() (*secboot_tpm2.Connection, *Transport) {
		return OpenDefaultTPMConnection(c, b.TPMFeatures)
	})

	b.TPMTest.SetUpTest(c)
	b.AddFixtureCleanup(func(c *C) {
		cleanup(c)
		b.TPMTest.TPM = nil
		b.TPMTest.TCTI = nil
		b.TPMTest.Transport = nil
		b.TPMTest.Device = nil
	})
}

// SetConnection can be called prior to SetUpTest in order to supply a
// TPM connection rather than having the fixture create one.
func (b *TPMTest) SetConnection(c *C, tpm *secboot_tpm2.Connection, transport *Transport) {
	b.tpmTestMixin.TPM = tpm
	b.tpmTestMixin.Transport = tpm.Transport().(*Transport)
	c.Assert(tpm.Transport(), Equals, transport)
}

func (b *TPMTest) TPM() *secboot_tpm2.Connection {
	return b.tpmTestMixin.TPM
}

func (b *TPMTest) Transport() *Transport {
	return b.tpmTestMixin.Transport
}

// ReinitTPMConnectionFromExisting recreates a new connection and TCTI
// from the existing ones. This is useful in scenarios where the fixture
// setup and test code should use a different connection.
func (b *TPMTest) ReinitTPMConnectionFromExisting(c *C) {
	b.reinitTPMConnectionFromExisting(c, &b.TPMTest)
}

// TPMSimulatorTest is a base test suite for all tests that require a TPM simulator.
// This test suite makes use of the test fixture from go-tpm2 which restores TPM
// state when the connection is closed at the end of a test.
type TPMSimulatorTest struct {
	tpm2_testutil.TPMSimulatorTest
	tpmTestMixin
}

// SetUpTest is called to set up the test fixture before each test. If
// SetConnection has not been called before this is called, a TPM simulator
// connection will be created automatically. If tpm2_testutil.TPMBackend is not
// TPMBackendMssim, then the test will be skipped.
//
// If SetConnection is called prior to calling SetUpTest, the supplied TPM connection
// will be used for the test.
//
// If the Device member is set prior to calling SetUpTest, a TPM connection and
// TPMContext is created using this.
//
// When TearDownTest is called, the TPM simulator is reset and cleared
// and the connection is closed.
func (b *TPMSimulatorTest) SetUpTest(c *C) {
	// Don't support setting these directly as it makes things
	// complicated.
	c.Assert(b.TPMTest.TPM, IsNil)
	c.Assert(b.TPMTest.Transport, IsNil)
	c.Assert(b.TPMTest.TCTI, IsNil)

	cleanup := b.setUpTest(c, &b.TPMTest, func() (*secboot_tpm2.Connection, *Transport) {
		return OpenDefaultTPMSimulatorConnection(c)
	})

	b.TPMSimulatorTest.SetUpTest(c)
	b.AddFixtureCleanup(func(c *C) {
		b.ResetAndClearTPMSimulatorUsingPlatformHierarchy(c)
		cleanup(c)
		b.TPMTest.TPM = nil
		b.TPMTest.TCTI = nil
		b.TPMTest.Transport = nil
		b.TPMTest.Device = nil
	})
}

// SetConnection can be called prior to SetUpTest in order to supply a
// TPM connection rather than having the fixture create one.
func (b *TPMSimulatorTest) SetConnection(c *C, tpm *secboot_tpm2.Connection, transport *Transport) {
	b.tpmTestMixin.TPM = tpm
	b.tpmTestMixin.Transport = transport
	c.Assert(tpm.Transport(), Equals, transport)
}

func (b *TPMSimulatorTest) TPM() *secboot_tpm2.Connection {
	return b.tpmTestMixin.TPM
}

func (b *TPMSimulatorTest) Transport() *Transport {
	return b.tpmTestMixin.Transport
}

// ReinitTPMConnectionFromExisting recreates a new connection and TCTI
// from the existing ones. This is useful in scenarios where the fixture
// setup and test code should use a different connection.
func (b *TPMSimulatorTest) ReinitTPMConnectionFromExisting(c *C) {
	b.reinitTPMConnectionFromExisting(c, &b.TPMTest)
}

// ResetTPMSimulator issues a Shutdown -> Reset -> Startup cycle of the TPM simulator and
// reinitializes the TPM connection.
func (b *TPMSimulatorTest) ResetTPMSimulator(c *C) {
	b.TPMSimulatorTest.ResetTPMSimulator(c)
	b.ReinitTPMConnectionFromExisting(c)
}

// ResetAndClearTPMSimulatorUsingPlatformHierarchy issues a Shutdown -> Reset ->
// Startup cycle of the TPM simulator which ensures that the platform hierarchy is
// enabled, reinitializes the TPM connection, enables the TPM2_Clear command and
// clears the TPM using the platform hierarchy.
func (b *TPMSimulatorTest) ResetAndClearTPMSimulatorUsingPlatformHierarchy(c *C) {
	b.ResetTPMSimulator(c)
	b.ClearTPMUsingPlatformHierarchy(c)
}
