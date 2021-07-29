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
	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

type tpmTestMixin struct {
	TPM  *secboot_tpm2.Connection
	TCTI *TCTI
}

func (m *tpmTestMixin) setUpTest(c *C, open func() (*secboot_tpm2.Connection, *TCTI)) (cleanup func(*C)) {
	// Some tests execute code which calls secboot_tpm2.ConnectToTPM.
	// Allow this code to get a new secboot_tpm2.Connection using the
	// tests existing underlying connection, but don't allow the code
	// to fully close the connection - leave this to the test fixture.
	restoreOpenDefaultTcti := MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		tcti := WrapTCTI(m.TCTI.Unwrap().(*tpm2_testutil.TCTI))
		tcti.SetKeepOpen(true)
		return tcti, nil
	})

	switch {
	case m.TPM != nil:
		// Allow the test to supply a secboot_tpm2.Connection
		c.Assert(m.TCTI, NotNil)
	case m.TCTI != nil:
		// Allow the test to supply an existing connection
		tpm, tcti, err := newTPMConnectionFromExisting(nil, m.TCTI)
		c.Assert(err, IsNil)
		m.TPM = tpm
		m.TCTI = tcti
	default:
		m.TPM, m.TCTI = open()
	}

	return func(c *C) {
		restoreOpenDefaultTcti()
		c.Check(m.TPM.Close(), IsNil)
		m.TCTI = nil
		m.TPM = nil
	}
}

func (m *tpmTestMixin) reinitTPMConnectionFromExisting(c *C) {
	tpm, tcti, err := newTPMConnectionFromExisting(m.TPM, m.TCTI)
	c.Assert(err, IsNil)
	m.TPM = tpm
	m.TCTI = tcti
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
// SetConnection has not been called before this is called, a TPM connection
// will be created automatically. In this case, the TPMFeatures member should
// be set prior to calling SetUpTest in order to declare the features that
// the test will require. If the test requires any features that are not included
// in tpm2_testutil.PermittedTPMFeatures, the test will be skipped. If
// tpm2_testutil.TPMBackend is TPMBackendNone, then the test will be skipped.
//
// If SetConnection has been called with a test provided TCTI, then a connection
// will be created from this.
//
// The TPM connection closed automatically when TearDownTest is called.
func (b *TPMTest) SetUpTest(c *C) {
	// Don't support setting these directly as it makes things
	// complicated.
	c.Assert(b.TPMTest.TPM, IsNil)
	c.Assert(b.TPMTest.TCTI, IsNil)

	cleanup := b.setUpTest(c, func() (*secboot_tpm2.Connection, *TCTI) {
		return OpenTPMConnection(c, b.TPMFeatures)
	})

	b.TPMTest.TPM = b.tpmTestMixin.TPM.TPMContext
	b.TPMTest.TCTI = b.tpmTestMixin.TCTI.Unwrap().(*tpm2_testutil.TCTI)

	b.TPMTest.SetUpTest(c)
	b.AddFixtureCleanup(func(c *C) {
		cleanup(c)
		b.TPMTest.TPM = nil
		b.TPMTest.TCTI = nil
	})
}

// SetConnection can be called prior to SetUpTest in order to supply a
// TPM connection rather than having the fixture create one.
func (b *TPMTest) SetConnection(tpm *secboot_tpm2.Connection, tcti *TCTI) {
	b.tpmTestMixin.TPM = tpm
	b.tpmTestMixin.TCTI = tcti
}

func (b *TPMTest) TPM() *secboot_tpm2.Connection {
	return b.tpmTestMixin.TPM
}

func (b *TPMTest) TCTI() *TCTI {
	return b.tpmTestMixin.TCTI
}

// ReinitTPMConnectionFromExisting recreates a new connection and TCTI
// from the existing ones. This is useful in scenarios where the fixture
// setup and test code should use a different connection.
func (b *TPMTest) ReinitTPMConnectionFromExisting(c *C) {
	b.reinitTPMConnectionFromExisting(c)
	b.TPMTest.TPM = b.tpmTestMixin.TPM.TPMContext
	b.TPMTest.TCTI = b.tpmTestMixin.TCTI.Unwrap().(*tpm2_testutil.TCTI)
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
// connection will be created automatically. If tpm2_testutil.TPMBackend is
// not TPMBackendMssim, then the test will be skipped.
//
// If SetConnection has been called with a test provided TCTI, then a connection
// will be created from this.
//
// When TearDownTest is called, the TPM simulator is reset and cleared
// and the connection is closed.
func (b *TPMSimulatorTest) SetUpTest(c *C) {
	// Don't support setting these directly as it makes things
	// complicated.
	c.Assert(b.TPMTest.TPM, IsNil)
	c.Assert(b.TPMTest.TCTI, IsNil)

	cleanup := b.setUpTest(c, func() (*secboot_tpm2.Connection, *TCTI) {
		return OpenTPMSimulatorConnection(c)
	})

	b.TPMTest.TPM = b.tpmTestMixin.TPM.TPMContext
	b.TPMTest.TCTI = b.tpmTestMixin.TCTI.Unwrap().(*tpm2_testutil.TCTI)

	b.TPMSimulatorTest.SetUpTest(c)
	b.AddFixtureCleanup(func(c *C) {
		b.ResetAndClearTPMSimulatorUsingPlatformHierarchy(c)
		cleanup(c)
		b.TPMTest.TPM = nil
		b.TPMTest.TCTI = nil
	})
}

// SetConnection can be called prior to SetUpTest in order to supply a
// TPM connection rather than having the fixture create one.
func (b *TPMSimulatorTest) SetConnection(tpm *secboot_tpm2.Connection, tcti *TCTI) {
	b.tpmTestMixin.TPM = tpm
	b.tpmTestMixin.TCTI = tcti
}

func (b *TPMSimulatorTest) TPM() *secboot_tpm2.Connection {
	return b.tpmTestMixin.TPM
}

func (b *TPMSimulatorTest) TCTI() *TCTI {
	return b.tpmTestMixin.TCTI
}

// ReinitTPMConnectionFromExisting recreates a new connection and TCTI
// from the existing ones. This is useful in scenarios where the fixture
// setup and test code should use a different connection.
func (b *TPMSimulatorTest) ReinitTPMConnectionFromExisting(c *C) {
	b.reinitTPMConnectionFromExisting(c)
	b.TPMTest.TPM = b.tpmTestMixin.TPM.TPMContext
	b.TPMTest.TCTI = b.tpmTestMixin.TCTI.Unwrap().(*tpm2_testutil.TCTI)
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
