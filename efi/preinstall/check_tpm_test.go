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

package preinstall_test

import (
	"bytes"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type tpmPropertyModifierMixin struct {
	transport *tpm2_testutil.Transport
}

// addTPMPropertyModifiers permits the test to run with well-known property values
func (m *tpmPropertyModifierMixin) addTPMPropertyModifiers(c *C, overrides map[tpm2.Property]uint32) {
	m.transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandles tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
		// Check we have the right command code
		if cmdCode != tpm2.CommandGetCapability {
			return
		}
		// TPM2_GetCapability has no command handles
		c.Assert(cmdHandles, HasLen, 0)

		// Test the command parameters
		var capability tpm2.Capability
		var property uint32
		var propertyCount uint32
		_, err := mu.UnmarshalFromBytes(cpBytes, &capability, &property, &propertyCount)
		c.Assert(err, IsNil)
		if capability != tpm2.CapabilityTPMProperties {
			return
		}

		// Unpack the response
		rc, rpBytes, rAuthArea, err := tpm2.ReadResponsePacket(rsp, nil)
		c.Assert(err, IsNil)
		if rc != tpm2.ResponseSuccess {
			// Do nothing if the TPM didn't return success
			return
		}

		// Unpack the response parameters
		var moreData bool
		var capabilityData *tpm2.CapabilityData
		_, err = mu.UnmarshalFromBytes(rpBytes, &moreData, &capabilityData)
		c.Assert(err, IsNil)
		c.Assert(capabilityData.Capability, Equals, tpm2.CapabilityTPMProperties)

		// Override the response parameters
		for i := range capabilityData.Data.TPMProperties {
			newValue, exists := overrides[capabilityData.Data.TPMProperties[i].Property]
			if !exists {
				continue
			}
			capabilityData.Data.TPMProperties[i].Value = newValue
		}

		// Repack the response parameters
		rpBytes = mu.MustMarshalToBytes(moreData, capabilityData)

		// Repack the response
		rsp.Reset()
		c.Check(tpm2.WriteResponsePacket(rsp, rc, nil, rpBytes, rAuthArea), IsNil)
	}
}

type tpmSuite struct {
	tpm2_testutil.TPMSimulatorTest
	tpmPropertyModifierMixin
}

func (s *tpmSuite) SetUpTest(c *C) {
	s.TPMSimulatorTest.SetUpTest(c)
	s.tpmPropertyModifierMixin.transport = s.Transport
}

var _ = Suite(&tpmSuite{})

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPreInstallNoVMInfiniteCountersDiscreteTPM(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsTrue)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPreInstallNoVMInfiniteCountersFWTPM(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsFalse)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPreInstallNoVMFiniteCountersDiscreteTPM(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        4,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsTrue)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallNoVMCountersCheckSkippedDiscreteTPM(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        5,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsTrue)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPreInstallVMInfiniteCounters(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerMSFT),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, CheckTPM2DeviceInVM)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsFalse)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallNoVMLockoutCheckSkipped(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        4,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Trip the DA logic by setting newMaxTries to 0
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 10000, 10000, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsFalse)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallNoVMLockoutOwnedCheckSkipped(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the lockout hierarchy auth value.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.LockoutHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsFalse)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallNoVMOwnerOwnedCheckSkipped(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the owner hierarchy auth value.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsFalse)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallNoVMEndorsmentOwnedCheckSkipped(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the endorsement hierarchy auth value.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.EndorsementHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsFalse)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceNoTPM(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrNoTPM2Device)
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceDisabled(c *C) {
	// Disable owner and endorsement hierarchies
	c.Assert(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
	c.Assert(s.TPM.HierarchyControl(s.TPM.EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrTPMDisabled)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceLockout(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Trip the DA logic by setting newMaxTries to 0
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 10000, 10000, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrTPMLockout)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedLockout(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the lockout hierarchy auth value so we get an error indicating that the TPM is already owned.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.LockoutHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `TPM lockout hierarchy is currently owned`)
	var he *TPM2HierarchyOwnedError
	c.Check(errors.As(err, &he), testutil.IsTrue)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedOwner(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the owner hierarchy auth value so we get an error indicating that the TPM is already owned.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `TPM owner hierarchy is currently owned`)
	var he *TPM2HierarchyOwnedError
	c.Check(errors.As(err, &he), testutil.IsTrue)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedEndorsement(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the endorsement hierarchy auth value so we get an error indicating that the TPM is already owned.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.EndorsementHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `TPM endorsement hierarchy is currently owned`)
	var he *TPM2HierarchyOwnedError
	c.Check(errors.As(err, &he), testutil.IsTrue)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceIsNotPCClient(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 2, // This is defined as PDA in the reference library specs
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrNoPCClientTPM)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceIsNotPCClientWithSWTPMWorkaround(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 2, // This is defined as PDA in the reference library specs
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, CheckTPM2DeviceInVM)
	c.Check(err, Equals, ErrNoPCClientTPM)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceInsufficientNVCountersPreInstall(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        5,
		tpm2.PropertyPSFamilyIndicator: 1,
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrTPMInsufficientNVCounters)
	c.Check(dev.NumberOpen(), Equals, int(0))
}
