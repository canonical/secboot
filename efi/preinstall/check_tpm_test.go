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
		rc, rpBytes, _, err := tpm2.ReadResponsePacket(bytes.NewReader(rsp.Bytes()), nil)
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
		c.Check(tpm2.WriteResponsePacket(rsp, rc, nil, rpBytes, nil), IsNil)
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
	// Test the good case for pre-install on bare-metal with a discrete TPM and
	// infinite NV counters.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (2 << 1)}))
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
	// Test the good case for pre-install on bare-metal with a firmware TPM and infinite
	// NV counters.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}))
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
	// Test the good case for pre-install on bare-metal with a discrete TPM, and a
	// finite but sufficient number of NV counters.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        4,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (2 << 1)}))
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
	// Test the good case for post-install on bare-metal with a discrete TPM, and make
	// sure we skip the NV counter index check.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        5,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (2 << 1)}))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsTrue)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallNoVMOwnershipCheckSkippedDiscreteTPM(c *C) {
	// Test the good case for post-install on bare-metal with a discrete TPM, and make
	// sure we skip the hierarchy ownership check.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	// Set the lockout hierarchy auth value.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.LockoutHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (2 << 1)}))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsTrue)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallNoVMOwnershipCheckSkippedDiscreteTPM_2(c *C) {
	// Test the good case for post-install on bare-metal with a discrete TPM, and make
	// sure we skip the hierarchy ownership check where we test for hierarchy policies.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	// Set the owner hierarchy auth policy.
	c.Assert(s.TPM.SetPrimaryPolicy(s.TPM.OwnerHandleContext(), make([]byte, 32), tpm2.HashAlgorithmSHA256, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (2 << 1)}))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsTrue)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallNoVMLockoutCheckSkipped(c *C) {
	// Test the good case for post-install on bare-metal with a firmware TPM, and make
	// sure we skip the lockout status check.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        4,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Trip the DA logic by setting newMaxTries to 0
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 10000, 10000, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}))
	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(discreteTPM, testutil.IsFalse)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPreInstallVMInfiniteCounters(c *C) {
	// Test the good case for pre-install on a VM with a swtpm that has
	// infinite NV counters.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerMSFT),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
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

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPreInstallVMInfiniteCountersWithSWTPMWorkaround(c *C) {
	// Test the good case for pre-install on a VM with a swtpm that has
	// infinite NV counters, using the workaround for invalid TPM_PT_PS_FAMILY_INDICATOR.
	family, err := s.TPM.GetCapabilityTPMProperty(tpm2.PropertyFamilyIndicator)
	c.Check(err, IsNil)
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: family,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerMSFT),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
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

// XXX: See the commented out TPM2_SelfTest result handling code in check_tpm.go
//func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPreInstallNoVMInfiniteCountersDiscreteTPMWithBackgroundSelfTest(c *C) {
//	// Test the good case for pre-install on bare-metal with a discrete TPM and
//	// infinite NV counters, mocking a TPM that performs self tests in the
//	// background.
//	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
//		tpm2.PropertyNVCountersMax:     0,
//		tpm2.PropertyPSFamilyIndicator: 1,
//		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
//	})
//
//	// The above call relies on this.
//	origIntercept := s.Transport.ResponseIntercept
//	getTestResultLooped := false
//	s.Transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandles tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
//		switch cmdCode {
//		case tpm2.CommandSelfTest:
//			// Unpack the response
//			rc, _, _, err := tpm2.ReadResponsePacket(bytes.NewReader(rsp.Bytes()), nil)
//			c.Assert(err, IsNil)
//			if rc != tpm2.ResponseSuccess {
//				// Do nothing if the TPM didn't return success
//				return
//			}
//
//			// Return a response indicating that the tests are running in the background.
//			rsp.Reset()
//			c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseTesting, nil, nil, nil), IsNil)
//
//		case tpm2.CommandGetTestResult:
//			// Unpack the response
//			rc, rpBytes, _, err := tpm2.ReadResponsePacket(bytes.NewReader(rsp.Bytes()), nil)
//			c.Assert(err, IsNil)
//			if rc != tpm2.ResponseSuccess {
//				// Do nothing if the TPM didn't return success
//				return
//			}
//
//			var outData tpm2.MaxBuffer
//			var testResult tpm2.ResponseCode
//			_, err = mu.UnmarshalFromBytes(rpBytes, &outData, &testResult)
//			if testResult != tpm2.ResponseSuccess {
//				// Do nothing if the tests actully failed
//				return
//			}
//
//			testResult = tpm2.ResponseSuccess
//			if !getTestResultLooped {
//				testResult = tpm2.ResponseTesting
//				getTestResultLooped = true
//			}
//
//			rsp.Reset()
//			rpBytes = mu.MustMarshalToBytes(outData, testResult)
//			c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseSuccess, nil, rpBytes, nil), IsNil)
//
//		default:
//			origIntercept(cmdCode, cmdHandles, cmdAuthArea, cpBytes, rsp)
//		}
//	}
//
//	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
//	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
//	tpm, discreteTPM, err := OpenAndCheckTPM2Device(env, 0)
//	c.Check(err, IsNil)
//	c.Assert(tpm, NotNil)
//	var tmpl tpm2_testutil.TransportWrapper
//	c.Assert(tpm.Transport(), Implements, &tmpl)
//	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
//	c.Check(discreteTPM, testutil.IsTrue)
//	c.Check(dev.NumberOpen(), Equals, int(1))
//}

// Error cases begin here.

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceNoTPM(c *C) {
	// Test the case where there isn't a TPM2 device.
	env := efitest.NewMockHostEnvironmentWithOpts()
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrNoTPM2Device)
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceBootGuardNoTPM(c *C) {
	// TPM2 is connected but BootGuard MSR says no TPM
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})
	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (0 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, Equals, ErrNoTPM2Device)
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceBootGuardTPM12(c *C) {
	// TPM2 is connected but BootGuard MSR says device is TPM1.2
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})
	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (1 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, Equals, ErrNoTPM2Device)
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceFailureMode(c *C) {
	// Test the case where the TPM is in failure mode.
	s.Mssim(c).TestFailureMode()

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrTPMFailure)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceWithBackgroundSelfTest(c *C) {
	// This case should fail for now because the code that handles it is
	// commented out.
	// XXX: See the commented out TPM2_SelfTest result handling code in check_tpm.go
	s.Transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandles tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
		switch cmdCode {
		case tpm2.CommandSelfTest:
			// Unpack the response
			rc, _, _, err := tpm2.ReadResponsePacket(bytes.NewReader(rsp.Bytes()), nil)
			c.Assert(err, IsNil)
			if rc != tpm2.ResponseSuccess {
				// Do nothing if the TPM didn't return success
				return
			}

			// Return a response indicating that the tests are running in the background.
			rsp.Reset()
			c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseTesting, nil, nil, nil), IsNil)
		}
	}

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `cannot perform partial self test: TPM returned a warning whilst executing command TPM_CC_SelfTest: TPM_RC_TESTING \(TPM is performing self-tests\)`)
	c.Check(tpm2.IsTPMWarning(err, tpm2.WarningTesting, tpm2.CommandSelfTest), testutil.IsTrue)
}

// XXX: See the commented out TPM2_SelfTest result handling code in check_tpm.go
//func (s *tpmSuite) TestOpenAndCheckTPM2DeviceFailureModeBackgroundTest(c *C) {
//	// Test the case where the TPM is in failure mode, and it performs self-tests
//	// in the background (we have to mock this behaviour because the simulator
//	// doesn't work like this).
//	getTestResultLooped := false
//	s.Transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandles tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
//		switch cmdCode {
//		case tpm2.CommandSelfTest:
//			// Unpack the response
//			rc, _, _, err := tpm2.ReadResponsePacket(rsp, nil)
//			c.Assert(err, IsNil)
//			if rc != tpm2.ResponseSuccess {
//				// Do nothing if the TPM didn't return success
//				return
//			}
//
//			// Return a response indicating that the tests are running in the background.
//			rsp.Reset()
//			c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseTesting, nil, nil, nil), IsNil)
//
//		case tpm2.CommandGetTestResult:
//			// Unpack the response
//			rc, rpBytes, _, err := tpm2.ReadResponsePacket(rsp, nil)
//			c.Assert(err, IsNil)
//			if rc != tpm2.ResponseSuccess {
//				// Do nothing if the TPM didn't return success
//				return
//			}
//
//			var outData tpm2.MaxBuffer
//			var testResult tpm2.ResponseCode
//			_, err = mu.UnmarshalFromBytes(rpBytes, &outData, &testResult)
//			if testResult != tpm2.ResponseSuccess {
//				// Do nothing if the tests actully failed
//				return
//			}
//
//			testResult = tpm2.ResponseFailure
//			if !getTestResultLooped {
//				testResult = tpm2.ResponseTesting
//				getTestResultLooped = true
//			}
//
//			rsp.Reset()
//			rpBytes = mu.MustMarshalToBytes(outData, testResult)
//			c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseSuccess, nil, rpBytes, nil), IsNil)
//		}
//	}
//
//	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
//	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
//	_, _, err := OpenAndCheckTPM2Device(env, 0)
//	c.Check(err, Equals, ErrTPMFailure)
///	c.Check(dev.NumberOpen(), Equals, int(0))
//}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceIsNotPCClient(c *C) {
	// Test for not having a PC Client TPM2 device.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 2, // This is defined as PDA in the reference library specs
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrNoPCClientTPM)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceIsNotPCClientWithSWTPMWorkaround(c *C) {
	// Test for not having a PC Client TPM2 device, when running in a VM, which
	// has a workaround for the swtpm.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 2, // This is defined as PDA in the reference library specs
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, CheckTPM2DeviceInVM)
	c.Check(err, Equals, ErrNoPCClientTPM)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceDisabled(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
	})

	// Disable owner and endorsement hierarchies
	c.Assert(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
	c.Assert(s.TPM.HierarchyControl(s.TPM.EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrTPMDisabled)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedLockout(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the lockout hierarchy auth value so we get an error indicating that the TPM is already owned.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.LockoutHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_LOCKOUT has an authorization value
`)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err, &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, DeepEquals, tpm2.HandleList{tpm2.HandleLockout})
	c.Check(e.WithAuthPolicy, HasLen, 0)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedOwner(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the owner hierarchy auth value so we get an error indicating that the TPM is already owned.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_OWNER has an authorization value
`)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err, &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, DeepEquals, tpm2.HandleList{tpm2.HandleOwner})
	c.Check(e.WithAuthPolicy, HasLen, 0)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedEndorsement(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the endorsement hierarchy auth value so we get an error indicating that the TPM is already owned.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.EndorsementHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_ENDORSEMENT has an authorization value
`)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err, &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, DeepEquals, tpm2.HandleList{tpm2.HandleEndorsement})
	c.Check(e.WithAuthPolicy, HasLen, 0)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedLockoutWithPolicy(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set an authorization policy and test that we get the appropriate error.
	c.Assert(s.TPM.SetPrimaryPolicy(s.TPM.LockoutHandleContext(), testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"), tpm2.HashAlgorithmSHA256, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_LOCKOUT has an authorization policy
`)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err, &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, HasLen, 0)
	c.Check(e.WithAuthPolicy, DeepEquals, tpm2.HandleList{tpm2.HandleLockout})
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedOwnerWithPolicy(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set an authorization policy and test that we get the appropriate error.
	c.Assert(s.TPM.SetPrimaryPolicy(s.TPM.OwnerHandleContext(), testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"), tpm2.HashAlgorithmSHA256, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_OWNER has an authorization policy
`)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err, &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, HasLen, 0)
	c.Check(e.WithAuthPolicy, DeepEquals, tpm2.HandleList{tpm2.HandleOwner})
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedEndorsementWithPolicy(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set an authorization policy and test that we get the appropriate error.
	c.Assert(s.TPM.SetPrimaryPolicy(s.TPM.EndorsementHandleContext(), testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"), tpm2.HashAlgorithmSHA256, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_ENDORSEMENT has an authorization policy
`)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err, &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, HasLen, 0)
	c.Check(e.WithAuthPolicy, DeepEquals, tpm2.HandleList{tpm2.HandleEndorsement})
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceLockout(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Trip the DA logic by setting newMaxTries to 0
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 10000, 10000, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrTPMLockout)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceHierarchyOwnershipHasPriorityOverLockout(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))

	// Trip the DA logic by setting newMaxTries to 0
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 10000, 10000, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (3 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_OWNER has an authorization value
`)
	c.Check(dev.NumberOpen(), Equals, int(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceInsufficientNVCountersPreInstall(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        5,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev),
		efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0x13a: (2 << 1)}))
	_, _, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, Equals, ErrTPMInsufficientNVCounters)
	c.Check(dev.NumberOpen(), Equals, int(0))
}
