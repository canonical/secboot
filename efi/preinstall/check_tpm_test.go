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
	"crypto/rand"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2_device"
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

func (s *tpmSuite) TestCheckTPM2ForRequiredPCClientFeatures(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyHRPersistentMin: 7, // The simulator seems to set this to 2
	})

	ok, err := CheckTPM2ForRequiredPCClientFeatures(s.TPM)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)
}

func (s *tpmSuite) TestCheckTPM2ForRequiredPCClientFeaturesFailTPMProperty(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyHRPersistentMin: 1,
	})

	ok, err := CheckTPM2ForRequiredPCClientFeatures(s.TPM)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsFalse)
}

func (s *tpmSuite) TestCheckTPM2ForRequiredPCClientFeaturesFailAlgorithm(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyHRPersistentMin: 7, // The simulator seems to set this to 2
	})

	origIntercept := s.Transport.ResponseIntercept
	s.transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandles tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
		if cmdCode != tpm2.CommandGetCapability {
			return
		}

		// Unpack the command parameters
		var capability tpm2.Capability
		var property uint32
		var propertyCount uint32
		_, err := mu.UnmarshalFromBytes(cpBytes, &capability, &property, &propertyCount)
		c.Assert(err, IsNil)
		if capability != tpm2.CapabilityAlgs {
			origIntercept(cmdCode, cmdHandles, cmdAuthArea, cpBytes, rsp)
			return
		}

		// Just return no algorithms
		rpBytes := mu.MustMarshalToBytes(false, &tpm2.CapabilityData{
			Capability: tpm2.CapabilityAlgs,
		})
		rsp.Reset()
		c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseSuccess, nil, rpBytes, nil), IsNil)
	}
	defer func() { s.Transport.ResponseIntercept = origIntercept }()

	ok, err := CheckTPM2ForRequiredPCClientFeatures(s.TPM)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsFalse)
}

func (s *tpmSuite) TestCheckTPM2ForRequiredPCClientFeaturesFailCurve(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyHRPersistentMin: 7, // The simulator seems to set this to 2
	})

	origIntercept := s.Transport.ResponseIntercept
	s.transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandles tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
		if cmdCode != tpm2.CommandGetCapability {
			return
		}

		// Unpack the command parameters
		var capability tpm2.Capability
		var property uint32
		var propertyCount uint32
		_, err := mu.UnmarshalFromBytes(cpBytes, &capability, &property, &propertyCount)
		c.Assert(err, IsNil)
		if capability != tpm2.CapabilityECCCurves {
			origIntercept(cmdCode, cmdHandles, cmdAuthArea, cpBytes, rsp)
			return
		}

		// Just return no algorithms
		rpBytes := mu.MustMarshalToBytes(false, &tpm2.CapabilityData{
			Capability: tpm2.CapabilityECCCurves,
		})
		rsp.Reset()
		c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseSuccess, nil, rpBytes, nil), IsNil)
	}
	defer func() { s.Transport.ResponseIntercept = origIntercept }()

	ok, err := CheckTPM2ForRequiredPCClientFeatures(s.TPM)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsFalse)
}

func (s *tpmSuite) TestCheckTPM2ForRequiredPCClientFeaturesFailPCRAttributes(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyHRPersistentMin: 7, // The simulator seems to set this to 2
	})

	origIntercept := s.Transport.ResponseIntercept
	s.transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandles tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
		if cmdCode != tpm2.CommandGetCapability {
			return
		}

		// Unpack the command parameters
		var capability tpm2.Capability
		var property uint32
		var propertyCount uint32
		_, err := mu.UnmarshalFromBytes(cpBytes, &capability, &property, &propertyCount)
		c.Assert(err, IsNil)
		if capability != tpm2.CapabilityPCRProperties {
			origIntercept(cmdCode, cmdHandles, cmdAuthArea, cpBytes, rsp)
			return
		}

		c.Assert(propertyCount, Equals, uint32(1))
		if property != uint32(tpm2.PropertyPCRNoIncrement) {
			return
		}

		rpBytes := mu.MustMarshalToBytes(false, tpm2.CapabilityPCRProperties, uint32(1), tpm2.PropertyPCRNoIncrement, mu.Sized1Bytes{0xff, 0xff, 0xff})
		rsp.Reset()
		c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseSuccess, nil, rpBytes, nil), IsNil)
	}
	defer func() { s.Transport.ResponseIntercept = origIntercept }()

	ok, err := CheckTPM2ForRequiredPCClientFeatures(s.TPM)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsFalse)
}

func (s *tpmSuite) TestCheckTPM2ForRequiredPCClientFeaturesFailCommand(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyHRPersistentMin: 7, // The simulator seems to set this to 2
	})

	origIntercept := s.Transport.ResponseIntercept
	s.transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandles tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
		if cmdCode != tpm2.CommandGetCapability {
			return
		}

		// Unpack the command parameters
		var capability tpm2.Capability
		var property uint32
		var propertyCount uint32
		_, err := mu.UnmarshalFromBytes(cpBytes, &capability, &property, &propertyCount)
		c.Assert(err, IsNil)
		if capability != tpm2.CapabilityCommands {
			origIntercept(cmdCode, cmdHandles, cmdAuthArea, cpBytes, rsp)
			return
		}

		// Just return no commands
		rpBytes := mu.MustMarshalToBytes(false, &tpm2.CapabilityData{
			Capability: tpm2.CapabilityCommands,
		})
		rsp.Reset()
		c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseSuccess, nil, rpBytes, nil), IsNil)
	}
	defer func() { s.Transport.ResponseIntercept = origIntercept }()

	ok, err := CheckTPM2ForRequiredPCClientFeatures(s.TPM)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsFalse)
}

func (s *tpmSuite) TestCheckTPM2ForRequiredPCClientFeaturesErrorTPMProperty(c *C) {
	s.transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandles tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
		if cmdCode != tpm2.CommandGetCapability {
			return
		}

		// Unpack the command parameters
		var capability tpm2.Capability
		var property uint32
		var propertyCount uint32
		_, err := mu.UnmarshalFromBytes(cpBytes, &capability, &property, &propertyCount)
		c.Assert(err, IsNil)
		if capability != tpm2.CapabilityTPMProperties {
			return
		}

		// Return an error.
		rsp.Reset()
		c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseFailure, nil, nil, nil), IsNil)
	}

	_, err := CheckTPM2ForRequiredPCClientFeatures(s.TPM)
	c.Check(err, ErrorMatches, `cannot obtain value of 270: TPM returned an error whilst executing command TPM_CC_GetCapability: TPM_RC_FAILURE \(commands not being accepted because of a TPM failure\)`)
	c.Check(tpm2.IsTPMError(err, tpm2.ErrorFailure, tpm2.CommandGetCapability), testutil.IsTrue)
}

func (s *tpmSuite) TestCheckTPM2ForRequiredPCClientFeaturesErrorPCRAttribute(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyHRPersistentMin: 7, // The simulator seems to set this to 2
	})

	origIntercept := s.Transport.ResponseIntercept
	s.transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandles tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
		if cmdCode != tpm2.CommandGetCapability {
			return
		}

		// Unpack the command parameters
		var capability tpm2.Capability
		var property uint32
		var propertyCount uint32
		_, err := mu.UnmarshalFromBytes(cpBytes, &capability, &property, &propertyCount)
		c.Assert(err, IsNil)
		if capability != tpm2.CapabilityPCRProperties {
			origIntercept(cmdCode, cmdHandles, cmdAuthArea, cpBytes, rsp)
			return
		}

		// Return an error.
		rsp.Reset()
		c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseFailure, nil, nil, nil), IsNil)
	}
	defer func() { s.Transport.ResponseIntercept = origIntercept }()

	_, err := CheckTPM2ForRequiredPCClientFeatures(s.TPM)
	c.Check(err, ErrorMatches, `cannot obtain value of 0: TPM returned an error whilst executing command TPM_CC_GetCapability: TPM_RC_FAILURE \(commands not being accepted because of a TPM failure\)`)
	c.Check(tpm2.IsTPMError(err, tpm2.ErrorFailure, tpm2.CommandGetCapability), testutil.IsTrue)
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPreInstallInfiniteCounters(c *C) {
	// Test the good case for pre-install with infinite NV counters.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     0,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPreInstallFiniteCounters(c *C) {
	// Test the good case for pre-install with a finite but sufficient number of NV counters.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        4,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallCountersCheckSkipped(c *C) {
	// Test the good case for post-install on bare-metal, making sure we skip the NV
	// counter index check.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        5,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallOwnershipCheckSkipped(c *C) {
	// Test the good case for post-install, making sure we skip the hierarchy ownership check.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	// Set the endorsement hierarchy auth value.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.EndorsementHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPostInstallOwnershipCheckSkipped_2(c *C) {
	// Test the good case for post-install, making sure we skip the
	// hierarchy ownership check where we test for hierarchy policies.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	// Set the owner hierarchy auth policy.
	c.Assert(s.TPM.SetPrimaryPolicy(s.TPM.OwnerHandleContext(), make([]byte, 32), tpm2.HashAlgorithmSHA256, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, IsNil)
	c.Assert(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceGoodPreinstallLockoutAvailabilityCheckClearsDALockout(c *C) {
	// Test the good case where the tests start with the TPM's DA lockout
	// mechanism tripped, but the lockout hierarchy availability check
	// clears it without having to return an error.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Trip the DA logic by triggering an auth failure with a DA protected
	// resource.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 1, 10000, 10000, nil), IsNil)
	pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, []byte("foo"), []byte("5678"))
	c.Assert(err, IsNil)
	key, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)
	key.SetAuthValue(nil)
	_, err = s.TPM.Unseal(key, nil)
	c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandUnseal, 1), testutil.IsTrue)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, IsNil)
	c.Check(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
	c.Check(dev.NumberOpen(), Equals, int(1))

	// Verify that the DA lockout has cleared.
	perm, err := s.TPM.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Check(err, IsNil)
	c.Check(tpm2.PermanentAttributes(perm)&tpm2.AttrInLockout, Equals, tpm2.PermanentAttributes(0))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceIsNotPCClientWithSuccessfulFeatureChecks(c *C) {
	// Test for not having a PC Client TPM2 device but where
	// the device passes the feature checks.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 2, // This is defined as PDA in the reference library specs
		tpm2.PropertyHRPersistentMin:   7, // The simulator seems to set this to 2
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, IsNil)
	c.Check(tpm, NotNil)
	var tmpl tpm2_testutil.TransportWrapper
	c.Assert(tpm.Transport(), Implements, &tmpl)
	c.Check(tpm.Transport().(tpm2_testutil.TransportWrapper).Unwrap(), Equals, s.Transport)
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
	_, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `cannot open TPM device: cannot obtain TPM device: no TPM2 device is available`)
	c.Check(errors.Is(err, ErrNoTPM2Device), testutil.IsTrue)
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceFailureMode(c *C) {
	// Test the case where the TPM is in failure mode.
	s.Mssim(c).TestFailureMode()

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	_, err := OpenAndCheckTPM2Device(env, 0)
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
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	_, err := OpenAndCheckTPM2Device(env, 0)
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

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceIsNotPCClientWithFailedFeatureChecks(c *C) {
	// Test for not having a PC Client TPM2 device.
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 2, // This is defined as PDA in the reference library specs
		tpm2.PropertyHRPersistentMin:   1,
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	_, err := OpenAndCheckTPM2Device(env, 0)
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
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	_, err := OpenAndCheckTPM2Device(env, 0)
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
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `2 errors detected:
- availability of TPM's lockout hierarchy was not checked because the lockout hierarchy has an authorization value set
- one or more of the TPM hierarchies is already owned:
  - TPM_RH_LOCKOUT has an authorization value
`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 2)

	c.Check(errors.Is(err.(CompoundError).Unwrap()[0], ErrTPMLockoutAvailabilityNotChecked), testutil.IsTrue)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err.(CompoundError).Unwrap()[1], &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, DeepEquals, tpm2.HandleList{tpm2.HandleLockout})
	c.Check(e.WithAuthPolicy, HasLen, 0)

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedOwner(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the owner hierarchy auth value so we get an error indicating that the TPM is already owned.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_OWNER has an authorization value
`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 1)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err.(CompoundError).Unwrap()[0], &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, DeepEquals, tpm2.HandleList{tpm2.HandleOwner})
	c.Check(e.WithAuthPolicy, HasLen, 0)

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedEndorsement(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set the endorsement hierarchy auth value so we get an error indicating that the TPM is already owned.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.EndorsementHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_ENDORSEMENT has an authorization value
`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 1)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err.(CompoundError).Unwrap()[0], &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, DeepEquals, tpm2.HandleList{tpm2.HandleEndorsement})
	c.Check(e.WithAuthPolicy, HasLen, 0)

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedLockoutWithPolicy(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set an authorization policy and test that we get the appropriate error.
	c.Assert(s.TPM.SetPrimaryPolicy(s.TPM.LockoutHandleContext(), testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"), tpm2.HashAlgorithmSHA256, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_LOCKOUT has an authorization policy
`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 1)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err.(CompoundError).Unwrap()[0], &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, HasLen, 0)
	c.Check(e.WithAuthPolicy, DeepEquals, tpm2.HandleList{tpm2.HandleLockout})

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedOwnerWithPolicy(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set an authorization policy and test that we get the appropriate error.
	c.Assert(s.TPM.SetPrimaryPolicy(s.TPM.OwnerHandleContext(), testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"), tpm2.HashAlgorithmSHA256, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_OWNER has an authorization policy
`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 1)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err.(CompoundError).Unwrap()[0], &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, HasLen, 0)
	c.Check(e.WithAuthPolicy, DeepEquals, tpm2.HandleList{tpm2.HandleOwner})

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceAlreadyOwnedEndorsementWithPolicy(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Set an authorization policy and test that we get the appropriate error.
	c.Assert(s.TPM.SetPrimaryPolicy(s.TPM.EndorsementHandleContext(), testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"), tpm2.HashAlgorithmSHA256, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `one or more of the TPM hierarchies is already owned:
- TPM_RH_ENDORSEMENT has an authorization policy
`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 1)

	var e *TPM2OwnedHierarchiesError
	c.Check(errors.As(err.(CompoundError).Unwrap()[0], &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, HasLen, 0)
	c.Check(e.WithAuthPolicy, DeepEquals, tpm2.HandleList{tpm2.HandleEndorsement})

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceLockout1(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Trip the DA logic by setting newMaxTries to 0. This also prevents
	// the lockout hierarchy availability test from clearing the lockout,
	// although that test does still run.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 10000, 10000, nil), IsNil)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `TPM is in DA lockout mode`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 1)

	c.Check(err.(CompoundError).Unwrap()[0], Equals, ErrTPMLockout)

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceLockout2(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Trip the DA logic by triggering an auth failure with a DA protected
	// resource. We set the lockout hierarchy auth value to disable the
	// lockout hierarchy availability check, which would otherwise clear
	// the lockout.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 1, 10000, 10000, nil), IsNil)
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
	pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, []byte("foo"), []byte("5678"))
	c.Assert(err, IsNil)
	key, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)
	key.SetAuthValue(nil)
	_, err = s.TPM.Unseal(key, nil)
	c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandUnseal, 1), testutil.IsTrue)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `3 errors detected:
- availability of TPM's lockout hierarchy was not checked because the lockout hierarchy has an authorization value set
- TPM is in DA lockout mode
- one or more of the TPM hierarchies is already owned:
  - TPM_RH_LOCKOUT has an authorization value
`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 3)

	c.Check(err.(CompoundError).Unwrap()[0], Equals, ErrTPMLockoutAvailabilityNotChecked)
	c.Check(err.(CompoundError).Unwrap()[1], Equals, ErrTPMLockout)

	var e *TPM2OwnedHierarchiesError
	c.Assert(errors.As(err.(CompoundError).Unwrap()[2], &e), testutil.IsTrue)
	c.Check(e.WithAuthValue, DeepEquals, tpm2.HandleList{tpm2.HandleLockout})
	c.Check(e.WithAuthPolicy, HasLen, 0)

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceLockoutPostInstall(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Trip the DA logic by triggering an auth failure with a DA protected
	// resource. We set the lockout hierarchy auth value to disable the
	// lockout hierarchy availability check, which would otherwise clear
	// the lockout.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 1, 10000, 10000, nil), IsNil)
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
	pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, []byte("foo"), []byte("5678"))
	c.Assert(err, IsNil)
	key, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)
	key.SetAuthValue(nil)
	_, err = s.TPM.Unseal(key, nil)
	c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandUnseal, 1), testutil.IsTrue)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, ErrorMatches, `2 errors detected:
- availability of TPM's lockout hierarchy was not checked because the lockout hierarchy has an authorization value set
- TPM is in DA lockout mode
`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 2)

	c.Check(err.(CompoundError).Unwrap()[0], Equals, ErrTPMLockoutAvailabilityNotChecked)
	c.Check(err.(CompoundError).Unwrap()[1], Equals, ErrTPMLockout)

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceLockoutLockedOut(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Disable the lockout hierarchy by authorizing it incorrectly
	s.TPM.LockoutHandleContext().SetAuthValue([]byte("1234"))
	err := s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil)
	c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandDictionaryAttackLockReset, 1), testutil.IsTrue)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)
	c.Check(err, ErrorMatches, `TPM's lockout hierarchy is unavailable because it is locked out`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 1)

	c.Check(err.(CompoundError).Unwrap()[0], Equals, ErrTPMLockoutLockedOut)

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceLockoutLockedOutPostInstall(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
	})

	// Disable the lockout hierarchy by authorizing it incorrectly
	s.TPM.LockoutHandleContext().SetAuthValue([]byte("1234"))
	err := s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil)
	c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandDictionaryAttackLockReset, 1), testutil.IsTrue)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall)
	c.Check(err, ErrorMatches, `TPM's lockout hierarchy is unavailable because it is locked out`)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 1)

	c.Check(err.(CompoundError).Unwrap()[0], Equals, ErrTPMLockoutLockedOut)

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceInsufficientNVCountersPreInstall(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyNVCountersMax:     6,
		tpm2.PropertyNVCounters:        5,
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, 0)

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 1)

	c.Check(err.(CompoundError).Unwrap()[0], Equals, ErrTPMInsufficientNVCounters)

	c.Check(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}

func (s *tpmSuite) TestOpenAndCheckTPM2DeviceLockoutAvailabilitySkipped(c *C) {
	s.addTPMPropertyModifiers(c, map[tpm2.Property]uint32{
		tpm2.PropertyPSFamilyIndicator: 1,
		tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
	})

	// Set the lockout hierarchy auth value.
	c.Assert(s.TPM.HierarchyChangeAuth(s.TPM.LockoutHandleContext(), []byte{1, 2, 3, 4}, nil), IsNil)

	// Disable the lockout hierarchy by authorizing it incorrectly
	s.TPM.LockoutHandleContext().SetAuthValue([]byte("5678"))
	err := s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil)
	c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandDictionaryAttackLockReset, 1), testutil.IsTrue)

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(newTpmDevice(dev, nil, tpm2_device.ErrNoPPI)))
	tpm, err := OpenAndCheckTPM2Device(env, CheckTPM2DevicePostInstall) // Post install so we get 1 error.

	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Assert(err.(CompoundError).Unwrap(), HasLen, 1)

	c.Check(err.(CompoundError).Unwrap()[0], Equals, ErrTPMLockoutAvailabilityNotChecked)

	c.Assert(tpm, NotNil)
	c.Check(dev.NumberOpen(), Equals, int(1))
}
