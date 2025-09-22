// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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
	"encoding/json"
	"errors"
	"time"

	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type tpmutilSuiteNoTPM struct{}

type tpmutilSuite struct {
	tpm2_testutil.TPMSimulatorTest
}

var _ = Suite(&tpmutilSuiteNoTPM{})
var _ = Suite(&tpmutilSuite{})

func (*tpmutilSuiteNoTPM) TestDeviceLockoutRecoveryArgJSON(c *C) {
	arg := TPMDeviceLockoutRecoveryArg(24 * time.Hour)
	data, err := json.Marshal(arg)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b226475726174696f6e223a38363430303030303030303030307d"))

	var arg2 TPMDeviceLockoutRecoveryArg
	c.Check(json.Unmarshal(data, &arg2), IsNil)
	c.Check(arg2, Equals, arg)
}

func (*tpmutilSuiteNoTPM) TestDeviceLockoutRecoveryArgDuration(c *C) {
	arg := TPMDeviceLockoutRecoveryArg(24 * time.Hour)
	c.Check(arg.Duration(), Equals, 24*time.Hour)
}

func (*tpmutilSuiteNoTPM) TestDeviceLockoutRecoveryArgLockoutClearsOnTPMStartupClearFalse(c *C) {
	arg := TPMDeviceLockoutRecoveryArg(24 * time.Hour)
	c.Check(arg.LockoutClearsOnTPMStartupClear(), testutil.IsFalse)
}

func (*tpmutilSuiteNoTPM) TestDeviceLockoutRecoveryArgLockoutClearsOnTPMStartupClearTrue(c *C) {
	var arg TPMDeviceLockoutRecoveryArg
	c.Check(arg.LockoutClearsOnTPMStartupClear(), testutil.IsTrue)
}

func (*tpmutilSuiteNoTPM) TestDeviceLockoutRecoveryArgIsValidTrue(c *C) {
	arg := TPMDeviceLockoutRecoveryArg(24 * time.Hour)
	c.Check(arg.IsValid(), testutil.IsTrue)
}

func (*tpmutilSuiteNoTPM) TestDeviceLockoutRecoveryArgIsValidFalse1(c *C) {
	arg := TPMDeviceLockoutRecoveryArg((24 * time.Hour) + (500 * time.Millisecond))
	c.Check(arg.IsValid(), testutil.IsFalse)
}

func (*tpmutilSuiteNoTPM) TestDeviceLockoutRecoveryArgIsValidFalse2(c *C) {
	arg := TPMDeviceLockoutRecoveryArg(-24 * time.Hour)
	c.Check(arg.IsValid(), testutil.IsFalse)
}

func (s *tpmutilSuite) TestClearTPMWithoutAuthValue(c *C) {
	// Set the authorization value for the storage hierarchy.
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	c.Check(ClearTPM(env, nil), IsNil)

	val, err := s.TPM.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Assert(err, IsNil)
	c.Check(tpm2.PermanentAttributes(val)&tpm2.AttrOwnerAuthSet, Equals, tpm2.PermanentAttributes(0))
}

func (s *tpmutilSuite) TestClearTPMWithAuthValue(c *C) {
	// Set the authorization value for the lockout hierarchy.
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	c.Check(ClearTPM(env, []byte("1234")), IsNil)

	val, err := s.TPM.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Assert(err, IsNil)
	c.Check(tpm2.PermanentAttributes(val)&tpm2.AttrLockoutAuthSet, Equals, tpm2.PermanentAttributes(0))
}

func (s *tpmutilSuite) TestClearTPMErrNoTPM2Device(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()

	err := ClearTPM(env, nil)
	c.Check(err, ErrorMatches, `cannot open TPM device: cannot obtain TPM device: no TPM2 device is available`)
	c.Check(errors.Is(err, ErrNoTPM2Device), testutil.IsTrue)
}

func (s *tpmutilSuite) TestClearTPMErrInconsistentAuthValue1(c *C) {
	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	err := ClearTPM(env, []byte("1234"))
	c.Check(err, ErrorMatches, `supplied TPM lockout hierarchy authorization value is inconsistent with the value of the TPM_PT_PERMANENT lockoutAuthSet attribute`)
	c.Check(err, Equals, ErrInvalidLockoutAuthValueSupplied)
}

func (s *tpmutilSuite) TestClearTPMErrInconsistentAuthValue2(c *C) {
	// Set the authorization value for the lockout hierarchy.
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))

	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	err := ClearTPM(env, nil)
	c.Check(err, ErrorMatches, `supplied TPM lockout hierarchy authorization value is inconsistent with the value of the TPM_PT_PERMANENT lockoutAuthSet attribute`)
	c.Check(err, Equals, ErrInvalidLockoutAuthValueSupplied)
}

func (s *tpmutilSuite) TestClearTPMErrClearCommandFails(c *C) {
	dev := tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	c.Check(s.TPM.ClearControl(s.TPM.LockoutHandleContext(), true, nil), IsNil)

	err := ClearTPM(env, nil)
	c.Check(err, ErrorMatches, `cannot clear TPM: TPM returned an error whilst executing command TPM_CC_Clear: TPM_RC_DISABLED \(the command is disabled\)`)
	c.Check(tpm2.IsTPMError(err, tpm2.ErrorDisabled, tpm2.CommandClear), testutil.IsTrue)
}
