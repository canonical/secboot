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
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/ppi"
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	. "gopkg.in/check.v1"
)

type mockPPI struct {
	sta    ppi.StateTransitionAction
	ops    map[ppi.OperationId]ppi.OperationStatus
	called []string
}

func (*mockPPI) Type() ppi.Type {
	return ppi.ACPI
}

func (*mockPPI) Version() ppi.Version {
	return ppi.Version13
}

func (p *mockPPI) StateTransitionAction() (ppi.StateTransitionAction, error) {
	return p.sta, nil
}

func (p *mockPPI) OperationStatus(op ppi.OperationId) (ppi.OperationStatus, error) {
	s, exists := p.ops[op]
	if !exists {
		return ppi.OperationNotImplemented, nil
	}
	return s, nil
}

func (p *mockPPI) EnableTPM() error {
	p.called = append(p.called, "EnableTPM()")
	return nil
}

func (*mockPPI) DisableTPM() error {
	return ppi.ErrOperationUnsupported
}

func (p *mockPPI) ClearTPM() error {
	p.called = append(p.called, "ClearTPM()")
	return nil
}

func (p *mockPPI) EnableAndClearTPM() error {
	p.called = append(p.called, "EnableAndClearTPM()")
	return nil
}

func (*mockPPI) SetPCRBanks(algs ...tpm2.HashAlgorithmId) error {
	return ppi.ErrOperationUnsupported
}

func (*mockPPI) ChangeEPS() error {
	return ppi.ErrOperationUnsupported
}

func (*mockPPI) LogAllDigests() error {
	return ppi.ErrOperationUnsupported
}

func (*mockPPI) DisableEndorsementAndEnableStorageHierarchy() error {
	return ppi.ErrOperationUnsupported
}

func (*mockPPI) SetPPRequiredForOperation(op ppi.OperationId) error {
	return ppi.ErrOperationUnsupported
}

func (*mockPPI) ClearPPRequiredForOperation(op ppi.OperationId) error {
	return ppi.ErrOperationUnsupported
}

func (*mockPPI) OperationResponse() (*ppi.OperationResponse, error) {
	return nil, nil
}

type mockTpm2Device struct {
	_ byte
}

func (*mockTpm2Device) Open() (tpm2.Transport, error) {
	return nil, errors.New("not supported")
}

func (*mockTpm2Device) String() string {
	return "mock TPM2 device"
}

type actionsPpiSuite struct {
	snapd_testutil.BaseTest

	devToPPIMap map[tpm2.TPMDevice]ppi.PPI
	ppiErr      error
}

func (s *actionsPpiSuite) SetUpTest(c *C) {
	s.devToPPIMap = make(map[tpm2.TPMDevice]ppi.PPI)
	s.ppiErr = nil

	restore := MockObtainTPMDevicePPI(func(dev tpm2.TPMDevice) (ppi.PPI, error) {
		if s.ppiErr != nil {
			return nil, s.ppiErr
		}
		return s.devToPPIMap[dev], nil
	})
	s.AddCleanup(restore)
}

var _ = Suite(&actionsPpiSuite{})

func (s *actionsPpiSuite) TestRunPPIActionEnableTPM(c *C) {
	dev := new(mockTpm2Device)
	p := &mockPPI{sta: ppi.StateTransitionRebootRequired}
	s.devToPPIMap[dev] = p

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	sta, err := RunPPIAction(env, ActionEnableTPMViaFirmware)
	c.Check(err, IsNil)
	c.Check(sta, Equals, ppi.StateTransitionRebootRequired)
	c.Check(p.called, DeepEquals, []string{"EnableTPM()"})
}

func (s *actionsPpiSuite) TestRunPPIActionEnableAndClearTPM(c *C) {
	dev := new(mockTpm2Device)
	p := &mockPPI{sta: ppi.StateTransitionRebootRequired}
	s.devToPPIMap[dev] = p

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	sta, err := RunPPIAction(env, ActionEnableAndClearTPMViaFirmware)
	c.Check(err, IsNil)
	c.Check(sta, Equals, ppi.StateTransitionRebootRequired)
	c.Check(p.called, DeepEquals, []string{"EnableAndClearTPM()"})
}

func (s *actionsPpiSuite) TestRunPPIActionClearTPM(c *C) {
	dev := new(mockTpm2Device)
	p := &mockPPI{sta: ppi.StateTransitionRebootRequired}
	s.devToPPIMap[dev] = p

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	sta, err := RunPPIAction(env, ActionClearTPMViaFirmware)
	c.Check(err, IsNil)
	c.Check(sta, Equals, ppi.StateTransitionRebootRequired)
	c.Check(p.called, DeepEquals, []string{"ClearTPM()"})
}

func (s *actionsPpiSuite) TestRunPPIActionEnableTPMWithShutdownSTA(c *C) {
	dev := new(mockTpm2Device)
	p := &mockPPI{sta: ppi.StateTransitionShutdownRequired}
	s.devToPPIMap[dev] = p

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	sta, err := RunPPIAction(env, ActionEnableTPMViaFirmware)
	c.Check(err, IsNil)
	c.Check(sta, Equals, ppi.StateTransitionShutdownRequired)
	c.Check(p.called, DeepEquals, []string{"EnableTPM()"})
}

func (s *actionsPpiSuite) TestRunPPIActionInvalidAction(c *C) {
	dev := new(mockTpm2Device)
	p := &mockPPI{sta: ppi.StateTransitionRebootRequired}
	s.devToPPIMap[dev] = p

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	_, err := RunPPIAction(env, ActionRebootToFWSettings)
	c.Check(err, ErrorMatches, `invalid PPI action "reboot-to-fw-settings"`)
}

func (s *actionsPpiSuite) TestRunPPIActionInvalidSTA(c *C) {
	dev := new(mockTpm2Device)
	p := &mockPPI{sta: ppi.StateTransitionActionOSVendorSpecific}
	s.devToPPIMap[dev] = p

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	_, err := RunPPIAction(env, ActionEnableTPMViaFirmware)
	c.Check(err, ErrorMatches, `unsupported state transition action "OS Vendor-specific"`)
}

func (s *actionsPpiSuite) TestRunPPIActionNoPPI(c *C) {
	dev := new(mockTpm2Device)

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	_, err := RunPPIAction(env, ActionEnableTPMViaFirmware)
	c.Check(err, Equals, ppi.ErrOperationUnsupported)
}

func (s *actionsPpiSuite) TestRunPPIActionPPIErr(c *C) {
	s.ppiErr = errors.New("some error")
	dev := new(mockTpm2Device)

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	_, err := RunPPIAction(env, ActionEnableTPMViaFirmware)
	c.Check(err, ErrorMatches, `cannot obtain physical presence interface: some error`)
}

func (s *actionsPpiSuite) TestIsPPIActionAvailableEnableTPM(c *C) {
	dev := new(mockTpm2Device)
	p := &mockPPI{ops: map[ppi.OperationId]ppi.OperationStatus{
		ppi.OperationEnableTPM: ppi.OperationPPRequired,
	}}
	s.devToPPIMap[dev] = p

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	avail, err := IsPPIActionAvailable(env, ActionEnableTPMViaFirmware)
	c.Check(err, IsNil)
	c.Check(avail, testutil.IsTrue)
}

func (s *actionsPpiSuite) TestIsPPIActionAvailableEnableAndClearTPM(c *C) {
	dev := new(mockTpm2Device)
	p := &mockPPI{ops: map[ppi.OperationId]ppi.OperationStatus{
		ppi.OperationEnableAndClearTPM: ppi.OperationPPRequired,
	}}
	s.devToPPIMap[dev] = p

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	avail, err := IsPPIActionAvailable(env, ActionEnableAndClearTPMViaFirmware)
	c.Check(err, IsNil)
	c.Check(avail, testutil.IsTrue)
}

func (s *actionsPpiSuite) TestIsPPIActionAvailableClearTPM(c *C) {
	dev := new(mockTpm2Device)
	p := &mockPPI{ops: map[ppi.OperationId]ppi.OperationStatus{
		ppi.OperationClearTPM: ppi.OperationPPRequired,
	}}
	s.devToPPIMap[dev] = p

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	avail, err := IsPPIActionAvailable(env, ActionClearTPMViaFirmware)
	c.Check(err, IsNil)
	c.Check(avail, testutil.IsTrue)
}

func (s *actionsPpiSuite) TestIsPPIActionAvailableEnableTPMNotAvailable(c *C) {
	dev := new(mockTpm2Device)
	p := &mockPPI{}
	s.devToPPIMap[dev] = p

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	avail, err := IsPPIActionAvailable(env, ActionEnableTPMViaFirmware)
	c.Check(err, IsNil)
	c.Check(avail, testutil.IsFalse)
}

func (s *actionsPpiSuite) TestIsPPIActionAvailableEnableTPMNoPPI(c *C) {
	dev := new(mockTpm2Device)

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	avail, err := IsPPIActionAvailable(env, ActionEnableTPMViaFirmware)
	c.Check(err, IsNil)
	c.Check(avail, testutil.IsFalse)
}

func (s *actionsPpiSuite) TestIsPPIActionAvailableEnableTPMPPIErr(c *C) {
	s.ppiErr = errors.New("some error")
	dev := new(mockTpm2Device)

	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithTPMDevice(dev))

	_, err := IsPPIActionAvailable(env, ActionEnableTPMViaFirmware)
	c.Check(err, ErrorMatches, `cannot obtain physical presence interface: some error`)
}
