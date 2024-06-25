// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2024 Canonical Ltd
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

package efi_test

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"
)

type defaultEnvSuite struct{}

func (s *defaultEnvSuite) mockSysfsPath(c *C, path string) (mockedPath string, restore func()) {
	dir := c.MkDir()

	cmd := exec.Command("tar", "xaf", path, "-C", dir)
	c.Assert(cmd.Run(), IsNil)

	return dir, MockSysfsPath(dir)
}

var _ = Suite(&defaultEnvSuite{})

type testKey struct{}

func (s *defaultEnvSuite) TestVarContext(c *C) {
	ctx := DefaultEnv.VarContext(context.WithValue(context.Background(), testKey{}, int64(10)))
	c.Assert(ctx, NotNil)

	expected := efi.WithDefaultVarsBackend(context.Background())
	c.Check(ctx.Value(efi.VarsBackendKey{}), Equals, expected.Value(efi.VarsBackendKey{}))

	// Make sure that the returned context has the right parent by testing the
	// value we attached to it.
	testVal := ctx.Value(testKey{})
	c.Assert(testVal, NotNil)
	testVali64, ok := testVal.(int64)
	c.Assert(ok, testutil.IsTrue)
	c.Check(testVali64, Equals, int64(10))
}

func (s *defaultEnvSuite) testReadEventLog(c *C, opts *efitest.LogOptions) {
	dir := c.MkDir()
	path := filepath.Join(dir, "log")

	log := efitest.NewLog(c, opts)

	logFile, err := os.Create(path)
	c.Assert(err, IsNil)
	defer logFile.Close()

	c.Check(log.Write(logFile), IsNil)

	restore := MockEventLogPath(path)
	defer restore()

	log, err = DefaultEnv.ReadEventLog()
	c.Assert(err, IsNil)

	_, err = logFile.Seek(0, io.SeekStart)
	c.Check(err, IsNil)
	expectedLog, err := tcglog.ReadLog(logFile, &tcglog.LogOptions{})
	c.Assert(err, IsNil)

	c.Check(log, DeepEquals, expectedLog)
}

func (s *defaultEnvSuite) TestReadEventLog1(c *C) {
	s.testReadEventLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
}

func (s *defaultEnvSuite) TestReadEventLog2(c *C) {
	s.testReadEventLog(c, &efitest.LogOptions{
		Algorithms:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		SecureBootDisabled: true,
	})
}

func (s *defaultEnvSuite) TestTPMDeviceRM(c *C) {
	rawDev := new(linux.RawDevice)
	restore := MockLinuxDefaultTPM2Device(rawDev, nil)
	defer restore()

	rmDev := new(linux.RMDevice)
	restore = MockLinuxRawDeviceResourceManagedDevice(c, rawDev, rmDev, nil)
	defer restore()

	dev, err := DefaultEnv.TPMDevice()
	c.Check(err, IsNil)
	c.Check(dev, Equals, rmDev)
}

func (s *defaultEnvSuite) TestTPMDeviceRaw(c *C) {
	rawDev := new(linux.RawDevice)
	restore := MockLinuxDefaultTPM2Device(rawDev, nil)
	defer restore()

	restore = MockLinuxRawDeviceResourceManagedDevice(c, rawDev, nil, linux.ErrNoResourceManagedDevice)
	defer restore()

	dev, err := DefaultEnv.TPMDevice()
	c.Check(err, IsNil)
	c.Check(dev, Equals, rawDev)
}

func (s *defaultEnvSuite) TestTPMDeviceNoDevicesErr(c *C) {
	restore := MockLinuxDefaultTPM2Device(nil, linux.ErrNoTPMDevices)
	defer restore()

	_, err := DefaultEnv.TPMDevice()
	c.Check(err, Equals, ErrNoTPM2Device)
}

func (s *defaultEnvSuite) TestTPMDeviceNoDevicesOtherErr(c *C) {
	restore := MockLinuxDefaultTPM2Device(nil, errors.New("some error"))
	defer restore()

	_, err := DefaultEnv.TPMDevice()
	c.Check(err, ErrorMatches, `some error`)
}

func (s *defaultEnvSuite) TestTPMDeviceRMOtherErr(c *C) {
	rawDev := new(linux.RawDevice)
	restore := MockLinuxDefaultTPM2Device(rawDev, nil)
	defer restore()

	restore = MockLinuxRawDeviceResourceManagedDevice(c, rawDev, nil, errors.New("some error"))
	defer restore()

	_, err := DefaultEnv.TPMDevice()
	c.Check(err, ErrorMatches, `some error`)
}

func (s *defaultEnvSuite) TestDetectVirtModeNoneAny(c *C) {
	cmd := snapd_testutil.MockCommand(c, "systemd-detect-virt", `echo none; exit 1`)
	defer cmd.Restore()

	virt, err := DefaultEnv.DetectVirtMode(DetectVirtModeAll)
	c.Check(err, IsNil)
	c.Check(virt, Equals, VirtModeNone)

	c.Check(cmd.Calls(), HasLen, 1)
	c.Check(cmd.Calls()[0], DeepEquals, []string{"systemd-detect-virt"})
}

func (s *defaultEnvSuite) TestDetectVirtModeKVMAny(c *C) {
	cmd := snapd_testutil.MockCommand(c, "systemd-detect-virt", `echo kvm`)
	defer cmd.Restore()

	virt, err := DefaultEnv.DetectVirtMode(DetectVirtModeAll)
	c.Check(err, IsNil)
	c.Check(virt, Equals, "kvm")

	c.Check(cmd.Calls(), HasLen, 1)
	c.Check(cmd.Calls()[0], DeepEquals, []string{"systemd-detect-virt"})
}

func (s *defaultEnvSuite) TestDetectVirtModeNoneContainer(c *C) {
	cmd := snapd_testutil.MockCommand(c, "systemd-detect-virt", `echo none; exit 1`)
	defer cmd.Restore()

	virt, err := DefaultEnv.DetectVirtMode(DetectVirtModeContainer)
	c.Check(err, IsNil)
	c.Check(virt, Equals, VirtModeNone)

	c.Check(cmd.Calls(), HasLen, 1)
	c.Check(cmd.Calls()[0], DeepEquals, []string{"systemd-detect-virt", "--container"})
}

func (s *defaultEnvSuite) TestDetectVirtModeLXCContainer(c *C) {
	cmd := snapd_testutil.MockCommand(c, "systemd-detect-virt", `echo lxc`)
	defer cmd.Restore()

	virt, err := DefaultEnv.DetectVirtMode(DetectVirtModeContainer)
	c.Check(err, IsNil)
	c.Check(virt, Equals, "lxc")

	c.Check(cmd.Calls(), HasLen, 1)
	c.Check(cmd.Calls()[0], DeepEquals, []string{"systemd-detect-virt", "--container"})
}

func (s *defaultEnvSuite) TestDetectVirtModeNoneVM(c *C) {
	cmd := snapd_testutil.MockCommand(c, "systemd-detect-virt", `echo none; exit 1`)
	defer cmd.Restore()

	virt, err := DefaultEnv.DetectVirtMode(DetectVirtModeVM)
	c.Check(err, IsNil)
	c.Check(virt, Equals, VirtModeNone)

	c.Check(cmd.Calls(), HasLen, 1)
	c.Check(cmd.Calls()[0], DeepEquals, []string{"systemd-detect-virt", "--vm"})
}

func (s *defaultEnvSuite) TestDetectVirtModeKVMVM(c *C) {
	cmd := snapd_testutil.MockCommand(c, "systemd-detect-virt", `echo kvm`)
	defer cmd.Restore()

	virt, err := DefaultEnv.DetectVirtMode(DetectVirtModeVM)
	c.Check(err, IsNil)
	c.Check(virt, Equals, "kvm")

	c.Check(cmd.Calls(), HasLen, 1)
	c.Check(cmd.Calls()[0], DeepEquals, []string{"systemd-detect-virt", "--vm"})
}

func (s *defaultEnvSuite) TestDetectVirtModeErr(c *C) {
	cmd := snapd_testutil.MockCommand(c, "systemd-detect-virt", `echo kvm; exit 1`)
	defer cmd.Restore()

	_, err := DefaultEnv.DetectVirtMode(DetectVirtModeAll)
	c.Check(err, ErrorMatches, `exit status 1`)

	c.Check(cmd.Calls(), HasLen, 1)
	c.Check(cmd.Calls()[0], DeepEquals, []string{"systemd-detect-virt"})
}

func (s *defaultEnvSuite) TestDevicesForClassMEI(c *C) {
	path, restore := s.mockSysfsPath(c, "testdata/sys.tar")
	defer restore()

	devices, err := DefaultEnv.DevicesForClass("mei")
	c.Check(err, IsNil)
	c.Assert(devices, HasLen, 1)
	c.Check(devices[0].Name(), Equals, "mei0")
	c.Check(devices[0].Path(), Equals, filepath.Join(path, "devices/pci00000:00/0000:00:16.0/mei/mei0"))
	c.Check(devices[0].Subsystem(), Equals, "mei")

	rc, err := devices[0].AttributeReader("fw_ver")
	c.Assert(err, IsNil)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`))
}

func (s *defaultEnvSuite) TestDevicesForClassIOMMU(c *C) {
	path, restore := s.mockSysfsPath(c, "testdata/sys.tar")
	defer restore()

	devices, err := DefaultEnv.DevicesForClass("iommu")
	c.Check(err, IsNil)
	c.Assert(devices, HasLen, 1)
	c.Check(devices[0].Name(), Equals, "dmar0")
	c.Check(devices[0].Path(), Equals, filepath.Join(path, "devices/virtual/iommu/dmar0"))
	c.Check(devices[0].Subsystem(), Equals, "iommu")
}
