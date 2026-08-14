// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2026 Canonical Ltd
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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/ppi"
	"github.com/canonical/tcglog-parser"
	"github.com/pilebones/go-udev/crawler"
	"github.com/pilebones/go-udev/netlink"
	. "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2_device"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"
)

type defaultEnvSuite struct{}

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

type mockTpmDevice struct {
	mode tpm2_device.DeviceMode
}

func (*mockTpmDevice) Open() (tpm2.Transport, error) {
	return nil, errors.New("not supported")
}

func (*mockTpmDevice) String() string {
	return "mock TPM device"
}

func (d *mockTpmDevice) Mode() tpm2_device.DeviceMode {
	return d.mode
}

func (*mockTpmDevice) PPI() (ppi.PPI, error) {
	return nil, tpm2_device.ErrNoPPI
}

func (s *defaultEnvSuite) TestTPMDevice(c *C) {
	expectedDev := &mockTpmDevice{mode: tpm2_device.DeviceModeResourceManaged}
	restore := MockDefaultTPM2Device(func(mode tpm2_device.DeviceMode) (tpm2_device.TPMDevice, error) {
		c.Assert(mode, Equals, tpm2_device.DeviceModeTryResourceManaged)
		return expectedDev, nil
	})
	defer restore()

	dev, err := DefaultEnv.TPMDevice()
	c.Check(err, IsNil)
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *defaultEnvSuite) TestTPMDeviceNoDevicesErr(c *C) {
	restore := MockDefaultTPM2Device(func(mode tpm2_device.DeviceMode) (tpm2_device.TPMDevice, error) {
		c.Check(mode, Equals, tpm2_device.DeviceModeTryResourceManaged)
		return nil, tpm2_device.ErrNoTPM2Device
	})
	defer restore()

	_, err := DefaultEnv.TPMDevice()
	c.Check(err, Equals, ErrNoTPM2Device)
}

func (s *defaultEnvSuite) TestTPMDeviceNoDevicesOtherErr(c *C) {
	restore := MockDefaultTPM2Device(func(mode tpm2_device.DeviceMode) (tpm2_device.TPMDevice, error) {
		c.Check(mode, Equals, tpm2_device.DeviceModeTryResourceManaged)
		return nil, errors.New("some error")
	})
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

func (s *defaultEnvSuite) mockCrawlerExistingDevices(c *C, expectedMatcher netlink.Matcher, responses ...any) (restore func()) {
	return MockCrawlerExistingDevices(func(queue chan crawler.Device, errs chan error, matcher netlink.Matcher) chan struct{} {
		c.Check(matcher, DeepEquals, expectedMatcher)

		quit := make(chan struct{})
		go func() {
			err := func() error {
				for {
					select {
					case <-quit:
						return errors.New("quit")
					default:
						if len(responses) == 0 {
							return nil
						}
						rsp := responses[0]
						responses = responses[1:]

						switch r := rsp.(type) {
						case crawler.Device:
							queue <- r
						case error:
							return r
						}
					}
				}
			}()
			if err != nil {
				errs <- err
			}
			close(queue)
		}()
		return quit
	})
}

func (s *defaultEnvSuite) TestEnumerateDevicesSubsystemMEI(c *C) {
	restore := s.mockCrawlerExistingDevices(
		c,
		&netlink.RuleDefinition{
			Env: map[string]string{
				"SUBSYSTEM": "mei",
			},
		},
		crawler.Device{
			KObj: "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0",
			Env: map[string]string{
				"MAJOR":     "511",
				"MINOR":     "0",
				"DEVNAME":   "mei0",
				"SUBSYSTEM": "mei",
			},
		},
		crawler.Device{
			KObj: "/sys/devices/platform/intel_vsc/mei/mei1",
			Env: map[string]string{
				"MAJOR":     "511",
				"MINOR":     "1",
				"DEVNAME":   "mei1",
				"SUBSYSTEM": "mei",
			},
		},
	)
	defer restore()

	devices, err := DefaultEnv.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "mei",
		},
	})
	c.Check(err, IsNil)
	c.Assert(devices, HasLen, 2)

	c.Check(devices[0].Path(), Equals, "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0")
	c.Check(devices[0].Properties(), DeepEquals, map[string]string{
		"MAJOR":   "511",
		"MINOR":   "0",
		"DEVNAME": "mei0",
	})
	c.Check(devices[0].Subsystem(), Equals, "mei")

	c.Check(devices[1].Path(), Equals, "/sys/devices/platform/intel_vsc/mei/mei1")
	c.Check(devices[1].Properties(), DeepEquals, map[string]string{
		"MAJOR":   "511",
		"MINOR":   "1",
		"DEVNAME": "mei1",
	})
	c.Check(devices[1].Subsystem(), Equals, "mei")
}

func (s *defaultEnvSuite) TestEnumerateDevicesSubsystemIOMMU(c *C) {
	restore := s.mockCrawlerExistingDevices(
		c,
		&netlink.RuleDefinition{
			Env: map[string]string{
				"SUBSYSTEM": "iommu",
			},
		},
		crawler.Device{
			KObj: "/sys/devices/virtual/iommu/dmar0",
			Env: map[string]string{
				"SUBSYSTEM": "iommu",
			},
		},
		crawler.Device{
			KObj: "/sys/devices/virtual/iommu/dmar1",
			Env: map[string]string{
				"SUBSYSTEM": "iommu",
			},
		},
	)
	defer restore()

	devices, err := DefaultEnv.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "iommu",
		},
	})
	c.Check(err, IsNil)
	c.Assert(devices, HasLen, 2)

	c.Check(devices[0].Path(), Equals, "/sys/devices/virtual/iommu/dmar0")
	c.Check(devices[0].Properties(), DeepEquals, map[string]string{})
	c.Check(devices[0].Subsystem(), Equals, "iommu")

	c.Check(devices[1].Path(), Equals, "/sys/devices/virtual/iommu/dmar1")
	c.Check(devices[1].Properties(), DeepEquals, map[string]string{})
	c.Check(devices[1].Subsystem(), Equals, "iommu")
}

func (s *defaultEnvSuite) TestEnumerateDevicesNotExist(c *C) {
	restore := s.mockCrawlerExistingDevices(
		c,
		&netlink.RuleDefinition{
			Env: map[string]string{
				"SUBSYSTEM": "iommu",
			},
		},
	)
	defer restore()

	devices, err := DefaultEnv.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "iommu",
		},
	})
	c.Check(err, IsNil)
	c.Assert(devices, HasLen, 0)
}

func (s *defaultEnvSuite) TestEnumerateDevicesError(c *C) {
	restore := s.mockCrawlerExistingDevices(
		c,
		&netlink.RuleDefinition{
			Env: map[string]string{
				"SUBSYSTEM": "iommu",
			},
		},
		crawler.Device{
			KObj: "/sys/devices/virtual/iommu/dmar0",
			Env: map[string]string{
				"SUBSYSTEM": "iommu",
			},
		},
		errors.New("some error"),
	)
	defer restore()

	_, err := DefaultEnv.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "iommu",
		},
	})
	c.Check(err, ErrorMatches, `some error`)
}

func (s *defaultEnvSuite) TestSysfsDeviceAttributeReader(c *C) {
	restore := s.mockCrawlerExistingDevices(
		c,
		&netlink.RuleDefinition{
			Env: map[string]string{
				"SUBSYSTEM": "mei",
			},
		},
		crawler.Device{
			KObj: "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0",
			Env: map[string]string{
				"MAJOR":     "511",
				"MINOR":     "0",
				"DEVNAME":   "mei0",
				"SUBSYSTEM": "mei",
			},
		},
	)
	defer restore()

	fwVer := []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`)

	dir := c.MkDir()
	devpath := "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0"
	c.Assert(os.MkdirAll(filepath.Join(dir, devpath), 0755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(dir, devpath, "fw_ver"), fwVer, 0444), IsNil)

	restore = MockOsOpen(func(path string) (*os.File, error) {
		return os.Open(filepath.Join(dir, path))
	})
	defer restore()

	devices, err := DefaultEnv.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "mei",
		},
	})
	c.Check(err, IsNil)
	c.Assert(devices, HasLen, 1)

	rc, err := devices[0].AttributeReader("fw_ver")
	c.Assert(err, IsNil)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, fwVer)
}

func (s *defaultEnvSuite) TestSysfsDeviceAttributeReaderNoAttr(c *C) {
	restore := s.mockCrawlerExistingDevices(
		c,
		&netlink.RuleDefinition{
			Env: map[string]string{
				"SUBSYSTEM": "mei",
			},
		},
		crawler.Device{
			KObj: "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0",
			Env: map[string]string{
				"MAJOR":     "511",
				"MINOR":     "0",
				"DEVNAME":   "mei0",
				"SUBSYSTEM": "mei",
			},
		},
	)
	defer restore()

	dir := c.MkDir()
	devpath := "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0"
	c.Assert(os.MkdirAll(filepath.Join(dir, devpath), 0755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(dir, devpath, "uevent"), []byte(`MAJOR=511
MINOR=0
DEVNAME=mei0
`), 0644), IsNil)
	c.Assert(os.Mkdir(filepath.Join(dir, devpath, "subsystem"), 0755), IsNil)

	restore = MockOsOpen(func(path string) (*os.File, error) {
		return os.Open(filepath.Join(dir, path))
	})
	defer restore()

	devices, err := DefaultEnv.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "mei",
		},
	})
	c.Check(err, IsNil)
	c.Assert(devices, HasLen, 1)

	_, err = devices[0].AttributeReader("uevent")
	c.Check(err, Equals, ErrNoDeviceAttribute)
	_, err = devices[0].AttributeReader("foo")
	c.Check(err, Equals, ErrNoDeviceAttribute)
	_, err = devices[0].AttributeReader("subsystem")
	c.Check(err, Equals, ErrNoDeviceAttribute)
}

func (s *defaultEnvSuite) TestSysfsDeviceParent(c *C) {
	restore := s.mockCrawlerExistingDevices(
		c,
		&netlink.RuleDefinition{
			Env: map[string]string{
				"SUBSYSTEM": "mei",
			},
		},
		crawler.Device{
			KObj: "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0",
			Env: map[string]string{
				"MAJOR":     "511",
				"MINOR":     "0",
				"DEVNAME":   "mei0",
				"SUBSYSTEM": "mei",
			},
		},
	)
	defer restore()

	dir := c.MkDir()
	devpath := "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0"
	c.Assert(os.MkdirAll(filepath.Join(dir, devpath), 0755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(dir, devpath, "../../uevent"), []byte(`DRIVER=mei_me
PCI_CLASS=78000
PCI_ID=8086:7E70
PCI_SUBSYS_ID=1028:0C63
PCI_SLOT_NAME=0000:00:16.0
MODALIAS=pci:v00008086d00007E70sv00001028sd00000C63bc07sc80i00
`), 0644), IsNil)

	restore = MockOsReadFile(func(path string) ([]byte, error) {
		return os.ReadFile(filepath.Join(dir, path))
	})
	defer restore()

	c.Assert(os.MkdirAll(filepath.Join(dir, "sys/bus/pci"), 0755), IsNil)
	c.Assert(os.Symlink("../../../bus/pci", filepath.Join(dir, devpath, "../../subsystem")), IsNil)

	restore = MockOsReadlink(func(path string) (string, error) {
		return os.Readlink(filepath.Join(dir, path))
	})
	defer restore()

	devices, err := DefaultEnv.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "mei",
		},
	})
	c.Check(err, IsNil)
	c.Assert(devices, HasLen, 1)

	parent, err := devices[0].Parent()
	c.Assert(err, IsNil)
	c.Assert(parent, NotNil)

	c.Check(parent.Path(), Equals, "/sys/devices/pci0000:00/0000:00:16.0")
	c.Check(parent.Properties(), DeepEquals, map[string]string{
		"DRIVER":        "mei_me",
		"PCI_CLASS":     "78000",
		"PCI_ID":        "8086:7E70",
		"PCI_SUBSYS_ID": "1028:0C63",
		"PCI_SLOT_NAME": "0000:00:16.0",
		"MODALIAS":      "pci:v00008086d00007E70sv00001028sd00000C63bc07sc80i00",
	})
	c.Check(parent.Subsystem(), Equals, "pci")
}

func (s *defaultEnvSuite) TestSysfsDeviceParentNoParent(c *C) {
	restore := s.mockCrawlerExistingDevices(
		c,
		&netlink.RuleDefinition{
			Env: map[string]string{
				"SUBSYSTEM": "pci",
				"PCI_CLASS": "78000",
			},
		},
		crawler.Device{
			KObj: "/sys/devices/pci0000:00/0000:00:16.0",
			Env: map[string]string{
				"DRIVER":        "mei_me",
				"PCI_CLASS":     "78000",
				"PCI_ID":        "8086:7E70",
				"PCI_SUBSYS_ID": "1028:0C63",
				"PCI_SLOT_NAME": "0000:00:16.0",
				"MODALIAS":      "pci:v00008086d00007E70sv00001028sd00000C63bc07sc80i00",
			},
		},
	)
	defer restore()

	dir := c.MkDir()
	devpath := "/sys/devices/pci0000:00/0000:00:16.0"
	c.Assert(os.MkdirAll(filepath.Join(dir, devpath), 0755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(dir, devpath, "../uevent"), []byte{}, 0644), IsNil)

	restore = MockOsReadFile(func(path string) ([]byte, error) {
		return os.ReadFile(filepath.Join(dir, path))
	})
	defer restore()

	restore = MockOsReadlink(func(path string) (string, error) {
		return os.Readlink(filepath.Join(dir, path))
	})
	defer restore()

	devices, err := DefaultEnv.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "pci",
			"PCI_CLASS": "78000",
		},
	})
	c.Check(err, IsNil)
	c.Assert(devices, HasLen, 1)

	parent, err := devices[0].Parent()
	c.Assert(err, IsNil)

	parent, err = parent.Parent()
	c.Check(err, IsNil)
	c.Check(parent, IsNil)
}

type defaultEnvAMD64Suite struct {
	restoreGOARCH func()
}

var _ = Suite(&defaultEnvAMD64Suite{})

func (s *defaultEnvAMD64Suite) SetUpTest(c *C) {
	s.restoreGOARCH = MockRuntimeGOARCH("amd64")
}

func (s *defaultEnvAMD64Suite) TearDownTest(c *C) {
	s.restoreGOARCH()
	s.restoreGOARCH = nil
}

func (s *defaultEnvAMD64Suite) TestCPUVendorIdentificatorIntel(c *C) {
	restore := MockCPUIDVendorIdentificator(func() string { return "GenuineIntel" })
	defer restore()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.CPUVendorIdentificator(), Equals, "GenuineIntel")
}

func (s *defaultEnvAMD64Suite) TestCPUVendorIdentificatorAMD(c *C) {
	restore := MockCPUIDVendorIdentificator(func() string { return "AuthenticAMD" })
	defer restore()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.CPUVendorIdentificator(), Equals, "AuthenticAMD")
}

func (s *defaultEnvAMD64Suite) TestCPUFamily1(c *C) {
	restore := MockCPUIDFamily(func() uint32 { return 0x12 })
	defer restore()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.CPUFamily(), Equals, uint32(0x12))
}

func (s *defaultEnvAMD64Suite) TestCPUFamily2(c *C) {
	restore := MockCPUIDFamily(func() uint32 { return 0x17 })
	defer restore()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.CPUFamily(), Equals, uint32(0x17))
}

func (s *defaultEnvAMD64Suite) TestCPUIDHasFeatureSDBGTrue(c *C) {
	restore := MockCPUIDHasFeature(func(feature uint64) bool {
		c.Check(feature, Equals, CPUIDFeatureSDBG)
		return true
	})
	defer restore()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.HasCPUIDFeature(CPUIDFeatureSDBG), testutil.IsTrue)
}

func (s *defaultEnvAMD64Suite) TestCPUIDHasFeatureSDBGFalse(c *C) {
	restore := MockCPUIDHasFeature(func(feature uint64) bool {
		c.Check(feature, Equals, CPUIDFeatureSDBG)
		return false
	})
	defer restore()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.HasCPUIDFeature(CPUIDFeatureSDBG), testutil.IsFalse)
}

func (s *defaultEnvAMD64Suite) TestCPUIDHasFeatureArbitraryBitPassedThrough(c *C) {
	// Verify that an arbitrary feature bit is forwarded unchanged to the
	// underlying hook (architecture-neutral replacement for SSE3-specific test).
	const arbitraryFeature = uint64(1) << 0 // leaf 1, ECX bit 0
	restore := MockCPUIDHasFeature(func(feature uint64) bool {
		c.Check(feature, Equals, arbitraryFeature)
		return true
	})
	defer restore()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.HasCPUIDFeature(arbitraryFeature), testutil.IsTrue)
}

func (s *defaultEnvAMD64Suite) TestReadMSR(c *C) {
	dir := c.MkDir()
	restore := MockDevcpuPath(dir)
	defer restore()

	c.Assert(os.Mkdir(filepath.Join(dir, "0"), 0755), IsNil)
	c.Assert(os.Mkdir(filepath.Join(dir, "1"), 0755), IsNil)

	data := make([]byte, 0xc80)
	var data8 [8]byte
	binary.LittleEndian.PutUint64(data8[:], 0x40000000)
	data = append(data, data8[:]...)

	c.Assert(os.WriteFile(filepath.Join(dir, "0/msr"), data, 0644), IsNil)
	c.Assert(os.WriteFile(filepath.Join(dir, "1/msr"), data, 0644), IsNil)

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	vals, err := amd64.ReadMSRs(0xc80)
	c.Assert(err, IsNil)
	c.Check(vals, DeepEquals, map[uint32]uint64{
		0: 0x40000000,
		1: 0x40000000,
	})
}

func (s *defaultEnvAMD64Suite) TestNotAMD64Host(c *C) {
	// Override the arch pinned by SetUpTest to simulate a non-amd64 host.
	// This now runs on every architecture including amd64 itself.
	restore := MockRuntimeGOARCH("arm64")
	defer restore()

	_, err := DefaultEnv.AMD64()
	c.Check(err, Equals, ErrNotAMD64Host)
}

type defaultEnvARM64Suite struct {
	snapd_testutil.BaseTest
}

var _ = Suite(&defaultEnvARM64Suite{})

func (s *defaultEnvARM64Suite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.AddCleanup(MockRuntimeGOARCH("arm64"))
}

// buildSMBIOSType4 constructs a synthetic SMBIOS type 4 (Processor Information)
// blob for testing. formattedArea contains the raw formatted area bytes
// (including the 4-byte header: type, length, handle×2); formattedArea[0]
// should be set to the desired type byte and formattedArea[1] is overwritten
// with len(formattedArea). strs are the string-set entries appended in order.
func buildSMBIOSType4(formattedArea []byte, strs ...string) []byte {
	fa := make([]byte, len(formattedArea))
	copy(fa, formattedArea)
	if len(fa) >= 2 {
		fa[1] = byte(len(fa))
	}
	out := append([]byte(nil), fa...)
	for _, s := range strs {
		out = append(out, s...)
		out = append(out, 0)
	}
	out = append(out, 0) // end-of-string-set sentinel
	return out
}

// makeValidType4Blob returns a minimal valid SMBIOS type 4 blob whose
// Manufacturer field (0x07) points to string 1 and Version field (0x10)
// points to string 2.
func makeValidType4Blob(manufacturer, version string) []byte {
	fa := make([]byte, 0x11) // 17 bytes: includes offsets 0x07 and 0x10
	fa[0] = 4                // structure type 4
	fa[0x07] = 1             // Manufacturer = string 1
	fa[0x10] = 2             // Version = string 2
	return buildSMBIOSType4(fa, manufacturer, version)
}

func (s *defaultEnvARM64Suite) TestCPUManufacturer(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			return makeValidType4Blob("NVIDIA", "GB10"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	manufacturer, err := arm64.CPUManufacturer()
	c.Check(err, IsNil)
	c.Check(manufacturer, Equals, "NVIDIA")
}

func (s *defaultEnvARM64Suite) TestCPUVersion(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			return makeValidType4Blob("NVIDIA", "GB10"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	version, err := arm64.CPUVersion()
	c.Check(err, IsNil)
	c.Check(version, Equals, "GB10")
}

func (s *defaultEnvARM64Suite) TestCPUManufacturerWhitespaceTrimming(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			return makeValidType4Blob("\t  Example Manufacturer  \t", "Example Version"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	manufacturer, err := arm64.CPUManufacturer()
	c.Check(err, IsNil)
	c.Check(manufacturer, Equals, "Example Manufacturer")
}

func (s *defaultEnvARM64Suite) TestCPUVersionWhitespaceTrimming(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			return makeValidType4Blob("Example Manufacturer", "\t  Example Version  \t"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	version, err := arm64.CPUVersion()
	c.Check(err, IsNil)
	c.Check(version, Equals, "Example Version")
}

func (s *defaultEnvARM64Suite) TestCPUManufacturerReadError(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		return nil, errors.New("some error")
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	_, err = arm64.CPUManufacturer()
	c.Check(err, ErrorMatches, "cannot read /sys/firmware/dmi/entries/4-0/raw: some error")
}

func (s *defaultEnvARM64Suite) TestCPUVersionReadError(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		return nil, errors.New("some error")
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	_, err = arm64.CPUVersion()
	c.Check(err, ErrorMatches, "cannot read /sys/firmware/dmi/entries/4-0/raw: some error")
}

func (s *defaultEnvARM64Suite) TestCPUManufacturerWrongStructureType(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			fa := make([]byte, 0x11)
			fa[0] = 1    // wrong type (System Information, not Processor Information)
			fa[0x07] = 1 // Manufacturer = string 1
			fa[0x10] = 2 // Version = string 2
			return buildSMBIOSType4(fa, "NVIDIA", "GB10"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	_, err = arm64.CPUManufacturer()
	c.Check(err, ErrorMatches, "unexpected SMBIOS structure type 1 \\(expected 4\\)")
}

func (s *defaultEnvARM64Suite) TestCPUManufacturerTooShortForHeader(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			return []byte{4, 3, 0}, nil // only 3 bytes, not enough for header
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	_, err = arm64.CPUManufacturer()
	c.Check(err, ErrorMatches, "SMBIOS structure too short for header: have 3 bytes")
}

func (s *defaultEnvARM64Suite) TestCPUManufacturerFormattedAreaTooShort(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			// Formatted area is only 7 bytes; Manufacturer is at 0x07,
			// so formattedLen (7) <= fieldOffset (7): field not present.
			fa := make([]byte, 7)
			fa[0] = 4
			fa[0x06] = 1 // not the manufacturer field, just filler
			return buildSMBIOSType4(fa, "NVIDIA"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	_, err = arm64.CPUManufacturer()
	c.Check(err, ErrorMatches, "SMBIOS structure too short to contain field at offset 0x07: formatted area length is 7")
}

func (s *defaultEnvARM64Suite) TestCPUManufacturerDataTruncated(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			// Length field says 0x11 bytes but we only provide 8.
			data := make([]byte, 8)
			data[0] = 4
			data[1] = 0x11 // claims 17-byte formatted area
			data[0x07] = 1
			return data, nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	_, err = arm64.CPUManufacturer()
	c.Check(err, ErrorMatches, "SMBIOS structure data truncated: have 8 bytes, formatted area length is 17")
}

func (s *defaultEnvARM64Suite) TestCPUManufacturerOutOfRangeStringIndex(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			fa := make([]byte, 0x11)
			fa[0] = 4
			fa[0x07] = 3 // Manufacturer = string 3, but only 2 strings exist
			fa[0x10] = 2
			return buildSMBIOSType4(fa, "NVIDIA", "GB10"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	_, err = arm64.CPUManufacturer()
	c.Check(err, ErrorMatches, "SMBIOS string index 3 is out of range")
}

func (s *defaultEnvARM64Suite) TestCPUManufacturerUnsetStringIndex(c *C) {
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			fa := make([]byte, 0x11)
			fa[0] = 4
			fa[0x07] = 0 // Manufacturer unset (index 0)
			fa[0x10] = 1
			return buildSMBIOSType4(fa, "GB10"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	_, err = arm64.CPUManufacturer()
	c.Check(err, ErrorMatches, "SMBIOS field at offset 0x07 is unset")
}

// makeRealisticType4Blob returns a SMBIOS type 4 blob laid out like the ones
// observed on real NVIDIA Spark hardware: a 0x32 byte formatted area, with
// Socket Designation as string 1, Manufacturer as string 2, Version as string
// 3, and further strings following Version.
func makeRealisticType4Blob(manufacturer, version string) []byte {
	fa := make([]byte, 0x32) // 50 bytes, as reported by dmidecode on DGX Spark and RTX Spark
	fa[0] = 4                // structure type 4
	fa[0x04] = 1             // Socket Designation = string 1
	fa[0x07] = 2             // Manufacturer = string 2
	fa[0x10] = 3             // Version = string 3
	return buildSMBIOSType4(fa, "CPU01", manufacturer, version, "NA", "NA", "Spark")
}

func (s *defaultEnvARM64Suite) TestCPUManufacturerAndVersionDGXSparkLayout(c *C) {
	// Regression test using the structure shape reported by a real DGX Spark,
	// where Version is string 3 and is followed by more strings.
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			return makeRealisticType4Blob("NVIDIA", "GB10"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	manufacturer, err := arm64.CPUManufacturer()
	c.Check(err, IsNil)
	c.Check(manufacturer, Equals, "NVIDIA")

	version, err := arm64.CPUVersion()
	c.Check(err, IsNil)
	c.Check(version, Equals, "GB10")
}

func (s *defaultEnvARM64Suite) TestCPUManufacturerAndVersionRTXSparkLayout(c *C) {
	// Regression test using the structure shape and version string reported by
	// a real RTX Spark.
	restore := MockOsReadFile(func(path string) ([]byte, error) {
		if path == "/sys/firmware/dmi/entries/4-0/raw" {
			return makeRealisticType4Blob("NVIDIA", "NVIDIA RTX Spark N1X (5120-core GPU, 18-core CPU)"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	defer restore()

	arm64, err := DefaultEnv.ARM64()
	c.Assert(err, IsNil)

	manufacturer, err := arm64.CPUManufacturer()
	c.Check(err, IsNil)
	c.Check(manufacturer, Equals, "NVIDIA")

	version, err := arm64.CPUVersion()
	c.Check(err, IsNil)
	c.Check(version, Equals, "NVIDIA RTX Spark N1X (5120-core GPU, 18-core CPU)")
}

func (s *defaultEnvARM64Suite) TestNotARM64Host(c *C) {
	// Override the arm64 mock installed by SetUpTest: on a non-arm64 host
	// ARM64() must return ErrNotARM64Host.
	restore := MockRuntimeGOARCH("amd64")
	defer restore()

	_, err := DefaultEnv.ARM64()
	c.Check(err, Equals, ErrNotARM64Host)
}
