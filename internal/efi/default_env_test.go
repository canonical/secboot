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
