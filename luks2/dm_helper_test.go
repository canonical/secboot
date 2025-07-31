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

package luks2_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/snapcore/secboot/internal/testutil"
	. "github.com/snapcore/secboot/luks2"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"
)

type fileInfo struct{}

func (*fileInfo) Name() string       { return "" }
func (*fileInfo) Size() int64        { return 0 }
func (*fileInfo) Mode() os.FileMode  { return 0 }
func (*fileInfo) ModTime() time.Time { return time.Time{} }
func (*fileInfo) IsDir() bool        { return false }
func (*fileInfo) Sys() any           { return nil }

type dmHelperSuite struct {
	snapd_testutil.BaseTest

	info   map[string]unix.Stat_t
	sysfs  string
	tables string
	cmd    *snapd_testutil.MockCmd
}

func (s *dmHelperSuite) SetUpTest(c *C) {
	s.info = make(map[string]unix.Stat_t)

	s.sysfs = c.MkDir()
	restore := MockSysfsRoot(s.sysfs)

	restore = MockOsStat(func(path string) (os.FileInfo, error) {
		_, exists := s.info[path]
		if !exists {
			return nil, &os.PathError{Op: "stat", Path: path, Err: syscall.ENOENT}
		}
		return new(fileInfo), nil
	})
	s.AddCleanup(restore)

	restore = MockUnixStat(func(path string, st *unix.Stat_t) error {
		s, exists := s.info[path]
		if !exists {
			return syscall.ENOENT
		}
		*st = s
		return nil
	})
	s.AddCleanup(restore)

	s.tables = c.MkDir()

	s.cmd = snapd_testutil.MockCommand(c, "dmsetup", fmt.Sprintf(`cat %s/"$2"`, s.tables))
	s.AddCleanup(s.cmd.Restore)
}

func (s *dmHelperSuite) addSysfsFileContents(c *C, path string, contents []byte) {
	c.Assert(os.MkdirAll(filepath.Dir(filepath.Join(s.sysfs, path)), 0755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(s.sysfs, path), contents, 0644), IsNil)
}

func (s *dmHelperSuite) addFileInfo(path string, st unix.Stat_t) {
	s.info[path] = st
}

func (s *dmHelperSuite) addTable(c *C, path, table string) {
	c.Assert(os.MkdirAll(filepath.Dir(filepath.Join(s.tables, path)), 0755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(s.tables, path), []byte(table), 0644), IsNil)
}

var _ = Suite(&dmHelperSuite{})

func (s *dmHelperSuite) TestDecodeKernelSysfsUeventAttr1(c *C) {
	s.addSysfsFileContents(c, "dev/block/252:0/uevent", []byte(`MAJOR=252
MINOR=0
DEVNAME=dm-0
DEVTYPE=disk
DISKSEQ=10
`))

	env, err := DecodeKernelSysfsUeventAttr("dev/block/252:0")
	c.Assert(err, IsNil)
	c.Check(env, DeepEquals, map[string]string{
		"DEVNAME": "dm-0",
		"DEVTYPE": "disk",
		"DISKSEQ": "10",
		"MAJOR":   "252",
		"MINOR":   "0",
	})
}

func (s *dmHelperSuite) TestDecodeKernelSysfsUeventAttr2(c *C) {
	s.addSysfsFileContents(c, "dev/block/259:3/uevent", []byte(`MAJOR=259
MINOR=3
DEVNAME=nvme0n1p3
DEVTYPE=partition
DISKSEQ=9
PARTN=3
PARTUUID=4ec529c3-02c9-4f0d-a73f-f1036b8cf1fb
`))

	env, err := DecodeKernelSysfsUeventAttr("dev/block/259:3")
	c.Assert(err, IsNil)
	c.Check(env, DeepEquals, map[string]string{
		"DEVNAME":  "nvme0n1p3",
		"DEVTYPE":  "partition",
		"DISKSEQ":  "9",
		"MAJOR":    "259",
		"MINOR":    "3",
		"PARTN":    "3",
		"PARTUUID": "4ec529c3-02c9-4f0d-a73f-f1036b8cf1fb",
	})
}

func (s *dmHelperSuite) TestDecodeKernelSysfsUeventAttrNotExist(c *C) {
	_, err := DecodeKernelSysfsUeventAttr("devices/pci0000:00/0000:00:0e.0/pci10000:e0/10000:e0:06.0/10000:e1:00.0/nvme/")
	c.Check(os.IsNotExist(err), testutil.IsTrue)
}

func (s *dmHelperSuite) TestDecodeKernelSysfsUeventAttrInvalidEntry(c *C) {
	s.addSysfsFileContents(c, "dev/block/259:3/uevent", []byte(`MAJOR=259
MINOR=3
DEVNAME=nvmen01p3
DEVTYPE=disk
DISKSEQ=10
PARTN=3
PARTUUID
`))

	_, err := DecodeKernelSysfsUeventAttr("dev/block/259:3")
	c.Assert(err, ErrorMatches, `invalid entry 6: \"PARTUUID\"`)
}

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceCrypt(c *C) {
	s.addSysfsFileContents(c, "dev/block/259:3/uevent", []byte(`MAJOR=259
MINOR=3
DEVNAME=nvme0n1p3
DEVTYPE=disk
DISKSEQ=10
PARTN=3
PARTUUID=4ec529c3-02c9-4f0d-a73f-f1036b8cf1fb
`))
	s.addFileInfo(filepath.Join(s.sysfs, "dev/block/252:0/dm"), unix.Stat_t{})
	s.addFileInfo("/dev/dm-0", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, 0)})
	s.addTable(c, "/dev/dm-0", "0 7807602688 crypt aes-xts-plain64 :64:logon:cryptsetup:ef2d659a-179b-4949-9caf-bd81f0e85272-d0 0 259:3 32768")

	path, err := SourceDeviceFromDMDevice(context.Background(), "/dev/dm-0")
	c.Check(err, IsNil)
	c.Check(path, Equals, "/dev/nvme0n1p3")

	c.Assert(s.cmd.Calls(), HasLen, 1)
	c.Check(s.cmd.Calls()[0], DeepEquals, []string{"dmsetup", "table", "/dev/dm-0"})
}

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceLinear(c *C) {
	s.addSysfsFileContents(c, "dev/block/252:0/uevent", []byte(`MAJOR=252
MINOR=0
DEVNAME=dm-0
DEVTYPE=disk
DISKSEQ=10
`))
	s.addFileInfo(filepath.Join(s.sysfs, "dev/block/252:1/dm"), unix.Stat_t{})
	s.addFileInfo("/dev/dm-1", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, 1)})
	s.addTable(c, "/dev/dm-1", "0 7807598592 linear 252:0 2048")

	path, err := SourceDeviceFromDMDevice(context.Background(), "/dev/dm-1")
	c.Check(err, IsNil)
	c.Check(path, Equals, "/dev/dm-0")

	c.Assert(s.cmd.Calls(), HasLen, 1)
	c.Check(s.cmd.Calls()[0], DeepEquals, []string{"dmsetup", "table", "/dev/dm-1"})
}

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceStackedLinearAndCrypt(c *C) {
	s.addSysfsFileContents(c, "dev/block/252:0/uevent", []byte(`MAJOR=252
MINOR=0
DEVNAME=dm-0
DEVTYPE=disk
DISKSEQ=10
`))
	s.addSysfsFileContents(c, "dev/block/259:3/uevent", []byte(`MAJOR=259
MINOR=3
DEVNAME=nvme0n1p3
DEVTYPE=disk
DISKSEQ=10
PARTN=3
PARTUUID=4ec529c3-02c9-4f0d-a73f-f1036b8cf1fb
`))
	s.addFileInfo(filepath.Join(s.sysfs, "dev/block/252:0/dm"), unix.Stat_t{})
	s.addFileInfo(filepath.Join(s.sysfs, "dev/block/252:1/dm"), unix.Stat_t{})
	s.addFileInfo("/dev/dm-0", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, 0)})
	s.addFileInfo("/dev/dm-1", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, 1)})
	s.addTable(c, "/dev/dm-0", "0 7807602688 crypt aes-xts-plain64 :64:logon:cryptsetup:ef2d659a-179b-4949-9caf-bd81f0e85272-d0 0 259:3 32768")
	s.addTable(c, "/dev/dm-1", "0 7807598592 linear 252:0 2048")

	path, err := SourceDeviceFromDMDevice(context.Background(), "/dev/dm-1")
	c.Check(err, IsNil)
	c.Check(path, Equals, "/dev/dm-0")

	path, err = SourceDeviceFromDMDevice(context.Background(), path)
	c.Check(err, IsNil)
	c.Check(path, Equals, "/dev/nvme0n1p3")

	c.Check(s.cmd.Calls(), DeepEquals, [][]string{
		[]string{"dmsetup", "table", "/dev/dm-1"},
		[]string{"dmsetup", "table", "/dev/dm-0"},
	})
}

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceNotBlockDev(c *C) {
	s.addFileInfo("/dev/null", unix.Stat_t{Mode: unix.S_IFCHR, Rdev: unix.Mkdev(1, 3)})

	_, err := SourceDeviceFromDMDevice(context.Background(), "/dev/null")
	c.Check(err, Equals, ErrNotDMBlockDevice)
}

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceNotDMDevice(c *C) {
	s.addFileInfo("/dev/nvme0n1p2", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(259, 2)})

	_, err := SourceDeviceFromDMDevice(context.Background(), "/dev/nvme0n1p2")
	c.Check(err, Equals, ErrNotDMBlockDevice)
}

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceUnrecognizedTarget(c *C) {
	s.addFileInfo("/dev/dm-0", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, 0)})
	s.addFileInfo(filepath.Join(s.sysfs, "dev/block/252:0/dm"), unix.Stat_t{})
	s.addTable(c, "/dev/dm-0", "0 7807602688 flakey 259:3 0 60 1")

	_, err := SourceDeviceFromDMDevice(context.Background(), "/dev/dm-0")
	c.Check(err, Equals, ErrUnsupportedTargetType)

	c.Assert(s.cmd.Calls(), HasLen, 1)
	c.Check(s.cmd.Calls()[0], DeepEquals, []string{"dmsetup", "table", "/dev/dm-0"})
}
