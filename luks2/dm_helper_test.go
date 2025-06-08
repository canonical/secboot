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

	symlinks map[string]string
	info     map[string]unix.Stat_t
	tables   string
	cmd      *snapd_testutil.MockCmd
}

func (s *dmHelperSuite) SetUpTest(c *C) {
	s.symlinks = make(map[string]string)
	s.info = make(map[string]unix.Stat_t)

	restore := MockFilepathEvalSymlinks(s.symlinks)
	s.AddCleanup(restore)

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

func (s *dmHelperSuite) addSymlink(target, link string) {
	s.symlinks[link] = target
}

func (s *dmHelperSuite) addFile(path string, st unix.Stat_t) {
	s.info[path] = st
}

func (s *dmHelperSuite) addTable(c *C, path, table string) {
	c.Assert(os.MkdirAll(filepath.Dir(filepath.Join(s.tables, path)), 0755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(s.tables, path), []byte(table), 0644), IsNil)
}

var _ = Suite(&dmHelperSuite{})

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceCrypt(c *C) {
	s.addSymlink("/sys/devices/pci0000:00/0000:00:0e.0/pci10000:e0/10000:e0:06.0/10000:e1:00.0/nvme/nvme0/nvme0n1/nvme0n1p3", "/sys/dev/block/259:3")
	s.addFile("/sys/dev/block/252:0/dm", unix.Stat_t{})
	s.addFile("/dev/dm-0", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, 0)})
	s.addTable(c, "/dev/dm-0", "0 7807602688 crypt aes-xts-plain64 :64:logon:cryptsetup:ef2d659a-179b-4949-9caf-bd81f0e85272-d0 0 259:3 32768")

	path, err := SourceDeviceFromDMDevice(context.Background(), "/dev/dm-0")
	c.Check(err, IsNil)
	c.Check(path, Equals, "/dev/nvme0n1p3")

	c.Assert(s.cmd.Calls(), HasLen, 1)
	c.Check(s.cmd.Calls()[0], DeepEquals, []string{"dmsetup", "table", "/dev/dm-0"})
}

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceLinear(c *C) {
	s.addSymlink("/sys/devices/virtual/block/dm-0", "/sys/dev/block/252:0")
	s.addFile("/sys/dev/block/252:1/dm", unix.Stat_t{})
	s.addFile("/dev/dm-1", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, 1)})
	s.addTable(c, "/dev/dm-1", "0 7807598592 linear 252:0 2048")

	path, err := SourceDeviceFromDMDevice(context.Background(), "/dev/dm-1")
	c.Check(err, IsNil)
	c.Check(path, Equals, "/dev/dm-0")

	c.Assert(s.cmd.Calls(), HasLen, 1)
	c.Check(s.cmd.Calls()[0], DeepEquals, []string{"dmsetup", "table", "/dev/dm-1"})
}

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceStackedLinearAndCrypt(c *C) {
	s.addSymlink("/sys/devices/virtual/block/dm-0", "/sys/dev/block/252:0")
	s.addSymlink("/sys/devices/pci0000:00/0000:00:0e.0/pci10000:e0/10000:e0:06.0/10000:e1:00.0/nvme/nvme0/nvme0n1/nvme0n1p3", "/sys/dev/block/259:3")
	s.addFile("/sys/dev/block/252:0/dm", unix.Stat_t{})
	s.addFile("/sys/dev/block/252:1/dm", unix.Stat_t{})
	s.addFile("/dev/dm-0", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, 0)})
	s.addFile("/dev/dm-1", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, 1)})
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
	s.addFile("/dev/null", unix.Stat_t{Mode: unix.S_IFCHR, Rdev: unix.Mkdev(1, 3)})

	_, err := SourceDeviceFromDMDevice(context.Background(), "/dev/null")
	c.Check(err, Equals, ErrNotDMBlockDevice)
}

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceNotDMDevice(c *C) {
	s.addFile("/dev/nvme0n1p2", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(259, 2)})

	_, err := SourceDeviceFromDMDevice(context.Background(), "/dev/nvme0n1p2")
	c.Check(err, Equals, ErrNotDMBlockDevice)
}

func (s *dmHelperSuite) TestSourceDeviceFromDMDeviceUnrecognizedTarget(c *C) {
	s.addFile("/dev/dm-0", unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(252, 0)})
	s.addFile("/sys/dev/block/252:0/dm", unix.Stat_t{})
	s.addTable(c, "/dev/dm-0", "0 7807602688 flakey 259:3 0 60 1")

	_, err := SourceDeviceFromDMDevice(context.Background(), "/dev/dm-0")
	c.Check(err, Equals, ErrUnsupportedTargetType)

	c.Assert(s.cmd.Calls(), HasLen, 1)
	c.Check(s.cmd.Calls()[0], DeepEquals, []string{"dmsetup", "table", "/dev/dm-0"})
}
