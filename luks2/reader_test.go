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
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/snapcore/secboot"
	internal_luks2 "github.com/snapcore/secboot/internal/luks2"
	. "github.com/snapcore/secboot/luks2"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"
)

type readerSuite struct {
	snapd_testutil.BaseTest

	containerData map[string]*mockContainerData
}

func (s *readerSuite) SetUpTest(c *C) {
	restore := MockLUKS2Ops(&Luks2Api{
		ListUnlockKeyNames:   s.listLUKS2ContainerUnlockKeyNames,
		ListRecoveryKeyNames: s.listLUKS2ContainerRecoveryKeyNames,
		NewKeyDataReader:     s.newLUKS2KeyDataReader,
	})
	s.AddCleanup(restore)

	s.containerData = make(map[string]*mockContainerData)

	restore = MockNewLuksView(func(ctx context.Context, path string) (LuksView, error) {
		data, exists := s.containerData[path]
		if !exists {
			return nil, fmt.Errorf("error with binary header: %w", internal_luks2.ErrInvalidMagic)
		}
		return newMockLuksView(data), nil
	})
	s.AddCleanup(restore)
}

func (s *readerSuite) listLUKS2ContainerUnlockKeyNames(devicePath string) ([]string, error) {
	data, exists := s.containerData[devicePath]
	if !exists {
		return nil, errors.New("unrecognized device path")
	}

	if data.listUnlockKeyNamesErr != nil {
		return nil, data.listUnlockKeyNamesErr
	}

	var out []string
	for name := range data.platformKeyslots {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func (s *readerSuite) listLUKS2ContainerRecoveryKeyNames(devicePath string) ([]string, error) {
	data, exists := s.containerData[devicePath]
	if !exists {
		return nil, errors.New("unrecognized device path")
	}

	if data.listRecoveryKeyNamesErr != nil {
		return nil, data.listRecoveryKeyNamesErr
	}

	var out []string
	for name := range data.recoveryKeyslots {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func (s *readerSuite) newLUKS2KeyDataReader(devicePath, name string) (Luks2KeyDataReader, error) {
	data, exists := s.containerData[devicePath]
	if !exists {
		return nil, errors.New("unrecognized device path")
	}

	r, exists := data.platformKeyslots[name]
	if !exists {
		return nil, errors.New("unrecognized platform keyslot name")
	}

	return r, nil
}

func (s *readerSuite) ensureContainerData(path string) {
	if _, exists := s.containerData[path]; exists {
		return
	}

	s.containerData[path] = newMockContainerData()
}

func (s *readerSuite) addRecoveryKeyslot(path, name string, slot int) {
	s.ensureContainerData(path)
	s.containerData[path].recoveryKeyslots[name] = slot
}

func (s *readerSuite) addUnlockKeyslot(path, name string, r Luks2KeyDataReader) {
	s.ensureContainerData(path)
	s.containerData[path].platformKeyslots[name] = r
}

var _ = Suite(&readerSuite{})

func (s *readerSuite) TestContainerReaderContainer(c *C) {
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	c.Check(r.Container(), Equals, container)
}

func (s *readerSuite) TestContainerReaderContainerClosed(c *C) {
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	c.Assert(r.Close(), IsNil)

	c.Check(r.Container(), IsNil)
}

func (s *readerSuite) TestContainerReaderClose(c *C) {
	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	c.Check(r.Close(), IsNil)
	c.Check(r.Close(), Equals, secboot.ErrStorageContainerClosed)
}

func (s *readerSuite) TestContainerReaderListKeyslotNames(c *C) {
	s.addRecoveryKeyslot("/dev/sda1", "default-recovery", 2)
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("", 0, 0, []byte("dummy keyslot metadata1")))
	s.addUnlockKeyslot("/dev/sda1", "default-fallback", newMockLuks2KeyDataReader("", 1, 0, []byte("dummy keyslot metadata2")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	names, err := r.ListKeyslotNames(context.Background())
	c.Check(err, IsNil)
	c.Check(names, DeepEquals, []string{"default", "default-fallback", "default-recovery"})
}

func (s *readerSuite) TestContainerReaderListKeyslotNamesDifferentPath(c *C) {
	s.addRecoveryKeyslot("/dev/nvme0n1p3", "default-recovery", 2)
	s.addUnlockKeyslot("/dev/nvme0n1p3", "default", newMockLuks2KeyDataReader("", 0, 0, []byte("dummy keyslot metadata1")))
	s.addUnlockKeyslot("/dev/nvme0n1p3", "default-fallback", newMockLuks2KeyDataReader("", 1, 0, []byte("dummy keyslot metadata2")))

	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	names, err := r.ListKeyslotNames(context.Background())
	c.Check(err, IsNil)
	c.Check(names, DeepEquals, []string{"default", "default-fallback", "default-recovery"})
}

func (s *readerSuite) TestContainerReaderListKeyslotNamesDifferentNames(c *C) {
	s.addRecoveryKeyslot("/dev/sda1", "recovery-1", 2)
	s.addUnlockKeyslot("/dev/sda1", "normal-1", newMockLuks2KeyDataReader("", 0, 0, []byte("dummy keyslot metadata1")))
	s.addUnlockKeyslot("/dev/sda1", "normal-2", newMockLuks2KeyDataReader("", 1, 0, []byte("dummy keyslot metadata2")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	names, err := r.ListKeyslotNames(context.Background())
	c.Check(err, IsNil)
	c.Check(names, DeepEquals, []string{"normal-1", "normal-2", "recovery-1"})
}

func (s *readerSuite) TestContainerReaderListKeyslotNamesCached(c *C) {
	s.addRecoveryKeyslot("/dev/sda1", "default-recovery", 2)
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("", 0, 0, []byte("dummy keyslot metadata1")))
	s.addUnlockKeyslot("/dev/sda1", "default-fallback", newMockLuks2KeyDataReader("", 1, 0, []byte("dummy keyslot metadata2")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	names, err := r.ListKeyslotNames(context.Background())
	c.Check(err, IsNil)
	c.Check(names, DeepEquals, []string{"default", "default-fallback", "default-recovery"})

	restore := MockLUKS2Ops(&Luks2Api{
		ListUnlockKeyNames: func(_ string) ([]string, error) {
			c.Error("call not expected")
			return nil, errors.New("call not expected")
		},
		ListRecoveryKeyNames: func(_ string) ([]string, error) {
			c.Error("call not expected")
			return nil, errors.New("call not expected")
		},
	})
	defer restore()

	names, err = r.ListKeyslotNames(context.Background())
	c.Check(err, IsNil)
	c.Check(names, DeepEquals, []string{"default", "default-fallback", "default-recovery"})
}

func (s *readerSuite) TestContainerReaderListKeyslotNamesClosed(c *C) {
	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	c.Assert(r.Close(), IsNil)

	_, err = r.ListKeyslotNames(context.Background())
	c.Check(err, Equals, secboot.ErrStorageContainerClosed)
}

func (s *readerSuite) TestContainerReaderReadKeyslotPlatform(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 0, 0, []byte("dummy keyslot metadata1")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	ki, err := r.ReadKeyslot(context.Background(), "default")
	c.Assert(err, IsNil)
	c.Check(ki.Type(), Equals, secboot.KeyslotTypePlatform)
	c.Check(ki.Name(), Equals, "default")
	c.Check(ki.Priority(), Equals, 0)

	c.Check(ki.Data().ReadableName(), Equals, "/dev/sda1:default")
	data, err := io.ReadAll(ki.Data())
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("dummy keyslot metadata1"))

	var tmpl KeyslotInfo
	c.Assert(ki, Implements, &tmpl)
	c.Check(ki.(KeyslotInfo).KeyslotID(), Equals, 0)
}

func (s *readerSuite) TestContainerReaderReadKeyslotPlatformDifferentName(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default-fallback", newMockLuks2KeyDataReader("/dev/sda1:default-fallback", 0, 0, []byte("dummy keyslot metadata1")))
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 1, 0, []byte("dummy keyslot metadata2")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	ki, err := r.ReadKeyslot(context.Background(), "default-fallback")
	c.Assert(err, IsNil)
	c.Check(ki.Type(), Equals, secboot.KeyslotTypePlatform)
	c.Check(ki.Name(), Equals, "default-fallback")
	c.Check(ki.Priority(), Equals, 0)

	c.Check(ki.Data().ReadableName(), Equals, "/dev/sda1:default-fallback")
	data, err := io.ReadAll(ki.Data())
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("dummy keyslot metadata1"))

	var tmpl KeyslotInfo
	c.Assert(ki, Implements, &tmpl)
	c.Check(ki.(KeyslotInfo).KeyslotID(), Equals, 0)
}

func (s *readerSuite) TestContainerReaderReadKeyslotPlatformDifferentDevice(c *C) {
	s.addUnlockKeyslot("/dev/nvme0n1p3", "default", newMockLuks2KeyDataReader("/dev/nvme0n1p3:default", 0, 0, []byte("dummy keyslot metadata1")))

	container := NewStorageContainer("/dev/nvme0n1p3", unix.Mkdev(259, 3))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	ki, err := r.ReadKeyslot(context.Background(), "default")
	c.Assert(err, IsNil)
	c.Check(ki.Type(), Equals, secboot.KeyslotTypePlatform)
	c.Check(ki.Name(), Equals, "default")
	c.Check(ki.Priority(), Equals, 0)

	c.Check(ki.Data().ReadableName(), Equals, "/dev/nvme0n1p3:default")
	data, err := io.ReadAll(ki.Data())
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("dummy keyslot metadata1"))

	var tmpl KeyslotInfo
	c.Assert(ki, Implements, &tmpl)
	c.Check(ki.(KeyslotInfo).KeyslotID(), Equals, 0)
}

func (s *readerSuite) TestContainerReaderReadKeyslotRecovery(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 0, 0, []byte("dummy keyslot metadata1")))
	s.addRecoveryKeyslot("/dev/sda1", "default-recovery", 1)

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	ki, err := r.ReadKeyslot(context.Background(), "default-recovery")
	c.Assert(err, IsNil)
	c.Check(ki.Type(), Equals, secboot.KeyslotTypeRecovery)
	c.Check(ki.Name(), Equals, "default-recovery")
	c.Check(ki.Priority(), Equals, 0)

	c.Check(ki.Data(), IsNil)

	var tmpl KeyslotInfo
	c.Assert(ki, Implements, &tmpl)
	c.Check(ki.(KeyslotInfo).KeyslotID(), Equals, 1)
}

func (s *readerSuite) TestContainerReaderReadKeyslotRecoveryDifferentKeyslotID(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 0, 0, []byte("dummy keyslot metadata1")))
	s.addRecoveryKeyslot("/dev/sda1", "default-recovery", 3)

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	ki, err := r.ReadKeyslot(context.Background(), "default-recovery")
	c.Assert(err, IsNil)
	c.Check(ki.Type(), Equals, secboot.KeyslotTypeRecovery)
	c.Check(ki.Name(), Equals, "default-recovery")
	c.Check(ki.Priority(), Equals, 0)

	c.Check(ki.Data(), IsNil)

	var tmpl KeyslotInfo
	c.Assert(ki, Implements, &tmpl)
	c.Check(ki.(KeyslotInfo).KeyslotID(), Equals, 3)
}

func (s *readerSuite) TestContainerReaderReadKeyslotPlatformDifferentPriority(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 0, 2, []byte("dummy keyslot metadata1")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	ki, err := r.ReadKeyslot(context.Background(), "default")
	c.Assert(err, IsNil)
	c.Check(ki.Type(), Equals, secboot.KeyslotTypePlatform)
	c.Check(ki.Name(), Equals, "default")
	c.Check(ki.Priority(), Equals, 2)

	c.Check(ki.Data().ReadableName(), Equals, "/dev/sda1:default")
	data, err := io.ReadAll(ki.Data())
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("dummy keyslot metadata1"))

	var tmpl KeyslotInfo
	c.Assert(ki, Implements, &tmpl)
	c.Check(ki.(KeyslotInfo).KeyslotID(), Equals, 0)
}

func (s *readerSuite) TestContainerReaderReadKeyslotPlatformDifferentKeyslotID(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 1, 0, []byte("dummy keyslot metadata1")))
	s.addUnlockKeyslot("/dev/sda1", "default-fallback", newMockLuks2KeyDataReader("/dev/sda1:default", 0, 0, []byte("dummy keyslot metadata2")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	ki, err := r.ReadKeyslot(context.Background(), "default")
	c.Assert(err, IsNil)
	c.Check(ki.Type(), Equals, secboot.KeyslotTypePlatform)
	c.Check(ki.Name(), Equals, "default")
	c.Check(ki.Priority(), Equals, 0)

	c.Check(ki.Data().ReadableName(), Equals, "/dev/sda1:default")
	data, err := io.ReadAll(ki.Data())
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("dummy keyslot metadata1"))

	var tmpl KeyslotInfo
	c.Assert(ki, Implements, &tmpl)
	c.Check(ki.(KeyslotInfo).KeyslotID(), Equals, 1)
}

func (s *readerSuite) TestContainerReaderReadKeyslotPlatformDifferentData(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default-fallback", newMockLuks2KeyDataReader("/dev/sda1:default-fallback", 1, 0, []byte("dummy keyslot metadata1")))
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 0, 0, []byte("dummy keyslot metadata2")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	ki, err := r.ReadKeyslot(context.Background(), "default")
	c.Assert(err, IsNil)
	c.Check(ki.Type(), Equals, secboot.KeyslotTypePlatform)
	c.Check(ki.Name(), Equals, "default")
	c.Check(ki.Priority(), Equals, 0)

	c.Check(ki.Data().ReadableName(), Equals, "/dev/sda1:default")
	data, err := io.ReadAll(ki.Data())
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("dummy keyslot metadata2"))

	var tmpl KeyslotInfo
	c.Assert(ki, Implements, &tmpl)
	c.Check(ki.(KeyslotInfo).KeyslotID(), Equals, 0)
}

func (s *readerSuite) TestContainerReaderReadKeyslotPlatformCached(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 0, 0, []byte("dummy keyslot metadata1")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	ki, err := r.ReadKeyslot(context.Background(), "default")
	c.Assert(err, IsNil)
	c.Check(ki.Type(), Equals, secboot.KeyslotTypePlatform)
	c.Check(ki.Name(), Equals, "default")
	c.Check(ki.Priority(), Equals, 0)

	c.Check(ki.Data().ReadableName(), Equals, "/dev/sda1:default")
	data, err := io.ReadAll(ki.Data())
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("dummy keyslot metadata1"))

	var tmpl KeyslotInfo
	c.Assert(ki, Implements, &tmpl)
	c.Check(ki.(KeyslotInfo).KeyslotID(), Equals, 0)

	restore := MockLUKS2Ops(&Luks2Api{
		ListUnlockKeyNames: func(_ string) ([]string, error) {
			c.Error("call not expected")
			return nil, errors.New("call not expected")
		},
		ListRecoveryKeyNames: func(_ string) ([]string, error) {
			c.Error("call not expected")
			return nil, errors.New("call not expected")
		},
		NewKeyDataReader: func(_, _ string) (Luks2KeyDataReader, error) {
			c.Error("call not expected")
			return nil, errors.New("call not expected")
		},
	})
	defer restore()

	ki2, err := r.ReadKeyslot(context.Background(), "default")
	c.Check(err, IsNil)
	c.Check(ki2, Equals, ki)
}

func (s *readerSuite) TestContainerReaderReadKeyslotRecoveryCached(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 0, 0, []byte("dummy keyslot metadata1")))
	s.addRecoveryKeyslot("/dev/sda1", "default-recovery", 1)

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	ki, err := r.ReadKeyslot(context.Background(), "default-recovery")
	c.Assert(err, IsNil)
	c.Check(ki.Type(), Equals, secboot.KeyslotTypeRecovery)
	c.Check(ki.Name(), Equals, "default-recovery")
	c.Check(ki.Priority(), Equals, 0)

	c.Check(ki.Data(), IsNil)

	var tmpl KeyslotInfo
	c.Assert(ki, Implements, &tmpl)
	c.Check(ki.(KeyslotInfo).KeyslotID(), Equals, 1)

	restore := MockLUKS2Ops(&Luks2Api{
		ListUnlockKeyNames: func(_ string) ([]string, error) {
			c.Error("call not expected")
			return nil, errors.New("call not expected")
		},
		ListRecoveryKeyNames: func(_ string) ([]string, error) {
			c.Error("call not expected")
			return nil, errors.New("call not expected")
		},
		NewKeyDataReader: func(_, _ string) (Luks2KeyDataReader, error) {
			c.Error("call not expected")
			return nil, errors.New("call not expected")
		},
	})
	defer restore()

	ki2, err := r.ReadKeyslot(context.Background(), "default-recovery")
	c.Check(err, IsNil)
	c.Check(ki2, Equals, ki)
}

func (s *readerSuite) TestContainerReaderReadKeyslotNotFound(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 0, 0, []byte("dummy keyslot metadata1")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	_, err = r.ReadKeyslot(context.Background(), "default-recovery")
	c.Check(err, Equals, secboot.ErrKeyslotNotFound)
}

func (s *readerSuite) TestContainerReaderReadKeyslotClosed(c *C) {
	s.addUnlockKeyslot("/dev/sda1", "default", newMockLuks2KeyDataReader("/dev/sda1:default", 0, 0, []byte("dummy keyslot metadata1")))

	container := NewStorageContainer("/dev/sda1", unix.Mkdev(8, 1))
	r, err := container.OpenRead(context.Background())
	c.Assert(err, IsNil)

	c.Assert(r.Close(), IsNil)

	_, err = r.ReadKeyslot(context.Background(), "default")
	c.Check(err, Equals, secboot.ErrStorageContainerClosed)
}
