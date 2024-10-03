//go:build amd64

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
	"encoding/binary"
	"os"
	"path/filepath"

	"github.com/canonical/cpuid"
	. "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type defaultEnvAMD64Suite struct{}

var _ = Suite(&defaultEnvAMD64Suite{})

func (s *defaultEnvAMD64Suite) TestCPUVendorIdentificatorIntel(c *C) {
	orig := cpuid.VendorIdentificatorString
	cpuid.VendorIdentificatorString = "GenuineIntel"
	defer func() { cpuid.VendorIdentificatorString = orig }()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.CPUVendorIdentificator(), Equals, "GenuineIntel")
}

func (s *defaultEnvAMD64Suite) TestCPUVendorIdentificatorAMD(c *C) {
	orig := cpuid.VendorIdentificatorString
	cpuid.VendorIdentificatorString = "AuthenticAMD"
	defer func() { cpuid.VendorIdentificatorString = orig }()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.CPUVendorIdentificator(), Equals, "AuthenticAMD")
}

func (s *defaultEnvAMD64Suite) TestCPUIDHasFeatureSDBGTrue(c *C) {
	restore := MockCPUIDHasFeature(func(feature uint64) bool {
		c.Check(feature, Equals, cpuid.SDBG)
		return true
	})
	defer restore()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.HasCPUIDFeature(cpuid.SDBG), testutil.IsTrue)
}

func (s *defaultEnvAMD64Suite) TestCPUIDHasFeatureSDBGFalse(c *C) {
	restore := MockCPUIDHasFeature(func(feature uint64) bool {
		c.Check(feature, Equals, cpuid.SDBG)
		return false
	})
	defer restore()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.HasCPUIDFeature(cpuid.SDBG), testutil.IsFalse)
}

func (s *defaultEnvAMD64Suite) TestCPUIDHasFeatureSSE3True(c *C) {
	restore := MockCPUIDHasFeature(func(feature uint64) bool {
		c.Check(feature, Equals, cpuid.SSE3)
		return true
	})
	defer restore()

	amd64, err := DefaultEnv.AMD64()
	c.Assert(err, IsNil)
	c.Check(amd64.HasCPUIDFeature(cpuid.SSE3), testutil.IsTrue)
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
