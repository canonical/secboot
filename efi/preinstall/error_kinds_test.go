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

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type errorKindsSuite struct{}

var _ = Suite(&errorKindsSuite{})

func (*errorKindsSuite) TestLoadedImagesInfoArgMarshal(c *C) {
	arg := LoadedImagesInfoArg{
		{
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0,
				},
				&efi.PCIDevicePathNode{
					Function: 0x1c,
					Device:   0x2,
				},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x0,
				},
				&efi.MediaRelOffsetRangeDevicePathNode{
					StartingOffset: 0x38,
					EndingOffset:   0x11dff,
				},
			},
			DigestAlg: tpm2.HashAlgorithmSHA256,
			Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
		},
		{
			Description:    "Mock sysprep app",
			LoadOptionName: "SysPrep0001",
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x1d},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x0},
				&efi.NVMENamespaceDevicePathNode{
					NamespaceID:   0x1,
					NamespaceUUID: efi.EUI64{}},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\Dell\\sysprep.efi"),
			},
			DigestAlg: tpm2.HashAlgorithmSHA384,
			Digest:    testutil.DecodeHexString(c, "11a4d03833dafa0f99ba8d983c52b35d0b26ed97d9600313ba7c27fbecda6fccba0a1f0a94c9970e73ce7596d3a4bf44"),
		},
	}

	data, err := json.Marshal(arg)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte(`{"images":[{"device-path":{"string":"\\PciRoot(0x0)\\Pci(0x2,0x1c)\\Pci(0x0,0x0)\\Offset(0x38,0x11dff)","bytes":"AgEMANBBAwoAAAAAAQEGABwCAQEGAAAABAgYAAAAAAA4AAAAAAAAAP8dAQAAAAAAf/8EAA=="},"digest-alg":"sha256","digest":"HpSq7SrVmkQJ8yMNyirYwD744/3nfMR9x7gbuLJC8+Y="},{"description":"Mock sysprep app","load-option-name":"SysPrep0001","device-path":{"string":"\\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1,00-00-00-00-00-00-00-00)\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960)\\\\EFI\\Dell\\sysprep.efi","bytes":"AgEMANBBAwoAAAAAAQEGAAAdAQEGAAAAAxcQAAEAAAAAAAAAAAAAAAQBKgABAAAAAAgAAAAAAAAAABAAAAAAAHuU3may/SVFt1Iw1muyuWACAgQEMABcAEUARgBJAFwARABlAGwAbABcAHMAeQBzAHAAcgBlAHAALgBlAGYAaQAAAH//BAA="},"digest-alg":"sha384","digest":"EaTQODPa+g+Zuo2YPFKzXQsm7ZfZYAMTunwn++zab8y6Ch8KlMmXDnPOdZbTpL9E"}]}`))
}

func (*errorKindsSuite) TestLoadedImagesInfoUnmarshal(c *C) {
	data := []byte(`{"images":[{"device-path":{"string":"\\PciRoot(0x0)\\Pci(0x2,0x1c)\\Pci(0x0,0x0)\\Offset(0x38,0x11dff)","bytes":"AgEMANBBAwoAAAAAAQEGABwCAQEGAAAABAgYAAAAAAA4AAAAAAAAAP8dAQAAAAAAf/8EAA=="},"digest-alg":"sha256","digest":"HpSq7SrVmkQJ8yMNyirYwD744/3nfMR9x7gbuLJC8+Y="},{"description":"Mock sysprep app","load-option-name":"SysPrep0001","device-path":{"string":"\\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1,00-00-00-00-00-00-00-00)\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960)\\\\EFI\\Dell\\sysprep.efi","bytes":"AgEMANBBAwoAAAAAAQEGAAAdAQEGAAAAAxcQAAEAAAAAAAAAAAAAAAQBKgABAAAAAAgAAAAAAAAAABAAAAAAAHuU3may/SVFt1Iw1muyuWACAgQEMABcAEUARgBJAFwARABlAGwAbABcAHMAeQBzAHAAcgBlAHAALgBlAGYAaQAAAH//BAA="},"digest-alg":"sha384","digest":"EaTQODPa+g+Zuo2YPFKzXQsm7ZfZYAMTunwn++zab8y6Ch8KlMmXDnPOdZbTpL9E"}]}`)
	var arg LoadedImagesInfoArg
	c.Check(json.Unmarshal(data, &arg), IsNil)
	c.Check(arg, DeepEquals, LoadedImagesInfoArg{
		{
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0,
				},
				&efi.PCIDevicePathNode{
					Function: 0x1c,
					Device:   0x2,
				},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x0,
				},
				&efi.MediaRelOffsetRangeDevicePathNode{
					StartingOffset: 0x38,
					EndingOffset:   0x11dff,
				},
			},
			DigestAlg: tpm2.HashAlgorithmSHA256,
			Digest:    testutil.DecodeHexString(c, "1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6"),
		},
		{
			Description:    "Mock sysprep app",
			LoadOptionName: "SysPrep0001",
			DevicePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x1d},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x0},
				&efi.NVMENamespaceDevicePathNode{
					NamespaceID:   0x1,
					NamespaceUUID: efi.EUI64{}},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\Dell\\sysprep.efi"),
			},
			DigestAlg: tpm2.HashAlgorithmSHA384,
			Digest:    testutil.DecodeHexString(c, "11a4d03833dafa0f99ba8d983c52b35d0b26ed97d9600313ba7c27fbecda6fccba0a1f0a94c9970e73ce7596d3a4bf44"),
		},
	})
}

func (*errorKindsSuite) TestLoadedImagesInfoUnmarshalErrorInvalidValue(c *C) {
	data := []byte(`{"images":[{"device-path":{"string":"","bytes":""},"digest-alg":"sha256","digest":"ERrlKxeySHNIs9q8gLiVvCXkV6sFWScKyvNGAaAHcp0="}]}`)
	var arg LoadedImagesInfoArg
	c.Check(json.Unmarshal(data, &arg), ErrorMatches, `cannot decode device path: cannot decode node 0: unexpected EOF`)
}

func (*errorKindsSuite) TestLoadedImagesInfoUnmarshalErrorMissingField(c *C) {
	data := []byte(`{"foo":[{"device-path":{"string":"\\PciRoot(0x0)\\Pci(0x2,0x1c)\\Pci(0x0,0x0)\\Offset(0x38,0x11dff)","bytes":"AgEMANBBAwoAAAAAAQEGABwCAQEGAAAABAgYAAAAAAA4AAAAAAAAAP8dAQAAAAAAf/8EAA=="},"digest-alg":"sha256","digest":"HpSq7SrVmkQJ8yMNyirYwD744/3nfMR9x7gbuLJC8+Y="}]}`)
	var arg LoadedImagesInfoArg
	c.Check(json.Unmarshal(data, &arg), ErrorMatches, `no "images" field`)
}
