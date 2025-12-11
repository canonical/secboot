// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type errorsSuite struct{}

var _ = Suite(&errorsSuite{})

func (s *errorsSuite) TestJoinError(c *C) {
	err := JoinErrors(
		errors.New("some error 1"),
		errors.New(`some error 2
across more than one line`),
		errors.New("some error 3"),
		errors.New(`some error 4
which also spans across
multiple lines
`),
	)

	c.Check(err.Error(), Equals, `4 errors detected:
- some error 1
- some error 2
  across more than one line
- some error 3
- some error 4
  which also spans across
  multiple lines
`)
}

func (s *errorsSuite) TestJoinErrorOneError(c *C) {
	err := JoinErrors(errors.New("some error"))
	c.Check(err.Error(), Equals, `some error`)
}

func (s *errorsSuite) TestLoadedImageInfoMarshalJSON1(c *C) {
	info := &LoadedImageInfo{
		Format: LoadedImageFormatPE,
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
	}

	data, err := json.Marshal(info)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte(`{"format":"pe","device-path":{"string":"\\PciRoot(0x0)\\Pci(0x2,0x1c)\\Pci(0x0,0x0)\\Offset(0x38,0x11dff)","bytes":"AgEMANBBAwoAAAAAAQEGABwCAQEGAAAABAgYAAAAAAA4AAAAAAAAAP8dAQAAAAAAf/8EAA=="},"digest-alg":"sha256","digest":"HpSq7SrVmkQJ8yMNyirYwD744/3nfMR9x7gbuLJC8+Y="}`))
}

func (s *errorsSuite) TestLoadedImageInfoMarshalJSON2(c *C) {
	info := &LoadedImageInfo{
		Format:    LoadedImageFormatBlob,
		DigestAlg: tpm2.HashAlgorithmSHA256,
		Digest:    testutil.DecodeHexString(c, "111ae52b17b2487348b3dabc80b895bc25e457ab0559270acaf34601a007729d"),
	}

	data, err := json.Marshal(info)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte(`{"format":"blob","device-path":{"string":"","bytes":"f/8EAA=="},"digest-alg":"sha256","digest":"ERrlKxeySHNIs9q8gLiVvCXkV6sFWScKyvNGAaAHcp0="}`))
}

func (s *errorsSuite) TestLoadedImageInfoMarshalJSON3(c *C) {
	info := &LoadedImageInfo{
		Format:         LoadedImageFormatPE,
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
	}

	data, err := json.Marshal(info)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte(`{"format":"pe","description":"Mock sysprep app","load-option-name":"SysPrep0001","device-path":{"string":"\\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1,00-00-00-00-00-00-00-00)\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960)\\\\EFI\\Dell\\sysprep.efi","bytes":"AgEMANBBAwoAAAAAAQEGAAAdAQEGAAAAAxcQAAEAAAAAAAAAAAAAAAQBKgABAAAAAAgAAAAAAAAAABAAAAAAAHuU3may/SVFt1Iw1muyuWACAgQEMABcAEUARgBJAFwARABlAGwAbABcAHMAeQBzAHAAcgBlAHAALgBlAGYAaQAAAH//BAA="},"digest-alg":"sha384","digest":"EaTQODPa+g+Zuo2YPFKzXQsm7ZfZYAMTunwn++zab8y6Ch8KlMmXDnPOdZbTpL9E"}`))
}

func (s *errorsSuite) TestLoadedImageInfoUnmashalJSON1(c *C) {
	data := []byte(`{"format":"pe","device-path":{"string":"\\PciRoot(0x0)\\Pci(0x2,0x1c)\\Pci(0x0,0x0)\\Offset(0x38,0x11dff)","bytes":"AgEMANBBAwoAAAAAAQEGABwCAQEGAAAABAgYAAAAAAA4AAAAAAAAAP8dAQAAAAAAf/8EAA=="},"digest-alg":"sha256","digest":"HpSq7SrVmkQJ8yMNyirYwD744/3nfMR9x7gbuLJC8+Y="}`)

	var info *LoadedImageInfo
	c.Check(json.Unmarshal(data, &info), IsNil)
	c.Check(info, DeepEquals, &LoadedImageInfo{
		Format: LoadedImageFormatPE,
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
	})
}

func (s *errorsSuite) TestLoadedImageInfoUnmashalJSON2(c *C) {
	data := []byte(`{"format":"blob","device-path":{"string":"","bytes":"f/8EAA=="},"digest-alg":"sha256","digest":"ERrlKxeySHNIs9q8gLiVvCXkV6sFWScKyvNGAaAHcp0="}`)

	var info *LoadedImageInfo
	c.Check(json.Unmarshal(data, &info), IsNil)
	c.Check(info, DeepEquals, &LoadedImageInfo{
		Format:    LoadedImageFormatBlob,
		DigestAlg: tpm2.HashAlgorithmSHA256,
		Digest:    testutil.DecodeHexString(c, "111ae52b17b2487348b3dabc80b895bc25e457ab0559270acaf34601a007729d"),
	})
}

func (s *errorsSuite) TestLoadedImageInfoUnmashalJSON3(c *C) {
	data := []byte(`{"format":"pe","description":"Mock sysprep app","load-option-name":"SysPrep0001","device-path":{"string":"\\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1,00-00-00-00-00-00-00-00)\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960)\\\\EFI\\Dell\\sysprep.efi","bytes":"AgEMANBBAwoAAAAAAQEGAAAdAQEGAAAAAxcQAAEAAAAAAAAAAAAAAAQBKgABAAAAAAgAAAAAAAAAABAAAAAAAHuU3may/SVFt1Iw1muyuWACAgQEMABcAEUARgBJAFwARABlAGwAbABcAHMAeQBzAHAAcgBlAHAALgBlAGYAaQAAAH//BAA="},"digest-alg":"sha384","digest":"EaTQODPa+g+Zuo2YPFKzXQsm7ZfZYAMTunwn++zab8y6Ch8KlMmXDnPOdZbTpL9E"}`)

	var info *LoadedImageInfo
	c.Check(json.Unmarshal(data, &info), IsNil)
	c.Check(info, DeepEquals, &LoadedImageInfo{
		Format:         LoadedImageFormatPE,
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
	})
}

func (s *errorsSuite) TestLoadedImageInfoUnmashalErrInvalidValue(c *C) {
	data := []byte(`{"format":"blob","device-path":{"string":"","bytes":"f/8EAA=="},"digest-alg":"","digest":"ERrlKxeySHNIs9q8gLiVvCXkV6sFWScKyvNGAaAHcp0="}`)

	var info *LoadedImageInfo
	c.Check(json.Unmarshal(data, &info), ErrorMatches, `unrecognized hash algorithm`)
}

func (s *errorsSuite) TestLoadedImageInfoUnmashalErrInvalidDevicePath(c *C) {
	data := []byte(`{"format":"blob","device-path":{"string":"","bytes":""},"digest-alg":"sha256","digest":"ERrlKxeySHNIs9q8gLiVvCXkV6sFWScKyvNGAaAHcp0="}`)

	var info *LoadedImageInfo
	c.Check(json.Unmarshal(data, &info), ErrorMatches, `cannot decode device path: cannot decode node 0: unexpected EOF`)
}

func (s *errorsSuite) TestLoadedImageInfoMarshalString1(c *C) {
	info := &LoadedImageInfo{
		Format: LoadedImageFormatPE,
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
	}

	c.Check(info.String(), Equals, `[no description] path=\PciRoot(0x0)\Pci(0x2,0x1c)\Pci(0x0,0x0)\Offset(0x38,0x11dff) authenticode-digest=TPM_ALG_SHA256:1e94aaed2ad59a4409f3230dca2ad8c03ef8e3fde77cc47dc7b81bb8b242f3e6`)
}

func (s *errorsSuite) TestLoadedImageInfoMarshalString2(c *C) {
	info := &LoadedImageInfo{
		Format:    LoadedImageFormatBlob,
		DigestAlg: tpm2.HashAlgorithmSHA256,
		Digest:    testutil.DecodeHexString(c, "111ae52b17b2487348b3dabc80b895bc25e457ab0559270acaf34601a007729d"),
	}

	c.Check(info.String(), Equals, `[no description] digest=TPM_ALG_SHA256:111ae52b17b2487348b3dabc80b895bc25e457ab0559270acaf34601a007729d`)
}

func (s *errorsSuite) TestLoadedImageInfoMarshalString3(c *C) {
	info := &LoadedImageInfo{
		Format:         LoadedImageFormatPE,
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
	}

	c.Check(info.String(), Equals, `Mock sysprep app path=\PciRoot(0x0)\Pci(0x1d,0x0)\Pci(0x0,0x0)\NVMe(0x1,00-00-00-00-00-00-00-00)\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960)\\EFI\Dell\sysprep.efi authenticode-digest=TPM_ALG_SHA384:11a4d03833dafa0f99ba8d983c52b35d0b26ed97d9600313ba7c27fbecda6fccba0a1f0a94c9970e73ce7596d3a4bf44 load-option=SysPrep0001`)
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorNoArgsOrActions(c *C) {
	kind := ErrorKind("foo")
	rawErr := errors.New("some error")
	err := NewWithKindAndActionsError(kind, nil, nil, rawErr)
	c.Check(err, DeepEquals, NewWithKindAndActionsErrorForTest(kind, nil, nil, rawErr))
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorNoArgs(c *C) {
	kind := ErrorKind("bar")
	actions := []Action{"action1", "action2"}
	rawErr := errors.New("another error")
	err := NewWithKindAndActionsError(kind, nil, actions, rawErr)
	c.Check(err, DeepEquals, NewWithKindAndActionsErrorForTest(kind, nil, actions, rawErr))
}

func (s *errorsSuite) TestNewWithKindAndActionsError(c *C) {
	kind := ErrorKind("foo")
	args := map[string]any{
		"arg1": 1,
		"arg2": "bar",
	}
	argJson := make(map[string]json.RawMessage)
	for k, v := range args {
		j, err := json.Marshal(v)
		c.Assert(err, IsNil)
		argJson[k] = j
	}
	actions := []Action{"action2", "action1"}
	rawErr := errors.New("some error")
	err := NewWithKindAndActionsError(kind, args, actions, rawErr)
	c.Check(err, DeepEquals, NewWithKindAndActionsErrorForTest(kind, argJson, actions, rawErr))
}

type withKindAndActionsErrorArgs struct {
	Arg1 string `json:"arg1"`
	Arg2 int    `json:"arg2"`
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorArgStructure(c *C) {
	kind := ErrorKind("foo")
	args := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 35}
	argsJson := map[string]json.RawMessage{
		"arg1": []byte("\"bar\""),
		"arg2": []byte("35"),
	}
	rawErr := errors.New("some error")
	err := NewWithKindAndActionsError(kind, args, nil, rawErr)
	c.Check(err, DeepEquals, NewWithKindAndActionsErrorForTest(kind, argsJson, nil, rawErr))
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorMarshal(c *C) {
	kind := ErrorKind("bar")
	args := &withKindAndActionsErrorArgs{Arg1: "foo", Arg2: 35}
	argsJson := map[string]json.RawMessage{
		"arg1": []byte("\"foo\""),
		"arg2": []byte("35"),
	}
	actions := []Action{"action1", "action2"}
	rawErr := errors.New("some error")

	data, err := json.Marshal(NewWithKindAndActionsError(kind, args, actions, rawErr))
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, testutil.DecodeHexString(c, "7b226b696e64223a22626172222c2261726773223a7b2261726731223a22666f6f222c2261726732223a33357d2c22616374696f6e73223a5b22616374696f6e31222c22616374696f6e32225d7d"))

	var decodedErr *WithKindAndActionsError
	c.Check(json.Unmarshal(data, &decodedErr), IsNil)
	c.Check(decodedErr, DeepEquals, NewWithKindAndActionsErrorForTest(kind, argsJson, actions, nil))
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorNoJsonArgsPanic(c *C) {
	c.Check(func() {
		NewWithKindAndActionsError("foo", []any{"bar1", json.RawMessage{0x22, 0x62, 0x61, 0x72}}, nil, errors.New("some error"))
	}, PanicMatches, `cannot serialize arguments to JSON: json: error calling MarshalJSON for type json.RawMessage: unexpected end of JSON input`)
}

func (s *errorsSuite) TestNewWithKindAndActionsErrorNoMapArgsPanic(c *C) {
	c.Check(func() { NewWithKindAndActionsError("foo", []string{"bar1", "bar2"}, nil, errors.New("some error")) }, PanicMatches, `cannot deserialize arguments JSON to map: json: cannot unmarshal array into Go value of type map\[string\]json.RawMessage`)
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgByName1(c *C) {
	kind := ErrorKind("foo")
	args := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 20}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, args, nil, rawErr)

	val, err := testErr.GetArgByName("arg1")
	c.Check(err, IsNil)
	c.Check(val, Equals, any("bar"))
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgByName2(c *C) {
	kind := ErrorKind("foo")
	args := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 20}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, args, nil, rawErr)

	val, err := testErr.GetArgByName("arg2")
	c.Check(err, IsNil)
	c.Check(val, Equals, any(float64(20)))
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgByNameMissingName(c *C) {
	kind := ErrorKind("foo")
	args := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 20}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, args, nil, rawErr)

	_, err := testErr.GetArgByName("missing")
	c.Check(err, ErrorMatches, `argument "missing" does not exist`)
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgByNameInvalidJSON(c *C) {
	kind := ErrorKind("foo")
	args := map[string]json.RawMessage{
		"arg": []byte("\"bar"),
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsErrorForTest(kind, args, nil, rawErr)

	_, err := testErr.GetArgByName("arg")
	c.Check(err, ErrorMatches, `cannot deserialize argument "arg" from JSON: unexpected end of JSON input`)
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgMap(c *C) {
	kind := ErrorKind("foo")
	args := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 20}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, args, nil, rawErr)

	val, err := testErr.GetArgMap()
	c.Assert(err, IsNil)
	c.Check(val, DeepEquals, map[string]any{
		"arg1": any("bar"),
		"arg2": any(float64(20)),
	})
}

func (s *errorsSuite) TestWithKindAndActionsErrorGetArgMapInvalidJSON(c *C) {
	kind := ErrorKind("foo")
	args := map[string]json.RawMessage{
		"arg1": []byte("\"bar"),
		"arg2": []byte("40"),
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsErrorForTest(kind, args, nil, rawErr)

	_, err := testErr.GetArgMap()
	c.Assert(err, ErrorMatches, `cannot deserialize argument "arg1" from JSON: unexpected end of JSON input`)
}

func (s *errorsSuite) TestGetWithKindAndActionsErrorArg1(c *C) {
	kind := ErrorKind("foo")
	expectedArgs := &withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 20}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, expectedArgs, nil, rawErr)

	args, err := GetWithKindAndActionsErrorArg[*withKindAndActionsErrorArgs](testErr)
	c.Assert(err, IsNil)
	c.Check(args, DeepEquals, expectedArgs)
}

func (s *errorsSuite) TestGetWithKindAndActionsErrorArg2(c *C) {
	kind := ErrorKind("foo")
	argsIn := map[string]any{
		"arg1": "bar",
		"arg2": 35,
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, argsIn, nil, rawErr)

	args, err := GetWithKindAndActionsErrorArg[withKindAndActionsErrorArgs](testErr)
	c.Assert(err, IsNil)
	c.Check(args, DeepEquals, withKindAndActionsErrorArgs{Arg1: "bar", Arg2: 35})
}

func (s *errorsSuite) TestGetWithKindAndActionsErrorInvalidMap(c *C) {
	kind := ErrorKind("foo")
	argsJson := map[string]json.RawMessage{
		"arg1": []byte("\"bar"),
		"arg2": []byte("40"),
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsErrorForTest(kind, argsJson, nil, rawErr)

	_, err := GetWithKindAndActionsErrorArg[*withKindAndActionsErrorArgs](testErr)
	c.Assert(err, ErrorMatches, `cannot serialize argument map to JSON: json: error calling MarshalJSON for type json.RawMessage: unexpected end of JSON input`)
}

func (s *errorsSuite) TestGetWithKindAndActionsErrorInvalidType1(c *C) {
	kind := ErrorKind("foo")
	argsIn := map[string]any{
		"arg3": "bar",
		"arg4": 35,
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, argsIn, nil, rawErr)

	_, err := GetWithKindAndActionsErrorArg[*withKindAndActionsErrorArgs](testErr)
	c.Assert(err, ErrorMatches, `cannot deserialize argument map from JSON to type \*preinstall_test.withKindAndActionsErrorArgs: json: unknown field "arg3"`)
}

func (s *errorsSuite) TestGetWithKindAndActionsErrorInvalidType2(c *C) {
	kind := ErrorKind("foo")
	argsIn := map[string]any{
		"arg1": "bar",
		"arg2": true,
	}
	rawErr := errors.New("some error")

	testErr := NewWithKindAndActionsError(kind, argsIn, nil, rawErr)

	_, err := GetWithKindAndActionsErrorArg[*withKindAndActionsErrorArgs](testErr)
	c.Assert(err, ErrorMatches, `cannot deserialize argument map from JSON to type \*preinstall_test.withKindAndActionsErrorArgs: json: cannot unmarshal bool into Go struct field withKindAndActionsErrorArgs.arg2 of type int`)
}

func (s *errorsSuite) TestMissingKernelModuleErrorModule(c *C) {
	c.Check(MissingKernelModuleError("msr").Module(), Equals, "msr")
	c.Check(MissingKernelModuleError("mei_me").Module(), Equals, "mei_me")
}
