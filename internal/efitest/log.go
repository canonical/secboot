// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package efitest

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"io"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

var (
	//go:embed DellPK2016.crt
	dellPKCert []byte

	//go:embed MicrosoftKEK.crt
	msKEKCert []byte

	//go:embed MicrosoftPCA.crt
	msPCACert []byte

	//go:embed MicrosoftUefiCA.crt
	msUefiCACert []byte

	//go:embed canonical-uefi-ca.crt
	canonicalCACert []byte
)

type logHashData interface {
	Write(w io.Writer) error
}

type bytesHashData []byte

func (d bytesHashData) Write(w io.Writer) error {
	_, err := w.Write(d)
	return err
}

type logEvent struct {
	pcrIndex  tcglog.PCRIndex
	eventType tcglog.EventType
	data      tcglog.EventData
}

type logBuilder struct {
	algs   []tpm2.HashAlgorithmId
	events []*tcglog.Event
}

func (b *logBuilder) hashLogExtendEvent(c *C, data logHashData, event *logEvent) {
	ev := &tcglog.Event{
		PCRIndex:  event.pcrIndex,
		EventType: event.eventType,
		Digests:   make(tcglog.DigestMap),
		Data:      event.data}

	for _, alg := range b.algs {
		h := alg.NewHash()
		c.Assert(data.Write(h), IsNil)
		ev.Digests[alg] = h.Sum(nil)
	}

	b.events = append(b.events, ev)
}

// LogOptions provides options for [NewLog].
type LogOptions struct {
	Algorithms []tpm2.HashAlgorithmId // the digest algorithms to include

	SecureBootDisabled           bool
	IncludeDriverLaunch          bool // include a driver launch in the log
	IncludeSysPrepAppLaunch      bool // include a system-preparation app launch in the log
	NoCallingEFIApplicationEvent bool // omit the EV_EFI_ACTION "Calling EFI Application from Boot Option" event.
	NoSBAT                       bool // omit the SbatLevel measurement.
}

// NewLog creates a mock TCG log for testing. The log will look like a standard
// Linux boot (shim -> grub -> kernel) and uses hard-coded values for signature
// databases and launch digests. The supplied options argument can be used for
// minimal customization.
func NewLog(c *C, opts *LogOptions) *tcglog.Log {
	builder := &logBuilder{algs: opts.Algorithms}

	var digestSizes []tcglog.EFISpecIdEventAlgorithmSize
	for _, alg := range builder.algs {
		digestSizes = append(digestSizes,
			tcglog.EFISpecIdEventAlgorithmSize{
				AlgorithmId: alg,
				DigestSize:  uint16(alg.Size()),
			})
	}

	builder.events = []*tcglog.Event{
		{
			PCRIndex:  0,
			EventType: tcglog.EventTypeNoAction,
			Digests:   tcglog.DigestMap{tpm2.HashAlgorithmSHA1: make(tcglog.Digest, tpm2.HashAlgorithmSHA1.Size())},
			Data: &tcglog.SpecIdEvent03{
				SpecVersionMajor: 2,
				UintnSize:        2,
				DigestSizes:      digestSizes,
			},
		},
	}

	// Mock S-CRTM measurements
	{
		data := tcglog.StringEventData("1.0")
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  0,
			eventType: tcglog.EventTypeSCRTMVersion,
			data:      data})
	}
	{
		blob := bytesHashData("mock platform firmware blob 1")
		var data [16]byte
		binary.LittleEndian.PutUint64(data[0:], 0x820000)
		binary.LittleEndian.PutUint64(data[8:], 0xe0000)
		builder.hashLogExtendEvent(c, blob, &logEvent{
			pcrIndex:  0,
			eventType: tcglog.EventTypeEFIPlatformFirmwareBlob,
			data:      tcglog.OpaqueEventData(data[:])})
	}
	{
		blob := bytesHashData("mock platform firmware blob 2")
		var data [16]byte
		binary.LittleEndian.PutUint64(data[0:], 0x900000)
		binary.LittleEndian.PutUint64(data[8:], 0xc00000)
		builder.hashLogExtendEvent(c, blob, &logEvent{
			pcrIndex:  0,
			eventType: tcglog.EventTypeEFIPlatformFirmwareBlob,
			data:      tcglog.OpaqueEventData(data[:])})
	}

	sbVal := []byte{0x01}
	if opts.SecureBootDisabled {
		sbVal = []byte{0x00}
	}

	// Mock secure boot config measurements
	for _, sbvar := range []struct {
		name efi.VariableDescriptor
		data []byte
	}{
		{
			name: efi.VariableDescriptor{Name: "SecureBoot", GUID: efi.GlobalVariable},
			data: sbVal,
		},
		{
			name: efi.VariableDescriptor{Name: "PK", GUID: efi.GlobalVariable},
			data: MakeVarPayload(c, NewSignatureListX509(c, testutil.DecodePEMType(c, "CERTIFICATE", dellPKCert), efi.MakeGUID(0x70564dce, 0x9afc, 0x4ee3, 0x85fc, [...]uint8{0x94, 0x96, 0x49, 0xd7, 0xe4, 0x5c}))),
		},
		{
			name: efi.VariableDescriptor{Name: "KEK", GUID: efi.GlobalVariable},
			data: MakeVarPayload(c, NewSignatureListX509(c, testutil.DecodePEMType(c, "CERTIFICATE", msKEKCert), efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}))),
		},
		{
			name: efi.VariableDescriptor{Name: "db", GUID: efi.ImageSecurityDatabaseGuid},
			data: MakeVarPayload(c, efi.SignatureDatabase{
				NewSignatureListX509(c, testutil.DecodePEMType(c, "CERTIFICATE", msPCACert), efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})),
				NewSignatureListX509(c, testutil.DecodePEMType(c, "CERTIFICATE", msUefiCACert), efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})),
			}),
		},
		{
			name: efi.VariableDescriptor{Name: "dbx", GUID: efi.ImageSecurityDatabaseGuid},
			data: MakeVarPayload(c, NewSignatureListNullSHA256(efi.MakeGUID(0xa0baa8a3, 0x041d, 0x48a8, 0xbc87, [...]uint8{0xc3, 0x6d, 0x12, 0x1b, 0x5e, 0x3d}))),
		},
	} {
		data := &tcglog.EFIVariableData{
			VariableName: sbvar.name.GUID,
			UnicodeName:  sbvar.name.Name,
			VariableData: sbvar.data}
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  7,
			eventType: tcglog.EventTypeEFIVariableDriverConfig,
			data:      data})

	}
	{
		data := &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventNormalValue}
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  7,
			eventType: tcglog.EventTypeSeparator,
			data:      data})
	}

	// Mock EFI driver launch
	if opts.IncludeDriverLaunch {
		if !opts.SecureBootDisabled {
			esd := &efi.SignatureData{
				Owner: efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}),
				Data:  testutil.DecodePEMType(c, "CERTIFICATE", msUefiCACert)}
			esdBytes := new(bytes.Buffer)
			esd.Write(esdBytes)
			data := &tcglog.EFIVariableData{
				VariableName: efi.ImageSecurityDatabaseGuid,
				UnicodeName:  "db",
				VariableData: esdBytes.Bytes()}
			builder.hashLogExtendEvent(c, data, &logEvent{
				pcrIndex:  7,
				eventType: tcglog.EventTypeEFIVariableAuthority,
				data:      data})
		}
		pe := bytesHashData("mock EFI driver")
		data := &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x41a2f024,
			LengthInMemory:   659024,
			DevicePath: efi.DevicePath{
				efi.MediaFvDevicePathNode(efi.MakeGUID(0x9b56c9db, 0x1936, 0x44a9, 0x9ed4, [...]uint8{0xb9, 0x2a, 0xef, 0xfc, 0xbb, 0x66})),
				efi.MediaFvFileDevicePathNode(efi.MakeGUID(0x15c7a296, 0xb470, 0x4b31, 0x8314, [...]uint8{0x7f, 0x6e, 0x56, 0x14, 0x37, 0xe5}))}}
		builder.hashLogExtendEvent(c, pe, &logEvent{
			pcrIndex:  2,
			eventType: tcglog.EventTypeEFIBootServicesDriver,
			data:      data})
	}
	if opts.IncludeSysPrepAppLaunch {
		if !opts.SecureBootDisabled && !opts.IncludeDriverLaunch {
			esd := &efi.SignatureData{
				Owner: efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}),
				Data:  testutil.DecodePEMType(c, "CERTIFICATE", msUefiCACert)}
			esdBytes := new(bytes.Buffer)
			esd.Write(esdBytes)
			data := &tcglog.EFIVariableData{
				VariableName: efi.ImageSecurityDatabaseGuid,
				UnicodeName:  "db",
				VariableData: esdBytes.Bytes()}
			builder.hashLogExtendEvent(c, data, &logEvent{
				pcrIndex:  7,
				eventType: tcglog.EventTypeEFIVariableAuthority,
				data:      data})
		}
		pe := bytesHashData("mock sysprep app")
		data := &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x18e4b324,
			LengthInMemory:   120948,
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
					NamespaceUUID: 0x0},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\Dell\\sysprep.efi")}}
		builder.hashLogExtendEvent(c, pe, &logEvent{
			pcrIndex:  4,
			eventType: tcglog.EventTypeEFIBootServicesApplication,
			data:      data})
	}

	// Mock sysprep app launch

	// Mock boot config measurements
	{
		var order [4]uint8
		binary.LittleEndian.PutUint16(order[0:], 3)
		binary.LittleEndian.PutUint16(order[2:], 1)
		builder.hashLogExtendEvent(c, bytesHashData(order[:]), &logEvent{
			pcrIndex:  1,
			eventType: tcglog.EventTypeEFIVariableBoot,
			data: &tcglog.EFIVariableData{
				VariableName: efi.GlobalVariable,
				UnicodeName:  "BootOrder",
				VariableData: order[:]}})
	}
	{
		option := &efi.LoadOption{
			Attributes:  1,
			Description: "ubuntu",
			FilePath: efi.DevicePath{
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
		optionBytes, err := option.Bytes()
		c.Assert(err, IsNil)
		builder.hashLogExtendEvent(c, option, &logEvent{
			pcrIndex:  1,
			eventType: tcglog.EventTypeEFIVariableBoot,
			data: &tcglog.EFIVariableData{
				VariableName: efi.GlobalVariable,
				UnicodeName:  "Boot0003",
				VariableData: optionBytes}})
	}
	{
		option := &efi.LoadOption{
			Attributes:  1,
			Description: "Linux Firmware Updater",
			FilePath: efi.DevicePath{
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")},
			OptionalData: []byte{0x5c, 0x00, 0x66, 0x00, 0x77, 0x00, 0x75, 0x00, 0x70, 0x00, 0x64, 0x00, 0x78, 0x00, 0x36, 0x00, 0x34, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x66, 0x00, 0x69, 0x00, 0x00, 0x00}}
		optionBytes, err := option.Bytes()
		c.Assert(err, IsNil)
		builder.hashLogExtendEvent(c, option, &logEvent{
			pcrIndex:  1,
			eventType: tcglog.EventTypeEFIVariableBoot,
			data: &tcglog.EFIVariableData{
				VariableName: efi.GlobalVariable,
				UnicodeName:  "Boot0001",
				VariableData: optionBytes}})
	}

	// Mock boundary between pre-OS and OS-present
	if !opts.NoCallingEFIApplicationEvent {
		data := tcglog.EFICallingEFIApplicationEvent
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  4,
			eventType: tcglog.EventTypeEFIAction,
			data:      data})
	}
	for _, pcr := range []tcglog.PCRIndex{0, 1, 2, 3, 4, 5, 6} {
		data := &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventNormalValue}
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  pcr,
			eventType: tcglog.EventTypeSeparator,
			data:      data})
	}

	// Mock shim launch
	if !opts.SecureBootDisabled && !opts.IncludeDriverLaunch && !opts.IncludeSysPrepAppLaunch {
		esd := &efi.SignatureData{
			Owner: efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}),
			Data:  testutil.DecodePEMType(c, "CERTIFICATE", msUefiCACert)}
		esdBytes := new(bytes.Buffer)
		esd.Write(esdBytes)
		data := &tcglog.EFIVariableData{
			VariableName: efi.ImageSecurityDatabaseGuid,
			UnicodeName:  "db",
			VariableData: esdBytes.Bytes()}
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  7,
			eventType: tcglog.EventTypeEFIVariableAuthority,
			data:      data})
	}
	{
		gptData := &tcglog.EFIGPTData{
			Hdr: efi.PartitionTableHeader{
				HeaderSize:               92,
				MyLBA:                    1,
				AlternateLBA:             4000797359,
				FirstUsableLBA:           34,
				LastUsableLBA:            4000797326,
				DiskGUID:                 efi.MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
				PartitionEntryLBA:        2,
				NumberOfPartitionEntries: 128,
				SizeOfPartitionEntry:     128,
				PartitionEntryArrayCRC32: 189081846},
			Partitions: []*efi.PartitionEntry{
				{
					PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
					UniquePartitionGUID: efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
					StartingLBA:         2048,
					EndingLBA:           1050623,
					Attributes:          0,
					PartitionName:       "EFI System Partition",
				},
				{
					PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
					UniquePartitionGUID: efi.MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
					StartingLBA:         1050624,
					EndingLBA:           2549759,
					Attributes:          0,
					PartitionName:       "",
				},
				{
					PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
					UniquePartitionGUID: efi.MakeGUID(0xc64af521, 0x14f1, 0x4ef2, 0xadb5, [...]uint8{0x20, 0xb5, 0x9c, 0xa2, 0x33, 0x5a}),
					StartingLBA:         2549760,
					EndingLBA:           4000796671,
					Attributes:          0,
					PartitionName:       "",
				}}}
		builder.hashLogExtendEvent(c, gptData, &logEvent{
			pcrIndex:  5,
			eventType: tcglog.EventTypeEFIGPTEvent,
			data:      gptData})
	}
	{
		pe := bytesHashData("mock shim executable")
		data := &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x6556c018,
			LengthInMemory:   955072,
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
					NamespaceUUID: 0x0},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
		builder.hashLogExtendEvent(c, pe, &logEvent{
			pcrIndex:  4,
			eventType: tcglog.EventTypeEFIBootServicesApplication,
			data:      data})
	}
	if !opts.NoSBAT {
		data := &tcglog.EFIVariableData{
			VariableName: efi.MakeGUID(0x605dab50, 0xe046, 0x4300, 0xabb6, [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}),
			UnicodeName:  "SbatLevel",
			VariableData: []byte("sbat,1,2021030218\n")}
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  7,
			eventType: tcglog.EventTypeEFIVariableAuthority,
			data:      data})
	}

	// Mock grub and kernel launch
	{
		pe := bytesHashData("mock grub executable")
		data := &tcglog.EFIImageLoadEvent{}
		builder.hashLogExtendEvent(c, pe, &logEvent{
			pcrIndex:  4,
			eventType: tcglog.EventTypeEFIBootServicesApplication,
			data:      data})
	}
	if !opts.SecureBootDisabled {
		data := &tcglog.EFIVariableData{
			VariableName: efi.MakeGUID(0x605dab50, 0xe046, 0x4300, 0xabb6, [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}),
			UnicodeName:  "Shim",
			VariableData: testutil.DecodePEMType(c, "CERTIFICATE", canonicalCACert)}
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  7,
			eventType: tcglog.EventTypeEFIVariableAuthority,
			data:      data})
	}
	{
		pe := bytesHashData("mock kernel executable")
		data := &tcglog.EFIImageLoadEvent{}
		builder.hashLogExtendEvent(c, pe, &logEvent{
			pcrIndex:  4,
			eventType: tcglog.EventTypeEFIBootServicesApplication,
			data:      data})
	}

	// Mock EBS
	for _, action := range []tcglog.StringEventData{tcglog.EFIExitBootServicesInvocationEvent, tcglog.EFIExitBootServicesSucceededEvent} {
		builder.hashLogExtendEvent(c, action, &logEvent{
			pcrIndex:  5,
			eventType: tcglog.EventTypeEFIAction,
			data:      action})
	}

	return tcglog.NewLogForTesting(builder.events)
}
