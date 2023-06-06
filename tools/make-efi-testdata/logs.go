package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
)

type Event struct {
	PCRIndex  tcglog.PCRIndex
	EventType tcglog.EventType
	Data      tcglog.EventData
}

type eventData interface {
	Write(w io.Writer) error
}

type bytesData []byte

func (d bytesData) Write(w io.Writer) error {
	_, err := w.Write(d)
	return err
}

type logWriter struct {
	algs   []tpm2.HashAlgorithmId
	events []*tcglog.Event
}

func newCryptoAgileLogWriter() *logWriter {
	event := &tcglog.Event{
		PCRIndex:  0,
		EventType: tcglog.EventTypeNoAction,
		Digests:   tcglog.DigestMap{tpm2.HashAlgorithmSHA1: make(tcglog.Digest, tpm2.HashAlgorithmSHA1.Size())},
		Data: &tcglog.SpecIdEvent03{
			SpecVersionMajor: 2,
			UintnSize:        2,
			DigestSizes: []tcglog.EFISpecIdEventAlgorithmSize{
				{AlgorithmId: tpm2.HashAlgorithmSHA1, DigestSize: uint16(tpm2.HashAlgorithmSHA1.Size())},
				{AlgorithmId: tpm2.HashAlgorithmSHA256, DigestSize: uint16(tpm2.HashAlgorithmSHA256.Size())}}}}

	return &logWriter{
		algs:   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256},
		events: []*tcglog.Event{event}}
}

func (w *logWriter) hashLogExtendEvent(data eventData, event *Event) {
	ev := &tcglog.Event{
		PCRIndex:  event.PCRIndex,
		EventType: event.EventType,
		Digests:   make(tcglog.DigestMap),
		Data:      event.Data}

	for _, alg := range w.algs {
		h := alg.NewHash()
		if err := data.Write(h); err != nil {
			panic(err)
		}
		ev.Digests[alg] = h.Sum(nil)
	}

	w.events = append(w.events, ev)

}

type logOptions struct {
	omitEFIActionEvents bool
	secureBootDisabled  bool
	noShimVerification  bool
	noSBAT              bool
}

func constructLog(vars map[string]map[string][]byte, certs map[string][]byte, opts *logOptions) *tcglog.Log {
	w := newCryptoAgileLogWriter()

	// Mock S-CRTM measurements
	{
		data := tcglog.StringEventData("1.0")
		w.hashLogExtendEvent(data, &Event{
			PCRIndex:  0,
			EventType: tcglog.EventTypeSCRTMVersion,
			Data:      data})
	}
	{
		blob := bytesData("mock platform firmware blob 1")
		var data [16]byte
		binary.LittleEndian.PutUint64(data[0:], 0x820000)
		binary.LittleEndian.PutUint64(data[8:], 0xe0000)
		w.hashLogExtendEvent(blob, &Event{
			PCRIndex:  0,
			EventType: tcglog.EventTypeEFIPlatformFirmwareBlob,
			Data:      tcglog.OpaqueEventData(data[:])})
	}
	{
		blob := bytesData("mock platform firmware blob 2")
		var data [16]byte
		binary.LittleEndian.PutUint64(data[0:], 0x900000)
		binary.LittleEndian.PutUint64(data[8:], 0xc00000)
		w.hashLogExtendEvent(blob, &Event{
			PCRIndex:  0,
			EventType: tcglog.EventTypeEFIPlatformFirmwareBlob,
			Data:      tcglog.OpaqueEventData(data[:])})
	}

	sbVal := []byte{0x01}
	if opts.secureBootDisabled {
		sbVal = []byte{0x00}
	}

	// Mock secure boot config measurements
	for _, sbconfig := range []struct {
		guid efi.GUID
		name string
		data []byte
	}{
		{
			guid: efi.GlobalVariable,
			name: "SecureBoot",
			data: sbVal,
		},
		{
			guid: efi.GlobalVariable,
			name: "PK",
			data: vars["efivars_ms"]["PK-8be4df61-93ca-11d2-aa0d-00e098032b8c"],
		},
		{
			guid: efi.GlobalVariable,
			name: "KEK",
			data: vars["efivars_ms"]["KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c"],
		},
		{
			guid: efi.ImageSecurityDatabaseGuid,
			name: "db",
			data: vars["efivars_ms"]["db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"],
		},
		{
			guid: efi.ImageSecurityDatabaseGuid,
			name: "dbx",
			data: vars["efivars_ms"]["dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"],
		},
	} {
		data := &tcglog.EFIVariableData{
			VariableName: sbconfig.guid,
			UnicodeName:  sbconfig.name,
			VariableData: sbconfig.data}
		w.hashLogExtendEvent(data, &Event{
			PCRIndex:  7,
			EventType: tcglog.EventTypeEFIVariableDriverConfig,
			Data:      data})
	}
	{
		data := &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventNormalValue}
		w.hashLogExtendEvent(data, &Event{
			PCRIndex:  7,
			EventType: tcglog.EventTypeSeparator,
			Data:      data})
	}

	// Mock boot config measurements
	{
		var order [4]uint8
		binary.LittleEndian.PutUint16(order[0:], 3)
		binary.LittleEndian.PutUint16(order[2:], 1)
		w.hashLogExtendEvent(bytesData(order[:]), &Event{
			PCRIndex:  1,
			EventType: tcglog.EventTypeEFIVariableBoot,
			Data: &tcglog.EFIVariableData{
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
		optionBytes := new(bytes.Buffer)
		option.Write(optionBytes)
		w.hashLogExtendEvent(bytesData(optionBytes.Bytes()), &Event{
			PCRIndex:  1,
			EventType: tcglog.EventTypeEFIVariableBoot,
			Data: &tcglog.EFIVariableData{
				VariableName: efi.GlobalVariable,
				UnicodeName:  "Boot0003",
				VariableData: optionBytes.Bytes()}})
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
		optionBytes := new(bytes.Buffer)
		option.Write(optionBytes)
		w.hashLogExtendEvent(bytesData(optionBytes.Bytes()), &Event{
			PCRIndex:  1,
			EventType: tcglog.EventTypeEFIVariableBoot,
			Data: &tcglog.EFIVariableData{
				VariableName: efi.GlobalVariable,
				UnicodeName:  "Boot0003",
				VariableData: optionBytes.Bytes()}})
	}

	// Mock boundary between pre-OS and OS-present
	if !opts.omitEFIActionEvents {
		data := tcglog.EFICallingEFIApplicationEvent
		w.hashLogExtendEvent(data, &Event{
			PCRIndex:  4,
			EventType: tcglog.EventTypeEFIAction,
			Data:      data})
	}
	for _, pcr := range []tcglog.PCRIndex{0, 1, 2, 3, 4, 5, 6} {
		data := &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventNormalValue}
		w.hashLogExtendEvent(data, &Event{
			PCRIndex:  pcr,
			EventType: tcglog.EventTypeSeparator,
			Data:      data})
	}

	// Mock shim launch
	if !opts.secureBootDisabled {
		esd := &efi.SignatureData{
			Owner: efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}),
			Data:  certs["MicrosoftUefiCA"]}
		esdBytes := new(bytes.Buffer)
		esd.Write(esdBytes)
		data := &tcglog.EFIVariableData{
			VariableName: efi.ImageSecurityDatabaseGuid,
			UnicodeName:  "db",
			VariableData: esdBytes.Bytes()}
		w.hashLogExtendEvent(data, &Event{
			PCRIndex:  7,
			EventType: tcglog.EventTypeEFIVariableAuthority,
			Data:      data})
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
		w.hashLogExtendEvent(gptData, &Event{
			PCRIndex:  5,
			EventType: tcglog.EventTypeEFIGPTEvent,
			Data:      gptData})
	}
	{
		pe := bytesData("mock shim executable")
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
		w.hashLogExtendEvent(pe, &Event{
			PCRIndex:  4,
			EventType: tcglog.EventTypeEFIBootServicesApplication,
			Data:      data})
	}
	if opts.noShimVerification {
		data := &tcglog.EFIVariableData{
			VariableName: efi.MakeGUID(0x605dab50, 0xe046, 0x4300, 0xabb6, [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}),
			UnicodeName:  "MokSBState",
			VariableData: []byte{0x01}}
		w.hashLogExtendEvent(data, &Event{
			PCRIndex:  7,
			EventType: tcglog.EventTypeEFIVariableAuthority,
			Data:      data})
		w.hashLogExtendEvent(bytesData{0x01}, &Event{
			PCRIndex:  14,
			EventType: tcglog.EventTypeIPL,
			Data:      tcglog.OpaqueEventData("MokSBState\x00")})
	}
	if !opts.noSBAT {
		data := &tcglog.EFIVariableData{
			VariableName: efi.MakeGUID(0x605dab50, 0xe046, 0x4300, 0xabb6, [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}),
			UnicodeName:  "SbatLevel",
			VariableData: []byte("sbat,1,2021030218\n")}
		w.hashLogExtendEvent(data, &Event{
			PCRIndex:  7,
			EventType: tcglog.EventTypeEFIVariableAuthority,
			Data:      data})
	}

	// Mock grub and kernel launch
	{
		pe := bytesData("mock grub executable")
		data := &tcglog.EFIImageLoadEvent{}
		w.hashLogExtendEvent(pe, &Event{
			PCRIndex:  4,
			EventType: tcglog.EventTypeEFIBootServicesApplication,
			Data:      data})
	}
	if !opts.noShimVerification && !opts.secureBootDisabled {
		data := &tcglog.EFIVariableData{
			VariableName: efi.MakeGUID(0x605dab50, 0xe046, 0x4300, 0xabb6, [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}),
			UnicodeName:  "Shim",
			VariableData: certs["canonical-uefi-ca"]}
		w.hashLogExtendEvent(data, &Event{
			PCRIndex:  7,
			EventType: tcglog.EventTypeEFIVariableAuthority,
			Data:      data})
	}
	{
		pe := bytesData("mock kernel executable")
		data := &tcglog.EFIImageLoadEvent{}
		w.hashLogExtendEvent(pe, &Event{
			PCRIndex:  4,
			EventType: tcglog.EventTypeEFIBootServicesApplication,
			Data:      data})
	}

	// Mock EBS
	if !opts.omitEFIActionEvents {
		for _, action := range []tcglog.StringEventData{tcglog.EFIExitBootServicesInvocationEvent, tcglog.EFIExitBootServicesSucceededEvent} {
			w.hashLogExtendEvent(action, &Event{
				PCRIndex:  5,
				EventType: tcglog.EventTypeEFIAction,
				Data:      action})
		}
	}

	return tcglog.NewLogForTesting(w.events)
}

type logData struct {
	name string
	opts logOptions
}

var logs = []logData{
	{name: "eventlog_sb"},
	{name: "eventlog_sb_no_efi_action", opts: logOptions{omitEFIActionEvents: true}},
	{name: "eventlog_sb_no_shim_verification", opts: logOptions{noShimVerification: true}},
	{name: "eventlog_sb_no_sbat", opts: logOptions{noSBAT: true}},
	{name: "eventlog_no_sb", opts: logOptions{secureBootDisabled: true}}}

func makeTCGLogs(srcDir, dstDir string) error {
	datas, err := newEfiVarData(srcDir)
	if err != nil {
		return err
	}

	vars := make(map[string]map[string][]byte)
	for _, data := range datas {
		vars[data.name] = make(map[string][]byte)
		for _, v := range data.vars {
			b, err := v.data()
			if err != nil {
				return xerrors.Errorf("cannot make var data for %s %s-%s: %w", data.name, v.name(), v.guid(), err)
			}
			vars[data.name][fmt.Sprintf("%s-%s", v.name(), v.guid())] = b
		}
	}

	certs, err := makeCertificates(srcDir)
	if err != nil {
		return xerrors.Errorf("cannot make certificates: %w", err)
	}

	if err := readSrcCertificates(srcDir, certs); err != nil {
		return xerrors.Errorf("cannot read src certificates: %w", err)
	}

	for _, data := range logs {
		f, err := os.OpenFile(filepath.Join(dstDir, data.name+".bin"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		if err := constructLog(vars, certs, &data.opts).Write(f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	return nil
}
