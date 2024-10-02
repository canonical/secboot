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
	"crypto"
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
	pcrIndex  tpm2.Handle
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

type DMAProtectionDisabledEventType int

const (
	DMAProtectionNotDisabled DMAProtectionDisabledEventType = iota
	DMAProtectionDisabled
	DMAProtectionDisabledNullTerminated
)

// LogOptions provides options for [NewLog].
type LogOptions struct {
	Algorithms []tpm2.HashAlgorithmId // the digest algorithms to include

	StartupLocality                   uint8                          // specify a startup locality other than 0
	FirmwareDebugger                  bool                           // indicate a firmware debugger endpoint is enabled
	DMAProtectionDisabled             DMAProtectionDisabledEventType // whether DMA protection is disabled
	SecureBootDisabled                bool                           // Whether secure boot is disabled
	DisallowPreOSVerification         bool                           // don't measure EV_SEPARATOR to PCR7 after the secure boot config is measured
	IncludeDriverLaunch               bool                           // include a driver launch from a PCI device in the log
	IncludeSysPrepAppLaunch           bool                           // include a system-preparation app launch in the log
	NoCallingEFIApplicationEvent      bool                           // omit the EV_EFI_ACTION "Calling EFI Application from Boot Option" event.
	IncludeOSPresentFirmwareAppLaunch efi.GUID                       // include a flash based application launch in the log as part of the OS-present phase
	NoSBAT                            bool                           // omit the SbatLevel measurement to mimic older versions of shim
	PreOSVerificationUsesDigests      crypto.Hash                    // Whether Driver or SysPrep launches are verified using a digest
}

// NewLog creates a mock TCG log for testing. The log will look like a standard
// Linux boot (shim -> grub -> kernel) and uses hard-coded values for signature
// databases (Microsoft UEFI CA 2011 configuration, and launch digests. The
// supplied options argument can be used for minimal customization.
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
			Digests:   tcglog.DigestMap{tpm2.HashAlgorithmSHA1: make(tpm2.Digest, tpm2.HashAlgorithmSHA1.Size())},
			Data: &tcglog.SpecIdEvent03{
				SpecVersionMajor: 2,
				UintnSize:        2,
				DigestSizes:      digestSizes,
			},
		},
	}

	if opts.StartupLocality > 0 {
		ev := &tcglog.Event{
			PCRIndex:  0,
			EventType: tcglog.EventTypeNoAction,
			Digests:   make(tcglog.DigestMap),
			Data:      &tcglog.StartupLocalityEventData{StartupLocality: opts.StartupLocality},
		}
		for _, alg := range opts.Algorithms {
			ev.Digests[alg] = make(tpm2.Digest, alg.Size())
		}
		builder.events = append(builder.events, ev)
	}

	// Mock S-CRTM measurements
	if opts.StartupLocality == 4 {
		// If the firmware indicates that the startup locality is 4 (with the EV_NO_ACTION
		// StartupLocality event of this value), it means that there was one or more H-CRTM event
		// sequences (_TPM_Hash_Start, _TPM_Hash_Data, and _TPM_Hash_End) executed by the firmware
		// before TPM2_Startup. In this case, there will be a EV_EFI_HCRTM_EVENT containing the
		// digest for each H-CRTM sequence, and some optional EV_NO_ACTION TCG_HCRTMComponentEvents
		// providing information about what was measured.
		ev := &tcglog.Event{
			PCRIndex:  0,
			EventType: tcglog.EventTypeNoAction,
			Digests:   make(tcglog.DigestMap),
			Data: &tcglog.HCRTMComponentEventData{
				ComponentDescription:  "S-CRTM contents",
				MeasurementFormatType: tcglog.HCRTMMeasurementFormatRawData,
				ComponentMeasurement:  []byte("mock S-CRTM contents"),
			},
		}
		for _, alg := range opts.Algorithms {
			ev.Digests[alg] = make(tpm2.Digest, alg.Size())
		}
		builder.events = append(builder.events, ev)

		blob := bytesHashData("mock S-CRTM contents")
		builder.hashLogExtendEvent(c, blob, &logEvent{
			pcrIndex:  0,
			eventType: tcglog.EventTypeEFIHCRTMEvent,
			data:      tcglog.StringEventData("HCRTM")})
	} else {
		{
			blob := bytesHashData("mock S-CRTM contents")
			data := &tcglog.EFIPlatformFirmwareBlob{
				BlobBase:   0xff000000,
				BlobLength: 25431}
			builder.hashLogExtendEvent(c, blob, &logEvent{
				pcrIndex:  0,
				eventType: tcglog.EventTypeSCRTMContents,
				data:      data})
		}
		{
			data := tcglog.GUIDEventData(efi.MakeGUID(0x8beb77ea, 0x5c75, 0x4d08, 0x8e2b, [...]byte{0x96, 0x34, 0x86, 0xda, 0xe7, 0xf7}))
			builder.hashLogExtendEvent(c, data, &logEvent{
				pcrIndex:  0,
				eventType: tcglog.EventTypeSCRTMVersion,
				data:      data})
		}
	}
	{
		blob := bytesHashData("mock platform firmware blob 1")
		data := &tcglog.EFIPlatformFirmwareBlob{
			BlobBase:   0xffc00000,
			BlobLength: 0xe0000,
		}
		builder.hashLogExtendEvent(c, blob, &logEvent{
			pcrIndex:  0,
			eventType: tcglog.EventTypeEFIPlatformFirmwareBlob,
			data:      data})
	}
	{
		blob := bytesHashData("mock platform firmware blob 2")
		data := &tcglog.EFIPlatformFirmwareBlob{
			BlobBase:   0xffce0000,
			BlobLength: 0xc00000,
		}
		builder.hashLogExtendEvent(c, blob, &logEvent{
			pcrIndex:  0,
			eventType: tcglog.EventTypeEFIPlatformFirmwareBlob,
			data:      data})
	}

	sbVal := []byte{0x01}
	if opts.SecureBootDisabled {
		sbVal = []byte{0x00}
	}

	// Mock secure boot config measurements
	if opts.FirmwareDebugger {
		data := tcglog.FirmwareDebuggerEvent
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  7,
			eventType: tcglog.EventTypeEFIAction,
			data:      data,
		})
	}

	db := efi.SignatureDatabase{
		NewSignatureListX509(c, testutil.DecodePEMType(c, "CERTIFICATE", msPCACert), efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})),
		NewSignatureListX509(c, testutil.DecodePEMType(c, "CERTIFICATE", msUefiCACert), efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})),
	}
	if opts.PreOSVerificationUsesDigests != crypto.Hash(0) {
		alg := opts.PreOSVerificationUsesDigests
		var digests [][]byte

		h := alg.New()
		io.WriteString(h, "mock EFI driver")
		digests = append(digests, h.Sum(nil))

		h = alg.New()
		io.WriteString(h, "mock sysprep app")
		digests = append(digests, h.Sum(nil))

		db = append(db, NewSignatureListDigests(c, alg, efi.MakeGUID(0x70564dce, 0x9afc, 0x4ee3, 0x85fc, [...]uint8{0x94, 0x96, 0x49, 0xd7, 0xe4, 0x5c}), digests...))
	}

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
			data: MakeVarPayload(c, db),
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
	if !opts.DisallowPreOSVerification {
		// Most firmware measures a EV_SEPARATOR here to separate config and verification,
		// but some older firmware implementations don't do this - it gets measured as part
		// of the pre-OS to OS-present transition later on.
		data := &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventNormalValue}
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  7,
			eventType: tcglog.EventTypeSeparator,
			data:      data})
	}
	if opts.DMAProtectionDisabled > DMAProtectionNotDisabled {
		var data tcglog.EventData
		switch opts.DMAProtectionDisabled {
		case DMAProtectionDisabled:
			data = tcglog.DMAProtectionDisabled
		case DMAProtectionDisabledNullTerminated:
			data = tcglog.OpaqueEventData(append([]byte(tcglog.DMAProtectionDisabled), 0x00))
		default:
			c.Fatal("invalid value for DMAProtectionDisabled")
		}
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  7,
			eventType: tcglog.EventTypeEFIAction,
			data:      data})
	}

	// Mock EFI driver launch
	if opts.IncludeDriverLaunch {
		pe := bytesHashData("mock EFI driver")
		if !opts.SecureBootDisabled {
			var esd *efi.SignatureData
			if opts.PreOSVerificationUsesDigests == crypto.Hash(0) {
				esd = &efi.SignatureData{
					Owner: efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}),
					Data:  testutil.DecodePEMType(c, "CERTIFICATE", msUefiCACert)}
			} else {
				h := opts.PreOSVerificationUsesDigests.New()
				pe.Write(h)
				esd = &efi.SignatureData{
					Owner: efi.MakeGUID(0x70564dce, 0x9afc, 0x4ee3, 0x85fc, [...]uint8{0x94, 0x96, 0x49, 0xd7, 0xe4, 0x5c}),
					Data:  h.Sum(nil),
				}
			}
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
		data := &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0x41a2f024,
			LengthInMemory:   659024,
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
				}}}
		builder.hashLogExtendEvent(c, pe, &logEvent{
			pcrIndex:  2,
			eventType: tcglog.EventTypeEFIBootServicesDriver,
			data:      data})
	}

	// Mock sysprep app launch
	if opts.IncludeSysPrepAppLaunch {
		pe := bytesHashData("mock sysprep app")
		if !opts.SecureBootDisabled {
			var esd *efi.SignatureData
			if opts.PreOSVerificationUsesDigests == crypto.Hash(0) {
				if !opts.IncludeDriverLaunch {
					// This has already been measured
					esd = &efi.SignatureData{
						Owner: efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}),
						Data:  testutil.DecodePEMType(c, "CERTIFICATE", msUefiCACert)}
				}
			} else {
				h := opts.PreOSVerificationUsesDigests.New()
				pe.Write(h)
				esd = &efi.SignatureData{
					Owner: efi.MakeGUID(0x70564dce, 0x9afc, 0x4ee3, 0x85fc, [...]uint8{0x94, 0x96, 0x49, 0xd7, 0xe4, 0x5c}),
					Data:  h.Sum(nil),
				}
			}
			if esd != nil {
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
		}

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

	// Mock boot config measurements
	{
		var order [6]uint8
		binary.LittleEndian.PutUint16(order[0:], 3)
		binary.LittleEndian.PutUint16(order[2:], 1)
		binary.LittleEndian.PutUint16(order[4:], 0)
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
	{
		option := &efi.LoadOption{
			Attributes:  1,
			Description: "External USB",
			FilePath: efi.DevicePath{
				&efi.ACPIDevicePathNode{
					HID: 0x0a0341d0,
					UID: 0x0},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x1d},
				&efi.PCIDevicePathNode{
					Function: 0x0,
					Device:   0x0},
				&efi.HardDriveDevicePathNode{
					PartitionNumber: 1,
					PartitionStart:  0x800,
					PartitionSize:   0x100000,
					Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x423f43ec, 0xd34e, 0x4b55, 0xb2d7, [...]uint8{0x42, 0x2b, 0xa5, 0x02, 0x1c, 0xc4})),
					MBRType:         efi.GPT},
				efi.FilePathDevicePathNode("\\EFI\\BOOT\\BOOTX64.EFI")}}
		optionBytes, err := option.Bytes()
		c.Assert(err, IsNil)
		builder.hashLogExtendEvent(c, option, &logEvent{
			pcrIndex:  1,
			eventType: tcglog.EventTypeEFIVariableBoot,
			data: &tcglog.EFIVariableData{
				VariableName: efi.GlobalVariable,
				UnicodeName:  "Boot0000",
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
	for _, pcr := range []tpm2.Handle{0, 1, 2, 3, 4, 5, 6} {
		data := &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventNormalValue}
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  pcr,
			eventType: tcglog.EventTypeSeparator,
			data:      data})
	}
	if opts.DisallowPreOSVerification {
		// We also need a EV_SEPARATOR in PCR7.
		data := &tcglog.SeparatorEventData{Value: tcglog.SeparatorEventNormalValue}
		builder.hashLogExtendEvent(c, data, &logEvent{
			pcrIndex:  7,
			eventType: tcglog.EventTypeSeparator,
			data:      data})
	}

	// Mock firmware application launch
	var zeroGuid efi.GUID
	if opts.IncludeOSPresentFirmwareAppLaunch != zeroGuid {
		pe := bytesHashData(opts.IncludeOSPresentFirmwareAppLaunch[:])
		data := &tcglog.EFIImageLoadEvent{
			LocationInMemory: 0xa7b34ff7,
			LengthInMemory:   56410,
			DevicePath: efi.DevicePath{
				efi.MediaFvDevicePathNode(efi.MakeGUID(0x983cc241, 0xb4f6, 0x4a85, 0x9733, [...]uint8{0x4c, 0x15, 0x4b, 0x3a, 0xa3, 0x27})),
				efi.MediaFvFileDevicePathNode(opts.IncludeOSPresentFirmwareAppLaunch)}}
		builder.hashLogExtendEvent(c, pe, &logEvent{
			pcrIndex:  4,
			eventType: tcglog.EventTypeEFIBootServicesApplication,
			data:      data})
	}

	// Mock shim launch
	if !opts.SecureBootDisabled && (opts.PreOSVerificationUsesDigests != crypto.Hash(0) || (!opts.IncludeDriverLaunch && !opts.IncludeSysPrepAppLaunch)) {
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
