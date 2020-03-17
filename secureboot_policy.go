// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package secboot

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
	"github.com/fullsailor/pkcs7"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"

	"golang.org/x/xerrors"
)

const (
	kekName     = "KEK"        // Unicode variable name for the EFI KEK database
	dbName      = "db"         // Unicode variable name for the EFI authorized signature database
	dbxName     = "dbx"        // Unicode variable name for the EFI forbidden signature database
	sbStateName = "SecureBoot" // Unicode variable name for the EFI secure boot configuration (enabled/disabled)

	mokListName    = "MokList"    // Unicode variable name for the shim MOK database
	mokSbStateName = "MokSBState" // Unicode variable name for the shim secure boot configuration (validation enabled/disabled)
	shimName       = "Shim"       // Unicode variable name used for recording events when shim's vendor certificate is used for verification

	kekFilename     = "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c"       // Filename in efivarfs for accessing the KEK database
	dbFilename      = "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"        // Filename in efivarfs for accessing the EFI authorized signature database
	dbxFilename     = "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"       // Filename in efivarfs for accessing the EFI forbidden signature database
	mokListFilename = "MokListRT-605dab50-e046-4300-abb6-3dd810dd8b23" // Filename in efivarfs for accessing a runtime copy of the shim MOK database

	uefiDriverPCR      = 2 // UEFI Drivers and UEFI Applications PCR
	bootManagerCodePCR = 4 // Boot Manager Code and Boot Attempts PCR
	secureBootPCR      = 7 // Secure Boot Policy Measurements PCR

	returningFromEfiApplicationEvent = "Returning from EFI Application from Boot Option" // EV_EFI_ACTION index 2: "Attempt to execute code from Boot Option was unsuccessful"

	sbKeySyncExe = "sbkeysync"

	winCertTypePKCSSignedData uint16 = 0x0002 // WIN_CERT_TYPE_PKCS_SIGNED_DATA
	winCertTypeEfiGuid        uint16 = 0x0EF1 // WIN_CERT_TYPE_EFI_GUID
)

var (
	shimGuid                     = tcglog.NewEFIGUID(0x605dab50, 0xe046, 0x4300, 0xabb6, [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}) // SHIM_LOCK_GUID
	efiGlobalVariableGuid        = tcglog.NewEFIGUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}) // EFI_GLOBAL_VARIABLE
	efiImageSecurityDatabaseGuid = tcglog.NewEFIGUID(0xd719b2cb, 0x3d3a, 0x4596, 0xa3bc, [...]uint8{0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}) // EFI_IMAGE_SECURITY_DATABASE_GUID

	efiCertX509Guid      = tcglog.NewEFIGUID(0xa5c059a1, 0x94e4, 0x4aa7, 0x87b5, [...]uint8{0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}) // EFI_CERT_X509_GUID
	efiCertTypePkcs7Guid = tcglog.NewEFIGUID(0x4aafd29d, 0x68df, 0x49ee, 0x8aa9, [...]uint8{0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7}) // EFI_CERT_TYPE_PKCS7_GUID

	eventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements" // Path of the TCG event log for the default TPM, in binary form
	efivarsPath  = "/sys/firmware/efi/efivars"                          // Default mount point for efivarfs
)

// EFIImage corresponds to a binary that is loaded, verified and executed before ExitBootServices.
type EFIImage interface {
	fmt.Stringer
	ReadAll() ([]byte, error) // Read the entire contents of the image
}

// SnapFileEFIImage corresponds to a binary contained within a snap file that is loaded, verified and executed before ExitBootServices.
type SnapFileEFIImage struct {
	Container snap.Container
	Path      string // The path of the snap image (used by the implementation of fmt.Stringer)
	FileName  string // The filename within the snap squashfs
}

func (f SnapFileEFIImage) String() string {
	return f.Path + ":" + f.FileName
}

func (f SnapFileEFIImage) ReadAll() ([]byte, error) {
	return f.Container.ReadFile(f.FileName)
}

// FileEFIImage corresponds to a file on disk that is loaded, verified and executed before ExitBootServices.
type FileEFIImage string

func (p FileEFIImage) String() string {
	return string(p)
}

func (p FileEFIImage) ReadAll() ([]byte, error) {
	f, err := os.Open(string(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}

// EFIImageLoadEventSource corresponds to the source of a EFIImageLoadEvent.
type EFIImageLoadEventSource int

const (
	// Firmware indicates that the source of a EFIImageLoadEvent was platform firmware, via the EFI_BOOT_SERVICES.LoadImage()
	// and EFI_BOOT_SERVICES.StartImage() functions, with the subsequently executed image being verified against the signatures
	// in the EFI authorized signature database.
	Firmware EFIImageLoadEventSource = iota

	// Shim indicates that the source of a EFIImageLoadEvent was shim, without relying on EFI boot services for loading, verifying
	// and executing the subsequently executed image. The image is verified by shim against the signatures in the EFI authorized
	// signature database, the MOK database or shim's built-in vendor certificate before being executed directly.
	Shim
)

// EFIImageLoadEvent corresponds to the execution of a verified EFIImage.
type EFIImageLoadEvent struct {
	Source EFIImageLoadEventSource // The source of the event
	Image  EFIImage                // The image
	Next   []*EFIImageLoadEvent    // A list of possible subsequent EFIImageLoadEvents
}

type winCertificate interface {
	wCertificateType() uint16
}

// winCertificateUefiGuid corresponds to the WIN_CERTIFICATE_UEFI_GUID type.
type winCertificateUefiGuid struct {
	CertType tcglog.EFIGUID // CertType
	Data     []byte         // CertData
}

func (c *winCertificateUefiGuid) wCertificateType() uint16 {
	return winCertTypeEfiGuid
}

type winCertificateAuthenticode struct {
	Data []byte
}

func (c *winCertificateAuthenticode) wCertificateType() uint16 {
	return winCertTypePKCSSignedData
}

// decodeWinCertificate decodes the WIN_CERTIFICATE implementation from r. Currently supported types are WIN_CERT_TYPE_PKCS_SIGNED_DATA
// and WIN_CERT_TYPE_EFI_GUID.
func decodeWinCertificate(r io.Reader) (winCertificate, error) {
	var hdr struct {
		Length          uint32
		Revision        uint16
		CertificateType uint16
	}
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, xerrors.Errorf("cannot read WIN_CERTIFICATE header fields: %w", err)
	}
	if hdr.Revision != 0x200 {
		return nil, fmt.Errorf("invalid wRevision value (0x%04x)", hdr.Revision)
	}

	switch hdr.CertificateType {
	case winCertTypePKCSSignedData:
		out := &winCertificateAuthenticode{}
		out.Data = make([]byte, int(hdr.Length)-binary.Size(hdr))
		if _, err := io.ReadFull(r, out.Data); err != nil {
			return nil, xerrors.Errorf("cannot read WIN_CERTIFICATE.bCertificate: %w", err)
		}
		return out, nil
	case winCertTypeEfiGuid:
		out := &winCertificateUefiGuid{}
		if err := binary.Read(r, binary.LittleEndian, &out.CertType); err != nil {
			return nil, xerrors.Errorf("cannot read WIN_CERTIFICATE_UEFI_GUID.CertType: %w", err)
		}
		out.Data = make([]byte, int(hdr.Length)-binary.Size(hdr)-binary.Size(out.CertType))
		if _, err := io.ReadFull(r, out.Data); err != nil {
			return nil, xerrors.Errorf("cannot read WIN_CERTIFICATE_UEFI_GUID.CertData: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("cannot decode unrecognized type (0x%04x)", hdr.CertificateType)
	}
}

// readShimVendorCert obtains the DER encoded built-in vendor certificate from the shim executable accessed via r.
func readShimVendorCert(r io.ReaderAt) ([]byte, error) {
	pefile, err := pe.NewFile(r)
	if err != nil {
		return nil, xerrors.Errorf("cannot decode PE binary: %w", err)
	}

	// Shim's vendor certificate is in the .vendor_cert section.
	section := pefile.Section(".vendor_cert")
	if section == nil {
		return nil, errors.New("missing .vendor_cert section")
	}

	// Shim's .vendor_cert section starts with a cert_table struct (see shim.c in the shim source)
	sr := io.NewSectionReader(section, 0, 16)

	// Read vendor_cert_size field
	var certSize uint32
	if err := binary.Read(sr, binary.LittleEndian, &certSize); err != nil {
		return nil, xerrors.Errorf("cannot read vendor cert size: %w", err)
	}

	// A size of zero is valid
	if certSize == 0 {
		return nil, nil
	}

	// Skip vendor_dbx_size
	sr.Seek(4, io.SeekCurrent)

	// Read vendor_cert_offset
	var certOffset uint32
	if err := binary.Read(sr, binary.LittleEndian, &certOffset); err != nil {
		return nil, xerrors.Errorf("cannot read vendor cert offset: %w", err)
	}

	sr = io.NewSectionReader(section, int64(certOffset), int64(certSize))
	certData, err := ioutil.ReadAll(sr)
	if err != nil {
		return nil, xerrors.Errorf("cannot read vendor cert data: %w", err)
	}

	return certData, nil
}

// secureBootDbIterator provides a mechanism to iterate over a set of EFI_SIGNATURE_LIST entries in a EFI signature database.
type secureBootDbIterator struct {
	r io.ReadSeeker
}

// nextSignatureList returns the SignatureType, SignatureHeader and EFI_SIGNATURE_DATA entries associated with the next
// EFI_SIGNATURE_LIST.
func (d *secureBootDbIterator) nextSignatureList() (*tcglog.EFIGUID, []byte, [][]byte, error) {
	start, _ := d.r.Seek(0, io.SeekCurrent)

	// Decode EFI_SIGNATURE_LIST.SignatureType
	var signatureType tcglog.EFIGUID
	if err := binary.Read(d.r, binary.LittleEndian, &signatureType); err != nil {
		if err == io.EOF {
			return nil, nil, nil, err
		}
		return nil, nil, nil, xerrors.Errorf("cannot read EFI_SIGNATURE_LIST.SignatureType: %w", err)
	}

	// Decode EFI_SIGNATURE_LIST.SignatureListSize, which indicates the size of the entire EFI_SIGNATURE_LIST,
	// including all of the EFI_SIGNATURE_DATA entries.
	var signatureListSize uint32
	if err := binary.Read(d.r, binary.LittleEndian, &signatureListSize); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot read EFI_SIGNATURE_LIST.SignatureListSize: %w", err)
	}

	// Decode EFI_SIGNATURE_LIST.SignatureHeaderSize, which indicates the size of the optional header data between
	// the core EFI_SIGNATURE_LIST fields and the EFI_SIGNATURE_DATA entries.
	// Always zero for the signature types we care about.
	var signatureHeaderSize uint32
	if err := binary.Read(d.r, binary.LittleEndian, &signatureHeaderSize); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot read EFI_SIGNATURE_LIST.SignatureHeaderSize: %w", err)
	}

	// Decode EFI_SIGNATURE_LIST.SignatureSize, which indicates the size of each EFI_SIGNATURE_DATA entry.
	var signatureSize uint32
	if err := binary.Read(d.r, binary.LittleEndian, &signatureSize); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot read EFI_SIGNATURE_LIST.SignatureSize: %w", err)
	}
	if signatureSize == 0 {
		return nil, nil, nil, errors.New("EFI_SIGNATURE_LIST.SignatureSize is zero")
	}

	signatureHeader := make([]byte, signatureHeaderSize)
	if _, err := io.ReadFull(d.r, signatureHeader); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot read EFI_SIGNATURE_LIST.SignatureHeader: %w", err)
	}

	// Calculate the number of EFI_SIGNATURE_DATA entries
	endOfHeader, _ := d.r.Seek(0, io.SeekCurrent)
	signatureDataSize := int64(signatureListSize) - endOfHeader + start
	if signatureDataSize%int64(signatureSize) != 0 {
		return nil, nil, nil, errors.New("EFI_SIGNATURE_LIST has inconsistent SignatureListSIze, SignatureHeaderSize and SignatureSize fields")
	}
	numOfSignatures := signatureDataSize / int64(signatureSize)

	var signatures [][]byte

	// Iterate over each EFI_SIGNATURE_DATA entry
	for i := int64(0); i < numOfSignatures; i++ {
		signature := make([]byte, signatureSize)
		if _, err := io.ReadFull(d.r, signature); err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot read EFI_SIGNATURE_DATA entry at index %d: %w", i, err)
		}
		signatures = append(signatures, signature)
	}

	return &signatureType, signatureHeader, signatures, nil
}

// efiSignatureData corresponds to a EFI_SIGNATURE_DATA entry from a secure boot database, with the inclusion of the SignatureType
// field of the EFI_SIGNATURE_LIST that the the signature was obtained from.
type efiSignatureData struct {
	signatureType tcglog.EFIGUID
	owner         tcglog.EFIGUID
	data          []byte
}

func (e *efiSignatureData) encode(buf io.Writer) error {
	if err := binary.Write(buf, binary.LittleEndian, e.owner); err != nil {
		return fmt.Errorf("cannot write signature owner: %v", err)
	}
	if _, err := buf.Write(e.data); err != nil {
		return fmt.Errorf("cannot write signature data: %v", err)
	}
	return nil
}

// decodeSecureBootDb parses a EFI signature database from r and returns a list of efiSignatureData structures corresponding to
// all of the EFI_SIGNATURE_DATA entries.
func decodeSecureBootDb(r io.ReadSeeker) ([]*efiSignatureData, error) {
	var out []*efiSignatureData

	iter := &secureBootDbIterator{r}
	for i := 0; ; i++ {
		sigType, _, sigs, err := iter.nextSignatureList()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, xerrors.Errorf("cannot obtain signature list at %d: %w", i, err)
		}

		for j, sig := range sigs {
			sr := bytes.NewReader(sig)

			// Decode EFI_SIGNATURE_DATA.SignatureOwner
			var signatureOwner tcglog.EFIGUID
			if err := binary.Read(sr, binary.LittleEndian, &signatureOwner); err != nil {
				return nil, xerrors.Errorf("cannot decode EFI_SIGNATURE_DATA.SignatureOwner for signature at index %d in list index %d: %w", j, i, err)
			}

			data, err := ioutil.ReadAll(sr)
			if err != nil {
				return nil, xerrors.Errorf("cannot obtain EFI_SIGNATURE_DATA.SignatureData for signature at index %d in list index %d: %w", j, i, err)
			}

			out = append(out, &efiSignatureData{signatureType: *sigType, owner: signatureOwner, data: data})
		}
	}

	return out, nil
}

// computeDbUpdate appends the EFI signature database update supplied via update to the signature database supplied via orig, filtering
// out EFI_SIGNATURE_DATA entries that are already in orig and then returning the result.
func computeDbUpdate(orig io.ReaderAt, update io.ReadSeeker) ([]byte, error) {
	// Skip over EFI_VARIABLE_AUTHENTICATION_2.TimeStamp
	update.Seek(16, io.SeekCurrent)

	var cert *winCertificateUefiGuid
	if c, err := decodeWinCertificate(update); err != nil {
		return nil, xerrors.Errorf("cannot decode EFI_VARIABLE_AUTHENTICATION_2.AuthInfo field from update: %w", err)
	} else if c.wCertificateType() != winCertTypeEfiGuid {
		return nil, fmt.Errorf("update has invalid EFI_VARIABLE_AUTHENTICATION_2.AuthInfo.Hdr.wCertificateType (0x%04x)", c.wCertificateType())
	} else {
		cert = c.(*winCertificateUefiGuid)
	}

	if cert.CertType != *efiCertTypePkcs7Guid {
		return nil, fmt.Errorf("update has invalid value for EFI_VARIABLE_AUTHENTICATION_2.AuthInfo.CertType (%s)", &cert.CertType)
	}

	filteredUpdate := new(bytes.Buffer)

	updateIter := &secureBootDbIterator{update}
	for i := 0; ; i++ {
		updateSigType, updateSigHeader, updateSigs, err := updateIter.nextSignatureList()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, xerrors.Errorf("cannot obtain signature list from update at index %d: %w", i, err)
		}

		var newSigs bytes.Buffer
		var updateSigSize int

		for _, updateSig := range updateSigs {
			isNewSig := true

			iter := &secureBootDbIterator{io.NewSectionReader(orig, 0, (1<<63)-1)}
			for j := 0; ; j++ {
				sigType, _, sigs, err := iter.nextSignatureList()
				if err != nil {
					if err == io.EOF {
						break
					}
					return nil, xerrors.Errorf("cannot obtain signature list from target at index %d: %w", j, err)
				}
				if *sigType != *updateSigType {
					// EFI_SIGNATURE_LIST.SignatureType doesn't match
					continue
				}
				for _, sig := range sigs {
					if bytes.Equal(sig, updateSig) {
						isNewSig = false
						break
					}
				}
				if !isNewSig {
					break
				}
			}

			if isNewSig {
				updateSigSize = len(updateSig)
				if _, err := newSigs.Write(updateSig); err != nil {
					return nil, xerrors.Errorf("cannot write new signature to temporary buffer: %w", err)
				}
			}
		}

		if newSigs.Len() == 0 {
			continue
		}

		// This EFI_SIGNATURE_LIST has new signatures, so encode them to filteredSrc

		// Encode EFI_SIGNATURE_LIST.SignatureType
		if err := binary.Write(filteredUpdate, binary.LittleEndian, updateSigType); err != nil {
			return nil, xerrors.Errorf("cannot encode new EFI_SIGNATURE_LIST.SignatureType: %w", err)
		}

		// Calculate and encode EFI_SIGNATURE_LIST.SignatureListSize. This includes EFI_SIGNATURE_LIST.SignatureType (16 bytes),
		// EFI_SIGNATURE_LIST.SignatureListSize (4 bytes), EFI_SIGNATURE_LIST.SignatureHeaderSize (4 bytes),
		// EFI_SIGNATURE_LIST.SignatureSize (4 bytes), EFI_SIGNATURE_LIST.SignatureHeader and EFI_SIGNATURE_LIST.Signatures.
		signatureListSize := uint32(binary.Size(tcglog.EFIGUID{})) + 12 + uint32(len(updateSigHeader)) + uint32(newSigs.Len())
		if err := binary.Write(filteredUpdate, binary.LittleEndian, uint32(signatureListSize)); err != nil {
			return nil, xerrors.Errorf("cannot write new EFI_SIGNATURE_LIST.SignatureListSize: %w", err)
		}

		// Encode EFI_SIGNATURE_LIST.SignatureHeaderSize
		if err := binary.Write(filteredUpdate, binary.LittleEndian, uint32(len(updateSigHeader))); err != nil {
			return nil, xerrors.Errorf("cannot write new EFI_SIGNATURE_LIST.SignatureHeaderSize: %w", err)
		}

		// Encode EFI_SIGNATURE_LIST.SignatureSize
		if err := binary.Write(filteredUpdate, binary.LittleEndian, uint32(updateSigSize)); err != nil {
			return nil, xerrors.Errorf("cannot write new EFI_SIGNATURE_LIST.SignatureSize: %w", err)
		}

		// Write EFI_SIGNATURE_LIST.SignatureHeader
		if _, err := filteredUpdate.Write(updateSigHeader); err != nil {
			return nil, xerrors.Errorf("cannot write new EFI_SIGNATURE_LIST.SignatureHeader: %w", err)
		}

		// Write the saved EFI_SIGNATURE_DATA entries for this list
		if _, err := filteredUpdate.ReadFrom(&newSigs); err != nil {
			return nil, xerrors.Errorf("cannot write new EFI_SIGNATURE_DATA entries: %w", err)
		}
	}

	res := new(bytes.Buffer)

	if _, err := res.ReadFrom(io.NewSectionReader(orig, 0, (1<<63)-1)); err != nil {
		return nil, xerrors.Errorf("cannot write original database to target: %w", err)
	}
	if _, err := res.ReadFrom(filteredUpdate); err != nil {
		return nil, xerrors.Errorf("cannot write filtered update to target: %w", err)
	}

	return res.Bytes(), nil
}

// secureBootDbUpdate corresponds to an on-disk EFI signature database update.
type secureBootDbUpdate struct {
	db   string
	path string
}

// buildSignatureDbUpdateList builds a list of EFI signature database updates that will be applied by sbkeysync when executed with
// the provided key stores.
func buildSignatureDbUpdateList(keystores []string) ([]*secureBootDbUpdate, error) {
	if len(keystores) == 0 {
		// Nothing to do
		return nil, nil
	}

	// Run sbkeysync in dry run mode to build a list of updates it will try to append. It will only try to append an update that
	// contains keys which don't currently exist in the firmware database.
	// FIXME: This isn't a guarantee that the update is actually applicable because it could fail a signature check. We should
	// probably filter updates out if they obviously won't apply.
	var updates []*secureBootDbUpdate

	sbKeySync, err := exec.LookPath(sbKeySyncExe)
	if err != nil {
		return nil, xerrors.Errorf("lookup failed %s: %w", sbKeySyncExe, err)
	}

	args := []string{"--dry-run", "--verbose", "--no-default-keystores", "--efivars-path", efivarsPath}
	for _, ks := range keystores {
		args = append(args, "--keystore", ks)
	}

	out, err := osutil.StreamCommand(sbKeySync, args...)
	if err != nil {
		return nil, xerrors.Errorf("cannot execute command: %v", err)
	}

	scanner := bufio.NewScanner(out)
	seenNewKeysHeader := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "New keys in filesystem:" {
			seenNewKeysHeader = true
			continue
		}
		if !seenNewKeysHeader {
			continue
		}
		line = strings.TrimSpace(line)
		for _, ks := range keystores {
			rel, err := filepath.Rel(ks, line)
			if err != nil {
				continue
			}
			if strings.HasPrefix("..", rel) {
				continue
			}
			updates = append(updates, &secureBootDbUpdate{db: filepath.Dir(rel), path: line})
		}
	}

	return updates, nil
}

// secureBootVerificationEvent corresponds to a EV_EFI_VARIABLE_AUTHORITY event and associated image load event
// (EV_EFI_BOOT_SERVICES_DRIVER, EV_EFI_RUNTIME_SERVICES_DRIVER or EV_EFI_BOOT_SERVICES_APPLICATION).
type secureBootVerificationEvent struct {
	event          *tcglog.Event
	imageLoadEvent *tcglog.Event
}

// identifyInitialOSLaunchVerificationEvent finds the secure boot verification event associated with the verification of the initial
// OS EFI image.
func identifyInitialOSLaunchVerificationEvent(events []*tcglog.Event) (*secureBootVerificationEvent, error) {
	var lastEvent *tcglog.Event
	var lastEventImageLoadEvent *tcglog.Event
	seenInitialOSLaunchVerificationEvent := false

Loop:
	for _, e := range events {
		switch e.PCRIndex {
		case uefiDriverPCR:
			if e.EventType != tcglog.EventTypeEFIBootServicesDriver && e.EventType != tcglog.EventTypeEFIRuntimeServicesDriver {
				continue
			}
			if lastEvent == nil {
				// Drivers can be launched without verification in some circumstances (eg, if loaded from a firmware volume)
				continue
			}
			if lastEventImageLoadEvent != nil {
				continue
			}
			lastEventImageLoadEvent = e
		case bootManagerCodePCR:
			if e.EventType != tcglog.EventTypeEFIBootServicesApplication {
				continue
			}
			if lastEvent == nil {
				return nil, errors.New("boot manager image load event occurred without a preceding verification event")
			}
			seenInitialOSLaunchVerificationEvent = true
			if lastEventImageLoadEvent == nil {
				lastEventImageLoadEvent = e
			}
			break Loop
		case secureBootPCR:
			if e.EventType != tcglog.EventTypeEFIVariableAuthority {
				continue
			}
			lastEvent = e
			lastEventImageLoadEvent = nil
		}
	}

	if !seenInitialOSLaunchVerificationEvent {
		return nil, errors.New("boot manager image load event not found")
	}
	return &secureBootVerificationEvent{event: lastEvent, imageLoadEvent: lastEventImageLoadEvent}, nil
}

// isSecureBootConfigMeasurementEvent determines if event corresponds to the measurement of a secure boot configuration.
func isSecureBootConfigMeasurementEvent(event *tcglog.Event, guid *tcglog.EFIGUID, name string) bool {
	if event.PCRIndex != secureBootPCR {
		return false
	}
	if event.EventType != tcglog.EventTypeEFIVariableDriverConfig {
		return false
	}

	efiVarData, isEfiVar := event.Data.(*tcglog.EFIVariableEventData)
	if !isEfiVar {
		return false
	}

	return efiVarData.VariableName == *guid && efiVarData.UnicodeName == name
}

// isKEKMeasurementEvent determines if event corresponds to the measurement of KEK.
func isKEKMeasurementEvent(event *tcglog.Event) bool {
	return isSecureBootConfigMeasurementEvent(event, efiGlobalVariableGuid, kekName)
}

// isDbMeasurementEvent determines if event corresponds to the measurement of UEFI authorized signature database.
func isDbMeasurementEvent(event *tcglog.Event) bool {
	return isSecureBootConfigMeasurementEvent(event, efiImageSecurityDatabaseGuid, dbName)
}

// isDbxMeasurementEvent determines if event corresponds to the measurement of UEFI forbidden signature database.
func isDbxMeasurementEvent(event *tcglog.Event) bool {
	return isSecureBootConfigMeasurementEvent(event, efiImageSecurityDatabaseGuid, dbxName)
}

// isVerificationEvent determines if event corresponds to the verification of a EFI image.
func isVerificationEvent(event *tcglog.Event) bool {
	return event.PCRIndex == secureBootPCR && event.EventType == tcglog.EventTypeEFIVariableAuthority
}

// isShimExecutable determines if the EFI executable read from r looks like a valid shim binary (ie, it has a ".vendor_cert" section.
func isShimExecutable(r io.ReaderAt) (bool, error) {
	pefile, err := pe.NewFile(r)
	if err != nil {
		return false, xerrors.Errorf("cannot decode PE binary: %w", err)
	}
	return pefile.Section(".vendor_cert") != nil, nil
}

// EFISecureBootPolicyProfileParams provide the arguments to AddEFISecureBootPolicyProfile.
type EFISecureBootPolicyProfileParams struct {
	PCRAlgorithm  tpm2.HashAlgorithmId
	LoadSequences []*EFIImageLoadEvent // A list of EFI image load sequences for which to compute PCR digests for

	// SignatureDbUpdateKeystores is a list of directories containing EFI signature database updates for which to compute PCR digests
	// for. These directories are passed to sbkeysync using the --keystore option.
	SignatureDbUpdateKeystores []string
}

// secureBootDb corresponds to a EFI signature database.
type secureBootDb struct {
	variableName tcglog.EFIGUID
	unicodeName  string
	signatures   []*efiSignatureData
}

// secureBootDbSet corresponds to a set of EFI signature databases.
type secureBootDbSet struct {
	uefiDb *secureBootDb
	mokDb  *secureBootDb
	shimDb *secureBootDb
}

// secureBootPolicyGenPath corresponds to a single path of secure boot policy events.
type secureBootPolicyGenPath struct {
	pcrValue                   tpm2.Digest     // The current computed PCR value associated with this event path
	dbUpdateLevel              int             // The number of EFI signature database events applied on this event path
	dbSet                      secureBootDbSet // The signature database set associated with this event path
	firmwareVerificationEvents tpm2.DigestList // The verification events recorded by firmware on this event path
	shimVerificationEvents     tpm2.DigestList // The verification events recorded by shim on this event path

	unbootable bool // Whether this event path is one that cannot be booted, and so it's digest shall be omitted
}

// extendMeasurement extends the supplied digest to the current value of pcrValue for this event path.
func (p *secureBootPolicyGenPath) extendMeasurement(alg tpm2.HashAlgorithmId, digest tpm2.Digest) {
	if len(digest) != alg.Size() {
		panic("invalid digest length")
	}

	h := alg.NewHash()
	h.Write(p.pcrValue)
	h.Write(digest)
	p.pcrValue = h.Sum(nil)
}

// extendVerificationMeasurement extends the supplied digest to the current value of pcrValue for this event path, and records the
// extended digest in order to avoid measuring the same verification event more than once.
func (p *secureBootPolicyGenPath) extendVerificationMeasurement(alg tpm2.HashAlgorithmId, digest tpm2.Digest, source EFIImageLoadEventSource) {
	var digests *tpm2.DigestList
	switch source {
	case Firmware:
		digests = &p.firmwareVerificationEvents
	case Shim:
		digests = &p.shimVerificationEvents
	}
	*digests = append(*digests, digest)
	p.extendMeasurement(alg, digest)
}

// duplicate makes a copy of this event path. Note that whilst the firmwareVerificationEvents and shimVerificationEvents slices
// are copied and can be mutated in the copy, the individual digests are not copied and should be considered read only. The pointers
// to secureBootDb structs are copied and can be changed in the copy, but the actual secureBootDb instances should also be considered
// read only.
func (p *secureBootPolicyGenPath) duplicate() *secureBootPolicyGenPath {
	n := &secureBootPolicyGenPath{}

	n.pcrValue = make(tpm2.Digest, len(p.pcrValue))
	copy(n.pcrValue, p.pcrValue)

	n.dbUpdateLevel = p.dbUpdateLevel
	n.dbSet = p.dbSet

	n.firmwareVerificationEvents = make(tpm2.DigestList, len(p.firmwareVerificationEvents))
	copy(n.firmwareVerificationEvents, p.firmwareVerificationEvents)
	n.shimVerificationEvents = make(tpm2.DigestList, len(p.shimVerificationEvents))
	copy(n.shimVerificationEvents, p.shimVerificationEvents)

	return n
}

type loadEventAndPaths struct {
	event *EFIImageLoadEvent
	paths []*secureBootPolicyGenPath
}

// secureBootPolicyGen is the main structure involved with computing secure boot policy PCR digests.
type secureBootPolicyGen struct {
	params *EFISecureBootPolicyProfileParams
}

// extendMeasurement extends the supplied digest to the current value of pcrValue for the specified event path.
func (g *secureBootPolicyGen) extendMeasurement(path *secureBootPolicyGenPath, digest tpm2.Digest) {
	path.extendMeasurement(g.params.PCRAlgorithm, digest)
}

// extendFirmwareVerificationMeasurement extends the supplied digest to the current value of pcrValue for the specified event path,
// and records the extended digest in order to avoid measuring the same verification event more than once.
func (g *secureBootPolicyGen) extendFirmwareVerificationMeasurement(path *secureBootPolicyGenPath, digest tpm2.Digest) {
	path.extendVerificationMeasurement(g.params.PCRAlgorithm, digest, Firmware)
}

// computeAndExtendVariableMeasurement computes a EFI variable measurement from the supplied arguments and extends that to the
// current value of pcrValue for the specified event path.
func (g *secureBootPolicyGen) computeAndExtendVariableMeasurement(path *secureBootPolicyGenPath, varName *tcglog.EFIGUID, unicodeName string, varData []byte) error {
	data := tcglog.EFIVariableEventData{
		VariableName: *varName,
		UnicodeName:  unicodeName,
		VariableData: varData}
	h := g.params.PCRAlgorithm.NewHash()
	if err := data.EncodeMeasuredBytes(h); err != nil {
		return xerrors.Errorf("cannot encode EFI_VARIABLE_DATA: %w", err)
	}
	g.extendMeasurement(path, h.Sum(nil))
	return nil
}

// computeAndExtendVerificationMeasurement computes a verification measurement for the EFI image obtained from r and extends that to
// the current value of pcrValue for the specified event paths. If the computed verification measurement has already been measured
// from the specified source on an event path, then it will not be measured again.
//
// In order to compute the measurement for each event path, the source of the certificate that will be used to verify the image
// needs to be determined. If the image is not signed with an authority that chains to a valid signature database for a specific path,
// then that path will be marked as unbootable and its computed PCR digest shall be omitted from the final results.
func (g *secureBootPolicyGen) computeAndExtendVerificationMeasurement(paths []*secureBootPolicyGenPath, r io.ReaderAt, source EFIImageLoadEventSource) error {
	pefile, err := pe.NewFile(r)
	if err != nil {
		return xerrors.Errorf("cannot decode PE binary: %w", err)
	}

	if pefile.OptionalHeader == nil {
		// Work around debug/pe not handling variable length optional headers - see
		// https://github.com/golang/go/commit/3b92f36d15c868e856be71c0fadfc7ff97039b96. We copy the required functionality from that commit
		// in to this package for now in order to avoid a hard dependency on newer go versions.
		h, err := readVariableLengthOptionalHeader(r, pefile.FileHeader.SizeOfOptionalHeader)
		if err != nil {
			return xerrors.Errorf("cannot decode PE binary optional header: %w", err)
		}
		pefile.OptionalHeader = h
	}

	// Obtain security directory entry from optional header
	var dd *pe.DataDirectory
	switch oh := pefile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes < 5 {
			return errors.New("cannot obtain security directory entry from PE binary: invalid number of data directories")
		}
		dd = &oh.DataDirectory[4]
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes < 5 {
			return errors.New("cannot obtain security directory entry from PE binary: invalid number of data directories")
		}
		dd = &oh.DataDirectory[4]
	default:
		return errors.New("cannot obtain security directory entry from PE binary: no optional header")
	}

	// Create a reader for the security directory entry, which points to a WIN_CERTIFICATE struct
	secReader := io.NewSectionReader(r, int64(dd.VirtualAddress), int64(dd.Size))

	var cert *winCertificateAuthenticode
	if c, err := decodeWinCertificate(secReader); err != nil {
		return xerrors.Errorf("cannot decode WIN_CERTIFICATE from security directory entry of PE binary: %w", err)
	} else if c.wCertificateType() != winCertTypePKCSSignedData {
		return fmt.Errorf("unexpected value for WIN_CERTIFICATE.wCertificateType (0x%04x): not an Authenticode signature", c.wCertificateType())
	} else {
		cert = c.(*winCertificateAuthenticode)
	}

	// Decode the signature
	p7, err := pkcs7.Parse(cert.Data)
	if err != nil {
		return xerrors.Errorf("cannot decode signature: %w", err)
	}

	// Grab the certificate for the signing key
	signer := p7.GetOnlySigner()
	if signer == nil {
		return errors.New("cannot obtain signer certificate from signature")
	}

	for _, p := range paths {
		if p.unbootable {
			continue
		}

		dbs := []*secureBootDb{p.dbSet.uefiDb}
		if source == Shim {
			if p.dbSet.shimDb == nil {
				return errors.New("shim specified as event source without a shim executable appearing in preceding events")
			}
			dbs = append(dbs, p.dbSet.mokDb, p.dbSet.shimDb)
		}

		var root *efiSignatureData
		var rootDb *secureBootDb
	Outer:
		for _, db := range dbs {
			if db == nil {
				continue
			}

			for _, s := range db.signatures {
				// Ignore signatures that aren't X509 certificates
				if s.signatureType != *efiCertX509Guid {
					continue
				}

				if bytes.Equal(s.data, signer.Raw) {
					// The signing certificate is actually the root in the DB
					root = s
					rootDb = db
					break Outer
				}

				c, err := x509.ParseCertificate(s.data)
				if err != nil {
					continue
				}

				if err := signer.CheckSignatureFrom(c); err == nil {
					// The signing certificate was issued by this root
					root = s
					rootDb = db
					break Outer
				}
			}
		}

		if root == nil {
			p.unbootable = true
			continue
		}

		// Serialize authority certificate for measurement
		var varData *bytes.Buffer
		switch source {
		case Firmware:
			// Firmware measures the entire EFI_SIGNATURE_DATA, including the SignatureOwner
			varData = new(bytes.Buffer)
			if err := root.encode(varData); err != nil {
				return xerrors.Errorf("cannot encode EFI_SIGNATURE_DATA for authority: %w", err)
			}
		case Shim:
			// Shim measures the certificate data, rather than the entire EFI_SIGNATURE_DATA
			varData = bytes.NewBuffer(root.data)
		}

		// Create event data, compute digest and perform extension for verification of this executable
		eventData := tcglog.EFIVariableEventData{
			VariableName: rootDb.variableName,
			UnicodeName:  rootDb.unicodeName,
			VariableData: varData.Bytes()}
		h := g.params.PCRAlgorithm.NewHash()
		if err := eventData.EncodeMeasuredBytes(h); err != nil {
			return xerrors.Errorf("cannot encode EFI_VARIABLE_DATA: %w", err)
		}
		digest := h.Sum(nil)

		// Don't measure events that have already been measured
		var digests *tpm2.DigestList
		switch source {
		case Firmware:
			digests = &p.firmwareVerificationEvents
		case Shim:
			digests = &p.shimVerificationEvents
		}
		measured := false
		for _, d := range *digests {
			if bytes.Equal(d, digest) {
				measured = true
				break
			}
		}
		if measured {
			continue
		}
		p.extendVerificationMeasurement(g.params.PCRAlgorithm, digest, source)
	}

	return nil
}

// processSignatureDbMeasurementEvent computes a EFI signature database measurement for the specified database and with the supplied
// updates, and then extends that to the current value of pcrValue for the specified event path.
func (g *secureBootPolicyGen) processSignatureDbMeasurementEvent(path *secureBootPolicyGenPath, guid *tcglog.EFIGUID, name, filename string, sigDbUpdates []*secureBootDbUpdate) ([]byte, error) {
	db, err := ioutil.ReadFile(filepath.Join(efivarsPath, filename))
	if err != nil && !os.IsNotExist(err) {
		return nil, xerrors.Errorf("cannot read current variable: %w", err)
	}
	if len(db) > 0 {
		if len(db) < 4 {
			return nil, errors.New("current variable data is too short")
		}
		db = db[4:]
	}

	for _, u := range sigDbUpdates {
		if u.db != name {
			continue
		}
		if f, err := os.Open(u.path); err != nil {
			return nil, xerrors.Errorf("cannot open signature DB update: %w", err)
		} else if d, err := computeDbUpdate(bytes.NewReader(db), f); err != nil {
			return nil, xerrors.Errorf("cannot compute signature DB update for %s: %w", u.path, err)
		} else {
			db = d
		}
	}

	if err := g.computeAndExtendVariableMeasurement(path, guid, name, db); err != nil {
		return nil, xerrors.Errorf("cannot compute and extend measurement: %w", err)
	}

	return db, nil
}

// processKEKMeasurementEvent computes a measurement of KEK with the supplied udates applied and then extends that to the current
// value of pcrValue for the specified event path.
func (g *secureBootPolicyGen) processKEKMeasurementEvent(path *secureBootPolicyGenPath, sigDbUpdates []*secureBootDbUpdate) error {
	if _, err := g.processSignatureDbMeasurementEvent(path, efiGlobalVariableGuid, kekName, kekFilename, sigDbUpdates); err != nil {
		return err
	}
	return nil
}

// processDbMeasurementEvent computes a measurement of the EFI authorized signature database with the supplied udates applied and then
// extends that to the current value of pcrValue for the specified event path. The specified event path is then updated to contain
// a list of signatures associated with the resulting authorized signature database contents, which is used later on when computing
// verification events in secureBootPolicyGen.computeAndExtendVerificationMeasurement.
func (g *secureBootPolicyGen) processDbMeasurementEvent(path *secureBootPolicyGenPath, sigDbUpdates []*secureBootDbUpdate) error {
	db, err := g.processSignatureDbMeasurementEvent(path, efiImageSecurityDatabaseGuid, dbName, dbFilename, sigDbUpdates)
	if err != nil {
		return err
	}

	sigs, err := decodeSecureBootDb(bytes.NewReader(db))
	if err != nil {
		return xerrors.Errorf("cannot decode DB contents: %w", err)
	}

	path.dbSet.uefiDb = &secureBootDb{variableName: *efiImageSecurityDatabaseGuid, unicodeName: dbName, signatures: sigs}

	return nil
}

// processDbxMeasurementEvent computes a measurement of the EFI forbidden signature database with the supplied udates applied and then
// extends that to the current value of pcrValue for the specified event path.
func (g *secureBootPolicyGen) processDbxMeasurementEvent(path *secureBootPolicyGenPath, sigDbUpdates []*secureBootDbUpdate) error {
	if _, err := g.processSignatureDbMeasurementEvent(path, efiImageSecurityDatabaseGuid, dbxName, dbxFilename, sigDbUpdates); err != nil {
		return err
	}
	return nil
}

// processPreOSEvents iterates over the pre-OS secure boot policy events contained within the supplied list of events and extends
// these to the current value of pcrValue for the specified event path. For events corresponding to the measurement of EFI signature
// databases, measurements are computed based on the current contents of each database with the supplied updates applied.
//
// Processing of the list of events stops when the verification event associated with the loading of the initial OS EFI executable
// is encountered.
func (g *secureBootPolicyGen) processPreOSEvents(path *secureBootPolicyGenPath, events []*tcglog.Event, initialOSVerificationEvent *secureBootVerificationEvent, sigDbUpdates []*secureBootDbUpdate) error {
	for len(events) > 0 && events[0] != initialOSVerificationEvent.event {
		e := events[0]
		events = events[1:]
		switch {
		case isKEKMeasurementEvent(e):
			if err := g.processKEKMeasurementEvent(path, sigDbUpdates); err != nil {
				return xerrors.Errorf("cannot process KEK measurement event: %w", err)
			}
		case isDbMeasurementEvent(e):
			if err := g.processDbMeasurementEvent(path, sigDbUpdates); err != nil {
				return xerrors.Errorf("cannot process db measurement event: %w", err)
			}
		case isDbxMeasurementEvent(e):
			if err := g.processDbxMeasurementEvent(path, sigDbUpdates); err != nil {
				return xerrors.Errorf("cannot process dbx measurement event: %w", err)
			}
		case isVerificationEvent(e):
			g.extendFirmwareVerificationMeasurement(path, tpm2.Digest(e.Digests[tcglog.AlgorithmId(g.params.PCRAlgorithm)]))
		case e.PCRIndex == secureBootPCR:
			g.extendMeasurement(path, tpm2.Digest(e.Digests[tcglog.AlgorithmId(g.params.PCRAlgorithm)]))
		}
	}

	if len(events) == 0 {
		return nil
	}

	if initialOSVerificationEvent.imageLoadEvent.PCRIndex == bootManagerCodePCR {
		return nil
	}

	// The verification event associated with the initial OS load event was recorded as part of a UEFI driver load, so we need to keep it.
	g.extendFirmwareVerificationMeasurement(path, tpm2.Digest(initialOSVerificationEvent.event.Digests[tcglog.AlgorithmId(g.params.PCRAlgorithm)]))

	return nil
}

// processShimExecutable extracts the vendor certificate from the shim executable read from r, and then updates the specified event
// paths to contain a reference to the vendor certificate so that it can be used later on when computing verification events in
// secureBootPolicyGen.computeAndExtendVerificationMeasurement.
func (g *secureBootPolicyGen) processShimExecutable(paths []*secureBootPolicyGenPath, r io.ReaderAt) error {
	// Extract this shim's vendor cert
	vendorCert, err := readShimVendorCert(r)
	if err != nil {
		return xerrors.Errorf("cannot extract vendor certificate: %w", err)
	}

	for _, p := range paths {
		p.dbSet.shimDb = &secureBootDb{variableName: *shimGuid, unicodeName: shimName}
		if vendorCert != nil {
			p.dbSet.shimDb.signatures = append(p.dbSet.shimDb.signatures, &efiSignatureData{signatureType: *efiCertX509Guid, data: vendorCert})
		}
		p.shimVerificationEvents = nil
	}

	return nil
}

// processOSLoadEvent computes a measurement associated with the supplied image load event and extends this to the current value of
// pcrValue for each of the specified event paths. If the image load corresponds to shim, then some additional processing is performed
// to extract the included vendor certificate (see secureBootPolicyGen.processShimExecutable).
func (g *secureBootPolicyGen) processOSLoadEvent(paths []*secureBootPolicyGenPath, event *EFIImageLoadEvent) error {
	b, err := event.Image.ReadAll()
	if err != nil {
		return xerrors.Errorf("cannot read image: %w", err)
	}

	r := bytes.NewReader(b)

	isShim, err := isShimExecutable(r)
	if err != nil {
		return xerrors.Errorf("cannot determine image type: %w", err)
	}

	if err := g.computeAndExtendVerificationMeasurement(paths, r, event.Source); err != nil {
		return xerrors.Errorf("cannot compute load verification event: %w", err)
	}

	if !isShim {
		return nil
	}

	if err := g.processShimExecutable(paths, r); err != nil {
		return xerrors.Errorf("cannot process shim executable: %w", err)
	}

	return nil
}

// run takes a TCG event log and computes a set of secure boot policy PCR digests from the supplied configuration (see
// EFISecureBootPolicyProfileParams)
func (g *secureBootPolicyGen) run(events []*tcglog.Event) (tpm2.DigestList, error) {
	sigDbUpdates, err := buildSignatureDbUpdateList(g.params.SignatureDbUpdateKeystores)
	if err != nil {
		return nil, xerrors.Errorf("cannot build list of UEFI signature DB updates: %w", err)
	}

	initialOSVerificationEvent, err := identifyInitialOSLaunchVerificationEvent(events)
	if err != nil {
		return nil, xerrors.Errorf("cannot identify initial OS launch verification event: %w", err)
	}

	var allPaths []*secureBootPolicyGenPath

	for i := 0; i <= len(sigDbUpdates); i++ {
		path := &secureBootPolicyGenPath{pcrValue: make(tpm2.Digest, g.params.PCRAlgorithm.Size()), dbUpdateLevel: i}
		if err := g.processPreOSEvents(path, events, initialOSVerificationEvent, sigDbUpdates[0:i]); err != nil {
			return nil, xerrors.Errorf("cannot process pre-OS events from event log: %w", err)
		}
		allPaths = append(allPaths, path)
	}

	numPreOSPaths := len(allPaths)

	duplicatePaths := func(paths []*secureBootPolicyGenPath) (out []*secureBootPolicyGenPath) {
		for _, p := range paths {
			p2 := p.duplicate()
			allPaths = append(allPaths, p2)
			out = append(out, p2)
		}
		return
	}

	var loadEvents []*loadEventAndPaths
	var nextLoadEvents []*loadEventAndPaths

	for i, e := range g.params.LoadSequences {
		var paths []*secureBootPolicyGenPath
		if i == 0 {
			paths = allPaths
		} else {
			paths = duplicatePaths(allPaths[0:numPreOSPaths])
		}
		loadEvents = append(loadEvents, &loadEventAndPaths{event: e, paths: paths})
	}

	for len(loadEvents) > 0 {
		e := loadEvents[0]
		loadEvents = loadEvents[1:]
		if err := g.processOSLoadEvent(e.paths, e.event); err != nil {
			return nil, xerrors.Errorf("cannot process OS load event for %s: %w", e.event.Image, err)
		}
		for i, n := range e.event.Next {
			var paths []*secureBootPolicyGenPath
			if i == 0 {
				paths = e.paths
			} else {
				paths = duplicatePaths(e.paths)
			}
			nextLoadEvents = append(nextLoadEvents, &loadEventAndPaths{event: n, paths: paths})
		}
		if len(loadEvents) == 0 {
			loadEvents = nextLoadEvents
			nextLoadEvents = nil
		}
	}

	var results tpm2.DigestList
	validPathsForCurrentDb := false

	for _, p := range allPaths {
		if p.unbootable {
			continue
		}
		if p.dbUpdateLevel == 0 {
			validPathsForCurrentDb = true
		}
		duplicate := false
		for _, d := range results {
			if bytes.Equal(d, p.pcrValue) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		results = append(results, p.pcrValue)
	}

	if !validPathsForCurrentDb {
		return nil, errors.New("no bootable paths with current EFI signature database")
	}

	return results, nil
}

// AddEFISecureBootPolicyProfile adds the UEFI secure boot policy profile to the provided PCR protection profile, in order to generate
// a PCR policy that restricts access to a key to a set of UEFI secure boot policies measured to PCR 7. The secure boot policy
// information that is measured to PCR 7 is defined in section 2.3.4.8 of the "TCG PC Client Platform Firmware Profile Specification".
//
// The secure boot policy measurements include events that correspond to the verification of loaded EFI images, and those events
// record the certificate of the authorities used to verify images. The params argument allows the generated PCR policy to be
// restricted to a specific set of chains of trust by specifying EFI image load sequences via the LoadSequences field.
//
// The secure boot policy measurements include the secure boot configuration, which includes the contents of the UEFI signature
// databases. In order to support atomic updates of these databases with the sbkeysync tool, it is possible to generate a PCR policy
// computed from pending signature database updates. This can be done by supplying the keystore directories passed to sbkeysync via
// the SignatureDbUpdateKeystores field of the params argument. This function assumes that sbkeysync is executed with the
// "--no-default-keystores" option. When there are pending updates in the specified directories, this function will generate a PCR
// policy that is compatible with the current database contents and the database contents computed for each individual update.
//
// For the most common case where there are no signature database updates pending in the specified keystore directories and each image
// load event sequence corresponds to loads of images that are all verified with the same chain of trust, this is a complicated way of
// adding a single PCR digest to the provided PCRProtectionProfile.
func AddEFISecureBootPolicyProfile(profile *PCRProtectionProfile, params *EFISecureBootPolicyProfileParams) error {
	// Load event log
	eventLog, err := os.Open(eventLogPath)
	if err != nil {
		return xerrors.Errorf("cannot open TCG event log: %w", err)
	}
	log, err := tcglog.NewLog(eventLog, tcglog.LogOptions{})
	if err != nil {
		return xerrors.Errorf("cannot parse TCG event log header: %w", err)
	}

	if !log.Algorithms.Contains(tcglog.AlgorithmId(params.PCRAlgorithm)) {
		return errors.New("cannot compute secure boot policy digests: the TCG event log does not have the requested algorithm")
	}

	// Parse events and make sure that the current boot is sane.
	var events []*tcglog.Event
	for {
		event, err := log.NextEvent()
		if err == io.EOF {
			break
		}
		if err != nil {
			return xerrors.Errorf("cannot parse TCG event log: %w", err)
		}

		switch event.PCRIndex {
		case bootManagerCodePCR:
			if event.EventType == tcglog.EventTypeEFIAction && event.Data.String() == returningFromEfiApplicationEvent {
				// Firmware should record this event if an EFI application returns to the boot manager. Bail out if this happened because the policy might not make sense.
				return errors.New("cannot compute secure boot policy digests: the current boot was preceeded by a boot attempt to an EFI " +
					"application that returned to the boot manager, without a reboot in between")
			}
		case secureBootPCR:
			switch event.EventType {
			case tcglog.EventTypeEFIVariableDriverConfig:
				efiVarData, isEfiVar := event.Data.(*tcglog.EFIVariableEventData)
				if !isEfiVar {
					return fmt.Errorf("%s secure boot policy event has invalid event data", event.EventType)
				}
				if efiVarData.VariableName == *efiGlobalVariableGuid && efiVarData.UnicodeName == sbStateName {
					switch {
					case event.Index > 0:
						// The spec says that secure boot policy must be measured again if the system supports changing it before ExitBootServices
						// without a reboot. But the policy we create won't make sense, so bail out
						return errors.New("cannot compute secure boot policy digests: secure boot configuration was modified after the initial " +
							"configuration was measured, without performing a reboot")
					case efiVarData.VariableData[0] == 0x00:
						return errors.New("cannot compute secure boot policy digests: the current boot was performed with secure boot disabled in firmware")
					}
				}
			case tcglog.EventTypeEFIVariableAuthority:
				efiVarData, isEfiVar := event.Data.(*tcglog.EFIVariableEventData)
				if !isEfiVar {
					return fmt.Errorf("%s secure boot policy event has invalid event data", event.EventType)
				}
				if efiVarData.VariableName == *shimGuid && efiVarData.UnicodeName == mokSbStateName {
					// MokSBState is set to 0x01 if secure boot enforcement is disabled in shim. The variable is deleted when secure boot enforcement
					// is enabled, so don't bother looking at the value here. It doesn't make a lot of sense to create a policy if secure boot
					// enforcement is disabled in shim
					return errors.New("cannot compute secure boot policy digests: the current boot was performed with validation disabled in Shim")
				}
			}
		}
		events = append(events, event)
	}

	gen := &secureBootPolicyGen{params: params}
	digests, err := gen.run(events)
	if err != nil {
		return xerrors.Errorf("cannot compute secure boot policy digests: %w", err)
	}

	var subProfiles []*PCRProtectionProfile
	for _, d := range digests {
		subProfiles = append(subProfiles, NewPCRProtectionProfile().AddPCRValue(params.PCRAlgorithm, secureBootPCR, d))
	}

	profile.AddProfileOR(subProfiles...)
	return nil
}
