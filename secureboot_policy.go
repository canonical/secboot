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
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/canonical/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"

	"golang.org/x/xerrors"

	"go.mozilla.org/pkcs7"
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

	oidSha256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// EFIImage corresponds to a binary that is loaded, verified and executed before ExitBootServices.
type EFIImage interface {
	fmt.Stringer
	Open() (interface {
		io.ReaderAt
		io.Closer
	}, error) // Open a handle to the image for reading
}

// SnapFileEFIImage corresponds to a binary contained within a snap file that is loaded, verified and executed before ExitBootServices.
type SnapFileEFIImage struct {
	Container snap.Container
	Path      string // The path of the snap image (used by the implementation of fmt.Stringer)
	FileName  string // The filename within the snap squashfs
}

func (f SnapFileEFIImage) String() string {
	return "snap:" + f.Path + ":" + f.FileName
}

func (f SnapFileEFIImage) Open() (interface {
	io.ReaderAt
	io.Closer
}, error) {
	return f.Container.RandomAccessFile(f.FileName)
}

// FileEFIImage corresponds to a file on disk that is loaded, verified and executed before ExitBootServices.
type FileEFIImage string

func (p FileEFIImage) String() string {
	return string(p)
}

func (p FileEFIImage) Open() (interface {
	io.ReaderAt
	io.Closer
}, error) {
	f, err := os.Open(string(p))
	if err != nil {
		return nil, err
	}
	return f, nil
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
func decodeWinCertificate(r io.Reader) (cert winCertificate, length int, err error) {
	var hdr struct {
		Length          uint32
		Revision        uint16
		CertificateType uint16
	}
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, 0, xerrors.Errorf("cannot read WIN_CERTIFICATE header fields: %w", err)
	}
	if hdr.Revision != 0x200 {
		return nil, 0, fmt.Errorf("invalid wRevision value (0x%04x)", hdr.Revision)
	}

	switch hdr.CertificateType {
	case winCertTypePKCSSignedData:
		out := &winCertificateAuthenticode{}
		out.Data = make([]byte, int(hdr.Length)-binary.Size(hdr))
		if _, err := io.ReadFull(r, out.Data); err != nil {
			return nil, 0, xerrors.Errorf("cannot read WIN_CERTIFICATE.bCertificate: %w", err)
		}
		return out, int(hdr.Length), nil
	case winCertTypeEfiGuid:
		out := &winCertificateUefiGuid{}
		if err := binary.Read(r, binary.LittleEndian, &out.CertType); err != nil {
			return nil, 0, xerrors.Errorf("cannot read WIN_CERTIFICATE_UEFI_GUID.CertType: %w", err)
		}
		out.Data = make([]byte, int(hdr.Length)-binary.Size(hdr)-binary.Size(out.CertType))
		if _, err := io.ReadFull(r, out.Data); err != nil {
			return nil, 0, xerrors.Errorf("cannot read WIN_CERTIFICATE_UEFI_GUID.CertData: %w", err)
		}
		return out, int(hdr.Length), nil
	default:
		return nil, 0, fmt.Errorf("cannot decode unrecognized type (0x%04x)", hdr.CertificateType)
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
	if c, _, err := decodeWinCertificate(update); err != nil {
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
	// PCRAlgorithm is the algorithm for which to compute PCR digests for. TPMs compliant with the "TCG PC Client Platform TPM Profile
	// (PTP) Specification" Level 00, Revision 01.03 v22, May 22 2017 are required to support tpm2.HashAlgorithmSHA1 and
	// tpm2.HashAlgorithmSHA256. Support for other digest algorithms is optional.
	PCRAlgorithm tpm2.HashAlgorithmId

	// LoadSequences is a list of EFI image load sequences for which to compute PCR digests for.
	LoadSequences []*EFIImageLoadEvent

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

type secureBootAuthority struct {
	signature *efiSignatureData
	source    *secureBootDb
}

type authenticodeSignerAndIntermediates struct {
	signer        *x509.Certificate
	intermediates *x509.CertPool
}

// secureBootPolicyGen is the main structure involved with computing secure boot policy PCR digests. It is essentially just
// a container for EFISecureBootPolicyProfileParams - per-branch context is maintained in secureBootPolicyGenBranch instead.
type secureBootPolicyGen struct {
	*EFISecureBootPolicyProfileParams
}

// secureBootPolicyGenBranch represents a branch of a PCRProtectionProfile. It contains its own PCRProtectionProfile in to which
// instructions can be recorded, as well as some other context associated with this branch.
type secureBootPolicyGenBranch struct {
	gen *secureBootPolicyGen

	profile     *PCRProtectionProfile        // The PCR profile containing the instructions for this branch
	subBranches []*secureBootPolicyGenBranch // Sub-branches, if this has been branched

	dbUpdateLevel              int             // The number of EFI signature database updates applied in this branch
	dbSet                      secureBootDbSet // The signature database set associated with this branch
	firmwareVerificationEvents tpm2.DigestList // The verification events recorded by firmware in this branch
	shimVerificationEvents     tpm2.DigestList // The verification events recorded by shim in this branch
}

// branch creates a branch point in the current branch if one doesn't exist already (although inserting this branch point with
// PCRProtectionProfile.AddProfileOR is deferred until later), and creates a new sub-branch at the current branch point. Once
// this has been called, no more instructions can be inserted in to the current branch.
func (b *secureBootPolicyGenBranch) branch() *secureBootPolicyGenBranch {
	c := &secureBootPolicyGenBranch{gen: b.gen, profile: NewPCRProtectionProfile()}
	b.subBranches = append(b.subBranches, c)

	// Preserve the context associated with this branch
	c.dbUpdateLevel = b.dbUpdateLevel
	c.dbSet = b.dbSet
	c.firmwareVerificationEvents = make(tpm2.DigestList, len(b.firmwareVerificationEvents))
	copy(c.firmwareVerificationEvents, b.firmwareVerificationEvents)
	c.shimVerificationEvents = make(tpm2.DigestList, len(b.shimVerificationEvents))
	copy(c.shimVerificationEvents, b.shimVerificationEvents)

	return c
}

// extendMeasurement extends the supplied digest to this branch.
func (b *secureBootPolicyGenBranch) extendMeasurement(digest tpm2.Digest) {
	if len(b.subBranches) > 0 {
		panic("This branch has already been branched")
	}
	b.profile.ExtendPCR(b.gen.PCRAlgorithm, secureBootPCR, digest)
}

// extendVerificationMeasurement extends the supplied digest and records that the digest has been measured by the specified source in
// to this branch.
func (b *secureBootPolicyGenBranch) extendVerificationMeasurement(digest tpm2.Digest, source EFIImageLoadEventSource) {
	var digests *tpm2.DigestList
	switch source {
	case Firmware:
		digests = &b.firmwareVerificationEvents
	case Shim:
		digests = &b.shimVerificationEvents
	}
	*digests = append(*digests, digest)
	b.extendMeasurement(digest)
}

// extendFirmwareVerificationMeasurement extends the supplied digest and records that the digest has been measured by the firmware
// in to this branch.
func (b *secureBootPolicyGenBranch) extendFirmwareVerificationMeasurement(digest tpm2.Digest) {
	b.extendVerificationMeasurement(digest, Firmware)
}

// omputeAndExtendVariableMeasurement computes a EFI variable measurement from the supplied arguments and extends that to
// this branch.
func (b *secureBootPolicyGenBranch) computeAndExtendVariableMeasurement(varName *tcglog.EFIGUID, unicodeName string, varData []byte) error {
	data := tcglog.EFIVariableEventData{
		VariableName: *varName,
		UnicodeName:  unicodeName,
		VariableData: varData}
	h := b.gen.PCRAlgorithm.NewHash()
	if err := data.EncodeMeasuredBytes(h); err != nil {
		return xerrors.Errorf("cannot encode EFI_VARIABLE_DATA: %w", err)
	}
	b.extendMeasurement(h.Sum(nil))
	return nil
}

// processSignatureDbMeasurementEvent computes a EFI signature database measurement for the specified database and with the supplied
// updates, and then extends that in to this branch.
func (b *secureBootPolicyGenBranch) processSignatureDbMeasurementEvent(guid *tcglog.EFIGUID, name, filename string, sigDbUpdates []*secureBootDbUpdate) ([]byte, error) {
	db, err := ioutil.ReadFile(filepath.Join(efivarsPath, filename))
	if err != nil && !os.IsNotExist(err) {
		return nil, xerrors.Errorf("cannot read current variable: %w", err)
	}
	if len(db) > 0 {
		if len(db) < 4 {
			return nil, errors.New("current variable data is too short")
		}
		// Skip over the 4-byte attribute field
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

	if err := b.computeAndExtendVariableMeasurement(guid, name, db); err != nil {
		return nil, xerrors.Errorf("cannot compute and extend measurement: %w", err)
	}

	return db, nil
}

// processKEKMeasurementEvent computes a measurement of KEK with the supplied udates applied and then extends that in to
// this branch.
func (b *secureBootPolicyGenBranch) processKEKMeasurementEvent(sigDbUpdates []*secureBootDbUpdate) error {
	if _, err := b.processSignatureDbMeasurementEvent(efiGlobalVariableGuid, kekName, kekFilename, sigDbUpdates); err != nil {
		return err
	}
	return nil
}

// processDbMeasurementEvent computes a measurement of the EFI authorized signature database with the supplied updates applied and
// then extends that in to this branch. The branch context is then updated to contain a list of signatures associated with the
// resulting authorized signature database contents, which is used later on when computing verification events in
// secureBootPolicyGen.computeAndExtendVerificationMeasurement.
func (b *secureBootPolicyGenBranch) processDbMeasurementEvent(sigDbUpdates []*secureBootDbUpdate) error {
	db, err := b.processSignatureDbMeasurementEvent(efiImageSecurityDatabaseGuid, dbName, dbFilename, sigDbUpdates)
	if err != nil {
		return err
	}

	sigs, err := decodeSecureBootDb(bytes.NewReader(db))
	if err != nil {
		return xerrors.Errorf("cannot decode DB contents: %w", err)
	}

	b.dbSet.uefiDb = &secureBootDb{variableName: *efiImageSecurityDatabaseGuid, unicodeName: dbName, signatures: sigs}

	return nil
}

// processDbxMeasurementEvent computes a measurement of the EFI forbidden signature database with the supplied updates applied and
// then extends that in to this branch.
func (b *secureBootPolicyGenBranch) processDbxMeasurementEvent(sigDbUpdates []*secureBootDbUpdate) error {
	if _, err := b.processSignatureDbMeasurementEvent(efiImageSecurityDatabaseGuid, dbxName, dbxFilename, sigDbUpdates); err != nil {
		return err
	}
	return nil
}

// processPreOSEvents iterates over the pre-OS secure boot policy events contained within the supplied list of events and extends
// these in to this branch. For events corresponding to the measurement of EFI signature databases, measurements are computed based
// on the current contents of each database with the supplied updates applied.
//
// Processing of the list of events stops when the verification event associated with the loading of the initial OS EFI executable
// is encountered.
func (b *secureBootPolicyGenBranch) processPreOSEvents(events []*tcglog.Event, initialOSVerificationEvent *secureBootVerificationEvent, sigDbUpdates []*secureBootDbUpdate) error {
	for len(events) > 0 && events[0] != initialOSVerificationEvent.event {
		e := events[0]
		events = events[1:]
		switch {
		case isKEKMeasurementEvent(e):
			if err := b.processKEKMeasurementEvent(sigDbUpdates); err != nil {
				return xerrors.Errorf("cannot process KEK measurement event: %w", err)
			}
		case isDbMeasurementEvent(e):
			if err := b.processDbMeasurementEvent(sigDbUpdates); err != nil {
				return xerrors.Errorf("cannot process db measurement event: %w", err)
			}
		case isDbxMeasurementEvent(e):
			if err := b.processDbxMeasurementEvent(sigDbUpdates); err != nil {
				return xerrors.Errorf("cannot process dbx measurement event: %w", err)
			}
		case isVerificationEvent(e):
			b.extendFirmwareVerificationMeasurement(tpm2.Digest(e.Digests[tcglog.AlgorithmId(b.gen.PCRAlgorithm)]))
		case e.PCRIndex == secureBootPCR:
			b.extendMeasurement(tpm2.Digest(e.Digests[tcglog.AlgorithmId(b.gen.PCRAlgorithm)]))
		}
	}

	if len(events) == 0 {
		return nil
	}

	if initialOSVerificationEvent.imageLoadEvent.PCRIndex == bootManagerCodePCR {
		return nil
	}

	// The verification event associated with the initial OS load event was recorded as part of a UEFI driver load, so we need to keep it.
	b.extendFirmwareVerificationMeasurement(tpm2.Digest(initialOSVerificationEvent.event.Digests[tcglog.AlgorithmId(b.gen.PCRAlgorithm)]))

	return nil
}

// processShimExecutableLaunch updates the context in this branch with the supplied shim vendor certificate so that it can be used
// later on when computing verification events in secureBootPolicyGenBranch.computeAndExtendVerificationMeasurement.
func (b *secureBootPolicyGenBranch) processShimExecutableLaunch(vendorCert []byte) {
	b.dbSet.shimDb = &secureBootDb{variableName: *shimGuid, unicodeName: shimName}
	if vendorCert != nil {
		b.dbSet.shimDb.signatures = append(b.dbSet.shimDb.signatures, &efiSignatureData{signatureType: *efiCertX509Guid, data: vendorCert})
	}
	b.shimVerificationEvents = nil
}

// hasVerificationEventBeenMeasuredBy determines whether the verification event with the associated digest has been measured by the
// supplied source already in this branch.
func (b *secureBootPolicyGenBranch) hasVerificationEventBeenMeasuredBy(digest tpm2.Digest, source EFIImageLoadEventSource) bool {
	var digests *tpm2.DigestList
	switch source {
	case Firmware:
		digests = &b.firmwareVerificationEvents
	case Shim:
		digests = &b.shimVerificationEvents
	}
	for _, d := range *digests {
		if bytes.Equal(d, digest) {
			return true
		}
	}
	return false
}

// computeAndExtendVerificationMeasurement computes a measurement for the the authentication of an EFI image using the supplied
// signatures and extends that in to this branch. If the computed measurement has already been measured by the specified source, then
// it will not be measured again.
//
// In order to compute the measurement, the CA certificate that will be used to authenticate the image using the supplied signatures,
// and the source of that certificate, needs to be determined. If the image is not signed with an authority that is trusted by a CA
// certificate that exists in this branch, then this branch will be marked as unbootable and it will be omitted from the final PCR
// profile.
func (b *secureBootPolicyGenBranch) computeAndExtendVerificationMeasurement(sigs []*authenticodeSignerAndIntermediates, source EFIImageLoadEventSource) error {
	if b.profile == nil {
		// This branch is going to be excluded because it is unbootable.
		return nil
	}

	dbs := []*secureBootDb{b.dbSet.uefiDb}
	if source == Shim {
		if b.dbSet.shimDb == nil {
			return errors.New("shim specified as event source without a shim executable appearing in preceding events")
		}
		dbs = append(dbs, b.dbSet.mokDb, b.dbSet.shimDb)
	}

	var authority *secureBootAuthority

	// To determine what CA certificate will be used to authenticate this image, iterate over the signatures in the order in which they
	// appear in the binary in this outer loop. Iterating over the CA certificates occurs in an inner loop. This behaviour isn't defined
	// in the UEFI specification but it matches EDK2 and the firmware on the Intel NUC. If an implementation iterates over the CA
	// certificates in an outer loop and the signatures in an inner loop, then this may produce the wrong result.
Outer:
	for _, sig := range sigs {
		for _, db := range dbs {
			if db == nil {
				continue
			}

			for _, caSig := range db.signatures {
				// Ignore signatures that aren't X509 certificates
				if caSig.signatureType != *efiCertX509Guid {
					continue
				}

				ca, err := x509.ParseCertificate(caSig.data)
				if err != nil {
					continue
				}

				// XXX: This doesn't work if there isn't a direct relationship between the
				// signing certificate and the CA (ie, there are intermediates). Ideally we
				// would use x509.Certificate.Verify here, but there is no way to turn off
				// time checking and UEFI doesn't consider expired certificates invalid.
				if bytes.Equal(ca.Raw, sig.signer.Raw) {
					// The signer certificate is the CA
					authority = &secureBootAuthority{signature: caSig, source: db}
					break Outer
				}
				if err := sig.signer.CheckSignatureFrom(ca); err == nil {
					// The signer certificate is directly trusted by the CA
					authority = &secureBootAuthority{signature: caSig, source: db}
					break Outer
				}
			}
		}
	}

	if authority == nil {
		// Mark this branch as unbootable by clearing its PCR profile
		b.profile = nil
		return nil
	}

	// Serialize authority certificate for measurement
	var varData *bytes.Buffer
	switch source {
	case Firmware:
		// Firmware measures the entire EFI_SIGNATURE_DATA, including the SignatureOwner
		varData = new(bytes.Buffer)
		if err := authority.signature.encode(varData); err != nil {
			return xerrors.Errorf("cannot encode EFI_SIGNATURE_DATA for authority: %w", err)
		}
	case Shim:
		// Shim measures the certificate data, rather than the entire EFI_SIGNATURE_DATA
		varData = bytes.NewBuffer(authority.signature.data)
	}

	// Create event data, compute digest and perform extension for verification of this executable
	eventData := tcglog.EFIVariableEventData{
		VariableName: authority.source.variableName,
		UnicodeName:  authority.source.unicodeName,
		VariableData: varData.Bytes()}
	h := b.gen.PCRAlgorithm.NewHash()
	if err := eventData.EncodeMeasuredBytes(h); err != nil {
		return xerrors.Errorf("cannot encode EFI_VARIABLE_DATA: %w", err)
	}
	digest := h.Sum(nil)

	// Don't measure events that have already been measured
	if b.hasVerificationEventBeenMeasuredBy(digest, source) {
		return nil
	}
	b.extendVerificationMeasurement(digest, source)
	return nil
}

// sbLoadEventAndBranches binds together a EFIImageLoadEvent and the branches that the event needs to be applied to.
type sbLoadEventAndBranches struct {
	event    *EFIImageLoadEvent
	branches []*secureBootPolicyGenBranch
}

func (e *sbLoadEventAndBranches) branch(event *EFIImageLoadEvent) *sbLoadEventAndBranches {
	var branches []*secureBootPolicyGenBranch
	for _, b := range e.branches {
		if b.profile == nil {
			continue
		}
		branches = append(branches, b.branch())
	}
	return &sbLoadEventAndBranches{event, branches}
}

// computeAndExtendVerificationMeasurement computes a measurement for the the authentication of the EFI image obtained from r and
// extends that to the supplied branches. If the computed measurement has already been measured by the specified source in a branch,
// then it will not be measured again.
//
// In order to compute the measurement for each branch, the CA certificate that will be used to authenticate the image and the
// source of that certificate needs to be determined. If the image is not signed with an authority that is trusted by a CA
// certificate for a particular branch, then that branch will be marked as unbootable and it will be omitted from the final PCR
// profile.
func (g *secureBootPolicyGen) computeAndExtendVerificationMeasurement(branches []*secureBootPolicyGenBranch, r io.ReaderAt, source EFIImageLoadEventSource) error {
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

	// Binaries can have multiple signers - this is achieved using multiple single-signed Authenticode signatures - see section 32.5.3.3
	// ("Secure Boot and Driver Signing - UEFI Image Validation - Signature Database Update - Authorization Process") of the UEFI
	// Specification, version 2.8.
	var sigs []*authenticodeSignerAndIntermediates
	read := 0
	for {
		// Signatures in this section are 8-byte aligned - see the PE spec:
		// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
		alignSize := (8 - (read & 7)) % 8
		read += alignSize
		secReader.Seek(int64(alignSize), io.SeekCurrent)

		if int64(read) >= secReader.Size() {
			break
		}

		c, n, err := decodeWinCertificate(secReader)
		switch {
		case err != nil:
			return xerrors.Errorf("cannot decode WIN_CERTIFICATE from security directory entry of PE binary: %w", err)
		case c.wCertificateType() != winCertTypePKCSSignedData:
			return fmt.Errorf("unexpected value for WIN_CERTIFICATE.wCertificateType (0x%04x): not an Authenticode signature", c.wCertificateType())
		}

		read += n

		// Decode the signature
		p7, err := pkcs7.Parse(c.(*winCertificateAuthenticode).Data)
		if err != nil {
			return xerrors.Errorf("cannot decode signature: %w", err)
		}

		// Grab the certificate of the signer
		signer := p7.GetOnlySigner()
		if signer == nil {
			return errors.New("cannot obtain signer certificate from signature")
		}

		// Reject any signature with a digest algorithm other than SHA256, as that's the only algorithm used for binaries we're
		// expected to support, and therefore required by the UEFI implementation.
		if !p7.Signers[0].DigestAlgorithm.Algorithm.Equal(oidSha256) {
			return errors.New("signature has unexpected digest algorithm")
		}

		// Grab all of the certificates in the signature and populate an intermediates pool
		intermediates := x509.NewCertPool()
		for _, c := range p7.Certificates {
			intermediates.AddCert(c)
		}

		sigs = append(sigs, &authenticodeSignerAndIntermediates{signer: p7.GetOnlySigner(), intermediates: intermediates})
	}

	if len(sigs) == 0 {
		return errors.New("no Authenticode signatures")
	}

	for _, b := range branches {
		if err := b.computeAndExtendVerificationMeasurement(sigs, source); err != nil {
			return err
		}
	}

	return nil
}

// processShimExecutableLaunch extracts the vendor certificate from the shim executable read from r, and then updates the specified
// branches to contain a reference to the vendor certificate so that it can be used later on when computing verification events in
// secureBootPolicyGen.computeAndExtendVerificationMeasurement for images that are authenticated by shim.
func (g *secureBootPolicyGen) processShimExecutableLaunch(branches []*secureBootPolicyGenBranch, r io.ReaderAt) error {
	// Extract this shim's vendor cert
	vendorCert, err := readShimVendorCert(r)
	if err != nil {
		return xerrors.Errorf("cannot extract vendor certificate: %w", err)
	}

	for _, b := range branches {
		b.processShimExecutableLaunch(vendorCert)
	}

	return nil
}

// processOSLoadEvent computes a measurement associated with the supplied image load event and extends this to the specified branches.
// If the image load corresponds to shim, then some additional processing is performed to extract the included vendor certificate
// (see secureBootPolicyGen.processShimExecutableLaunch).
func (g *secureBootPolicyGen) processOSLoadEvent(branches []*secureBootPolicyGenBranch, event *EFIImageLoadEvent) error {
	r, err := event.Image.Open()
	if err != nil {
		return xerrors.Errorf("cannot open image: %w", err)
	}
	defer r.Close()

	isShim, err := isShimExecutable(r)
	if err != nil {
		return xerrors.Errorf("cannot determine image type: %w", err)
	}

	if err := g.computeAndExtendVerificationMeasurement(branches, r, event.Source); err != nil {
		return xerrors.Errorf("cannot compute load verification event: %w", err)
	}

	if !isShim {
		return nil
	}

	if err := g.processShimExecutableLaunch(branches, r); err != nil {
		return xerrors.Errorf("cannot process shim executable: %w", err)
	}

	return nil
}

// run takes a TCG event log and builds a PCR profile from the supplied configuration (see EFISecureBootPolicyProfileParams)
func (g *secureBootPolicyGen) run(profile *PCRProtectionProfile, events []*tcglog.Event) error {
	// Compute a list of pending EFI signature DB updates.
	sigDbUpdates, err := buildSignatureDbUpdateList(g.SignatureDbUpdateKeystores)
	if err != nil {
		return xerrors.Errorf("cannot build list of UEFI signature DB updates: %w", err)
	}

	// Find the verification event corresponding to the load of the first OS binary.
	initialOSVerificationEvent, err := identifyInitialOSLaunchVerificationEvent(events)
	if err != nil {
		return xerrors.Errorf("cannot identify initial OS launch verification event: %w", err)
	}

	// Process the pre-OS events for the current signature DB and then with each pending update applied
	// in turn.
	var roots []*secureBootPolicyGenBranch
	for i := 0; i <= len(sigDbUpdates); i++ {
		branch := &secureBootPolicyGenBranch{gen: g, profile: NewPCRProtectionProfile(), dbUpdateLevel: i}
		if err := branch.processPreOSEvents(events, initialOSVerificationEvent, sigDbUpdates[0:i]); err != nil {
			return xerrors.Errorf("cannot process pre-OS events from event log: %w", err)
		}
		roots = append(roots, branch)
	}

	allBranches := make([]*secureBootPolicyGenBranch, len(roots))
	copy(allBranches, roots)

	var loadEvents []*sbLoadEventAndBranches
	var nextLoadEvents []*sbLoadEventAndBranches

	if len(g.LoadSequences) == 1 {
		loadEvents = append(loadEvents, &sbLoadEventAndBranches{event: g.LoadSequences[0], branches: roots})
	} else {
		for _, e := range g.LoadSequences {
			var branches []*secureBootPolicyGenBranch
			for _, b := range roots {
				branches = append(branches, b.branch())
			}
			allBranches = append(allBranches, branches...)
			loadEvents = append(loadEvents, &sbLoadEventAndBranches{event: e, branches: branches})
		}
	}

	for len(loadEvents) > 0 {
		e := loadEvents[0]
		loadEvents = loadEvents[1:]

		if err := g.processOSLoadEvent(e.branches, e.event); err != nil {
			return xerrors.Errorf("cannot process OS load event for %s: %w", e.event.Image, err)
		}

		if len(e.event.Next) == 1 {
			nextLoadEvents = append(nextLoadEvents, &sbLoadEventAndBranches{event: e.event.Next[0], branches: e.branches})
		} else {
			for _, n := range e.event.Next {
				ne := e.branch(n)
				allBranches = append(allBranches, ne.branches...)
				nextLoadEvents = append(nextLoadEvents, ne)
			}
		}

		if len(loadEvents) == 0 {
			loadEvents = nextLoadEvents
			nextLoadEvents = nil
		}
	}

	for i := len(allBranches) - 1; i >= 0; i-- {
		b := allBranches[i]

		if len(b.subBranches) == 0 {
			// This is a leaf branch
			continue
		}

		var subProfiles []*PCRProtectionProfile
		for _, sb := range b.subBranches {
			if sb.profile == nil {
				// This sub-branch has been marked unbootable
				continue
			}
			subProfiles = append(subProfiles, sb.profile)
		}

		if len(subProfiles) == 0 {
			// All sub branches are unbootable, so ensure our parent branch omits us too.
			b.profile = nil
			continue
		}

		b.profile.AddProfileOR(subProfiles...)
	}

	validPathsForCurrentDb := false
	var subProfiles []*PCRProtectionProfile
	for _, b := range roots {
		if b.profile == nil {
			// This branch has no bootable paths
			continue
		}
		if b.dbUpdateLevel == 0 {
			validPathsForCurrentDb = true
		}
		subProfiles = append(subProfiles, b.profile)
	}

	if !validPathsForCurrentDb {
		return errors.New("no bootable paths with current EFI signature database")
	}

	profile.AddProfileOR(subProfiles...)

	return nil
}

// AddEFISecureBootPolicyProfile adds the UEFI secure boot policy profile to the provided PCR protection profile, in order to generate
// a PCR policy that restricts access to a sealed key to a set of UEFI secure boot policies measured to PCR 7. The secure boot policy
// information that is measured to PCR 7 is defined in section 2.3.4.8 of the "TCG PC Client Platform Firmware Profile Specification".
//
// This function can only be called if the current boot was performed with secure boot enabled. An error will be returned if the
// current boot was performed with secure boot disabled. It can only generate a PCR profile that will work when secure boot is
// enabled.
//
// The secure boot policy measurements include events that correspond to the authentication of loaded EFI images, and those events
// record the certificate of the authorities used to authenticate these images. The params argument allows the generated PCR policy
// to be restricted to a specific set of chains of trust by specifying EFI image load sequences via the LoadSequences field. This
// function will compute the measurements associated with the authentication of these load sequences. Each of the EFIImage instances
// reachable from the LoadSequences field of params must correspond to an EFI image with one or more Authenticode signatures. These
// signatures are used to determine the CA certificate that will be used to authenticate them in order to compute authentication
// meausurement events. The digest algorithm of the Authenticode signatures must be SHA256. If there are no signatures, or the
// binary's certificate table contains non-Authenticode entries, or contains any Authenticode signatures with a digest algorithm other
// than SHA256, then an error will be returned. Note that this function assumes that any signatures are correct and does not ensure
// that they are so - it only determines if there is a chain of trust beween the signing certificate and a CA certificate in order to
// determine which certificate will be used for authentication, and what the source of that certificate is (for UEFI images that are
// loaded by shim).
//
// If none of the sequences in the LoadSequences field of params can be authenticated by the current authorized signature database
// contents, then an error will be returned.
//
// This function does not support computing measurements for images that are authenticated by an image digest rather than an
// Authenticode signature. If an image has a signature where the signer has a chain of trust to a CA certificate in the authorized
// signature database (or shim's vendor certificate) but that image is authenticated because an image digest is present in the
// authorized signature database instead, then this function will generate a PCR profile that is incorrect.
//
// If an image has a signature that can be authenticated by multiple CA certificates in the authorized signature database, this
// function assumes that the firmware will try the CA certificates in the order in which they appear in the database and authenticate
// the image with the first valid certificate. If the firmware does not do this, then this function may generate a PCR profile that is
// incorrect for binaries that have a signature that can be authenticated by more than one CA certificate. Note that the structure of
// the signature database means that it can only really be iterated in one direction anyway.
//
// For images with multiple Authenticode signatures, this function assumes that the device's firmware will iterate over the signatures
// in the order in which they appear in the binary's certificate table in an outer loop during image authentication (ie, for each
// signature, attempt to authenticate the binary using one of the CA certificates). If a device's firmware iterates over the
// authorized signature database in an outer loop instead (ie, for each CA certificate, attempt to authenticate the binary using one
// of its signatures), then this function may generate a PCR profile that is incorrect for binaries that have multiple signatures
// where both signers have a chain of trust to a different CA certificate but the signatures appear in a different order to which
// their CA certificates are enrolled.
//
// This function does not consider the contents of the forbidden signature database. This is most relevant for images with multiple
// signatures. If an image has more than one signature where the signing certificates have chains of trust to different CA
// certificates, but the first signature is not used to authenticate the image because one of the certificates in its chain is
// blacklisted, then this function will generate a PCR profile that is incorrect.
//
// In determining whether a signing certificate has a chain of trust to a CA certificate, this function expects there to be a direct
// relationship between the CA certificate and signing certificate. It does not currently detect that there is a chain of trust if
// intermediate certificates form part of the chain. This is most relevant for images with multiple signatures. If an image has more
// than one signature where the signing certificate have chains of trust to different CA certificate, but the first signature's chain
// involves intermediate certificates, then this function will generate a PCR profile that is incorrect.
//
// This function does not support computing measurements for images that are authenticated by shim using a machine owner key (MOK).
//
// The secure boot policy measurements include the secure boot configuration, which includes the contents of the UEFI signature
// databases. In order to support atomic updates of these databases with the sbkeysync tool, it is possible to generate a PCR policy
// computed from pending signature database updates. This can be done by supplying the keystore directories passed to sbkeysync via
// the SignatureDbUpdateKeystores field of the params argument. This function assumes that sbkeysync is executed with the
// "--no-default-keystores" option. When there are pending updates in the specified directories, this function will generate a PCR
// policy that is compatible with the current database contents and the database contents computed for each individual update.
// Note that sbkeysync ignores errors when applying updates - if any of the pending updates don't apply for some reason, the generated
// PCR profile will be invalid.
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
		return errors.New("cannot compute secure boot policy profile: the TCG event log does not have the requested algorithm")
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
				return errors.New("cannot compute secure boot policy profile: the current boot was preceeded by a boot attempt to an EFI " +
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
						return errors.New("cannot compute secure boot policy profile: secure boot configuration was modified after the initial " +
							"configuration was measured, without performing a reboot")
					case efiVarData.VariableData[0] == 0x00:
						return errors.New("cannot compute secure boot policy profile: the current boot was performed with secure boot disabled in firmware")
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
					return errors.New("cannot compute secure boot policy profile: the current boot was performed with validation disabled in Shim")
				}
			}
		}
		events = append(events, event)
	}

	// Initialize the secure boot PCR to 0
	profile.AddPCRValue(params.PCRAlgorithm, secureBootPCR, make(tpm2.Digest, params.PCRAlgorithm.Size()))

	gen := &secureBootPolicyGen{params}
	if err := gen.run(profile, events); err != nil {
		return xerrors.Errorf("cannot compute secure boot policy profile: %w", err)
	}

	return nil
}
