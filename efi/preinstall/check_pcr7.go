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

package preinstall

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	secboot_efi "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	pe "github.com/snapcore/secboot/internal/pe1.14"
)

var (
	internal_efiSecureBootSignaturesFromPEFile = internal_efi.SecureBootSignaturesFromPEFile
	peNewFile                                  = pe.NewFile
)

// checkSecureBootVariableData checks the variable data associated with a configuration
// measurement. For "SecureBoot", it just ensures it contains 0x1. For PK, it makes sure
// it contains only a single X.509 signature. For the other veriables, it makes sure that
// the signature databases decode properly.
//
// If the supplied parameter is for a signature database, the decoded signature database
// is returned, else nil is returned
func checkSecureBootVariableData(data *tcglog.EFIVariableData) (sigDb efi.SignatureDatabase, err error) {
	switch data.UnicodeName {
	case "SecureBoot":
		// Make sure the SecureBoot value in the log matches the EFI variable,
		// (ie, []byte{1}). We don't do this for other variables because they can
		// be updated from the OS, making them potentially inconsistent. The
		// SecureBoot variable is read only after ExitBootServices.
		if !bytes.Equal(data.VariableData, []byte{1}) {
			return nil, errors.New("SecureBoot value is not consistent with the current EFI variable value")
		}
	case "PK":
		// Make sure that we can parse the PK database and it contains a single
		// X.509 entry.
		sigDb, err = efi.ReadSignatureDatabase(bytes.NewReader(data.VariableData))
		if err != nil {
			return nil, fmt.Errorf("cannot decode PK contents: %w", err)
		}
		switch len(sigDb) {
		case 0:
			// This should never be empty when secure boot is enabled,
			// so if it does then the firmware is broken.
			return nil, errors.New("invalid PK contents: no signature list when secure boot is enabled")
		case 1:
			// PK only contains one ESL with the type EFI_CERT_X509_GUID
			esl := sigDb[0]
			if esl.Type != efi.CertX509Guid {
				// PK can only contain a X.509 certificate. If we get another
				// type then the firmwar is broken.
				return nil, fmt.Errorf("invalid PK contents: signature list has an unexpected type: %v", esl.Type)
			}
			if len(esl.Signatures) != 1 {
				// EFI_CERT_X509_GUID signature lists can only contain a single
				// signature. Note that it's quite likely that go-efilib would have
				// failed to decode already in this case because all signatures
				// within a signature list have to be the same size.
				//
				// In any case, if this happens the firmware is broken.
				return nil, fmt.Errorf("invalid PK contents: signature list should only have one signature, but got %d", len(esl.Signatures))
			}
			if _, err := x509.ParseCertificate(esl.Signatures[0].Data); err != nil {
				return nil, fmt.Errorf("invalid PK contents: cannot decode PK certificate: %w", err)
			}
		default:
			// If PK contains more than 1 ESL, then the firmware is broken.
			return nil, errors.New("invalid PK contents: more than one signature list is present")
		}
	default:
		// Make sure that we can parse all other signature databases ok
		sigDb, err = efi.ReadSignatureDatabase(bytes.NewReader(data.VariableData))
		if err != nil {
			return nil, fmt.Errorf("cannot decode %s contents: %w", data.UnicodeName, err)
		}
	}

	return sigDb, nil
}

// checkX509CertificatePublicKeyStrength checks whether the supplied certificate's
// public key is considered strong enough for signing. This will return true if it is
// or false if it isn't. It will return an error for unsupported public key algorithms
// or if the public key's concrete type is inconsistent with the algorithm.
func checkX509CertificatePublicKeyStrength(cert *x509.Certificate) (ok bool, err error) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		pubKey, isRsa := cert.PublicKey.(*rsa.PublicKey)
		if !isRsa {
			return false, errors.New("unsupported public key type")
		}
		if pubKey.Size() < 256 {
			// Anything less than 2048-bits is considered weak
			return false, nil
		}
	default:
		// EFI implementations aren't required to support anything other
		// than RSA.
		return false, errors.New("unsupported public key algorithm")
	}

	return true, nil
}

// checkSignatureDataStrength will check if the signature data of the supplied type is
// strong enough for authenticating images. This will return true if it is or false if
// it isn't.
func checkSignatureDataStrength(eslType efi.GUID, esdData []byte) (ok bool, err error) {
	switch eslType {
	case efi.CertX509Guid:
		cert, err := x509.ParseCertificate(esdData)
		if err != nil {
			return false, fmt.Errorf("cannot decode certificate: %w", err)
		}
		return checkX509CertificatePublicKeyStrength(cert)
	case efi.CertSHA1Guid:
		return false, nil
	case efi.CertSHA224Guid, efi.CertSHA256Guid, efi.CertSHA384Guid, efi.CertSHA512Guid:
		return true, nil
	default:
		return false, fmt.Errorf("unrecognized signature type: %v", eslType)
	}
}

var errNoSignerWithTrustAnchor = errors.New("image has no signer associated with any of the supplied authorities")

// extractSignerWithTrustAnchorFromImage extracts and returns the signing certificate from any
// signature where the signer chains to one of the supplied authorities. As with signature
// verification in EFI, it tests each of the image's signatures against each of the supplied
// authorities in turn, and will return the first signature that chains to the first authority.
func extractSignerWithTrustAnchorFromImage(authorities []*X509CertificateID, image secboot_efi.Image) (*x509.Certificate, error) {
	r, err := image.Open()
	if err != nil {
		return nil, fmt.Errorf("cannot open image: %w", err)
	}
	defer r.Close()

	pefile, err := peNewFile(r)
	if err != nil {
		return nil, fmt.Errorf("cannot decode image: %w", err)
	}

	sigs, err := internal_efiSecureBootSignaturesFromPEFile(pefile, r)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain secure boot signatures from image %s: %w", image, err)
	}

	// Make sure that one of the CA's measured for verification so far
	// is a trust anchor for one of the signatures on the image.
	var foundSig *efi.WinCertificateAuthenticode
	for _, cert := range authorities {
		for _, sig := range sigs {
			if sig.CertWithIDLikelyTrustAnchor(cert) {
				foundSig = sig
				break
			}
		}
		if foundSig != nil {
			break
		}
	}
	if foundSig == nil {
		return nil, errNoSignerWithTrustAnchor
	}

	return foundSig.GetSigner(), nil
}

// handleVariableAuthority event processes the event data for the supplied EV_EFI_VARIABLE_AUTHORITY
// event. It expects the authority to be the UEFI db, and if verifyEventDigest is true, it expects
// the digests associated with pcrAlg to match the digest computed from the event data. It will return
// an error if the digest already appears in the provided alreadyMeasured argument, as the firmware
// should only measure a digest once. It uses the supplied db to match the EFI_SIGNATURE_DATA in the
// event data to a EFI_SIGNATURE_LIST, in order to obtain the signature type. On success, the function
// returns the signature type and signature data (without the owner). The caller should subsequently add
// the measurement digest to the alreadyMeasured slice.
func handleVariableAuthorityEvent(pcrAlg tpm2.HashAlgorithmId, db efi.SignatureDatabase, alreadyMeasured tpm2.DigestList, ev *tcglog.Event, verifyEventDigest bool) (eslType efi.GUID, esdData []byte, err error) {
	// Decode the verification event
	data, ok := ev.Data.(*tcglog.EFIVariableData)
	if !ok {
		// if decoding failed, the resulting data is guaranteed to implement error.
		return efi.GUID{}, nil, fmt.Errorf("event has wong data format: %w", ev.Data.(error))
	}

	// As we're only checking events up to the launch of the IBL, we don't expect
	// to see anything other than verification events from db here.
	if data.VariableName != efi.ImageSecurityDatabaseGuid || data.UnicodeName != "db" {
		return efi.GUID{}, nil, fmt.Errorf("event is not from db (got %s-%v)", data.UnicodeName, data.VariableName)
	}

	if verifyEventDigest {
		expectedDigest := tcglog.ComputeEFIVariableDataDigest(pcrAlg.GetHash(), data.UnicodeName, data.VariableName, data.VariableData)
		if !bytes.Equal(ev.Digests[pcrAlg], expectedDigest) {
			return efi.GUID{}, nil, fmt.Errorf("event data inconsistent with %v event digest (log digest:%#x, expected digest:%#x)", pcrAlg, ev.Digests[pcrAlg], expectedDigest)
		}
	}

	// Make sure that this signature hasn't already been measured. Duplicate signatures measured
	// by the firmware may result in incorrectly computed PCR policies.
	// Unfortunately, this test isn't 100% reliable as we stop processing events after the launch
	// of the IBL (usually shim). Once the IBL has launched, we can't tell whether subsequent events
	// were generated by the firmware because an OS component made use of LoadImage (where we would
	// want to make sure it isn't measured again) or whether subsequent events are measured via some
	// other mechanism by an OS component, such as the shim verification (which we wouldn't want to
	// check, because we're only testing firmware compatbility here). I can't think of a way to make
	// this 100% reliable other than by ensuring OS components never measure events with "db" and
	// IMAGE_SECURITY_DATABASE_GUID in their event data, as a way of being able to distinguish
	// firmware generated events from OS component generated events. It's a legitimate scenario for
	// both the firmware and shim to both measure the same signature they used for verification from db
	// because they both maintain their own de-duplication lists.
	//
	// If this test fails, the firmware is definitely broken. If this test doesn't fail, the opposite is
	// not true - it's not a definitive guarantee that the firmware isn't broken, unfortunately.
	for _, measured := range alreadyMeasured {
		if bytes.Equal(measured, ev.Digests[pcrAlg]) {
			return efi.GUID{}, nil, fmt.Errorf("digest %#x has been measured by the firmware already", ev.Digests[pcrAlg])
		}
	}

	// Try to discover the type of authentication. The measured EFI_SIGNATURE_DATA doesn't
	// contain this.

	// First of all, construct a signature data entry from the raw event data.
	esd := new(efi.SignatureData)
	r := bytes.NewReader(data.VariableData)

	// THE EFI_SIGNATURE_DATA entry starts with the owner GUID
	sigOwner, err := efi.ReadGUID(r)
	if err != nil {
		return efi.GUID{}, nil, fmt.Errorf("cannot decode owner GUID from event: %w", err)
	}
	esd.Owner = sigOwner

	// The rest of the EFI_SIGNATURE_DATA entry is the data
	sigData, err := io.ReadAll(r)
	if err != nil {
		return efi.GUID{}, nil, fmt.Errorf("cannot read data from event: %w", err)
	}
	esd.Data = sigData

	// We have a fully constructed EFI_SIGNATURE_DATA. Now iterate over db to see if this
	// EFI_SIGNATURE_DATA belongs to any EFI_SIGNATURE_LIST, in order to grab its type.
	var matchedEsl *efi.SignatureList
	for _, list := range db {
		for _, sig := range list.Signatures {
			if sig.Equal(esd) {
				matchedEsl = list
				break
			}
		}
		if matchedEsl != nil {
			break
		}
	}
	if matchedEsl == nil {
		return efi.GUID{}, nil, fmt.Errorf("event does not match any db EFI_SIGNATURE_LIST")
	}

	return matchedEsl.Type, esd.Data, nil
}

type secureBootPolicyResultFlags int

const (
	secureBootIncludesWeakAlg                 secureBootPolicyResultFlags = 1 << iota // Weak algorithms were used during image verification.
	secureBootPreOSVerificationIncludesDigest                                         // Authenticode digests were used to authenticate pre-OS components.
)

// secureBootPolicyResult is the result of a successful call to checkSecureBootPolicyMeasurementsAndObtainAuthorities.
type secureBootPolicyResult struct {
	UsedAuthorities []*X509CertificateID // CA's used to authenticate boot components.
	Flags           secureBootPolicyResultFlags
}

// checkSecureBootPolicyMeasurementsAndObtainAuthorities performs some checks on the secure boot policy PCR (7).

// The supplied context is used to attach an EFI variable backend to, for functions that read
// from EFI variables. The supplied env and log arguments provide other inputs to this function.
// The pcrAlg argument is the PCR bank that is chosen as the best one to use. The iblImage
// corresponds to the initial boot loader image for the current boot. This is used to detect the
// launch of the OS, at which checks for PCR7 end. There are some limitations of this, ie, we may
// not detect LoadImage bugs that happen later on, but once the OS has loaded, it's impossible to
// tell whicj events come from firmware and which are under the control of OS components.

// This ensures that secure boot is enabled, else an error is returned, as WithSecureBootPolicyProfile
// only generates profiles compatible with secure boot being enabled.

// If the version of UEFI is >= 2.5, it also makes sure that the secure boot mode is "deployed mode".
// If the secure boot mode is "user mode", then the "AuditMode" and "DeployedMode" values are measured to PCR7,
// something that WithSecureBootPolicyProfile doesn't support today. Support for "user mode" will be added
// in the future, although the public RunChecks API will probably require a flag to opt in to supporting user
// mode, as it is the less secure mode of the 2 (see the documentation for SecureBootMode in
// github.com/canonical/go-efilib).

// It also reads the "OsIndicationsSupported" variable to test for features that are not supported by
// WithSecureBootPolicyProfile. These are timestamp revocation (which requires an extra signature database -
// "dbt") and OS recovery (which requires an extra signature database -"dbr", used to control access to
// OsRecoveryOrder and OsRecover#### variables). Of the 2, it's likely that we might need to add support for
// timestamp revocation at some point in the future.

// It reads the "BootCurrent" EFI variable and matches this to the EFI_LOAD_OPTION associated with the current
// boot from the TCG log - it uses the log as "BootXXXX" EFI variables can be updated at runtime and
// might be out of data when this code runs. It uses this to detect the launch of the initial boot loader,
// which might not necessarily be the first EV_EFI_BOOT_SERVICES_APPLICATION event in the OS-present
// environment in PCR4 (eg, if Absolute is active).

// After these checks, it iterates over the secure boot configuration in the log, making sure that the
// configuration is measured in the correct order, that the event data is valid, and that the measured digest
// is the tagged hash of the event data. It makes sure that the value of "SecureBoot" in the log is consistent
// with the "SecureBoot" variable (which is read-only at runtime), and it verifies that all of the signature
// databases are formatted correctly and can be decoded. It will return an error if any of these checks fail.

// If the pre-OS environment contains events other than EV_EFI_VARIABLE_DRIVER_CONFIG, it will return an error.
// This can happen a firmware debugger is enabled, in which case PCR7 will begin with a EV_EFI_ACTION
// "UEFI Debug Mode" event. This case is detected by earlier firmware protection checks.

// If not all of the expected secure boot configuration is measured, an error is returned.

// Once the secure boot configuration has been measured, it looks for EV_EFI_VARIABLE_AUTHORITY events in PCR7,
// until it detects the launch of the initial boot loader. It verifies that each of these come from db, and
// if the log is in the OS-present environment, it ensures that the measured digest is the tagged hash of the
// event data. It doesn't do this for events in the pre-OS environment because WithSecureBootPolicyProfile
// just copies these to the profile. It verifies that the firmware doesn't measure a signature more than once.
// For each EV_EFI_VARIABLE_AUTHORITY event, it also matches the measured signature to a EFI_SIGNATURE_LIST
// structure in db. If the matched ESL is a X.509 certificate, it records the use of this CA in the return value.
// If the CA is an RSA certificate with a public modulus of < 256 bytes, it sets a flag in the return value
// indicating a weak algorithm. If the matched ESL is a Authenticode digest, it sets a flag in the return value
// indicating that pre-OS components were verified using digests rather than signatures. This only applies to the
// pre-OS environment and makes PCR7 fragile wrt firmware updates, because it means db needs to be updated to
// reflect the new components each time. If the digest being matched is SHA-1, it sets the flag in the return
// value indicating a weak algorithm. If any of these checks fail, an error is returned. If an event type
// other than EV_EFI_VARIABLE_AUTHORITY is detected, an error is returned.

// Upon detecting the launch of the initial boot loader in PCR4, it extracts the authenticode signatures from
// the supplied image, and matches these to a previously measured CA. If no match is found, an error is returned.
// If a match is found, it ensures that the signing certificate has an RSA public key with a modulus that is at
// least 256 bytes, else it sets a flag in the return value indicating a weak algorithm.
//
// Once the event for the initial boot loader is complete, the function returns. It doesn't process any more
// EV_EFI_VARIABLE_AUTHORITY events because it's impossible to determine if these result from a call to the
// firmware's LoadImage API, or if they are logged by an OS component, both of which may maintain their own
// de-duplication lists (this is certainly the case for shim). Ideally, checking would continue but this trade
// off was made instead.
//
// If the end of the log is reached without encountering the launch of the initial boot loader, an error is returned.
func checkSecureBootPolicyMeasurementsAndObtainAuthorities(ctx context.Context, env internal_efi.HostEnvironment, log *tcglog.Log, pcrAlg tpm2.HashAlgorithmId, iblImage secboot_efi.Image, permitDMAProtectionDisabledEvent bool) (result *secureBootPolicyResult, err error) {
	if iblImage == nil {
		return nil, errors.New("must supply the initial boot loader image")
	}

	varCtx := env.VarContext(ctx)

	// Make sure that secure boot is enabled - we don't generate PCR7 policies for systems
	// without secure boot enabled.
	secureBoot, err := efi.ReadSecureBootVariable(varCtx)
	if err != nil {
		return nil, fmt.Errorf("cannot read SecureBoot variable: %w", err)
	}
	if !secureBoot {
		// WithSecureBootPolicyProfile() doesn't generate working profiles if secure
		// boot is disabled.
		return nil, ErrNoSecureBoot
	}

	// On UEFI 2.5 and later, we require that deployed mode is enabled, because if it's disabled, it
	// changes the sequence of events for PCR7 (the DeployedMode and AuditMode global variables are
	// also measured).
	// TODO(chrisccoulson): relax this later on in the profile generation to support user mode, but
	// maybe add a new flag (RequireDeployedMode or AllowUserMode) to RunChecks. We should be
	// able to generate policies for user mode as well - it shouldn't be necessary to enable deployed
	// mode as long as secure boot is enabled, particularly because the only paths back from deployed
	// mode are platform specific (ie, it could be a one way operation!)
	if efi.IsDeployedModeSupported(varCtx) {
		secureBootMode, err := efi.ComputeSecureBootMode(varCtx)
		if err != nil {
			return nil, fmt.Errorf("cannot compute secure boot mode: %w", err)
		}
		if secureBootMode != efi.DeployedMode {
			// WithSecureBootPolicyProfile() doesn't generate working profiles if deployed mode is not
			// enabled on UEFI >= 2.5.
			return nil, ErrNoDeployedMode
		}
	}

	// Make sure this system doesn't support features that affect PCR7 and which we don't
	// currently support.
	osIndicationsSupported, err := efi.ReadOSIndicationsSupportedVariable(varCtx)
	if err != nil {
		return nil, fmt.Errorf("cannot read OsIndicationsSupported variable: %w", err)
	}
	if osIndicationsSupported&efi.OSIndicationTimestampRevocation > 0 {
		// Timestamp verification relies on another database (dbt) which we currently don't support
		// in WithSecureBootPolicyProfile(). It's theoretically possible we might see this in the
		// wild and might have to add support for it in the future.
		return nil, errors.New("generating secure boot profiles for systems with timestamp revocation (dbt) support is currently not supported")
	}
	if osIndicationsSupported&efi.OSIndicationStartOSRecovery > 0 {
		// OS recovery relies on another database (dbr) which we currently don't support in
		// WithSecureBootPolicyProfile(), but given this also depends on EFI_VARIABLE_AUTHENTICATION_3,
		// it's unlikely we'll ever see this in the wild.
		return nil, errors.New("generating secure boot profiles for systems with OS recovery support, which requires dbr support, is not supported")
	}
	// TODO(chrisccoulson): Not sure if there's any indication that we might get SPDM related measurements,
	// which our profile generation for PCR7 currently doesn't support.

	// Obtain the load option for the current boot. We need this so that we can identify the launch of
	// the initial boot loader later on.
	bootOpt, err := readCurrentBootLoadOptionFromLog(varCtx, log)
	if err != nil {
		return nil, err
	}

	// Make sure that the secure boot config in the log is measured in the
	// expected order, else WithSecureBootPolicyProfile() will generate an invalid policy,
	// because we hard code the order. The order here is what we expect to see.
	configs := []efi.VariableDescriptor{
		{Name: "SecureBoot", GUID: efi.GlobalVariable},
		{Name: "PK", GUID: efi.GlobalVariable},
		{Name: "KEK", GUID: efi.GlobalVariable},
		{Name: "db", GUID: efi.ImageSecurityDatabaseGuid},
		{Name: "dbx", GUID: efi.ImageSecurityDatabaseGuid},
		// TODO: Add optional dbt / SPDM in the future.
	}

	result = new(secureBootPolicyResult)
	var (
		db                        efi.SignatureDatabase // The authorized signature database from the TCG log.
		measuredSignatures        tpm2.DigestList       // The verification event digests measured by the firmware
		seenOSPresentVerification bool                  // Whether we've seen a verification event in the OS-present phase
		seenIBLLoadEvent          bool                  // Whether we've seen the launch event for the OS initial boot loader
	)

	phaseTracker := newTcgLogPhaseTracker()
NextEvent:
	for _, ev := range log.Events {
		phase, err := phaseTracker.processEvent(ev)
		if err != nil {
			return nil, err
		}

		switch phase {
		case tcglogPhasePreOSMeasuringSecureBootConfig:
			if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
				// Not PCR7
				continue NextEvent
			}

			switch ev.EventType {
			case tcglog.EventTypeEFIVariableDriverConfig:
				if len(configs) == 0 {
					// Unexpected config event - we're not expecting another secure boot variable
					// to measure. We should have exitted the loop by now.
					return nil, errors.New("unexpected EV_EFI_VARIABLE_DRIVER_CONFIG event: all expected secure boot variable have been measured")
				}

				// Pop the next secure boot config name
				config := configs[0]
				configs = configs[1:]

				data, ok := ev.Data.(*tcglog.EFIVariableData)
				if !ok {
					// The data resulting from decode errors are guaranteed to implement the error interface
					return nil, fmt.Errorf("invalid event data for EV_EFI_VARIABLE_DRIVER_CONFIG event: %w", ev.Data.(error))
				}
				// Make sure this is the event we're expecting to be measured. If they're
				// measured in an unexpected order, then WithSecureBootPolicyProfile() will
				// generate an invalid policy.
				if data.VariableName != config.GUID || data.UnicodeName != config.Name {
					return nil, fmt.Errorf("unexpected EV_EFI_VARIABLE_DRIVER_CONFIG event ordering (expected %s-%v, got %s-%v)",
						config.Name, config.GUID, data.UnicodeName, data.VariableName)
				}

				// Compute the expected digest from the event data in the log and make
				// sure it's consistent with the measured digest.
				expectedDigest := tcglog.ComputeEFIVariableDataDigest(pcrAlg.GetHash(), data.UnicodeName, data.VariableName, data.VariableData)
				if !bytes.Equal(ev.Digests[pcrAlg], expectedDigest) {
					return nil, fmt.Errorf("event data inconsistent with measured digest for EV_EFI_VARIABLE_DRIVER_CONFIG event (name:%q, GUID:%v, expected digest:%#x, measured digest:%#x)",
						data.UnicodeName, data.VariableName, expectedDigest, ev.Digests[pcrAlg])
				}

				sigDb, err := checkSecureBootVariableData(data)
				if err != nil {
					return nil, fmt.Errorf("invalid event data for EV_EFI_VARIABLE_DRIVER_CONFIG event: %w", err)
				}
				if data.UnicodeName == "db" {
					// Capture the db from the log for future use.
					// We don't check the EFI_SIGNATURE_LIST types contained in db. Any OS component with a valid
					// Authenticode signature (WIN_CERT_TYPE_PKCS_SIGNED_DATA) or a valid PKCS7 signature
					// (WIN_CERT_TYPE_EFI_GUID with the type EFI_CERT_TYPE_PKCS7_GUID) is authenticated with
					// signature verification using the matching EFI_CERT_X509_GUID entry first, and the profile
					// generation in secboot efi makes sure a signed binary has a matching root in the relevant
					// trust stores. The presence of digest signatures (EFI_CERT_SHA*) shouldn't matter because
					// these are only used to authenticate unsigned images (which the profile generation in the
					// secboot efi package rejects) or as a fallback for signed image where signature verification
					// fails. Digests may be permitted for authenticating unsigned pre-OS components.
					db = sigDb
				}
			case tcglog.EventTypeEFIAction:
				// An EV_EFI_ACTION events with the string "UEFI Debug Mode" appears at the
				// start of the log if a debugging endpoint is enabled. It's also possible that
				// EV_EFI_ACTION events are used for other conditions in PCR7 that weaken device
				// security (eg, the "DMA Protection Disabled" event).
				//
				// In general, it's not normal to see EV_EFI_ACTION events and these indicate some
				// sort of abnormal condition that has a detrimental effect on device security.
				// WithSecureBootPolicyProfile() will generate an invalid policy in this case because,
				// with some exceptions, it doesn't emit them.
				//
				// Just return an error here to prevent the use of WithSecureBootPolicyProfile(). The
				// "UEFI Debug Mode" and "DMA Protection Disabled" cases are already picked up by the
				// firmware protection checks, so we don't need any special handling here.
				//
				// We do permit the "DMA Protection Disabled" case if required. In this case,
				// WithSecureBootPolicyProfile() needs a separate option.
				if permitDMAProtectionDisabledEvent && (bytes.Equal(ev.Data.Bytes(), []byte(tcglog.DMAProtectionDisabled)) ||
					bytes.Equal(ev.Data.Bytes(), append([]byte(tcglog.DMAProtectionDisabled), 0x00))) {
					// This event is detected by the host security checks so we can skip it here.
					// We'll emit a flag in the results which is picked up by the code in profile.go
					// to add an option to permit this with WithSecureBootPolicyProfile().
					permitDMAProtectionDisabledEvent = false // Don't allow this more than once.
					continue NextEvent
				}
				fallthrough
			default:
				// Anything that isn't EV_EFI_VARIABLE_DRIVER_CONFIG ends up here.
				return nil, fmt.Errorf("unexpected %v event %q whilst measuring config", ev.EventType, ev.Data)
			}
		case tcglogPhasePreOSAfterMeasureSecureBootConfig:
			if len(configs) > 0 {
				// We've transitioned to a phase where components can be loaded and verified but we haven't
				// measured all of the secure boot variables. We'll fail to generate a valid policy with
				// WithSecureBootPolicyProfile() in this case.
				return nil, errors.New("EV_EFI_VARIABLE_DRIVER_CONFIG events for some secure boot variables missing from log")
			}

			if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
				// Not PCR7
				continue NextEvent
			}

			switch ev.EventType {
			case tcglog.EventTypeEFIVariableAuthority:
				eslType, esdData, err := handleVariableAuthorityEvent(pcrAlg, db, measuredSignatures, ev, false)
				if err != nil {
					return nil, fmt.Errorf("cannot handle EV_EFI_VARIABLE_AUTHORITY event in pre-OS phase: %w", err)
				}

				measuredSignatures = append(measuredSignatures, ev.Digests[pcrAlg])

				ok, err := checkSignatureDataStrength(eslType, esdData)
				if err != nil {
					return nil, fmt.Errorf("cannot check strength of EFI_SIGNATURE_DATA associated with EV_EFI_VARIABLE_AUTHORITY event in pre-OS phase: %w", err)
				}
				if !ok {
					// XXX: unfortunately in the case where an image is signed, the verification event only includes the CA
					// certificate - it's not possible from this to determine the actual signing certificate, it's signature
					// algorithm, and the algorithm used for signing the binary. In this case, the check is on the CA's
					// public key, which still has some value.
					result.Flags |= secureBootIncludesWeakAlg
				}
				if eslType == efi.CertX509Guid {
					cert, err := x509.ParseCertificate(esdData)
					if err != nil {
						return nil, fmt.Errorf("cannot decode X.509 certificate associated with EV_EFI_VARIABLE_AUTHORITY event in pre-OS phase: %w", err)
					}
					result.UsedAuthorities = append(result.UsedAuthorities, newX509CertificateID(cert))
				} else {
					// Hopefully there shouldn't be any components being authenticated by a digest. We don't support this for
					// OS components but this could be allowed for pre-OS, but it would make PCR7 incredibly fragile.
					result.Flags |= secureBootPreOSVerificationIncludesDigest
				}
			case tcglog.EventTypeSeparator:
				// ok
			case tcglog.EventTypeEFIAction:
				// In general, it's not normal to see EV_EFI_ACTION events and these indicate some
				// sort of abnormal condition that has a detrimental effect on device security.
				// WithSecureBootPolicyProfile() will generate an invalid policy in this case because,
				// with some exceptions, it doesn't emit them.
				//
				// Just return an error here to prevent the use of WithSecureBootPolicyProfile(). The
				// "UEFI Debug Mode" and "DMA Protection Disabled" cases are already picked up by the
				// firmware protection checks, so we don't need any special handling here.
				//
				// We do permit the "DMA Protection Disabled" case if required. In this case,
				// WithSecureBootPolicyProfile() needs a separate option. Some firmware measures
				// this after the EV_SEPARATOR in PCR7 but part of the pre-OS environment.
				if permitDMAProtectionDisabledEvent && (bytes.Equal(ev.Data.Bytes(), []byte(tcglog.DMAProtectionDisabled)) ||
					bytes.Equal(ev.Data.Bytes(), append([]byte(tcglog.DMAProtectionDisabled), 0x00))) {
					// This event is detected by the host security checks so we can skip it here.
					// We'll emit a flag in the results which is picked up by the code in profile.go
					// to add an option to permit this with WithSecureBootPolicyProfile().
					permitDMAProtectionDisabledEvent = false // Don't allow this more than once.
					continue NextEvent
				}
				fallthrough
			default:
				// Anything that isn't EV_EFI_VARIABLE_AUTHORITY ends up here.
				return nil, fmt.Errorf("unexpected %v event %q whilst measuring verification", ev.EventType, ev.Data)
			}
		case tcglogPhaseOSPresent:
			if len(configs) > 0 {
				// We've transitioned to a phase where components can be loaded and verified but we haven't
				// measured all of the secure boot variables. We'll fail to generate a valid policy with
				// WithSecureBootPolicyProfile() in this case.
				return nil, errors.New("EV_EFI_VARIABLE_DRIVER_CONFIG events for some secure boot variables missing from log")
			}

			if ev.PCRIndex == internal_efi.BootManagerCodePCR &&
				ev.EventType == tcglog.EventTypeEFIBootServicesApplication &&
				!seenIBLLoadEvent {
				// This is an EV_EFI_BOOT_SERVICES_APPLICATION event during OS-present,
				// and we haven't seen the event for the IBL yet. We stop once we see this
				// because at this point, the rest of the measurements in this PCR are under
				// the control of the OS.
				yes, err := isLaunchedFromLoadOption(ev, bootOpt)
				if err != nil {
					return nil, fmt.Errorf("cannot determine if OS-present EV_EFI_BOOT_SERVICES_APPLICATION event for is associated with the current boot load option: %w", err)
				}
				if !yes {
					// This is not the launch event for the initial boot loader - ignore it.
					if seenOSPresentVerification {
						// The way we build profiles for PCR7 requires that any verification
						// events in PCR7 during OS-present to be associated with the OS. If
						// we've seen a verification event and we're in OS-present, then the
						// next expected event is the load event for the initial boot loader.
						// If we get verification events for Absolute (which is loaded from
						// Flash and is normally verified earlier on with the verification of
						// other Flash volumes), then we'll generate a potentially invalid
						// profile for PCR7, because we don't copy events from the log once
						// we're in OS-present.
						return nil, fmt.Errorf("unexpected EV_EFI_BOOT_SERVICES_APPLICATION event for %v after already seeing a verification event during the OS-present environment. "+
							"This event should be for the initial boot loader", ev.Data.(*tcglog.EFIImageLoadEvent).DevicePath)
					}
					continue NextEvent
				}

				// This is the IBL for the OS. Obtain signatures from binary
				seenIBLLoadEvent = true
				signer, err := extractSignerWithTrustAnchorFromImage(result.UsedAuthorities, iblImage)
				switch {
				case err == errNoSignerWithTrustAnchor:
					return nil, errors.New("OS initial boot loader was not verified by any X.509 certificate measured by any EV_EFI_VARIABLE_AUTHORITY event")
				case err != nil:
					return nil, fmt.Errorf("cannot determine if OS initial boot loader was verified by any X.509 certificate measured by any EV_EFI_VARIABLE_AUTHORITY event: %w", err)
				}

				ok, err := checkX509CertificatePublicKeyStrength(signer)
				if err != nil {
					return nil, fmt.Errorf("cannot determine public key strength of initial OS boot loader signer: %w", err)
				}
				if !ok {
					result.Flags |= secureBootIncludesWeakAlg
				}

				// This is the launch of the IBL. At this point, events are under control of the
				// OS, so we stop checking, even though we may miss some events created by
				// firmware via the LoadImage API.
				break NextEvent
			}

			if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
				// Not PCR7
				continue NextEvent
			}

			switch ev.EventType {
			case tcglog.EventTypeEFIVariableAuthority:
				// Make sure that the expected digest from the event data in the log is consistent
				// with the measured digest. We only do this for OS-present events because these are
				// the ones we compute. Pre-OS events are just copied from the log, so we don't check
				// them.
				eslType, esdData, err := handleVariableAuthorityEvent(pcrAlg, db, measuredSignatures, ev, true)
				if err != nil {
					return nil, fmt.Errorf("cannot handle EV_EFI_VARIABLE_AUTHORITY event in OS-present phase: %w", err)
				}

				measuredSignatures = append(measuredSignatures, ev.Digests[pcrAlg])
				seenOSPresentVerification = true
				ok, err := checkSignatureDataStrength(eslType, esdData)
				if err != nil {
					return nil, fmt.Errorf("cannot check strength of EFI_SIGNATURE_DATA associated with EV_EFI_VARIABLE_AUTHORITY event in OS-present phase: %w", err)
				}
				if !ok {
					// XXX: unfortunately in the case where an image is signed, the verification event only includes the CA
					// certificate - it's not possible from this to determine the actual signing certificate, it's signature
					// algorithm, and the algorithm used for signing the binary. In this case, the check is on the CA's
					// public key, which still has some value.
					result.Flags |= secureBootIncludesWeakAlg
				}
				if eslType != efi.CertX509Guid {
					return nil, errors.New("encountered EV_EFI_VARIABLE_AUTHORITY event without X.509 certificate during OS present, which is not supported")
				}
				cert, err := x509.ParseCertificate(esdData)
				if err != nil {
					return nil, fmt.Errorf("cannot decode X.509 certificate associated with EV_EFI_VARIABLE_AUTHORITY event in OS-present phase: %w", err)
				}
				result.UsedAuthorities = append(result.UsedAuthorities, newX509CertificateID(cert))
			case tcglog.EventTypeSeparator:
				// ok
			default:
				// Anything that isn't EV_EFI_VARIABLE_AUTHORITY ends up here.
				return nil, fmt.Errorf("unexpected %v event %q whilst measuring verification", ev.EventType, ev.Data)
			}
		case tcglogPhasePreOSAfterMeasureSecureBootConfigUnterminated:
			if ev.PCRIndex == internal_efi.SecureBootPolicyPCR {
				return nil, fmt.Errorf("unexpected %v event in PCR7 after measuring config but before transitioning to OS-present", ev.EventType)
			}
		}
	}

	if !seenIBLLoadEvent {
		return nil, errors.New("missing load event for initial boot loader")
	}
	return result, nil
}
