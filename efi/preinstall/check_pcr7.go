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

type secureBootPolicyResultFlags int

const (
	secureBootIncludesWeakAlg secureBootPolicyResultFlags = 1 << iota
	secureBootPreOSVerificationIncludesDigest
)

type secureBootPolicyResult struct {
	UsedAuthorities []*x509.Certificate
	Flags           secureBootPolicyResultFlags
}

func checkSecureBootPolicyMeasurementsAndObtainAuthorities(ctx context.Context, env internal_efi.HostEnvironment, log *tcglog.Log, pcrAlg tpm2.HashAlgorithmId, iblImage secboot_efi.Image) (result *secureBootPolicyResult, err error) {
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

	// Obtain the BootCurrent variable and use this to obtain the corresponding load option
	// that was measured to the log. BootXXXX variables are measured to the TPM and so we don't
	// need to read back from an EFI variable that could have been modified between boot time
	// and now. We need this so that we can identify the launch of the initial boot loader later
	// on. This uses the same code that we use for PCR4 checks.
	current, err := efi.ReadBootCurrentVariable(varCtx)
	if err != nil {
		return nil, fmt.Errorf("cannot read BootCurrent variable: %w", err)
	}
	bootOpt, err := readLoadOptionFromLog(log, current)
	if err != nil {
		return nil, fmt.Errorf("cannot read current Boot%04x load option from log: %w", current, err)
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

				switch data.UnicodeName {
				case "SecureBoot":
					// Make sure the SecureBoot value in the log matches the EFI variable,
					// (ie, []byte{1}). We don't do this for other variables because they can
					// be updated from the OS, making them potentially inconsistent. The
					// SecureBoot variable is read only after ExitBootServices.
					if !bytes.Equal(data.VariableData, []byte{1}) {
						return nil, errors.New("SecureBoot variable is not consistent with the corresponding EV_EFI_VARIABLE_DRIVER_CONFIG event value in the TCG log")
					}
				case "PK":
					// Make sure that we can parse the PK database and it contains a single
					// X.509 entry.
					pk, err := efi.ReadSignatureDatabase(bytes.NewReader(data.VariableData))
					if err != nil {
						return nil, fmt.Errorf("cannot decode PK contents from EV_EFI_VARIABLE_DRIVER_CONFIG event data: %w", err)
					}
					switch len(pk) {
					case 0:
						// This should never be empty when secure boot is enabled,
						// so if it does then the firmware is broken.
						return nil, errors.New("invalid PK contents from EV_EFI_VARIABLE_DRIVER_CONFIG event: no signature list when secure boot is enabled")
					case 1:
						esl := pk[0]
						if esl.Type != efi.CertX509Guid {
							// PK can only contain a X.509 certificate. If we get another
							// type then the firmwar is broken.
							return nil, fmt.Errorf("invalid PK contents from EV_EFI_VARIABLE_DRIVER_CONFIG event: signature list has an unexpected type: %v", esl.Type)
						}
						if len(esl.Signatures) != 1 {
							// EFI_CERT_X509_GUID signature lists can only contain a single
							// signature. If there isn't then the firmware is broken.
							return nil, fmt.Errorf("invalid PK contents from EV_EFI_VARIABLE_DRIVER_CONFIG event: signature list should only have one signature, but got %d", len(esl.Signatures))
						}
						if _, err := x509.ParseCertificate(esl.Signatures[0].Data); err != nil {
							return nil, fmt.Errorf("invalid PK contents from EV_EFI_VARIABLE_DRIVER_CONFIG event: cannot decode PK certificate: %w", err)
						}
					default:
						// If PK contains more than 1 ESL, then the firmware is broken.
						return nil, errors.New("invalid PK contents from EV_EFI_VARIABLE_DRIVER_CONFIG event: more than one signature list is present")
					}
				case "db":
					// Capture the db from the log for future use.
					var err error
					db, err = efi.ReadSignatureDatabase(bytes.NewReader(data.VariableData))
					if err != nil {
						return nil, fmt.Errorf("cannot decode db contents from EV_EFI_VARIABLE_DRIVER_CONFIG event: %w", err)
					}
					// We don't check the EFI_SIGNATURE_LIST types contained in db. Any OS component with a valid
					// Authenticode signature (WIN_CERT_TYPE_PKCS_SIGNED_DATA) or a valid PKCS7 signature
					// (WIN_CERT_TYPE_EFI_GUID with the type EFI_CERT_TYPE_PKCS7_GUID) is authenticated with
					// signature verification using the matching EFI_CERT_X509_GUID entry first, and the profile
					// generation in secboot efi makes sure a signed binary has a matching root in the relevant
					// trust stores. The presence of digest signatures (EFI_CERT_SHA*) shouldn't matter because
					// these are only used to authenticate unsigned images (which the profile generation in the
					// secboot efi package rejects) or as a fallback for signed image where signature verification
					// fails. Digests may be permitted for authenticating unsigned pre-OS components.
				default:
					// Make sure that we can parse all other signature databases ok
					if _, err = efi.ReadSignatureDatabase(bytes.NewReader(data.VariableData)); err != nil {
						return nil, fmt.Errorf("cannot decode %s contents from EV_EFI_VARIABLE_DRIVER_CONFIG event: %w", data.UnicodeName, err)
					}
				}
			case tcglog.EventTypeEFIAction:
				// This branch exists here for documentation purposes - it falls through to the
				// default branch below, which returns an error.
				//
				// An EV_EFI_ACTION events with the string "UEFI Debug Mode" appears at the
				// start of the log if a debugging endpoint is enabled. It's also possible that
				// EV_EFI_ACTION events are used for other conditions in PCR7 that weaken device
				// security (eg, the "DMA Protection Disabled" event).
				//
				// In general, it's not normal to see EV_EFI_ACTION events and these indicate some
				// sort of abnormal condition that has a detrimental effect on device security.
				// WithSecureBootPolicyProfile() will generate an invalid policy in this case because
				// it doesn't emit them.
				//
				// Just return an error here to prevent the use of WithSecureBootPolicyProfile(). The
				// "UEFI Debug Mode" and "DMA Protection Disabled" cases are already picked up by the
				// firmware protection checks, so we don't need any special handling here.
				fallthrough
			default:
				// Anything that isn't EV_EFI_VARIABLE_DRIVER_CONFIG ends up here.
				return nil, fmt.Errorf("unexpected %v event %q whilst measuring config", ev.EventType, ev.Data)
			}
		case tcglogPhasePreOSAfterMeasureSecureBootConfig, tcglogPhaseOSPresent:
			if len(configs) > 0 {
				// We've transitioned to a phase where components can be loaded and verified but we haven't
				// measured all of the secure boot variables. We'll fail to generate a valid policy with
				// WithSecureBootPolicyProfile() in this case.
				return nil, errors.New("EV_EFI_VARIABLE_DRIVER_CONFIG events for some secure boot variables missing from log")
			}

			if ev.PCRIndex == internal_efi.BootManagerCodePCR &&
				ev.EventType == tcglog.EventTypeEFIBootServicesApplication &&
				phase == tcglogPhaseOSPresent &&
				!seenIBLLoadEvent {
				// This is an EV_EFI_BOOT_SERVICES_APPLICATION event during OS-present,
				// and we haven't seen the event for the IBL yet. We stop once we see this
				// because at this point, the rest of the measurements in this PCR are under
				// the control of the OS.
				data, ok := ev.Data.(*tcglog.EFIImageLoadEvent)
				if !ok {
					return nil, fmt.Errorf("invalid OS-present EV_EFI_BOOT_SERVICES_APPLICATION event data: %w", ev.Data.(error))
				}

				yes, err := isLaunchedFromLoadOption(ev, bootOpt)
				if err != nil {
					return nil, fmt.Errorf("cannot determine if OS-present EV_EFI_BOOT_SERVICES_APPLICATION event for %v is associated with the current boot load option: %w", data.DevicePath, err)
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
						return nil, fmt.Errorf("unexpected EV_EFI_BOOT_SERVICES_APPLICATION event for %v after already seeing a verification event during the OS-present environment. This event should be for the initial boot loader", data.DevicePath)
					}
					continue NextEvent
				}

				// This is the IBL for the OS. Obtain signatures from binary
				seenIBLLoadEvent = true
				sigs, err := func() ([]*efi.WinCertificateAuthenticode, error) {
					r, err := iblImage.Open()
					if err != nil {
						return nil, fmt.Errorf("cannot open image: %w", err)
					}
					defer r.Close()

					pefile, err := peNewFile(r)
					if err != nil {
						return nil, fmt.Errorf("cannot decode image: %w", err)
					}

					return internal_efiSecureBootSignaturesFromPEFile(pefile, r)
				}()
				if err != nil {
					return nil, fmt.Errorf("cannot obtain secure boot signatures from image %s: %w", iblImage, err)
				}

				// Make sure that one of the CA's used for verification so far
				// is a trust anchor for one of the signatures on the image.
				var foundSig *efi.WinCertificateAuthenticode
				for _, cert := range result.UsedAuthorities {
					for _, sig := range sigs {
						if sig.CertLikelyTrustAnchor(cert) {
							foundSig = sig
							break
						}
					}
					if foundSig != nil {
						break
					}
				}
				if foundSig == nil {
					return nil, errors.New("OS initial boot loader was not verified by any X.509 certificate measured by any EV_EFI_VARIABLE_AUTHORITY event")
				}

				signer := foundSig.GetSigner()
				switch signer.PublicKeyAlgorithm {
				case x509.RSA:
					pubKey, ok := signer.PublicKey.(*rsa.PublicKey)
					if !ok {
						return nil, errors.New("signer certificate for OS initial boot loader contains unsupported public key type")
					}
					if pubKey.N.BitLen() <= 1024 {
						result.Flags |= secureBootIncludesWeakAlg
					}
				default:
					return nil, errors.New("signer certificate for OS initial boot loader contains unsupported public key algorithm")
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
				// Decode the verification event
				data, ok := ev.Data.(*tcglog.EFIVariableData)
				if !ok {
					// if decoding failed, the resulting data is guaranteed to implement error.
					return nil, fmt.Errorf("EV_EFI_VARIABLE_AUTHORITY event has wrong data format: %w", ev.Data.(error))
				}

				// As we're only checking events up to the launch of the IBL, we don't expect
				// to see anything other than verification events from db here.
				if data.VariableName != efi.ImageSecurityDatabaseGuid || data.UnicodeName != "db" {
					return nil, fmt.Errorf("EV_EFI_VARIABLE_AUTHORITY event is not from db (got %s-%v)", data.UnicodeName, data.VariableName)
				}

				if phase == tcglogPhaseOSPresent {
					// Compute the expected digest from the event data in the log and make
					// sure it's consistent with the measured digest. We only do this for
					// OS-present events because these are the ones we compute. Pre-OS
					// events are just copied from the log.
					seenOSPresentVerification = true
					expectedDigest := tcglog.ComputeEFIVariableDataDigest(pcrAlg.GetHash(), data.UnicodeName, data.VariableName, data.VariableData)
					if !bytes.Equal(ev.Digests[pcrAlg], expectedDigest) {
						return nil, fmt.Errorf("event data inconsistent with %v event digest for EV_EFI_VARIABLE_AUTHORITY event (log digest:%#x, expected digest:%#x)", pcrAlg, ev.Digests[pcrAlg], expectedDigest)
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
				for _, measured := range measuredSignatures {
					if bytes.Equal(measured, ev.Digests[pcrAlg]) {
						return nil, fmt.Errorf("EV_EFI_VARIABLE_AUTHORITY digest %#x has been measured by the firmware more than once", ev.Digests[pcrAlg])
					}
				}
				measuredSignatures = append(measuredSignatures, ev.Digests[pcrAlg])

				// Try to discover the type of authentication. The measured EFI_SIGNATURE_DATA doesn't
				// contain this.

				// First of all, construct a signature data entry from the raw event data.
				esd := new(efi.SignatureData)
				r := bytes.NewReader(data.VariableData)

				// THE EFI_SIGNATURE_DATA entry starts with the owner GUID
				sigOwner, err := efi.ReadGUID(r)
				if err != nil {
					return nil, fmt.Errorf("cannot decode owner GUID from EV_EFI_VARIABLE_AUTHORITY event: %w", err)
				}
				esd.Owner = sigOwner

				// The rest of the EFI_SIGNATURE_DATA entry is the data
				sigData, err := io.ReadAll(r)
				if err != nil {
					return nil, fmt.Errorf("cannot read data from EV_EFI_VARIABLE_AUTHORITY event: %w", err)
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
					return nil, fmt.Errorf("encountered db EV_EFI_VARIABLE_AUTHORITY event with data that doesn't match to any db EFI_SIGNATURE_LIST")
				}

				switch matchedEsl.Type {
				case efi.CertX509Guid:
					cert, err := x509.ParseCertificate(esd.Data)
					if err != nil {
						return nil, fmt.Errorf("cannot decode X.509 certificate from db EV_EFI_VARIABLE_AUTHORITY event: %w", err)
					}
					result.UsedAuthorities = append(result.UsedAuthorities, cert)

					switch cert.PublicKeyAlgorithm {
					case x509.RSA:
						pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
						if !ok {
							return nil, errors.New("db EV_EFI_VARIABLE_AUTHORITY event includes X.509 certificate with unsupported public key type")
						}
						if pubKey.N.BitLen() <= 1024 {
							result.Flags |= secureBootIncludesWeakAlg
						}
					default:
						return nil, errors.New("db EV_EFI_VARIABLE_AUTHORITY event includes X.509 certificate with unsupported public key algorithm")
					}
					// XXX: unfortunately the verification event only includes the CA certificate - it's not possible from this to
					// determine the actual signing certificate, it's signature algorithm, and the algorithm used for signing the
					// binary.
				case efi.CertSHA1Guid:
					// Hopefully there shouldn't be any components being authenticated by a digest. We don't support this for
					// OS components so this might be relevant for pre-OS, but it would make PCR7 incredibly fragile.
					result.Flags |= secureBootIncludesWeakAlg
					fallthrough
				case efi.CertSHA224Guid, efi.CertSHA256Guid, efi.CertSHA384Guid, efi.CertSHA512Guid:
					if phase == tcglogPhaseOSPresent {
						return nil, errors.New("encountered EV_EFI_VARIABLE_AUTHORITY event without X.509 certificate during OS present, which is not supported")
					}
					result.Flags |= secureBootPreOSVerificationIncludesDigest
				default:
					return nil, fmt.Errorf("unrecognized EFI_SIGNATURE_DATA type for EV_EFI_VARIABLE_AUTHORITY event: %v", matchedEsl.Type)
				}
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
