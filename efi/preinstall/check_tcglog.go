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
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

var (
	// supportedAlgs specifies the supported PCR banks, in order of preference.
	// XXX: We disallow SHA-1 here - perhaps this should be optionally permitted?
	supportedAlgs = []tpm2.HashAlgorithmId{
		tpm2.HashAlgorithmSHA512,
		tpm2.HashAlgorithmSHA384,
		tpm2.HashAlgorithmSHA256,
	}

	// supportedPcrs specifies all of the TCG defined PCRs, although we don't actually
	// support generating profiles for all of them at the moment, nor are we likely to
	// for some of them in the future.
	supportedPcrs = []tpm2.Handle{
		internal_efi.PlatformFirmwarePCR, // WithPlatformFirmwareProfile()
		internal_efi.PlatformConfigPCR,
		internal_efi.DriversAndAppsPCR, // WithDriversAndAppsProfile()
		internal_efi.DriversAndAppsConfigPCR,
		internal_efi.BootManagerCodePCR, // WithBootManagerCodeProfile()
		internal_efi.BootManagerConfigPCR,
		internal_efi.PlatformManufacturerPCR,
		internal_efi.SecureBootPolicyPCR, // WithSecureBootPolicyProfile()
	}
)

// pcrResult represents the result of reconstructing the log for a single PCR in a single bank
type pcrResults struct {
	mandatory    bool        // Errors from testing this PCR can't be ignored
	initialValue tpm2.Digest // The initial value for the PCR. Initialized to the size of the digest of the bank during construction.
	logValue     tpm2.Digest // The expected TPM PCR value from the reconstructed log. Initialized to the same value as initialValue during construction.
	pcrValue     tpm2.Digest // The actual TPM PCR value. Will be empty until set by setPcrValue

	err error // This is set for any error that occurred.
}

// Ok indicates that the reconstructed log is consistent with the TPM PCR value and
// that no other error occurred. If this returns false, [Err] will return an error.
func (r *pcrResults) Ok() bool {
	return r.Err() == nil
}

// Err returns any error that occurred when checking the log consistency with the
// associated TPM PCR value.
func (r *pcrResults) Err() error {
	if r.err != nil {
		// Return the first explicitly set error.
		return r.err
	}
	if len(r.pcrValue) == 0 {
		return errors.New("PCR value has not been obtained from TPM yet")
	}
	if !r.extended() {
		// Return an error if the PCR hasn't been extended.
		return errors.New("PCR has not been extended by platform firmware")
	}
	if !bytes.Equal(r.pcrValue, r.logValue) {
		// The PCR value is inconsistent with the log value.
		return fmt.Errorf("PCR value mismatch (actual from TPM %#x, reconstructed from log %#x)", r.pcrValue, r.logValue)
	}
	return nil
}

// extended indicates that extend has already been called.
func (r *pcrResults) extended() bool {
	return !bytes.Equal(r.initialValue, r.logValue)
}

// setInitialValue sets the initial value for the associated PCR in the associated bank.
// This will panic if extend has already been called, so the caller should check this. It
// will also panic if the supplied digest has the wrong size.
func (r *pcrResults) setInitialValue(digest tpm2.Digest) {
	if r.extended() {
		panic("cannot set initial log value for PCR once extend has been called")
	}
	if len(digest) != len(r.initialValue) {
		panic("invalid initial digest length")
	}
	copy(r.initialValue, digest)
	copy(r.logValue, digest)
}

// extend performs a hash extend of the logValue field with the supplied digest using the
// specified algorithm. This will return an error if the supplied digest has the wrong
// length.
func (r *pcrResults) extend(alg tpm2.HashAlgorithmId, digest tpm2.Digest) error {
	if alg.Size() != len(r.logValue) {
		panic("invalid algorithm supplied")
	}
	if alg.Size() != len(digest) {
		// Don't panic here because digest comes from the log and perhaps the log
		// defines the wrong size for the algorithm
		return errors.New("invalid digest length")
	}
	h := alg.NewHash()
	h.Write(r.logValue)
	h.Write(digest)
	r.logValue = h.Sum(nil)
	return nil
}

// setPcrValue records the PCR value from the TPM. This will panic if it's called more than
// once. It will return an error if the value length doesn't match the log value length, just
// in case the TPM results are garbage.
func (r *pcrResults) setPcrValue(value tpm2.Digest) error {
	if len(r.pcrValue) > 0 {
		panic("cannot set PCR value more than once")
	}
	if len(value) != len(r.logValue) {
		// Don't panic here because the digest is returned directly
		// from the TPM
		return errors.New("invalid digest length")
	}
	r.pcrValue = value
	return nil
}

// setErr sets an error for the associated PCR in the associated bank. This doesn't
// overwrite previously set errors (ie, [Err] will return the first set error).
func (r *pcrResults) setErr(err error) {
	if r.err != nil {
		return
	}
	r.err = err
}

// pcrBankResults represents the result of reconstructing the log for an entire
// PCR bank.
type pcrBankResults struct {
	Alg             tpm2.HashAlgorithmId // the digest algorithm of the PCR bank
	StartupLocality uint8                // the startup locality
	pcrs            [8]pcrResults        // individual PCR results
}

// newPcrBankResults creates a new pcrBankResults for the specified algorithm. If any
// of the supplied mandatory PCRs fail, this entire bank will be marked as failed.
func newPcrBankResults(alg tpm2.HashAlgorithmId, mandatoryPcrs tpm2.HandleList) (out *pcrBankResults) {
	out = &pcrBankResults{
		Alg:             alg,
		StartupLocality: 0,
	}
	for pcr := range out.pcrs {
		result := out.Lookup(tpm2.Handle(pcr))
		for _, mandatoryPcr := range mandatoryPcrs {
			if mandatoryPcr == tpm2.Handle(pcr) {
				result.mandatory = true
				break
			}
		}
		result.initialValue = make(tpm2.Digest, alg.Size())
		result.logValue = make(tpm2.Digest, alg.Size())
		// leave the pcrValue field uninitialized for now
	}
	return out
}

// Ok indicates that the log was reconstructed ok for all mandatory PCRs for the associated PCR bank.
func (r *pcrBankResults) Ok() bool {
	for _, result := range r.pcrs {
		if !result.Ok() && result.mandatory {
			return false
		}
	}
	return true
}

// Lookup looks up the result for the specified PCR. This will panic if the supplied
// PCR is out of range (ie, not 0-7).
func (r *pcrBankResults) Lookup(pcr tpm2.Handle) *pcrResults {
	if !internal_efi.IsTCGDefinedPCR(pcr) {
		panic("invalid PCR index")
	}
	return &r.pcrs[pcr]
}

// extend performs a hash extend of the logValue field of the pcrResult struct
// associated with the specified pcr, using the supplied digest. It will panic
// if the specified PCR is out of range. It will return an error if the supplied
// digest has the wrong size.
func (r *pcrBankResults) extend(pcr tpm2.Handle, digest tpm2.Digest) error {
	return r.Lookup(pcr).extend(r.Alg, digest)
}

// setPcrValues records the PCR values obtained from the TPM. It will panic
// if this is called more than once. It will return an error if any value returned
// from the TPM has the wrong size.
func (r *pcrBankResults) setPcrValues(values tpm2.PCRValues) error {
	for pcr, digest := range values[r.Alg] {
		if !internal_efi.IsTCGDefinedPCR(tpm2.Handle(pcr)) {
			continue
		}
		if err := r.Lookup(tpm2.Handle(pcr)).setPcrValue(digest); err != nil {
			return fmt.Errorf("cannot record value for PCR %d: %w", pcr, err)
		}
	}
	return nil
}

// pcrErrs returns a map of PCRs to errors for individual PCRs associated with this bank.
func (r *pcrBankResults) pcrErrs() (out map[tpm2.Handle]error) {
	out = make(map[tpm2.Handle]error)
	for pcr, result := range r.pcrs {
		err := result.Err()
		if err == nil {
			continue
		}
		out[tpm2.Handle(pcr)] = err
	}
	return out
}

// checkFirmwareLogAgainstTPMForAlg checks the supplied TCG log consistency, reconstructed against the
// TPM PCRs for the specified algorithm. This only checks TCG defined PCRs (0-7). The supplied
// mandatoryPcrs argument is required by the returned results so that it can use this to make a decision
// on whether the bank is ok.
func checkFirmwareLogAgainstTPMForAlg(tpm *tpm2.TPMContext, log *tcglog.Log, alg tpm2.HashAlgorithmId, mandatoryPcrs tpm2.HandleList) (results *pcrBankResults, err error) {
	// Check that the TCG log contains the specified algorithm
	supported := false
	for _, logAlg := range log.Algorithms {
		if logAlg != alg {
			continue
		}
		// It does, so that's a good start.
		supported = true
		break
	}
	if !supported {
		// The log doesn't contain the specified algorithm
		return nil, errors.New("digest algorithm not present in log")
	}

	// Create the result tracker for PCRs 0-7
	results = newPcrBankResults(alg, mandatoryPcrs)

	seenStartupLocalityEvent := false

	// Iterate over the log
	for i, ev := range log.Events {
		if !internal_efi.IsTCGDefinedPCR(ev.PCRIndex) {
			// Skip all events that aren't defined by the TCG
			continue
		}

		if ev.EventType == tcglog.EventTypeNoAction {
			// EV_NO_ACTION events are informational and not measured, so ignore most of them with the exception
			// of StartupLocality events, which affects the initial value of PCR0.
			startupLocalityData, isStartupLocality := ev.Data.(*tcglog.StartupLocalityEventData)
			if !isStartupLocality {
				// Not a StartupLocality event.
				continue
			}

			// This is the StartupLocality event which is added to the log to indicate
			// which locality the TPM2_Startup command was executed from. The reference
			// TPM implementation only allows this to be executed from localities 0 and 3.
			// The platform may restrict access to locality 3 from the host OS (even from
			// code running in the kernel). The startup locality affects the reset value of
			// PCR0 - the least significant byte is set to the startup locality value. PCR0
			// can also be initialized before TPM2_Startup by a H-CRTM event sequence from
			// locality 4, which will be reflected in this event in this case by setting the
			// startup locality to 4, regardless of what locality TPM2_Startup is subsequently
			// called from.
			if ev.PCRIndex != internal_efi.PlatformFirmwarePCR {
				// This event should only ever appear in PCR0
				results.Lookup(ev.PCRIndex).setErr(errors.New("unexpected StartupLocality event (should be in PCR0)"))
				continue
			}
			if results.Lookup(0).extended() {
				// This event should not appear in the log after events that have already been measured
				results.Lookup(0).setErr(errors.New("unexpected StartupLocality event after measurements already made"))
				continue
			}
			if seenStartupLocalityEvent {
				results.Lookup(0).setErr(errors.New("unexpected StartupLocality event - more than one appears in log"))
				continue
			}
			seenStartupLocalityEvent = true

			switch startupLocalityData.StartupLocality {
			case 0, 3, 4:
				// Valid startup locality values, with 4 meaning there was a H-CRTM event sequence.
				results.StartupLocality = startupLocalityData.StartupLocality
				digest := make(tpm2.Digest, alg.Size())
				digest[alg.Size()-1] = results.StartupLocality
				results.Lookup(0).setInitialValue(digest)
			default:
				// Invalid startup locality value
				results.Lookup(0).setErr(fmt.Errorf("invalid StartupLocality value %d - "+
					"TPM2_Startup is only permitted from locality 0 or 3, "+
					"or PCR0 can be initialized from locality 4 by a H-CRTM event before TPM2_Startup is called", startupLocalityData.StartupLocality))
				results.StartupLocality = 0
			}
			continue
		}

		// XXX: The TGC PC-Client PFP spec v1.06 is a bit vague wrt EV_S_CRTM_CONTENTS and EV_S_CRTM_VERSION events when there was a H-CRTM
		// event sequence. Table 27 says that EV_S_CRTM_CONTENTS and EV_S_CRTM_VERSION events are always measured, but the guidelines for
		// measuring to PCR0 separately say:
		// - If an H-CRTM measured the SRTM version, log the SRTM version identifier measurement using an EV_S_CRTM_VERSION event.
		// - If an H-CRTM measured the SRTM contents, log the SRTM contents measurement(s) using an EV_S_CRTM_CONTENTS event.
		// ... which suggests that these events are added to the log just to provide information, like EV_NO_ACTION events, in order
		// to accompany the EV_EFI_HCRTM_EVENT events from which would contain the actual measured digests.
		//
		// I don't know what this looks like in practise because I've never come across a device that uses H-CRTM event sequences, so
		// we'll just treat EV_S_CRTM_CONTENTS and EV_S_CRTM_VERSION events after a H-CRTM event as an error.
		if results.StartupLocality == 4 && (ev.EventType == tcglog.EventTypeSCRTMContents || ev.EventType == tcglog.EventTypeSCRTMVersion) {
			results.Lookup(0).setErr(fmt.Errorf("unsure how to handle %v event types after H-CRTM events", ev.EventType))
			continue
		}

		// This is a TCG defined event that is measured, so perform a hash extend
		if err := results.extend(ev.PCRIndex, ev.Digests[alg]); err != nil {
			// This should only return an error if the spec ID event at the start
			// of the log specifies the wrong size for the algorithm, in which case
			// all events will be wrong. Best to just bail here rather than set an
			// error on just this PCR.
			return nil, fmt.Errorf("cannot perform extend with event %d from PCR %d: %w", i, ev.PCRIndex, err)
		}
	}

	// Read the actual PCR values from the TPM.
	var pcrs []int
	for _, pcr := range supportedPcrs {
		pcrs = append(pcrs, int(pcr))
	}
	selections := tpm2.PCRSelectionList{{Hash: alg, Select: pcrs}}
	_, values, err := tpm.PCRRead(selections)
	if err != nil {
		return nil, err
	}

	// Record these values on the results
	if err := results.setPcrValues(values); err != nil {
		return nil, fmt.Errorf("cannot process PCR values from TPM: %w", err)
	}

	return results, nil
}

// tcglogPhase describes the phase of a TCG log
type tcglogPhase int

const (
	// tcglogPhasePreOSBeforeMeasureSecureBootConfig is the pre-OS phase of the log
	// before measurement of the secure boot configuration has begun. This is the
	// starting point.
	tcglogPhasePreOSBeforeMeasureSecureBootConfig tcglogPhase = iota

	// tcglogPhasePreOSMeasuringSecureBootConfig is the pre-OS phase of the log where
	// the secure boot configuration is being measured.
	// tcglogPhasePreOSBeforeMeasureSecureBootConfig transitions to this phase by the
	// first non EV_SEPARATOR event in PCR7.
	tcglogPhasePreOSMeasuringSecureBootConfig tcglogPhase = iota

	// tcglogPhasePreOSAfterMeasureSecureBootConfig is the pre-OS phase of the log after
	// measuring the secure boot configuration and which may contain authentication and
	// loading of pre-OS components. An EV_SEPARATOR in PCR7 transitions
	// tcglogPhasePreOSMeasuringSecureBootConfig to this phase. Some older firmware
	// implementations skip this phase because they measure EV_SEPARATORS in PCRs 0-7 to
	// indicate the transition to OS-present.
	tcglogPhasePreOSAfterMeasureSecureBootConfig

	// tcglogPhasePreOSAfterMeasureSecureBootConfigUnterminated happens on some older firmware
	// implementations that don't use a EV_SEPARATOR in PCR7 to separate secure boot config
	// from secure boot verification, but instead measure the separator as part of the pre-OS
	// to OS-present transition. There shouldn't be any more events in PCR7 until
	// tcglogPhaseOSPresent.
	tcglogPhasePreOSAfterMeasureSecureBootConfigUnterminated

	// tcglogPhaseTransitioningToOSPresent describes the phase of the log where the transition
	// to OS-present happens. Either of the 2 previous pre-OS phases can transition to this one
	// by an EV_SEPARATOR event in PCRs 0-6.
	tcglogPhaseTransitioningToOSPresent

	// tcglogPhaseOSPresent describes the phase of the log where the OS is in control. The
	// tcglogPhaseTransitioningToOSPresent phase transitions to this when all EV_SEPARATOR
	// events in PCRs 0-7 have been seen.
	tcglogPhaseOSPresent

	// tcglogPhaseErr indicates that a previous event was interpreted as an error. Attempting
	// to process the rest of the log will cause a panic.
	tcglogPhaseErr
)

// tcglogPhaseTracker tracks the phases of a TCG log up to OS-present, and processes
// events to validate the general consistency of the structure of the log and sequence
// of events.
type tcglogPhaseTracker struct {
	phase             tcglogPhase
	numSeparatorsSeen int
	pcrSeparatorsSeen map[tpm2.Handle]bool
}

// newTcgLogPhaseTracker returns a new tcglogPhaseTracker
func newTcgLogPhaseTracker() *tcglogPhaseTracker {
	return &tcglogPhaseTracker{
		phase:             tcglogPhasePreOSBeforeMeasureSecureBootConfig,
		numSeparatorsSeen: 0,
		pcrSeparatorsSeen: make(map[tpm2.Handle]bool),
	}
}

// processEvent processes the supplied event. If a previous call returned an error, this
// function will panic.
//
// On success, it will return the new TCG log phase.
func (t *tcglogPhaseTracker) processEvent(ev *tcglog.Event) (phase tcglogPhase, err error) {
	defer func() {
		// Indicate an error occurred if we return any error so that subsequent
		// calls cause a panic.
		if err == nil {
			return
		}
		t.phase = tcglogPhaseErr
	}()

	// Check terminal phases first.
	switch t.phase {
	case tcglogPhaseOSPresent:
		// This is the OS-present phase, we no longer care for anything in the log once
		// we're in this phase.
		return t.phase, nil
	case tcglogPhaseErr:
		panic("not expecting any more events after returning an error")
	}

	// We're not in OS-present phase, so make sure the measurement is to a TCG defined PCR
	if !internal_efi.IsTCGDefinedPCR(ev.PCRIndex) {
		return 0, fmt.Errorf("measurements were made by firmware from pre-OS environment to non-TCG defined PCR %d", ev.PCRIndex)
	}

	// Handle any EV_SEPARATOR event
	if ev.EventType == tcglog.EventTypeSeparator {
		// Make sure it's the only one seen for this PCR
		if _, exists := t.pcrSeparatorsSeen[ev.PCRIndex]; exists {
			return 0, fmt.Errorf("more than one EV_SEPARATOR event exists for PCR %d", ev.PCRIndex)
		}

		// Make sure the separator doesn't signal an error condition. If an error condition occurs,
		// the firmware should cap all PCRs with EV_SEPARATOR events that indicate that an error
		// occurred.
		data, ok := ev.Data.(*tcglog.SeparatorEventData)
		if !ok {
			// if it failed to decode then it's guaranteed to implement the error interface.
			return 0, fmt.Errorf("invalid event data for EV_SEPARATOR event in PCR %d: %w", ev.PCRIndex, ev.Data.(error))
		}
		if data.IsError() {
			// The EV_SEPARATOR event indicates that an error occurred.
			return 0, fmt.Errorf("EV_SEPARATOR event for PCR %d indicates an error occurred (error code in log: %d)", ev.PCRIndex, binary.LittleEndian.Uint32(data.Bytes()))
		}

		t.pcrSeparatorsSeen[ev.PCRIndex] = true // Mark the EV_SEPARATOR as seen for this PCR
		t.numSeparatorsSeen += 1                // Count the number of EV_SEPARATORs seen.
	}

	// Handle phase transitions
	switch {
	case t.phase == tcglogPhasePreOSBeforeMeasureSecureBootConfig:
		switch {
		case ev.EventType == tcglog.EventTypeSeparator:
			// An EV_SEPARATOR during this phase is used to signal an error condition, but
			// the data for the separator should have indicated the error, which is caught above.
			// If we get here then this is a normal EV_SEPARATOR event.
			return 0, fmt.Errorf("unexpected normal EV_SEPARATOR event in PCR %d", ev.PCRIndex)
		case ev.PCRIndex == internal_efi.SecureBootPolicyPCR:
			// A non EV_SEPARATOR event to PCR7 signals the beginning of the secure boot config measurements.
			t.phase = tcglogPhasePreOSMeasuringSecureBootConfig
		default:
			// No change for any other event
		}
	case t.phase == tcglogPhasePreOSMeasuringSecureBootConfig:
		switch {
		case ev.PCRIndex != internal_efi.SecureBootPolicyPCR && ev.EventType == tcglog.EventTypeSeparator:
			// An EV_SEPARATOR event in PCRs 0-6 after measuring the secure boot configuration begins the
			// transition to OS-present, skipping the part of the pre-OS phase after the secure boot config
			// has been measured.
			t.phase = tcglogPhaseTransitioningToOSPresent
		case ev.PCRIndex != internal_efi.SecureBootPolicyPCR:
			// Any other events that aren't to PCR7 terminate the measurement of the secure
			// boot config. This path should only happen on older firmware implementations.
			t.phase = tcglogPhasePreOSAfterMeasureSecureBootConfigUnterminated
		case ev.EventType == tcglog.EventTypeSeparator:
			// An EV_SEPARATOR in PCR7 transitions to the part of the pre-OS phase where pre-OS
			// components can be verified and executed.
			t.phase = tcglogPhasePreOSAfterMeasureSecureBootConfig
		default:
			// No change for any other event to PCR7
		}
	case t.phase == tcglogPhasePreOSAfterMeasureSecureBootConfigUnterminated:
		// XXX(chrisccoulson): It's not clear whether this should return to
		// tcglogPhasePreOSMeasuringSecureBootConfig if there is an event in PCR7. The
		// justification for this is that PCR7 should begin with an extra event indicating
		// that there is a debugger active if that is the case. EDK2 measures this in the
		// same block of events as the secure boot configuration, but we don't know whether
		// all firmware does this. The consequence of some firmware measuring it separately
		// is that we may end up failing other PCRs unnecessarily for tests that use this
		// functionality, because of the logic here.
		switch {
		case ev.EventType == tcglog.EventTypeSeparator:
			// Any EV_SEPARATOR from this phase begins the transition to OS present.
			t.phase = tcglogPhaseTransitioningToOSPresent
		default:
			// No change for events in any other PCR.
		}
	case t.phase == tcglogPhasePreOSAfterMeasureSecureBootConfig:
		switch {
		case ev.EventType == tcglog.EventTypeSeparator:
			// Any EV_SEPARATOR from this phase begins the transition to OS present.
			t.phase = tcglogPhaseTransitioningToOSPresent
		default:
			// No change for any other event
		}
	case t.phase == tcglogPhaseTransitioningToOSPresent:
		switch {
		case ev.EventType == tcglog.EventTypeSeparator:
			// No change here - we're still transitioning to OS present.
		case t.numSeparatorsSeen != 8:
			// If we see any other event type before seeing all EV_SEPARATOR
			// events, return an error
			return 0, fmt.Errorf("unexpected %v event in PCR %d whilst transitioning to OS-present (expected EV_SEPARATOR)", ev.EventType, ev.PCRIndex)
		default:
			// Any non EV_SEPARATOR event when we've seen all expected separators
			// completes the transition to OS-present, and we're done!
			t.phase = tcglogPhaseOSPresent
		}
	}

	return t.phase, nil
}

func (t *tcglogPhaseTracker) reachedOSPresent() bool {
	return t.phase == tcglogPhaseOSPresent
}

// checkFirmwareLogAndChoosePCRBank verifies that the firmware TCG log is in crypto-agile form and
// consistent with at least one supported PCR bank for the specified mandatory PCRs when reconstructed
// for the TCG defined PCRs (0-7). It also ensures that:
//   - the TCG defined PCRs contain a EV_SEPARATOR event between the pre-OS and OS-present environment (
//     although the one in PCR7 separates secure boot configuratuib from secure boot authentication).
//   - that none of the EV_SEPARATORs in the TCG defined PCRs indicated that an error occurred.
//   - there are no pre-OS measurements to non-TCG defined PCRs (8-).
//
// This won't return an error for failures in TCG defined PCRs if they aren't part of the specified mandatory
// PCRs set, but the errors will be accessible on the returned results struct.
//
// The returned results struct indicates the best PCR bank to use and specifies the TPM startup locality as well.
func checkFirmwareLogAndChoosePCRBank(tpm *tpm2.TPMContext, log *tcglog.Log, mandatoryPcrs tpm2.HandleList) (results *pcrBankResults, err error) {
	// Make sure it's a crypto-agile log
	if !log.Spec.IsEFI_2() {
		return nil, errors.New("invalid log spec")
	}

	// Chose the best PCR bank, ordered from SHA-512, SHA-384 to SHA-256. We're most
	// likely to get SHA-256 here - it's only in very recent devices that we have TPMs with
	// SHA-384 support and corresponding firmware integration.
	// We try to keep all errors enountered during selection here.
	mainErr := new(NoSuitablePCRAlgorithmError)
	var chosenResults *pcrBankResults
	for _, alg := range supportedAlgs {
		if chosenResults != nil {
			// We've already got a good PCR bank, so no need to carry on.
			break
		}

		results, err := checkFirmwareLogAgainstTPMForAlg(tpm, log, alg, mandatoryPcrs)
		switch {
		case err != nil:
			// This entire bank is bad
			mainErr.setBankErr(alg, err)
		case results.Ok():
			// This is a good PCR bank
			chosenResults = results
		default:
			// This isn't a good PCR bank because some mandatory PCRs
			// failed. Record the individual PCR errors.
			mainErr.setPcrErrs(results)
		}
	}

	if chosenResults == nil {
		// No suitable PCR bank was found, so return an error that's hopefully useful :(
		return nil, mainErr
	}

	// Make sure that the log is well formed and has well defined phases and that there are no measurements
	// to non-TCG defined PCRs until OS-present.
	phaseTracker := newTcgLogPhaseTracker()
	for _, ev := range log.Events {
		phase, err := phaseTracker.processEvent(ev)
		if err != nil {
			return nil, err
		}
		if phase == tcglogPhaseOSPresent {
			// We've hit OS-present - we don't care about the rest of the log at
			// this stage
			break
		}
	}
	if !phaseTracker.reachedOSPresent() {
		return nil, errors.New("reached the end of the log without seeing EV_SEPARATOR events in all TCG defined PCRs")
	}

	// At this point, we've selected a PCR bank where the TCG log is consistent with the PCR values for
	// mandatory PCRs, and the log is generally in good order, although there are more detailed PCR-specific
	// tests to perform later on as well.
	return chosenResults, nil
}
