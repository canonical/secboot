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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
)

// ensureLockNVIndices creates a pair of NV indices at well known handles for locking access to sealed keys with
// LockAccessToSealedKeys if they don't exist already, and the TPM doesn't contain a valid legacy lock NV index.
//
// These indices are used for locking access to any sealed key objects we create until the next TPM restart or reset. The same
// handles are used for all keys, regardless of individual key policy.
//
// The traditional way of achieving this is by extending another value to a PCR that is included in the PCR selection for a
// sealed key's authorization policy after the key has been unsealed, which makes its authorization policy non-satisfiable until
// the next reset or restart. The issue with this is that it makes the feature dependent on the PCR profile.
//
// This feature is not designed to protect the key that you need to unseal to boot the current OS, but to protect keys that you
// don't need and may not even be aware of in order to boot the current OS - eg, say you boot from external media on a device that
// has an internal encrypted drive, or you insert and boot from an additional internal drive on a device that already has an
// encrypted install. The feature is designed to protect the contents of an encrypted drive belonging to someone else from being
// accessed by an adversary that just boots the same OS from another drive on a device, but where the OS provided by the adversary
// is configured to permit some form of shell access with their own credentials.
//
// In order to do this, it needs to work universally and it needs to work without being dependent on accessing key data for the
// keys it is meant to protect. Given that there could keys with slightly different PCR profiles, it's not really possible to make
// the feature work universally and without being dependent on accessing key data if it relies on PCRs.
//
// The implementation here uses a pair of NV indices at well known handles and takes advantage of a couple of properties of NV
// index read locks:
// - Once enabled, they can only be disabled by a TPM reset or restart.
// - Enabling a read lock sets the index's TPMA_NV_READLOCKED attribute which changes its name.
// Sealed keys created by this package have an authorization policy that asserts that these NV indices exists at their well known
// handles. Calling LockAccessToSealedKeys enables the read lock for one of them, which changes its name and makes this assertion
// fail.
//
// The problem with this approach though is that the TPM owner (ie, anyone who knows the authorization value for the storage hierarchy,
// which is empty by default) can undefine and redefine a NV index in order to clear the read lock attribute, thus re-enabling access
// to sealed keys. One approach to prevent this from happening relies on the fact that writing to a NV index for the first time sets
// the TPMA_NV_WRITTEN attribute which also changes its name. If the index is defined with the TPMA_NV_POLICY_WRITE attribute and an
// authorization policy that can only be satisfied by an assertion signed with an ephemeral key (using TPM2_PolicySigned), and sealed
// keys have authorization policies that can only be satisfied by the presence of the initialized index, then it is not possible for
// an adversary without the private part of the ephemeral key to undefine and redefine an identical NV index in order to remove the
// TPMA_NV_READLOCKED attribute and reenable access to sealed keys. This was the approach previously taken by secboot, but this had
// its own problem - if the NV index is accidentally undefined, then this would make all sealed keys permanently unrecoverable.
// Ideally, provisioning the TPM without clearing it should be able to remedy any accidental changes and restore access to valid
// sealed keys in all cases except where the storage primary seed has been changed (ie, the TPM has been cleared).
//
// The current approach used for protecting the NV index used by LockAccessToSealedKeys makes use of 2 NV indices and has the property
// that the NV indices have names that are common to all devices and can always be recreated, but they have authorization policies
// that enforce a creation sequence that means that they can only be created in the locked state. The way this works is as follows:
// - A bootstrap index is created at handle 2 with TPMA_NV_AUTHREAD and TPMA_NV_AUTHWRITE attributes and an empty authorization
//   policy.
// - An empty write is performed to initialize the bootstrap index.
// - An index is created at handle 1 with TPMA_NV_AUTHREAD, TPMA_NV_POLICY_WRITE and TPMA_NV_READ_STCLEAR attributes, and an
//   authorization policy that can only be satisfied by the presence of the initialized bootstrap index.
// - An empty write is performed to initialize index 1 using a policy session.
// - The bootstrap index is undefined and another index is created at handle 2 with TPMA_NV_AUTHREAD and TPMA_NV_POLICY_WRITE
//   attributes, and an authorization policy that can only be satisfied by the presence of the initialized index at handle 1 with
//   its read lock enabled.
// - The read lock for the index at handle 1 is enabled.
// - An empty write is performed to initialize index 2 using a policy session.
//
// Authorization policies for sealed keys must assert the presence of both of these NV indices using the names of the initialized
// indices without the read lock enabled. Enabling the read lock on index 1 by calling LockAccessToSealedKeys will disable access to
// these keys.
//
// It isn't possible to recreate these indices in their unlocked state. Although they can be recovered if they are undefined
// accidentally, they will not return to their unlocked state until the next TPM reset or restart.
//
// An adversary can't undefine and redefine either index in order to reenable access to sealed keys. Eg, say an adversary performs the
// following actions:
// - They undefine and redefine index 1. The new index isn't read locked, but sealed keys can't be unsealed until the new index has
//   been written to. But it has an authorization policy that requires index 2 to be undefined and replaced with the bootstrap index.
// - They undefine index 2 and create the boostrap index in its place.
// - They perform an empty write to index 1 to initialize it. Index 1 now has the expected name, but sealed keys still can't be
//   accessed because index 2 no longer exists.
// - They undefine the bootstrap index again and redefine index 2. However, sealed keys still can't be unsealed until the new index
//   has been written to. But it has an authorization policy that requires the read lock to be enabled on index 1.
// - They enable the read lock on index 1.
// - They perform an empty write to index 2 to initialize it. Index 2 now has the expected name, but sealed keys still can't be
//   accessed because index 1 is read locked. This can ony be undone by performing a TPM reset or restart.
//
// If this device has been provisioned with the legacy index, or has valid new-style indices, then this function does nothing.
func ensureLockNVIndices(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	if _, err := validateLockNVIndices(tpm, session); err == nil {
		// Nothing to do
		return nil
	}

	bootstrapPub, index1Pub, index2Pub, err := computeLockNVIndexTemplates()
	if err != nil {
		return xerrors.Errorf("cannot compute public areas for indices: %w", err)
	}

	for _, h := range []tpm2.Handle{index1Pub.Index, index2Pub.Index} {
		index, err := tpm.CreateResourceContextFromTPM(h)
		switch {
		case err != nil && !tpm2.IsResourceUnavailableError(err, h):
			// Unexpected error
			return xerrors.Errorf("cannot create context to determine if index is already defined: %w", err)
		case tpm2.IsResourceUnavailableError(err, h):
			// No existing index defined
		default:
			// Undefine the current index
			if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, session); err != nil {
				return xerrors.Errorf("cannot undefine existing index: %w", err)
			}
		}
	}

	succeeded := false

	bootstrap, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, bootstrapPub, session)
	if err != nil {
		return xerrors.Errorf("cannot create bootstrap index: %w", err)
	}
	defer func() {
		if succeeded || bootstrap.Handle() == tpm2.HandleUnassigned {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), bootstrap, session)
	}()

	if err := tpm.NVWrite(bootstrap, bootstrap, nil, 0, session); err != nil {
		return xerrors.Errorf("cannot initialize bootstrap index: %w", err)
	}

	index1, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, index1Pub, session)
	if err != nil {
		return xerrors.Errorf("cannot create index 1: %w", err)
	}
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index1, session)
	}()

	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, index1Pub.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot begin policy session to initialize indices: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if _, _, err := tpm.PolicySecret(bootstrap, policySession, nil, nil, 0, session); err != nil {
		return xerrors.Errorf("cannot execute assertion to initialize index 1: %w", err)
	}

	if err := tpm.NVWrite(index1, index1, nil, 0, policySession.IncludeAttrs(tpm2.AttrContinueSession), session.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return xerrors.Errorf("cannot initialize index 1: %w", err)
	}
	if err := tpm.NVReadLock(index1, index1, session); err != nil {
		return xerrors.Errorf("cannot enable read lock for index 1: %w", err)
	}

	if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), bootstrap, session); err != nil {
		return xerrors.Errorf("cannot undefine bootstrap index: %w", err)
	}

	index2, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, index2Pub, session)
	if err != nil {
		return xerrors.Errorf("cannot create index 2: %w", err)
	}
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index2, session)
	}()

	if _, _, err := tpm.PolicySecret(index1, policySession, nil, nil, 0, session); err != nil {
		return xerrors.Errorf("cannot execute assertion to initialize index 2: %w", err)
	}

	if err := tpm.NVWrite(index2, index2, nil, 0, policySession, session.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return xerrors.Errorf("cannot initialize index 2: %w", err)
	}

	succeeded = true

	return nil
}

// computeLockNVIndexTemplates computes the templates used to define the 2 NV indices used for locking access to sealed keys. It
// returns 3 templates - The templates have authorization policies that enforce a specific initialization order:
// - The first template is for a bootstrap index, which should be defined first. This has TPMA_NV_AUTHREAD and TPMA_NV_AUTHWRITE
//   attributes set and an empty authorization policy.
// - An empty write should be performed to initialize the bootstrap index.
// - The second template is for index 1, which should be defined next. This has TPMA_NV_AUTHREAD, TPMA_NV_POLICY_WRITE and
//   TPMA_NV_READ_STCLEAR attributes and an authorization policy that can only be satisfied by the presence of the previously
//   created and initialized bootstrap index.
// - An empty write should be performed to initialize index 1, using a policy session that contains a TPM2_PolicySecret assertion
//   against the bootstrap index.
// - The bootstrap index should be undefined. The third template is for index 2, which should be defined next. This is defined at
//   the same handle as the bootstrap index. It has TPMA_NV_AUTHREAD and TPMA_NV_POLICY_WRITE attributes set and an authorization
//   policy that can only be satisfied by the presence of the previously created and initialized index 1 with its read lock enabled.
// - The read lock for index 1 should be enabled.
// - An empty write should be performed to initialize index 2, using a policy session that contains a TPM2_PolicySecret assertion
//   against index 1.
// See the description of ensureLockNVIndices for a more complete explanation.
func computeLockNVIndexTemplates() (bootstrap *tpm2.NVPublic, index1 *tpm2.NVPublic, index2 *tpm2.NVPublic, err error) {
	bootstrap = &tpm2.NVPublic{
		Index:   lockNVHandle2,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		Size:    0}
	bootstrap.Attrs |= tpm2.AttrNVWritten
	bootstrapName, err := bootstrap.Name()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot compute name of bootstrap index: %w", err)
	}
	bootstrap.Attrs &^= tpm2.AttrNVWritten

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicySecret(bootstrapName, nil)

	index1 = &tpm2.NVPublic{
		Index:      lockNVHandle1,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      lockNVIndex1Attrs,
		AuthPolicy: trial.GetDigest(),
		Size:       0}
	index1.Attrs |= tpm2.AttrNVReadLocked | tpm2.AttrNVWritten
	index1LockedName, err := index1.Name()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot compute name of index 1: %w", err)
	}
	index1.Attrs &^= tpm2.AttrNVReadLocked | tpm2.AttrNVWritten

	trial, _ = tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicySecret(index1LockedName, nil)

	index2 = &tpm2.NVPublic{
		Index:      lockNVHandle2,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		AuthPolicy: trial.GetDigest(),
		Size:       0}

	return
}

// computeLockNVIndexNames computes the names of the 2 NV indices at well-known locations that are used for locking access to
// sealed keys. These names are not unique, and the presence of indices with these names should be asserted in any authorization
// policy that wants to benefit from locking.
func computeLockNVIndexNames() (tpm2.Name, tpm2.Name, error) {
	_, index1, index2, err := computeLockNVIndexTemplates()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute public areas for indices: %w", err)
	}

	// index1 and index2 are the creation templates. Require that the indices are initalized (written to)
	// by computing their names with the TPMA_NV_WRITTEN attribute set.
	index1.Attrs |= tpm2.AttrNVWritten
	index2.Attrs |= tpm2.AttrNVWritten

	index1Name, err := index1.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of index 1: %w", err)
	}
	index2Name, err := index2.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of index 2: %w", err)
	}

	return index1Name, index2Name, nil
}

// A keysLockSolution implements the policy facet involved in
// supporting locking the sealed keys independently of other policy details.
type keysLockSolution interface {
	// tryPolicy applies the keys lock policy facet under trial.
	tryPolicy(trial *tpm2.TrialAuthPolicy)
	// executeInPolicySession executes the keys lock policy facet in the session.
	executeInPolicySession(tpm *tpm2.TPMContext, policySession tpm2.SessionContext) error
}

// validateLegacyLockNVIndex validates that the supplied NV index is a valid legacy lock index and is safe to protect a new key against. It returns the corresponding keysLockSolution to try or execute the corresponding authorization policy
// using the name of index public area.
func validateLegacyLockNVIndex(tpm *tpm2.TPMContext, index, dataIndex tpm2.ResourceContext, session tpm2.SessionContext) (keysLockSolution, error) {
	var s tpm2.SessionContext
	if session != nil {
		s = session.IncludeAttrs(tpm2.AttrAudit)
	}

	dataPub, _, err := tpm.NVReadPublic(dataIndex)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of policy data index: %w", err)
	}
	data, err := tpm.NVRead(dataIndex, dataIndex, dataPub.Size, 0, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot read policy data: %w", err)
	}

	// Unmarshal the data
	var version uint8
	var keyName tpm2.Name
	var clock uint64
	if _, err := mu.UnmarshalFromBytes(data, &version, &keyName, &clock); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal policy data: %w", err)
	}

	// Allow for future changes to the public attributes or auth policy configuration.
	if version != 0 {
		return nil, errors.New("unrecognized version for policy data")
	}

	// Read the TPM clock (no session here because some Infineon devices don't allow them, despite being permitted in the spec
	// and reference implementation)
	time, err := tpm.ReadClock()
	if err != nil {
		return nil, xerrors.Errorf("cannot read current time: %w", err)
	}

	// Make sure the window beyond which this index can be written has passed or about to pass.
	if time.ClockInfo.Clock+5000 < clock {
		return nil, errors.New("unexpected clock value in policy data")
	}

	// Read the public area of the lock NV index.
	pub, _, err := tpm.NVReadPublic(index, s)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of index: %w", err)
	}

	pub.Attrs &^= tpm2.AttrNVReadLocked
	// Validate its attributes
	if pub.Attrs != lockNVIndex1Attrs|tpm2.AttrNVWritten {
		return nil, errors.New("unexpected index attributes")
	}

	clockBytes := make([]byte, binary.Size(clock))
	binary.BigEndian.PutUint64(clockBytes, clock)

	// Compute the expected authorization policy from the contents of the data index, and make sure that this matches the public area.
	// This verifies that the lock NV index has a valid authorization policy.
	trial, err := tpm2.ComputeAuthPolicy(pub.NameAlg)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute expected policy for index: %w", err)
	}
	trial.PolicyCommandCode(tpm2.CommandNVWrite)
	trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
	trial.PolicySigned(keyName, nil)

	if !bytes.Equal(trial.GetDigest(), pub.AuthPolicy) {
		return nil, errors.New("incorrect policy for index")
	}

	// legacyLockIndexName corresponds to a valid legacy global lock NV index that cannot be recreated!

	legacyLockIndexName, err := pub.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute lock NV index name: %w", err)
	}
	return &legacyKeysLockSolution{lockIndexName: legacyLockIndexName}, nil
}

// validateCurrentLockNVIndices validates that the supplied NV indices correspond to valid new-style lock NV indices. It returns the corresponding keysLockSolution to try or execute the corresponding authorization policy using their names.
func validateCurrentLockNVIndices(tpm *tpm2.TPMContext, index1, index2 tpm2.ResourceContext, session tpm2.SessionContext) (keysLockSolution, error) {
	var s tpm2.SessionContext
	if session != nil {
		s = session.IncludeAttrs(tpm2.AttrAudit)
	}

	index1Pub, _, err := tpm.NVReadPublic(index1, s)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of index 1: %w", err)
	}
	index1Pub.Attrs &^= tpm2.AttrNVReadLocked
	index1Name, err := index1Pub.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name of index 1: %w", err)
	}

	index1ExpectedName, index2ExpectedName, err := computeLockNVIndexNames()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute expected names: %w", err)
	}

	if !bytes.Equal(index1Name, index1ExpectedName) || !bytes.Equal(index2.Name(), index2ExpectedName) {
		return nil, errors.New("found indices with unexpected names")
	}

	return &twoIndicesKeysLockSolution{
		lockIndex1Name: index1ExpectedName,
		lockIndex2Name: index2ExpectedName,
	}, nil
}

// validateLockNVIndices checks that the NV indices at the global handles used for locking access to sealed keys are valid lock
// indices, and returns an error if they aren't.
// It returns the corresponding keysLockSolution for the setup to try
// or execute the corresponding authorization policy.
func validateLockNVIndices(tpm *tpm2.TPMContext, session tpm2.SessionContext) (keysLockSolution, error) {
	var s tpm2.SessionContext
	if session != nil {
		s = session.IncludeAttrs(tpm2.AttrAudit)
	}
	index1, err := tpm.CreateResourceContextFromTPM(lockNVHandle1, s)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for index 1: %w", err)
	}
	index2, err := tpm.CreateResourceContextFromTPM(lockNVHandle2, s)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for index 2: %w", err)
	}

	sol, err1 := validateCurrentLockNVIndices(tpm, index1, index2, session)
	if err1 == nil {
		return sol, nil
	}

	legacySol, err2 := validateLegacyLockNVIndex(tpm, index1, index2, session)
	if err2 != nil {
		return nil, fmt.Errorf("cannot detect new indices (%v) or legacy index (%v)", err1, err2)
	}

	return legacySol, nil
}

// current keys lock solution

type twoIndicesKeysLockSolution struct {
	lockIndex1Name tpm2.Name
	lockIndex2Name tpm2.Name
}

func (sol *twoIndicesKeysLockSolution) tryPolicy(trial *tpm2.TrialAuthPolicy) {
	trial.PolicyNV(sol.lockIndex1Name, nil, 0, tpm2.OpEq)
	trial.PolicyNV(sol.lockIndex2Name, nil, 0, tpm2.OpEq)
}

func (sol *twoIndicesKeysLockSolution) executeInPolicySession(tpm *tpm2.TPMContext, policySession tpm2.SessionContext) error {
	return keysLockIndicesPolicy(tpm, policySession, lockNVHandle1, lockNVHandle2)
}

func keysLockIndicesPolicy(tpm *tpm2.TPMContext, policySession tpm2.SessionContext, lockNVHandles ...tpm2.Handle) error {
	for _, h := range lockNVHandles {
		index, err := tpm.CreateResourceContextFromTPM(h)
		if err != nil {
			return xerrors.Errorf("cannot obtain context for lock NV index: %w", err)
		}
		if err := tpm.PolicyNV(index, index, policySession, nil, 0, tpm2.OpEq, nil); err != nil {
			return xerrors.Errorf("policy lock check failed: %w", err)
		}
	}
	return nil
}

// legacy keys lock solution

type legacyKeysLockSolution struct {
	lockIndexName tpm2.Name
}

func (sol *legacyKeysLockSolution) tryPolicy(trial *tpm2.TrialAuthPolicy) {
	trial.PolicyNV(sol.lockIndexName, nil, 0, tpm2.OpEq)
}

func (sol *legacyKeysLockSolution) executeInPolicySession(tpm *tpm2.TPMContext, policySession tpm2.SessionContext) error {
	return keysLockIndicesPolicy(tpm, policySession, lockNVHandle1)
}

// LockAccessToSealedKeys locks access to keys sealed by this package until the next TPM restart (equivalent to eg, system resume
// from suspend-to-disk) or TPM reset (equivalent to booting after a system restart). This works for all keys sealed by this package
// regardless of their PCR protection profile.
//
// On success, subsequent calls to SealedKeyObject.UnsealFromTPM will fail with a ErrSealedKeyAccessLocked error until the next TPM
// restart or TPM reset.
func LockAccessToSealedKeys(tpm *TPMConnection) error {
	session := tpm.HmacSession()

	handles, err := tpm.GetCapabilityHandles(lockNVHandle1, 1, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot obtain handles from TPM: %w", err)
	}
	if len(handles) == 0 || handles[0] != lockNVHandle1 {
		// Not provisioned, so no keys created by this package can be unsealed by this TPM
		return nil
	}
	lock, err := tpm.CreateResourceContextFromTPM(lockNVHandle1)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for lock NV index: %w", err)
	}
	lockPublic, _, err := tpm.NVReadPublic(lock, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot read public area of lock NV index: %w", err)
	}
	if lockPublic.Attrs != lockNVIndex1Attrs|tpm2.AttrNVWritten {
		// Definitely not an index created by us, so no keys created by this package can be unsealed by this TPM.
		return nil
	}
	if err := tpm.NVReadLock(lock, lock, session); err != nil {
		if isAuthFailError(err, tpm2.CommandNVReadLock, 1) {
			// The index has an authorization value, so it wasn't created by this package and no keys created by this package can be unsealed
			// by this TPM.
			return nil
		}
		return xerrors.Errorf("cannot lock NV index for reading: %w", err)
	}
	return nil
}
