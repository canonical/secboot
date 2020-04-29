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
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/canonical/go-tpm2"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const (
	minArgon2TimeCost   = 4
	minArgon2MemoryCost = 32 * 1024
)

type pinData struct {
	EncryptedIK    *afSplitData
	IKIV           []byte
	ArgonVersion   byte
	Salt           []byte
	Time           uint32
	Memory         uint32
	Threads        uint8
	DerivedKeySize uint32
}

func timeArgon2Execution(password, salt []byte, timeCost, memoryCost uint32, threads uint8, keyLen uint32, iterations, targetMs uint) uint {
	var minMs uint

	for i := uint(0); i < iterations; i++ {
		fmt.Printf("   timing argon2 execution (%d), timeCost=%d, memoryCost=%d\n", i, timeCost, memoryCost)
		start := time.Now()
		_ = argon2.Key(password, salt, timeCost, memoryCost, threads, keyLen)
		end := time.Now()
		ms := uint(end.Sub(start) / time.Millisecond)
		fmt.Printf("   ...%dms\n", ms)

		runtime.GC()

		if i == 0 {
			minMs = ms
		}
		if ms < minMs {
			minMs = ms
		}
		if minMs < targetMs {
			break
		}
	}

	return minMs
}

func computeNextArgon2Params(maxMemory uint32, targetMs, ms uint, timeCost, memoryCost uint32) (newTimeCost uint32, newMemoryCost uint32, done bool) {
	newTimeCost = timeCost
	newMemoryCost = memoryCost

	switch {
	case ms < targetMs:
		switch {
		case memoryCost < maxMemory:
			newMemoryCost = uint32((uint(memoryCost) * targetMs) / ms)
			if newMemoryCost > maxMemory {
				newMemoryCost = maxMemory
				newTimeCost = uint32((uint(timeCost*memoryCost) * targetMs) / (ms * uint(maxMemory)))
			}
		default:
			newTimeCost = uint32((uint(timeCost) * targetMs) / ms)
		}
	case ms > targetMs:
		switch {
		case timeCost > minArgon2TimeCost:
			newTimeCost = uint32((uint(timeCost) * targetMs) / ms)
			if newTimeCost < minArgon2TimeCost {
				newTimeCost = minArgon2TimeCost
				newMemoryCost = uint32((uint(memoryCost*timeCost) * targetMs) / (ms * minArgon2TimeCost))
				if newMemoryCost < minArgon2MemoryCost {
					newMemoryCost = minArgon2MemoryCost
					done = true
				}
			}
		default:
			newMemoryCost = uint32((uint(memoryCost) * targetMs) / ms)
			if newMemoryCost < minArgon2MemoryCost {
				newMemoryCost = minArgon2MemoryCost
				done = true
			}
		}
	}

	if timeCost == newTimeCost && memoryCost == newMemoryCost {
		done = true
	}
	return
}

func benchmarkArgon2(password, salt []byte, threads uint8, keyLen, maxMemoryCost uint32, targetMs uint) (timeCost uint32, memoryCost uint32) {
	fmt.Printf("Benchmarking argon2, threads=%d, maxMemoryCost=%d, targetMs=%d\n", threads, maxMemoryCost, targetMs)
	const (
		initialTargetMs = 250
		tolerance       = 0.05
	)

	timeCost = minArgon2TimeCost
	memoryCost = minArgon2MemoryCost
	var ms uint

	for i := 0; ms < initialTargetMs; i++ {
		if i > 0 {
			if ms < 25 {
				ms = 25
			}
			var done bool
			timeCost, memoryCost, done = computeNextArgon2Params(maxMemoryCost, initialTargetMs, ms, timeCost, memoryCost)
			if done {
				break
			}
		}

		ms = timeArgon2Execution(password, salt, timeCost, memoryCost, threads, keyLen, 3, initialTargetMs)
	}

	minTargetMs := targetMs - uint(float64(targetMs)*tolerance)
	maxTargetMs := targetMs + uint(float64(targetMs)*tolerance)
	for ms < minTargetMs || ms > maxTargetMs {
		var done bool
		timeCost, memoryCost, done = computeNextArgon2Params(maxMemoryCost, targetMs, ms, timeCost, memoryCost)
		if done {
			break
		}

		ms = timeArgon2Execution(password, salt, timeCost, memoryCost, threads, keyLen, 1, minTargetMs)
	}

	fmt.Printf("...done, timeCost=%d, memoryCost=%d, ms=%d\n", timeCost, memoryCost, ms)
	return
}

// computePinNVIndexPostInitAuthPolicies computes the authorization policy digests associated with the post-initialization
// actions on a NV index created with createPinNVIndex. These are:
// - A policy for updating the index to revoke old dynamic authorization policies, requiring an assertion signed by the key
//   associated with updateKeyName.
// - A policy for updating the authorization value (PIN / passphrase), requiring knowledge of the current authorization value.
// - A policy for reading the counter value without knowing the authorization value, as the value isn't secret.
// - A policy for using the counter value in a TPM2_PolicyNV assertion without knowing the authorization value.
func computePinNVIndexPostInitAuthPolicies(alg tpm2.HashAlgorithmId, updateKeyName tpm2.Name) (tpm2.DigestList, error) {
	var out tpm2.DigestList
	// Compute a policy for incrementing the index to revoke dynamic authorization policies, requiring an assertion signed by the
	// key associated with updateKeyName.
	trial, err := tpm2.ComputeAuthPolicy(alg)
	if err != nil {
		return nil, err
	}
	trial.PolicyCommandCode(tpm2.CommandNVIncrement)
	trial.PolicyNvWritten(true)
	trial.PolicySigned(updateKeyName, nil)
	out = append(out, trial.GetDigest())

	// Compute a policy for updating the authorization value of the index, requiring knowledge of the current authorization value.
	trial, err = tpm2.ComputeAuthPolicy(alg)
	if err != nil {
		return nil, err
	}
	trial.PolicyCommandCode(tpm2.CommandNVChangeAuth)
	trial.PolicyAuthValue()
	out = append(out, trial.GetDigest())

	// Compute a policy for reading the counter value without knowing the authorization value.
	trial, err = tpm2.ComputeAuthPolicy(alg)
	if err != nil {
		return nil, err
	}
	trial.PolicyCommandCode(tpm2.CommandNVRead)
	out = append(out, trial.GetDigest())

	// Compute a policy for using the counter value in a TPM2_PolicyNV assertion without knowing the authorization value.
	trial, err = tpm2.ComputeAuthPolicy(alg)
	if err != nil {
		return nil, err
	}
	trial.PolicyCommandCode(tpm2.CommandPolicyNV)
	out = append(out, trial.GetDigest())

	return out, nil
}

// createPinNVIndex creates a NV index that is associated with a sealed key object and is used for implementing PIN support. It is
// also used as a counter to support revoking of dynamic authorization policies.
//
// To prevent someone with knowledge of the owner authorization (which is empty unless someone has taken ownership of the TPM) from
// resetting the PIN by just undefining and redifining a new NV index with the same properties, we need a way to prevent someone
// from being able to create an index with the same name. To do this, we require the NV index to have been written to and only allow
// the initial write with a signed authorization policy. Once initialized, the signing key that authorized the initial write is
// discarded. This works because the name of the signing key is included in the authorization policy digest for the NV index, and the
// authorization policy digest and attributes are included in the name of the NV index. Without the private part of the signing key,
// it is impossible to create a new NV index with the same name, and so, if this NV index is undefined then it becomes impossible to
// satisfy the authorization policy for the sealed key object to which it is associated.
//
// The NV index will be created with an authorization policy that permits TPM2_NV_Read and TPM2_PolicyNV without knowing the PIN,
// and an authorization policy that permits TPM2_NV_Increment with a signed authorization policy, signed by the key associated with
// updateKeyName.
func createPinNVIndex(tpm *tpm2.TPMContext, handle tpm2.Handle, updateKeyName tpm2.Name, hmacSession tpm2.SessionContext) (*tpm2.NVPublic, tpm2.DigestList, error) {
	initKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create signing key for initializing NV index: %w", err)
	}

	initKeyPublic := createPublicAreaForRSASigningKey(&initKey.PublicKey)
	initKeyName, err := initKeyPublic.Name()
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute name of signing key for initializing NV index: %w", err)
	}

	nameAlg := tpm2.HashAlgorithmSHA256

	// The NV index requires 5 policies:
	// - A policy for initializing the index, requiring an assertion signed with an ephemeral key so that the index cannot be recreated.
	// - A policy for updating the index to revoke old dynamic authorization policies, requiring a signed assertion.
	// - A policy for updating the authorization value (PIN / passphrase), requiring knowledge of the current authorization value.
	// - A policy for reading the counter value without knowing the authorization value, as the value isn't secret.
	// - A policy for using the counter value in a TPM2_PolicyNV assertion without knowing the authorization value.
	var authPolicies tpm2.DigestList

	// Compute a policy for initialization which requires an assertion signed with an ephemeral key (initKey)
	trial, _ := tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyCommandCode(tpm2.CommandNVIncrement)
	trial.PolicyNvWritten(false)
	trial.PolicySigned(initKeyName, nil)
	authPolicies = append(authPolicies, trial.GetDigest())

	// Compute the remaining 4 post-initalization policies.
	postInitAuthPolicies, err := computePinNVIndexPostInitAuthPolicies(nameAlg, updateKeyName)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot compute authorization policies: %w", err)
	}
	authPolicies = append(authPolicies, postInitAuthPolicies...)

	trial, _ = tpm2.ComputeAuthPolicy(nameAlg)
	trial.PolicyOR(authPolicies)

	// Define the NV index
	public := &tpm2.NVPublic{
		Index:      handle,
		NameAlg:    nameAlg,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead),
		AuthPolicy: trial.GetDigest(),
		Size:       8}

	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, public, hmacSession)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot define NV space: %w", err)
	}

	// NVDefineSpace was integrity protected, so we know that we have an index with the expected public area at the handle we specified
	// at this point.

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, hmacSession)
	}()

	// Begin a session to initialize the index.
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, nameAlg)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot begin policy session to initialize NV index: %w", err)
	}
	defer tpm.FlushContext(policySession)

	// Compute a digest for signing with our key
	signDigest := tpm2.HashAlgorithmSHA256
	h := signDigest.NewHash()
	h.Write(policySession.NonceTPM())
	binary.Write(h, binary.BigEndian, int32(0))

	// Sign the digest
	sig, err := rsa.SignPSS(rand.Reader, initKey, signDigest.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
	}

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	initKeyContext, err := tpm.LoadExternal(nil, initKeyPublic, tpm2.HandleEndorsement)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot load public part of key used to initialize NV index to the TPM: %w", err)
	}
	defer tpm.FlushContext(initKeyContext)

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSAPSS,
		Signature: tpm2.SignatureU{
			Data: &tpm2.SignatureRSAPSS{
				Hash: signDigest,
				Sig:  tpm2.PublicKeyRSA(sig)}}}

	// Execute the policy assertions
	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVIncrement); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyNvWritten(policySession, false); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}
	if _, _, err := tpm.PolicySigned(initKeyContext, policySession, true, nil, nil, 0, &signature); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}
	if err := tpm.PolicyOR(policySession, authPolicies); err != nil {
		return nil, nil, xerrors.Errorf("cannot execute assertion to initialize NV index: %w", err)
	}

	// Initialize the index
	if err := tpm.NVIncrement(index, index, policySession, hmacSession.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return nil, nil, xerrors.Errorf("cannot initialize NV index: %w", err)
	}

	// The index has a different name now that it has been written, so update the public area we return so that it can be used
	// to construct an authorization policy.
	public.Attrs |= tpm2.AttrNVWritten

	succeeded = true
	return public, authPolicies, nil
}

// performTPMPinChange changes the authorization value of the PIN NV index associated with the public argument. This requires the
// authorization policy digests initially returned from createPinNVIndex in order to execute the policy session required to change
// the authorization value. The current authorization value must be provided via the oldAuth argument.
//
// On success, the authorization value of the PIN NV index will be changed to newAuth.
func performTPMPinChange(tpm *tpm2.TPMContext, public *tpm2.NVPublic, authPolicies tpm2.DigestList, oldAuth, newAuth []byte, hmacSession tpm2.SessionContext) error {
	index, err := tpm2.CreateNVIndexResourceContextFromPublic(public)
	if err != nil {
		return xerrors.Errorf("cannot create resource context for NV index: %w", err)
	}
	index.SetAuthValue(oldAuth)

	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, public.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVChangeAuth); err != nil {
		return xerrors.Errorf("cannot execute assertion: %w", err)
	}
	if err := tpm.PolicyAuthValue(policySession); err != nil {
		return xerrors.Errorf("cannot execute assertion: %w", err)
	}
	if err := tpm.PolicyOR(policySession, authPolicies); err != nil {
		return xerrors.Errorf("cannot execute assertion: %w", err)
	}

	if err := tpm.NVChangeAuth(index, newAuth, policySession, hmacSession.IncludeAttrs(tpm2.AttrCommandEncrypt)); err != nil {
		return xerrors.Errorf("cannot change authorization value for NV index: %w", err)
	}

	return nil
}

func (d *pinData) decryptIKAndObtainTPMAuthValue(pin string) (*afSplitData, []byte, error) {
	if d.Time == 0 || d.Threads == 0 || d.DerivedKeySize == 0 {
		return nil, nil, errors.New("invalid argon2 parameters")
	}
	derivedKey := argon2.Key([]byte(pin), d.Salt, d.Time, d.Memory, d.Threads, d.DerivedKeySize*2)
	data, err := d.EncryptedIK.decrypt(derivedKey[0:d.DerivedKeySize], d.IKIV)
	if err != nil {
		return nil, nil, err
	}

	return data, derivedKey[d.DerivedKeySize:], nil
}

func (d *pinData) validate() error {
	if d.Time == 0 || d.Threads == 0 || d.DerivedKeySize == 0 {
		return errors.New("invalid argon2 parameters")
	}
	if len(d.IKIV) != aes.BlockSize {
		return errors.New("invalid IV length")
	}
	if len(d.EncryptedIK.Data)%aes.BlockSize != 0 {
		return errors.New("invalid intermediate key length")
	}
	if err := d.EncryptedIK.validate(); err != nil {
		return err
	}
	return nil
}

func encryptIKAndComputeTPMAuthValue(params *PINParams, ik *afSplitData, auth string) (*pinData, []byte, error) {
	const derivedKeySize uint32 = 32

	var sysInfo unix.Sysinfo_t
	if err := unix.Sysinfo(&sysInfo); err != nil {
		return nil, nil, xerrors.Errorf("cannot determine available memory: %w", err)
	}
	maxMemoryCost := uint32(sysInfo.Totalram) / 2
	if params.MaxMemoryCost < maxMemoryCost {
		maxMemoryCost = params.MaxMemoryCost
	}

	threads := uint8(runtime.NumCPU())
	if threads > 4 {
		threads = 4
	}

	timeCost, memoryCost := benchmarkArgon2([]byte("foo"), []byte("0123456789abcdefghijklmnopqrstuv"), threads, derivedKeySize*2,
		maxMemoryCost, uint(params.TimeCost/1e6))

	var iv [16]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return nil, nil, xerrors.Errorf("cannot create new IV: %w", err)
	}

	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, nil, xerrors.Errorf("cannot create new salt: %w", err)
	}

	derivedKey := argon2.Key([]byte(auth), salt[:], timeCost, memoryCost, threads, derivedKeySize*2)
	runtime.GC()

	ikEnc, err := ik.encrypt(derivedKey[0:derivedKeySize], iv[:])
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot encrypt intermediate key: %w", err)
	}

	return &pinData{
		EncryptedIK:    ikEnc,
		IKIV:           iv[:],
		ArgonVersion:   argon2.Version,
		Salt:           salt[:],
		Time:           timeCost,
		Memory:         memoryCost,
		Threads:        threads,
		DerivedKeySize: derivedKeySize}, derivedKey[derivedKeySize:], nil
}

// PINParams provides some additional parameters to ChangePIN.
type PINParams struct {
	// MaxMemoryCost is used to specify the maximum amount of memory in KiB to use when performing key derivation with the PIN.
	MaxMemoryCost uint32

	// TimeCost is used to specify the target time when computing the key derivation parameters for the PIN.
	TimeCost time.Duration
}

// ChangePIN changes the PIN for the key data file at the specified path. The existing PIN must be supplied via the oldPIN argument.
// Setting newPIN to an empty string will clear the PIN and set a hint on the key data file that no PIN is set.
//
// If the TPM's dictionary attack logic has been triggered, a ErrTPMLockout error will be returned.
//
// If the file at the specified path cannot be opened, then a wrapped *os.PathError error will be returned.
//
// If the supplied key data file fails validation checks, an InvalidKeyFileError error will be returned.
//
// If oldPIN is incorrect, then a ErrPINFail error will be returned and the TPM's dictionary attack counter will be incremented.
func ChangePIN(tpm *TPMConnection, path string, params *PINParams, oldPIN, newPIN string) error {
	// Check if the TPM is in lockout mode
	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return xerrors.Errorf("cannot fetch properties from TPM: %w", err)
	}

	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrInLockout > 0 {
		return ErrTPMLockout
	}

	// Open the key data file
	keyFile, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("cannot open key data file: %w", err)
	}
	defer keyFile.Close()

	// Read and validate the key data file
	data, _, pinIndexPublic, err := readAndValidateKeyData(tpm.TPMContext, keyFile, nil, tpm.HmacSession())
	if err != nil {
		var kfErr keyFileError
		if xerrors.As(err, &kfErr) {
			return InvalidKeyFileError{err.Error()}
		}
		return xerrors.Errorf("cannot read and validate key data file: %w", err)
	}

	var ik *afSplitData
	var oldTpmAuthValue []byte
	if data.AuthModeHint == AuthModeNone {
		ik = data.UnprotectedIK
	} else {
		var err error
		ik, oldTpmAuthValue, err = data.PINData.decryptIKAndObtainTPMAuthValue(oldPIN)
		if err != nil {
			return err
		}
	}

	if newPIN == "" {
		data.AuthModeHint = AuthModeNone
	} else {
		data.AuthModeHint = AuthModePIN
	}

	var newTpmAuthValue []byte
	if data.AuthModeHint == AuthModeNone {
		data.UnprotectedIK = ik
		data.PINData = nil
	} else {
		data.UnprotectedIK = nil
		pd, authValue, err := encryptIKAndComputeTPMAuthValue(params, ik, newPIN)
		if err != nil {
			return xerrors.Errorf("cannot encrypt intermediate key with new PIN: %w", err)
		}
		newTpmAuthValue = authValue
		data.PINData = pd
	}

	// Change the PIN on the TPM
	if err := performTPMPinChange(tpm.TPMContext, pinIndexPublic, data.StaticPolicyData.PinIndexAuthPolicies, oldTpmAuthValue,
		newTpmAuthValue, tpm.HmacSession()); err != nil {
		if isAuthFailError(err, tpm2.CommandNVChangeAuth, 1) {
			return ErrPINFail
		}
		return err
	}

	if err := data.writeToFileAtomic(path); err != nil {
		return xerrors.Errorf("cannot write key data file: %v", err)
	}

	return nil
}
