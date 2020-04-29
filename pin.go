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
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot/internal/tcg"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const (
	minArgon2TimeCost   = 4
	minArgon2MemoryCost = 32 * 1024
)

func timeArgon2Execution(password, salt []byte, timeCost, memoryCost uint32, threads uint8, keyLen uint32, iterations int, targetDuration time.Duration) time.Duration {
	var minDuration time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		_ = argon2.Key(password, salt, timeCost, memoryCost, threads, keyLen)
		duration := time.Now().Sub(start)

		runtime.GC()

		if i == 0 {
			minDuration = duration
		}
		if duration < minDuration {
			minDuration = duration
		}
		if minDuration < targetDuration {
			break
		}
	}

	return minDuration
}

func computeNextArgon2Params(maxMemoryCost uint32, targetDuration, duration time.Duration, timeCost, memoryCost uint32) (newTimeCost uint32, newMemoryCost uint32, done bool) {
	newTimeCost = timeCost
	newMemoryCost = memoryCost

	switch {
	case duration < targetDuration:
		switch {
		case memoryCost < maxMemoryCost:
			newMemoryCost = uint32((int64(memoryCost) * int64(targetDuration)) / int64(duration))
			if newMemoryCost > maxMemoryCost {
				newMemoryCost = maxMemoryCost
				newTimeCost = uint32((int64(timeCost*memoryCost) * int64(targetDuration)) / (int64(duration) * int64(maxMemoryCost)))
			}
		default:
			newTimeCost = uint32((int64(timeCost) * int64(targetDuration)) / int64(duration))
		}
	case duration > targetDuration:
		switch {
		case timeCost > minArgon2TimeCost:
			newTimeCost = uint32((int64(timeCost) * int64(targetDuration)) / int64(duration))
			if newTimeCost < minArgon2TimeCost {
				newTimeCost = minArgon2TimeCost
				newMemoryCost = uint32((int64(memoryCost*timeCost) * int64(targetDuration)) / (int64(duration) * minArgon2TimeCost))
				if newMemoryCost < minArgon2MemoryCost {
					newMemoryCost = minArgon2MemoryCost
					done = true
				}
			}
		default:
			newMemoryCost = uint32((int64(memoryCost) * int64(targetDuration)) / int64(duration))
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

func benchmarkArgon2(password, salt []byte, threads uint8, keyLen, maxMemoryCost uint32, targetDuration time.Duration) (timeCost uint32, memoryCost uint32) {
	const (
		initialTargetDuration = 250 * time.Millisecond
		tolerance             = 0.05
	)

	timeCost = minArgon2TimeCost
	memoryCost = minArgon2MemoryCost
	var duration time.Duration

	for i := 0; duration < initialTargetDuration; i++ {
		if i > 0 {
			if duration < 25*time.Millisecond {
				duration = 25 * time.Millisecond
			}
			var done bool
			timeCost, memoryCost, done = computeNextArgon2Params(maxMemoryCost, initialTargetDuration, duration, timeCost, memoryCost)
			if done {
				break
			}
		}

		duration = timeArgon2Execution(password, salt, timeCost, memoryCost, threads, keyLen, 3, initialTargetDuration)
	}

	minTargetDuration := targetDuration - time.Duration(float64(targetDuration)*tolerance)
	maxTargetDuration := targetDuration + time.Duration(float64(targetDuration)*tolerance)
	for duration < minTargetDuration || duration > maxTargetDuration {
		var done bool
		timeCost, memoryCost, done = computeNextArgon2Params(maxMemoryCost, targetDuration, duration, timeCost, memoryCost)
		if done {
			break
		}

		duration = timeArgon2Execution(password, salt, timeCost, memoryCost, threads, keyLen, 1, minTargetDuration)
	}

	return
}

type pinDataRaw struct {
	EncryptedIK    []byte
	IKIV           []byte
	ArgonVersion   byte
	Salt           []byte
	Time           uint32
	Memory         uint32
	Threads        uint8
	DerivedKeySize uint32
}

func (d *pinDataRaw) data() *pinData {
	return &pinData{
		encryptedIK: encryptedIK{
			data: d.EncryptedIK,
			iv:   d.IKIV},
		argonVersion:   d.ArgonVersion,
		salt:           d.Salt,
		time:           d.Time,
		memory:         d.Memory,
		threads:        d.Threads,
		derivedKeySize: d.DerivedKeySize}
}

func makePinDataRaw(d *pinData) *pinDataRaw {
	if d == nil {
		return nil
	}
	return &pinDataRaw{
		EncryptedIK:    d.encryptedIK.data,
		IKIV:           d.encryptedIK.iv,
		ArgonVersion:   d.argonVersion,
		Salt:           d.salt,
		Time:           d.time,
		Memory:         d.memory,
		Threads:        d.threads,
		DerivedKeySize: d.derivedKeySize}
}

type encryptedIK struct {
	data []byte
	iv   []byte
}

func (e encryptedIK) decrypt(key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, xerrors.Errorf("cannot create block cipher: %w", err)
	}
	if len(e.iv) != c.BlockSize() {
		return nil, errors.New("invalid IV length")
	}
	if len(e.data) != ikLength {
		return nil, errors.New("invalid data length")
	}
	b := cipher.NewCBCDecrypter(c, e.iv)
	out := make([]byte, ikLength)
	b.CryptBlocks(out, e.data)
	return out, nil
}

func (e encryptedIK) validate() error {
	if len(e.iv) != aes.BlockSize {
		return errors.New("invalid IV length")
	}
	if len(e.data) != ikLength {
		return errors.New("invalid intermediate key length")
	}
	return nil
}

type pinData struct {
	encryptedIK    encryptedIK
	argonVersion   byte
	salt           []byte
	time           uint32
	memory         uint32
	threads        uint8
	derivedKeySize uint32
}

func (d *pinData) Marshal(w io.Writer) (int, error) {
	panic("cannot be marshalled")
}

func (d *pinData) Unmarshal(r io.Reader) (int, error) {
	panic("cannot be unmarshalled")
}

func (d *pinData) decryptIKAndObtainTPMAuthValue(pin string, tpmAuthValueSz int) ([]byte, []byte, error) {
	if d.time == 0 || d.threads == 0 || d.derivedKeySize == 0 {
		return nil, nil, errors.New("invalid argon2 parameters")
	}
	derivedKey := argon2.Key([]byte(pin), d.salt, d.time, d.memory, d.threads, d.derivedKeySize+uint32(tpmAuthValueSz))
	ik, err := d.encryptedIK.decrypt(derivedKey[0:d.derivedKeySize])
	if err != nil {
		return nil, nil, err
	}

	return ik, derivedKey[d.derivedKeySize:], nil
}

func (d *pinData) validate() error {
	if d.time == 0 || d.threads == 0 || d.derivedKeySize == 0 {
		return errors.New("invalid argon2 parameters")
	}
	return d.encryptedIK.validate()
}

func encryptIKAndComputeTPMAuthValue(params *PINParams, ik []byte, auth string, tpmAuthValueSz int) (*pinData, []byte, error) {
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

	timeCost, memoryCost := benchmarkArgon2([]byte("foo"), []byte("0123456789abcdefghijklmnopqrstuv"), threads,
		derivedKeySize+uint32(tpmAuthValueSz), maxMemoryCost, params.TimeCost)

	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, nil, xerrors.Errorf("cannot create new salt: %w", err)
	}

	var iv [aes.BlockSize]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return nil, nil, xerrors.Errorf("cannot create new IV: %w", err)
	}

	derivedKey := argon2.Key([]byte(auth), salt[:], timeCost, memoryCost, threads, derivedKeySize+uint32(tpmAuthValueSz))
	runtime.GC()

	c, err := aes.NewCipher(derivedKey[0:derivedKeySize])
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create block cipher: %w", err)
	}
	b := cipher.NewCBCEncrypter(c, iv[:])

	ikEnc := make([]byte, len(ik))
	b.CryptBlocks(ikEnc, ik)

	return &pinData{
		encryptedIK: encryptedIK{
			data: ikEnc,
			iv:   iv[:]},
		argonVersion:   argon2.Version,
		salt:           salt[:],
		time:           timeCost,
		memory:         memoryCost,
		threads:        threads,
		derivedKeySize: derivedKeySize}, derivedKey[derivedKeySize:], nil
}

// computeV0PinNVIndexPostInitAuthPolicies computes the authorization policy digests associated with the post-initialization
// actions on a NV index created with the removed createPinNVIndex for version 0 key files. These are:
func computeV0PinNVIndexPostInitAuthPolicies(alg tpm2.HashAlgorithmId, updateKeyName tpm2.Name) (tpm2.DigestList, error) {
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

// performPinChangeV0 changes the authorization value of the dynamic authorization policy counter associated with the public
// argument, for PIN integration in version 0 key files. This requires the authorization policy digests initially returned from
// (the now removed) createPinNVIndex function in order to execute the policy session required to change the authorization value.
// The current authorization value must be provided via the oldAuth argument.
//
// On success, the authorization value of the counter will be changed to newAuth.
func performPinChangeV0(tpm *tpm2.TPMContext, public *tpm2.NVPublic, authPolicies tpm2.DigestList, oldPIN, newPIN string, hmacSession tpm2.SessionContext) error {
	index, err := tpm2.CreateNVIndexResourceContextFromPublic(public)
	if err != nil {
		return xerrors.Errorf("cannot create resource context for NV index: %w", err)
	}
	index.SetAuthValue([]byte(oldPIN))

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

	if err := tpm.NVChangeAuth(index, []byte(newPIN), policySession, hmacSession.IncludeAttrs(tpm2.AttrCommandEncrypt)); err != nil {
		return xerrors.Errorf("cannot change authorization value for NV index: %w", err)
	}

	return nil
}

// performTPMPinChange changes the authorization value of the sealed key object associated with keyPrivate and keyPublic, for PIN
// integration in current key files. The sealed key file must be created without the AttrAdminWithPolicy attribute. The current
// authorization value must be provided via the oldAuth argument.
//
// On success, a new private area will be returned for the sealed key object, containing the new PIN.
func performTPMPinChange(tpm *tpm2.TPMContext, keyPrivate tpm2.Private, keyPublic *tpm2.Public, oldAuth, newAuth []byte, session tpm2.SessionContext) (tpm2.Private, error) {
	srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	key, err := tpm.Load(srk, keyPrivate, keyPublic, session)
	if err != nil {
		return nil, xerrors.Errorf("cannot load sealed key object in to TPM: %w", err)
	}
	defer tpm.FlushContext(key)

	key.SetAuthValue(oldAuth)

	newKeyPrivate, err := tpm.ObjectChangeAuth(key, srk, newAuth, session.IncludeAttrs(tpm2.AttrCommandEncrypt))
	if err != nil {
		return nil, xerrors.Errorf("cannot change sealed key object authorization value: %w", err)
	}

	return newKeyPrivate, nil
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
//
// Depending on the value of params.PINParams, this function can be memory intensive and can run multiple garbage collections
// before completing.
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
	data, _, pcrPolicyCounterPub, err := decodeAndValidateKeyData(tpm.TPMContext, keyFile, nil, tpm.HmacSession())
	if err != nil {
		if isKeyFileError(err) {
			return InvalidKeyFileError{err.Error()}
		}
		return xerrors.Errorf("cannot read and validate key data file: %w", err)
	}

	var newAuthModeHint AuthMode
	if newPIN == "" {
		newAuthModeHint = AuthModeNone
	} else {
		newAuthModeHint = AuthModePIN
	}

	// Change the PIN
	if data.version == 0 {
		if err := performPinChangeV0(tpm.TPMContext, pcrPolicyCounterPub, data.staticPolicyData.v0PinIndexAuthPolicies, oldPIN, newPIN, tpm.HmacSession()); err != nil {
			if isAuthFailError(err, tpm2.CommandNVChangeAuth, 1) {
				return ErrPINFail
			}
			return err
		}
	} else {
		var ik []byte
		var oldTpmAuthValue []byte
		if data.authModeHint == AuthModeNone {
			ik = data.unprotectedIK
		} else {
			var err error
			ik, oldTpmAuthValue, err = data.pinData.decryptIKAndObtainTPMAuthValue(oldPIN, data.sealedKey.public.NameAlg.Size())
			if err != nil {
				return err
			}
			runtime.GC()
		}

		var newTpmAuthValue []byte
		if newAuthModeHint == AuthModeNone {
			data.unprotectedIK = ik
			data.pinData = nil
		} else {
			data.unprotectedIK = nil
			pd, authValue, err := encryptIKAndComputeTPMAuthValue(params, ik, newPIN, data.sealedKey.public.NameAlg.Size())
			if err != nil {
				return xerrors.Errorf("cannot encrypt intermediate key with new PIN: %w", err)
			}
			newTpmAuthValue = authValue
			data.pinData = pd
		}

		sealedKey := data.sealedKey
		newKeyPrivate, err := performTPMPinChange(tpm.TPMContext, sealedKey.private, sealedKey.public, oldTpmAuthValue, newTpmAuthValue,
			tpm.HmacSession())
		if err != nil {
			if isAuthFailError(err, tpm2.CommandObjectChangeAuth, 1) {
				return ErrPINFail
			}
			return err
		}
		data.sealedKey.private = newKeyPrivate
	}

	// Update the metadata and write a new key data file
	origAuthModeHint := data.authModeHint
	data.authModeHint = newAuthModeHint

	if origAuthModeHint == data.authModeHint && data.version == 0 {
		return nil
	}

	if err := data.writeToFileAtomic(path); err != nil {
		return xerrors.Errorf("cannot write key data file: %v", err)
	}

	return nil
}
