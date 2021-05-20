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

package secboot_test

import (
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type cryptTPMSimulatorSuite struct {
	testutil.TPMSimulatorTestBase
	cryptTestBase

	recoveryKey RecoveryKey

	keyFile        string
	authPrivateKey TPMPolicyAuthKey
}

var _ = Suite(&cryptTPMSimulatorSuite{})

func (s *cryptTPMSimulatorSuite) AddCleanup(f func()) {
	s.TPMSimulatorTestBase.AddCleanup(f)
}

func (s *cryptTPMSimulatorSuite) SetUpSuite(c *C) {
	s.cryptTestBase.SetUpSuite(c)
}

func (s *cryptTPMSimulatorSuite) SetUpTest(c *C) {
	s.TPMSimulatorTestBase.SetUpTest(c)
	s.cryptTestBase.SetUpTest(c)

	c.Assert(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	s.ResetTPMSimulator(c)

	dir := c.MkDir()
	s.keyFile = dir + "/keydata"

	primaryKey := s.newPrimaryKey()

	pcrPolicyCounterHandle := tpm2.Handle(0x0181fff0)
	authPrivateKey, err := SealKeyToTPM(s.TPM, primaryKey, s.keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: pcrPolicyCounterHandle})
	c.Assert(err, IsNil)
	s.authPrivateKey = authPrivateKey
	pcrPolicyCounter, err := s.TPM.CreateResourceContextFromTPM(pcrPolicyCounterHandle)
	c.Assert(err, IsNil)
	s.AddCleanupNVSpace(c, s.TPM.OwnerHandleContext(), pcrPolicyCounter)

	s.addMockKeyslot(c, primaryKey)

	s.recoveryKey = s.newRecoveryKey()
	s.addMockKeyslot(c, s.recoveryKey[:])

	// Some tests may increment the DA lockout counter
	s.AddCleanup(func() {
		c.Check(s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil), IsNil)
	})
}

func (s *cryptTPMSimulatorSuite) TearDownTest(c *C) {
	s.cryptTestBase.TearDownTest(c)
	s.TPMSimulatorTestBase.TearDownTest(c)
}

type testActivateVolumeWithMultipleTPMSealedKeysData struct {
	volumeName       string
	sourceDevicePath string
	keyFiles         []string
	pinTries         int
	recoveryKeyTries int
	keyringPrefix    string
	activateTries    int
	pins             []string
	authPrivateKey   TPMPolicyAuthKey
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithMultipleTPMSealedKeys(c *C, data *testActivateVolumeWithMultipleTPMSealedKeysData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.pins, "\n")+"\n"), 0644), IsNil)

	options := ActivateVolumeOptions{
		PassphraseTries:  data.pinTries,
		RecoveryKeyTries: data.recoveryKeyTries,
		KeyringPrefix:    data.keyringPrefix}
	success, err := ActivateVolumeWithMultipleTPMSealedKeys(s.TPM, data.volumeName, data.sourceDevicePath, data.keyFiles, nil, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, len(data.pins))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":" + data.sourceDevicePath, "Please enter the PIN for disk " + data.sourceDevicePath + ":"})
	}

	c.Check(s.mockLUKS2ActivateCalls, HasLen, data.activateTries)
	for _, call := range s.mockLUKS2ActivateCalls {
		c.Check(call.volumeName, Equals, data.volumeName)
		c.Check(call.sourceDevicePath, Equals, data.sourceDevicePath)
	}
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys1(c *C) {
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{s.keyFile, keyFile},
		activateTries:    1,
		authPrivateKey:   s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys2(c *C) {
	// Test with a different volumeName / sourceDevicePath
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:       "foo",
		sourceDevicePath: "/dev/vda2",
		keyFiles:         []string{s.keyFile, keyFile},
		activateTries:    1,
		authPrivateKey:   s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys3(c *C) {
	// Test with the key files switched around - should still activate with the first key.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	authPrivateKey, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{keyFile, s.keyFile},
		activateTries:    1,
		authPrivateKey:   authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys4(c *C) {
	// Test that ActivateVolumeWithTPMSealedKey creates a SRK when it can, rather than fallback back to the recovery key.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	srk, err := s.TPM.CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), srk, srk.Handle(), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{s.keyFile, keyFile},
		activateTries:    1,
		authPrivateKey:   s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys5(c *C) {
	// Test with 1 invalid and 1 valid key, with the invalid key being tried first.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	pcrProfile := NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).ExtendPCR(tpm2.HashAlgorithmSHA256, 7, make([]byte, 32))
	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{keyFile, s.keyFile},
		activateTries:    1,
		authPrivateKey:   s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys6(c *C) {
	// Test with 2 keys, with 1 requiring a passphrase. Should activate with the key not
	// requiring a passphrase, regardless of key order.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)
	c.Assert(ChangePIN(s.TPM, keyFile, "", "1234"), IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{keyFile, s.keyFile},
		activateTries:    1,
		authPrivateKey:   s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys7(c *C) {
	// Test with 2 keys that both require a passhprase
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)
	c.Assert(ChangePIN(s.TPM, keyFile, "", "1234"), IsNil)
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", "1234"), IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{s.keyFile, keyFile},
		pinTries:         1,
		activateTries:    1,
		pins:             []string{"1234"},
		authPrivateKey:   s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys8(c *C) {
	// Test with 2 keys that both require a passhprase, with only 1 passphrase attempt per
	// key permitted and the first attempt being incorrect (should activate with second key).
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	authPrivateKey, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)
	c.Assert(ChangePIN(s.TPM, keyFile, "", "1234"), IsNil)
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", "1234"), IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{s.keyFile, keyFile},
		pinTries:         1,
		activateTries:    1,
		pins:             []string{"foo", "1234"},
		authPrivateKey:   authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys9(c *C) {
	// Test with 2 keys that both require a passhprase, with 2 passphrase attempts per
	// key permitted and the first attempt being incorrect (should activate with first key).
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)
	c.Assert(ChangePIN(s.TPM, keyFile, "", "1234"), IsNil)
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", "1234"), IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{s.keyFile, keyFile},
		pinTries:         2,
		activateTries:    1,
		pins:             []string{"foo", "1234"},
		authPrivateKey:   s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys10(c *C) {
	// Test with 2 keys - 1 invalid that doesn't require a passphrase, and 1 valid that
	// does require a passphrase. Should activate successfully regardless of key order.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	pcrProfile := NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).ExtendPCR(tpm2.HashAlgorithmSHA256, 7, make([]byte, 32))
	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", "1234"), IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{keyFile, s.keyFile},
		pinTries:         1,
		activateTries:    1,
		pins:             []string{"1234"},
		authPrivateKey:   s.authPrivateKey})
}

type testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData struct {
	keyFiles         []string
	pinTries         int
	recoveryKeyTries int
	keyringPrefix    string
	passphrases      []string
	activateTries    int
	success          bool
	errChecker       Checker
	errCheckerArgs   []interface{}
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c *C, data *testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData) {
	s.addTryPassphrases(c, data.passphrases)

	options := ActivateVolumeOptions{
		PassphraseTries:  data.pinTries,
		RecoveryKeyTries: data.recoveryKeyTries,
		KeyringPrefix:    data.keyringPrefix}
	success, err := ActivateVolumeWithMultipleTPMSealedKeys(s.TPM, "data", "/dev/sda1", data.keyFiles, nil, &options)
	c.Check(err, data.errChecker, data.errCheckerArgs...)
	c.Check(success, Equals, data.success)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.passphrases))
	for i, call := range s.mockSdAskPassword.Calls() {
		passphraseType := "PIN"
		if i >= data.pinTries {
			passphraseType = "recovery key"
		}
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the " + passphraseType + " for disk /dev/sda1:"})
	}

	c.Assert(s.mockLUKS2ActivateCalls, HasLen, data.activateTries)
	for _, call := range s.mockLUKS2ActivateCalls {
		c.Check(call.volumeName, Equals, "data")
		c.Check(call.sourceDevicePath, Equals, "/dev/sda1")
	}

	if !data.success {
		return
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyInKeyring(c, data.keyringPrefix, "/dev/sda1", s.recoveryKey)
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeysErrorHandling1(c *C) {
	// Test that recovery fallback works with the TPM in DA lockout mode.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData{
		keyFiles:         []string{s.keyFile, keyFile},
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    1,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot unseal key: the TPM is in DA lockout mode" +
			"\n- .*/keydata2: cannot unseal key: the TPM is in DA lockout mode" +
			"\nbut activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeysErrorHandling2(c *C) {
	// Test that recovery fallback works when there is no SRK and a new one can't be created.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	srk, err := s.TPM.CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), srk, srk.Handle(), nil)
	c.Assert(err, IsNil)
	s.SetHierarchyAuth(c, tpm2.HandleOwner)
	s.TPM.OwnerHandleContext().SetAuthValue(nil)
	defer s.TPM.OwnerHandleContext().SetAuthValue(testAuth)

	s.testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData{
		keyFiles:         []string{s.keyFile, keyFile},
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    1,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot unseal key: the TPM is not correctly provisioned" +
			"\n- .*/keydata2: cannot unseal key: the TPM is not correctly provisioned" +
			"\nbut activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeysErrorHandling3(c *C) {
	// Test that recovery fallback works when the unsealed key is incorrect.
	key := make([]byte, 64)
	rand.Read(key)

	incorrectKey := make([]byte, 32)
	rand.Read(incorrectKey)
	c.Assert(os.RemoveAll(filepath.Join(s.mockKeyslotsDir, "0")), IsNil)
	s.addMockKeyslot(c, incorrectKey)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData{
		keyFiles:         []string{s.keyFile, keyFile},
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    3,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot activate volume: systemd-cryptsetup failed with: exit status 1" +
			"\n- .*/keydata2: cannot activate volume: systemd-cryptsetup failed with: exit status 1" +
			"\nbut activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeysErrorHandling4(c *C) {
	// Test that activation fails if RecoveryKeyTries is zero.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData{
		keyFiles:   []string{s.keyFile, keyFile},
		errChecker: ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot unseal key: the TPM is in DA lockout mode" +
			"\n- .*/keydata2: cannot unseal key: the TPM is in DA lockout mode" +
			"\nand activation with recovery key failed: no recovery key tries permitted"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeysErrorHandling5(c *C) {
	// Test that activation fails if the wrong recovery key is supplied.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData{
		keyFiles:         []string{s.keyFile, keyFile},
		activateTries:    1,
		recoveryKeyTries: 1,
		passphrases:      []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot unseal key: the TPM is in DA lockout mode" +
			"\n- .*/keydata2: cannot unseal key: the TPM is in DA lockout mode" +
			"\nand activation with recovery key failed: " +
			"cannot activate volume: systemd-cryptsetup failed with: exit status 1"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeysErrorHandling6(c *C) {
	// Test that recovery fallback works when a passphrase is required for all keys, but
	// no passphrase attempts are permitted.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)
	c.Assert(ChangePIN(s.TPM, keyFile, "", "1234"), IsNil)
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", "1234"), IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData{
		keyFiles:         []string{s.keyFile, keyFile},
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    1,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: no PIN tries permitted when a PIN is required" +
			"\n- .*/keydata2: no PIN tries permitted when a PIN is required" +
			"\nbut activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeysErrorHandling7(c *C) {
	// Test that recovery fallback works when the sealed key authorization policies are wrong.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	_, err = s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData{
		keyFiles:         []string{s.keyFile, keyFile},
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    1,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot unseal key: invalid key data file: cannot complete authorization policy assertions: cannot " +
			"complete OR assertions: current session digest not found in policy data" +
			"\n- .*/keydata2: cannot unseal key: invalid key data file: cannot complete authorization policy assertions: cannot " +
			"complete OR assertions: current session digest not found in policy data" +
			"\nbut activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeysErrorHandling8(c *C) {
	// Test that recovery fallback works when one key has an invalid authorization policy, and
	// we supply the wrong passphrase to the second key.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	pcrProfile := NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).ExtendPCR(tpm2.HashAlgorithmSHA256, 7, make([]byte, 32))
	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	c.Assert(ChangePIN(s.TPM, s.keyFile, "", "1234"), IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData{
		keyFiles:         []string{s.keyFile, keyFile},
		pinTries:         1,
		recoveryKeyTries: 1,
		passphrases:      []string{"foo", s.recoveryKey.String()},
		activateTries:    1,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot unseal key: the provided PIN is incorrect" +
			"\n- .*/keydata2: cannot unseal key: invalid key data file: cannot complete authorization policy assertions: cannot " +
			"complete OR assertions: current session digest not found in policy data" +
			"\nbut activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeysErrorHandling9(c *C) {
	// Test that recovery fallback works with more than one attempt at providing the recovery key.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData{
		keyFiles:         []string{s.keyFile, keyFile},
		recoveryKeyTries: 2,
		passphrases: []string{
			"00000-00000-00000-00000-00000-00000-00000-00000",
			s.recoveryKey.String(),
		},
		activateTries: 2,
		success:       true,
		errChecker:    ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot unseal key: the TPM is in DA lockout mode" +
			"\n- .*/keydata2: cannot unseal key: the TPM is in DA lockout mode" +
			"\nbut activation with recovery key was successful"},
	})
}

type testActivateVolumeWithTPMSealedKeyNo2FAData struct {
	volumeName       string
	sourceDevicePath string
	pinTries         int
	recoveryKeyTries int
	keyringPrefix    string
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithTPMSealedKeyNo2FA(c *C, data *testActivateVolumeWithTPMSealedKeyNo2FAData) {
	options := ActivateVolumeOptions{
		PassphraseTries:  data.pinTries,
		RecoveryKeyTries: data.recoveryKeyTries,
		KeyringPrefix:    data.keyringPrefix}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, data.volumeName, data.sourceDevicePath, s.keyFile, nil, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, 0)

	c.Assert(s.mockLUKS2ActivateCalls, HasLen, 1)
	c.Check(s.mockLUKS2ActivateCalls[0].volumeName, Equals, data.volumeName)
	c.Check(s.mockLUKS2ActivateCalls[0].sourceDevicePath, Equals, data.sourceDevicePath)
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyNo2FA1(c *C) {
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyNo2FA2(c *C) {
	// Test with a non-zero PassphraseTries when a PIN isn't set.
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		pinTries:         1,
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyNo2FA3(c *C) {
	// Test with a non-zero RecoveryKeyTries.
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		recoveryKeyTries: 1,
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyNo2FA4(c *C) {
	// Test with a different volume name / device path.
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "foo",
		sourceDevicePath: "/dev/vda2",
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyNo2FA5(c *C) {
	// Test that ActivateVolumeWithTPMSealedKey creates a SRK when it can, rather than fallback back to the recovery key.
	srk, err := s.TPM.CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), srk, srk.Handle(), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyNo2FA6(c *C) {
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyringPrefix:    "test",
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyMissingCustomSRK(c *C) {
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
			tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	c.Assert(s.TPM.EnsureProvisionedWithCustomSRK(ProvisionModeFull, nil, &template), IsNil)

	dir := c.MkDir()
	keyFile := dir + "/keydata"

	primaryKey := s.newPrimaryKey()

	_, err := SealKeyToTPM(s.TPM, primaryKey, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.addMockKeyslot(c, primaryKey)

	srk, err := s.TPM.CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), srk, srk.Handle(), nil)
	c.Assert(err, IsNil)

	options := ActivateVolumeOptions{}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, "data", "/dev/sda1", keyFile, nil, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, 0)

	c.Assert(s.mockLUKS2ActivateCalls, HasLen, 1)
	c.Check(s.mockLUKS2ActivateCalls[0].volumeName, Equals, "data")
	c.Check(s.mockLUKS2ActivateCalls[0].sourceDevicePath, Equals, "/dev/sda1")
}

type testActivateVolumeWithTPMSealedKeyAndPINData struct {
	pins     []string
	pinTries int
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithTPMSealedKeyAndPIN(c *C, data *testActivateVolumeWithTPMSealedKeyAndPINData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.pins, "\n")+"\n"), 0644), IsNil)

	options := ActivateVolumeOptions{PassphraseTries: data.pinTries}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, "data", "/dev/sda1", s.keyFile, nil, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.pins))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the PIN for disk /dev/sda1:"})
	}

	c.Assert(s.mockLUKS2ActivateCalls, HasLen, 1)
	c.Check(s.mockLUKS2ActivateCalls[0].volumeName, Equals, "data")
	c.Check(s.mockLUKS2ActivateCalls[0].sourceDevicePath, Equals, "/dev/sda1")
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyAndPIN1(c *C) {
	// Test with a single PIN attempt.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)
	s.testActivateVolumeWithTPMSealedKeyAndPIN(c, &testActivateVolumeWithTPMSealedKeyAndPINData{
		pins:     []string{testPIN},
		pinTries: 1,
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyAndPIN2(c *C) {
	// Test with 2 PIN attempts.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)
	s.testActivateVolumeWithTPMSealedKeyAndPIN(c, &testActivateVolumeWithTPMSealedKeyAndPINData{
		pins:     []string{"", testPIN},
		pinTries: 2,
	})
}

type testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData struct {
	pins            []string
	pinFileContents string
	pinTries        int
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c *C, data *testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.pins, "\n")+"\n"), 0644), IsNil)
	c.Assert(ioutil.WriteFile(filepath.Join(s.dir, "pinfile"), []byte(data.pinFileContents), 0644), IsNil)

	r, err := os.Open(filepath.Join(s.dir, "pinfile"))
	c.Assert(err, IsNil)
	defer r.Close()

	options := ActivateVolumeOptions{PassphraseTries: data.pinTries}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, "data", "/dev/sda1", s.keyFile, r, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.pins))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the PIN for disk /dev/sda1:"})
	}

	c.Assert(s.mockLUKS2ActivateCalls, HasLen, 1)
	c.Check(s.mockLUKS2ActivateCalls[0].volumeName, Equals, "data")
	c.Check(s.mockLUKS2ActivateCalls[0].sourceDevicePath, Equals, "/dev/sda1")
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader1(c *C) {
	// Test with the correct PIN provided via the io.Reader.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pinFileContents: testPIN + "\n",
		pinTries:        1,
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader2(c *C) {
	// Test with the correct PIN provided via the io.Reader when the file doesn't end in a newline.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pinFileContents: testPIN,
		pinTries:        1,
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader3(c *C) {
	// Test falling back to asking for a PIN if the wrong PIN is provided via the io.Reader.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pins:            []string{testPIN},
		pinFileContents: "5678" + "\n",
		pinTries:        2,
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader4(c *C) {
	// Test falling back to asking for a PIN without using a try if the io.Reader has no contents.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pins:     []string{testPIN},
		pinTries: 1,
	})
}

type testActivateVolumeWithTPMSealedKeyErrorHandlingData struct {
	pinTries         int
	recoveryKeyTries int
	keyringPrefix    string
	passphrases      []string
	activateTries    int
	success          bool
	errChecker       Checker
	errCheckerArgs   []interface{}
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithTPMSealedKeyErrorHandling(c *C, data *testActivateVolumeWithTPMSealedKeyErrorHandlingData) {
	s.addTryPassphrases(c, data.passphrases)

	options := ActivateVolumeOptions{
		PassphraseTries:  data.pinTries,
		RecoveryKeyTries: data.recoveryKeyTries,
		KeyringPrefix:    data.keyringPrefix}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, "data", "/dev/sda1", s.keyFile, nil, &options)
	c.Check(err, data.errChecker, data.errCheckerArgs...)
	c.Check(success, Equals, data.success)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.passphrases))
	for i, call := range s.mockSdAskPassword.Calls() {
		passphraseType := "PIN"
		if i >= data.pinTries {
			passphraseType = "recovery key"
		}
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the " + passphraseType + " for disk /dev/sda1:"})
	}

	c.Assert(s.mockLUKS2ActivateCalls, HasLen, data.activateTries)
	for _, call := range s.mockLUKS2ActivateCalls {
		c.Check(call.volumeName, Equals, "data")
		c.Check(call.sourceDevicePath, Equals, "/dev/sda1")
	}

	if !data.success {
		return
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyInKeyring(c, data.keyringPrefix, "/dev/sda1", s.recoveryKey)
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling1(c *C) {
	// Test with an invalid value for PassphraseTries.
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		pinTries:       -1,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"invalid PassphraseTries"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling2(c *C) {
	// Test with an invalid value for RecoveryKeyTries.
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: -1,
		errChecker:       ErrorMatches,
		errCheckerArgs:   []interface{}{"invalid RecoveryKeyTries"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling3(c *C) {
	// Test that recovery fallback works with the TPM in DA lockout mode.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    1,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling4(c *C) {
	// Test that recovery fallback works when there is no SRK and a new one can't be created.
	srk, err := s.TPM.CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), srk, srk.Handle(), nil)
	c.Assert(err, IsNil)
	s.SetHierarchyAuth(c, tpm2.HandleOwner)
	s.TPM.OwnerHandleContext().SetAuthValue(nil)
	defer s.TPM.OwnerHandleContext().SetAuthValue(testAuth)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 2,
		passphrases: []string{
			"00000-00000-00000-00000-00000-00000-00000-00000",
			s.recoveryKey.String(),
		},
		activateTries: 2,
		success:       true,
		errChecker:    ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is not correctly " +
			"provisioned\\) but activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling5(c *C) {
	// Test that recovery fallback works when the unsealed key is incorrect.
	incorrectKey := make([]byte, 32)
	rand.Read(incorrectKey)
	c.Assert(os.RemoveAll(filepath.Join(s.mockKeyslotsDir, "0")), IsNil)
	s.addMockKeyslot(c, incorrectKey)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    2,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot activate volume: " +
			"systemd-cryptsetup failed with: exit status 1\\) but activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling6(c *C) {
	// Test that activation fails if RecoveryKeyTries is zero.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		success:    false,
		errChecker: ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) " +
			"and activation with recovery key failed \\(no recovery key tries permitted\\)"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling7(c *C) {
	// Test that activation fails if the wrong recovery key is provided.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		activateTries:    1,
		success:          false,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) " +
			"and activation with recovery key failed \\(cannot activate volume: systemd-cryptsetup failed with: exit status 1\\)"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling8(c *C) {
	// Test that recovery fallback works if the wrong PIN is supplied.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		pinTries:         1,
		recoveryKeyTries: 1,
		passphrases: []string{
			"",
			s.recoveryKey.String(),
		},
		activateTries: 1,
		success:       true,
		errChecker:    ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the provided PIN is incorrect\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling9(c *C) {
	// Test that recovery fallback works if a PIN is set but no PIN attempts are permitted.
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", "1234"), IsNil)
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    1,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(no PIN tries permitted when a PIN is required\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling10(c *C) {
	// Test that recovery fallback works when the sealed key authorization policy is wrong.
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    1,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: invalid key data file: cannot complete " +
			"authorization policy assertions: cannot complete OR assertions: current session digest not found in policy data\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling11(c *C) {
	// Test that recovery fallback works when the sealed key authorization policy is wrong, and make sure that
	// the recovery key is added to the keyring with our specified prefix
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		keyringPrefix:    "test",
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    1,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: invalid key data file: cannot complete " +
			"authorization policy assertions: cannot complete OR assertions: current session digest not found in policy data\\) but " +
			"activation with recovery key was successful"},
	})
}
