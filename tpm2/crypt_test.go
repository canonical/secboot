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

package tpm2_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/canonical/go-tpm2"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	"golang.org/x/xerrors"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	. "github.com/snapcore/secboot/tpm2"
)

type cryptTPMSimulatorSuite struct {
	testutil.TPMSimulatorTestBase

	passwordFile string // a newline delimited list of passwords for the mock systemd-ask-password to return

	mockKeyslotsDir        string
	mockKeyslotsCount      int
	mockLUKS2ActivateCalls []struct {
		volumeName       string
		sourceDevicePath string
	}

	mockActivateVolumeWithRecoveryKeyCalls []string

	keyFile        string
	authPrivateKey PolicyAuthKey

	recoveryKey secboot.RecoveryKey

	mockSdAskPassword *snapd_testutil.MockCmd
}

var _ = Suite(&cryptTPMSimulatorSuite{})

func (s *cryptTPMSimulatorSuite) SetUpTest(c *C) {
	s.TPMSimulatorTestBase.SetUpTest(c)

	dir := c.MkDir()
	s.passwordFile = filepath.Join(dir, "password") // passwords to be returned by the mock sd-ask-password

	s.mockKeyslotsCount = 0
	s.mockKeyslotsDir = c.MkDir()

	activateFn := func(volumeName, sourceDevicePath string, key []byte) error {
		s.mockLUKS2ActivateCalls = append(s.mockLUKS2ActivateCalls, struct {
			volumeName       string
			sourceDevicePath string
		}{volumeName, sourceDevicePath})

		f, err := os.Open(s.mockKeyslotsDir)
		if err != nil {
			return err
		}
		defer f.Close()

		slots, err := f.Readdir(0)
		if err != nil {
			return err
		}

		for _, slot := range slots {
			k, err := ioutil.ReadFile(filepath.Join(s.mockKeyslotsDir, slot.Name()))
			if err != nil {
				return err
			}
			if bytes.Equal(k, key) {
				return nil
			}
		}

		return errors.New("systemd-cryptsetup failed with: exit status 1")
	}

	s.mockLUKS2ActivateCalls = nil
	s.AddCleanup(MockLUKS2Activate(activateFn))

	s.mockActivateVolumeWithRecoveryKeyCalls = nil
	s.AddCleanup(MockActivateVolumeWithRecoveryKey(func(volumeName, sourceDevicePath string, keyReader io.Reader, options *secboot.ActivateVolumeOptions) error {
		s.mockActivateVolumeWithRecoveryKeyCalls = append(s.mockActivateVolumeWithRecoveryKeyCalls, options.KeyringPrefix)

		if options.RecoveryKeyTries <= 0 {
			return errors.New("no recovery key tries permitted")
		}

		var lastErr error

		for i := 0; i < options.RecoveryKeyTries; i++ {
			lastErr = nil

			cmd := exec.Command("systemd-ask-password",
				"--icon", "drive-harddisk",
				"--id", filepath.Base(os.Args[0])+":"+sourceDevicePath,
				"Please enter the recovery key for disk "+sourceDevicePath+":")
			var out bytes.Buffer
			cmd.Stdout = &out
			if err := cmd.Run(); err != nil {
				return err
			}
			pw, err := out.ReadString('\n')
			if err != nil {
				return fmt.Errorf("cannot read result from systemd-ask-password: %v", err)
			}

			key, err := secboot.ParseRecoveryKey(strings.TrimRight(pw, "\n"))
			if err != nil {
				lastErr = xerrors.Errorf("cannot decode recovery key: %w", err)
				continue
			}

			if err := activateFn(volumeName, sourceDevicePath, key[:]); err != nil {
				lastErr = xerrors.Errorf("cannot activate volume: %w", err)
				continue
			}

			break
		}

		return lastErr
	}))

	c.Assert(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	s.ResetTPMSimulator(c)

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

	sdAskPasswordBottom := `
head -1 %[1]s
sed -i -e '1,1d' %[1]s
`
	s.mockSdAskPassword = snapd_testutil.MockCommand(c, "systemd-ask-password", fmt.Sprintf(sdAskPasswordBottom, s.passwordFile))
	s.AddCleanup(s.mockSdAskPassword.Restore)

	// Some tests may increment the DA lockout counter
	s.AddCleanup(func() {
		c.Check(s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil), IsNil)
	})
}

func (s *cryptTPMSimulatorSuite) addMockKeyslot(c *C, key []byte) {
	c.Assert(ioutil.WriteFile(filepath.Join(s.mockKeyslotsDir, fmt.Sprintf("%d", s.mockKeyslotsCount)), key, 0644), IsNil)
	s.mockKeyslotsCount++
}

func (s *cryptTPMSimulatorSuite) removeMockKeyslot(c *C, n int) {
	c.Assert(os.Remove(filepath.Join(s.mockKeyslotsDir, fmt.Sprintf("%d", n))), IsNil)
}

func (s *cryptTPMSimulatorSuite) newPrimaryKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func (s *cryptTPMSimulatorSuite) newRecoveryKey() secboot.RecoveryKey {
	var key secboot.RecoveryKey
	rand.Read(key[:])
	return key
}

func (s *cryptTPMSimulatorSuite) addTryPassphrases(c *C, passphrases []string) {
	for _, passphrase := range passphrases {
		f, err := os.OpenFile(s.passwordFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		c.Assert(err, IsNil)
		_, err = f.WriteString(passphrase + "\n")
		c.Check(err, IsNil)
		f.Close()
	}
}

type testActivateVolumeWithMultipleSealedKeysData struct {
	volumeName       string
	sourceDevicePath string
	keyFiles         []string
	recoveryKeyTries int
	keyringPrefix    string
	activateTries    int
	authPrivateKey   PolicyAuthKey
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithMultipleSealedKeys(c *C, data *testActivateVolumeWithMultipleSealedKeysData) {
	options := secboot.ActivateVolumeOptions{
		RecoveryKeyTries: data.recoveryKeyTries,
		KeyringPrefix:    data.keyringPrefix}
	success, err := ActivateVolumeWithMultipleSealedKeys(s.TPM, data.volumeName, data.sourceDevicePath, data.keyFiles, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(s.mockLUKS2ActivateCalls, HasLen, data.activateTries)
	for _, call := range s.mockLUKS2ActivateCalls {
		c.Check(call.volumeName, Equals, data.volumeName)
		c.Check(call.sourceDevicePath, Equals, data.sourceDevicePath)
	}
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeys1(c *C) {
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleSealedKeys(c, &testActivateVolumeWithMultipleSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{s.keyFile, keyFile},
		activateTries:    1,
		authPrivateKey:   s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeys2(c *C) {
	// Test with a different volumeName / sourceDevicePath
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleSealedKeys(c, &testActivateVolumeWithMultipleSealedKeysData{
		volumeName:       "foo",
		sourceDevicePath: "/dev/vda2",
		keyFiles:         []string{s.keyFile, keyFile},
		activateTries:    1,
		authPrivateKey:   s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeys3(c *C) {
	// Test with the key files switched around - should still activate with the first key.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	authPrivateKey, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleSealedKeys(c, &testActivateVolumeWithMultipleSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{keyFile, s.keyFile},
		activateTries:    1,
		authPrivateKey:   authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeys4(c *C) {
	// Test that ActivateVolumeWithSealedKey creates a SRK when it can, rather than fallback back to the recovery key.
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

	s.testActivateVolumeWithMultipleSealedKeys(c, &testActivateVolumeWithMultipleSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{s.keyFile, keyFile},
		activateTries:    1,
		authPrivateKey:   s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeys5(c *C) {
	// Test with 1 invalid and 1 valid key, with the invalid key being tried first.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	pcrProfile := NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).ExtendPCR(tpm2.HashAlgorithmSHA256, 7, make([]byte, 32))
	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleSealedKeys(c, &testActivateVolumeWithMultipleSealedKeysData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyFiles:         []string{keyFile, s.keyFile},
		activateTries:    1,
		authPrivateKey:   s.authPrivateKey})
}

type testActivateVolumeWithMultipleSealedKeysErrorHandlingData struct {
	keyFiles         []string
	recoveryKeyTries int
	keyringPrefix    string
	passphrases      []string
	activateTries    int
	success          bool
	errChecker       Checker
	errCheckerArgs   []interface{}
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithMultipleSealedKeysErrorHandling(c *C, data *testActivateVolumeWithMultipleSealedKeysErrorHandlingData) {
	s.addTryPassphrases(c, data.passphrases)

	options := secboot.ActivateVolumeOptions{
		RecoveryKeyTries: data.recoveryKeyTries,
		KeyringPrefix:    data.keyringPrefix}
	success, err := ActivateVolumeWithMultipleSealedKeys(s.TPM, "data", "/dev/sda1", data.keyFiles, &options)
	c.Check(err, data.errChecker, data.errCheckerArgs...)
	c.Check(success, Equals, data.success)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.passphrases))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the recovery key for disk /dev/sda1:"})
	}

	c.Assert(s.mockLUKS2ActivateCalls, HasLen, data.activateTries)
	for _, call := range s.mockLUKS2ActivateCalls {
		c.Check(call.volumeName, Equals, "data")
		c.Check(call.sourceDevicePath, Equals, "/dev/sda1")
	}

	c.Check(s.mockActivateVolumeWithRecoveryKeyCalls, DeepEquals, []string{data.keyringPrefix})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeysErrorHandling1(c *C) {
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

	s.testActivateVolumeWithMultipleSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleSealedKeysErrorHandlingData{
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

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeysErrorHandling2(c *C) {
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

	s.testActivateVolumeWithMultipleSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleSealedKeysErrorHandlingData{
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

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeysErrorHandling3(c *C) {
	// Test that recovery fallback works when the unsealed key is incorrect.
	key := make([]byte, 64)
	rand.Read(key)

	incorrectKey := make([]byte, 32)
	rand.Read(incorrectKey)
	s.removeMockKeyslot(c, 0)
	s.addMockKeyslot(c, incorrectKey)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleSealedKeysErrorHandlingData{
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

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeysErrorHandling4(c *C) {
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

	s.testActivateVolumeWithMultipleSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleSealedKeysErrorHandlingData{
		keyFiles:   []string{s.keyFile, keyFile},
		errChecker: ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot unseal key: the TPM is in DA lockout mode" +
			"\n- .*/keydata2: cannot unseal key: the TPM is in DA lockout mode" +
			"\nand activation with recovery key failed: no recovery key tries permitted"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeysErrorHandling5(c *C) {
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

	s.testActivateVolumeWithMultipleSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleSealedKeysErrorHandlingData{
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

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeysErrorHandling7(c *C) {
	// Test that recovery fallback works when the sealed key authorization policies are wrong.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	_, err = s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleSealedKeysErrorHandlingData{
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

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleSealedKeysErrorHandling9(c *C) {
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

	s.testActivateVolumeWithMultipleSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleSealedKeysErrorHandlingData{
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

type testActivateVolumeWithSealedKeyNo2FAData struct {
	volumeName       string
	sourceDevicePath string
	recoveryKeyTries int
	keyringPrefix    string
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithSealedKeyNo2FA(c *C, data *testActivateVolumeWithSealedKeyNo2FAData) {
	options := secboot.ActivateVolumeOptions{
		RecoveryKeyTries: data.recoveryKeyTries,
		KeyringPrefix:    data.keyringPrefix}
	success, err := ActivateVolumeWithSealedKey(s.TPM, data.volumeName, data.sourceDevicePath, s.keyFile, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, 0)

	c.Assert(s.mockLUKS2ActivateCalls, HasLen, 1)
	c.Check(s.mockLUKS2ActivateCalls[0].volumeName, Equals, data.volumeName)
	c.Check(s.mockLUKS2ActivateCalls[0].sourceDevicePath, Equals, data.sourceDevicePath)
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyNo2FA1(c *C) {
	s.testActivateVolumeWithSealedKeyNo2FA(c, &testActivateVolumeWithSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyNo2FA2(c *C) {
	// Test with a non-zero PassphraseTries when a PIN isn't set.
	s.testActivateVolumeWithSealedKeyNo2FA(c, &testActivateVolumeWithSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyNo2FA3(c *C) {
	// Test with a non-zero RecoveryKeyTries.
	s.testActivateVolumeWithSealedKeyNo2FA(c, &testActivateVolumeWithSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		recoveryKeyTries: 1,
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyNo2FA4(c *C) {
	// Test with a different volume name / device path.
	s.testActivateVolumeWithSealedKeyNo2FA(c, &testActivateVolumeWithSealedKeyNo2FAData{
		volumeName:       "foo",
		sourceDevicePath: "/dev/vda2",
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyNo2FA5(c *C) {
	// Test that ActivateVolumeWithSealedKey creates a SRK when it can, rather than fallback back to the recovery key.
	srk, err := s.TPM.CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), srk, srk.Handle(), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithSealedKeyNo2FA(c, &testActivateVolumeWithSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyNo2FA6(c *C) {
	s.testActivateVolumeWithSealedKeyNo2FA(c, &testActivateVolumeWithSealedKeyNo2FAData{
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

	options := secboot.ActivateVolumeOptions{}
	success, err := ActivateVolumeWithSealedKey(s.TPM, "data", "/dev/sda1", keyFile, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, 0)

	c.Assert(s.mockLUKS2ActivateCalls, HasLen, 1)
	c.Check(s.mockLUKS2ActivateCalls[0].volumeName, Equals, "data")
	c.Check(s.mockLUKS2ActivateCalls[0].sourceDevicePath, Equals, "/dev/sda1")
}

type testActivateVolumeWithSealedKeyErrorHandlingData struct {
	recoveryKeyTries int
	keyringPrefix    string
	passphrases      []string
	activateTries    int
	success          bool
	errChecker       Checker
	errCheckerArgs   []interface{}
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithSealedKeyErrorHandling(c *C, data *testActivateVolumeWithSealedKeyErrorHandlingData) {
	s.addTryPassphrases(c, data.passphrases)

	options := secboot.ActivateVolumeOptions{
		RecoveryKeyTries: data.recoveryKeyTries,
		KeyringPrefix:    data.keyringPrefix}
	success, err := ActivateVolumeWithSealedKey(s.TPM, "data", "/dev/sda1", s.keyFile, &options)
	c.Check(err, data.errChecker, data.errCheckerArgs...)
	c.Check(success, Equals, data.success)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.passphrases))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the recovery key for disk /dev/sda1:"})
	}

	c.Assert(s.mockLUKS2ActivateCalls, HasLen, data.activateTries)
	for _, call := range s.mockLUKS2ActivateCalls {
		c.Check(call.volumeName, Equals, "data")
		c.Check(call.sourceDevicePath, Equals, "/dev/sda1")
	}

	if data.recoveryKeyTries >= 0 {
		c.Check(s.mockActivateVolumeWithRecoveryKeyCalls, DeepEquals, []string{data.keyringPrefix})
	} else {
		c.Check(s.mockActivateVolumeWithRecoveryKeyCalls, DeepEquals, []string(nil))
	}
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyErrorHandling2(c *C) {
	// Test with an invalid value for RecoveryKeyTries.
	s.testActivateVolumeWithSealedKeyErrorHandling(c, &testActivateVolumeWithSealedKeyErrorHandlingData{
		recoveryKeyTries: -1,
		errChecker:       ErrorMatches,
		errCheckerArgs:   []interface{}{"invalid RecoveryKeyTries"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyErrorHandling3(c *C) {
	// Test that recovery fallback works with the TPM in DA lockout mode.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithSealedKeyErrorHandling(c, &testActivateVolumeWithSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    1,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyErrorHandling4(c *C) {
	// Test that recovery fallback works when there is no SRK and a new one can't be created.
	srk, err := s.TPM.CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), srk, srk.Handle(), nil)
	c.Assert(err, IsNil)
	s.SetHierarchyAuth(c, tpm2.HandleOwner)
	s.TPM.OwnerHandleContext().SetAuthValue(nil)
	defer s.TPM.OwnerHandleContext().SetAuthValue(testAuth)

	s.testActivateVolumeWithSealedKeyErrorHandling(c, &testActivateVolumeWithSealedKeyErrorHandlingData{
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

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyErrorHandling5(c *C) {
	// Test that recovery fallback works when the unsealed key is incorrect.
	incorrectKey := make([]byte, 32)
	rand.Read(incorrectKey)
	s.removeMockKeyslot(c, 0)
	s.addMockKeyslot(c, incorrectKey)

	s.testActivateVolumeWithSealedKeyErrorHandling(c, &testActivateVolumeWithSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateTries:    2,
		success:          true,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot activate volume: " +
			"systemd-cryptsetup failed with: exit status 1\\) but activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyErrorHandling6(c *C) {
	// Test that activation fails if RecoveryKeyTries is zero.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithSealedKeyErrorHandling(c, &testActivateVolumeWithSealedKeyErrorHandlingData{
		success:    false,
		errChecker: ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) " +
			"and activation with recovery key failed \\(no recovery key tries permitted\\)"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyErrorHandling7(c *C) {
	// Test that activation fails if the wrong recovery key is provided.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithSealedKeyErrorHandling(c, &testActivateVolumeWithSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		activateTries:    1,
		success:          false,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) " +
			"and activation with recovery key failed \\(cannot activate volume: systemd-cryptsetup failed with: exit status 1\\)"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyErrorHandling10(c *C) {
	// Test that recovery fallback works when the sealed key authorization policy is wrong.
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithSealedKeyErrorHandling(c, &testActivateVolumeWithSealedKeyErrorHandlingData{
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

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithSealedKeyErrorHandling11(c *C) {
	// Test that recovery fallback works when the sealed key authorization policy is wrong, and make sure that
	// the recovery key is added to the keyring with our specified prefix
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithSealedKeyErrorHandling(c, &testActivateVolumeWithSealedKeyErrorHandlingData{
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
