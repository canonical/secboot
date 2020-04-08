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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/chrisccoulson/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/snapd/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

const (
	sessionKeyring = -3
	userKeyring    = -4
)

func getKeyringKeys(c *C, keyringId int) (out []int) {
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyringId, nil, 0)
	c.Assert(err, IsNil)
	buf := make([]byte, n)
	_, err = unix.KeyctlBuffer(unix.KEYCTL_READ, keyringId, buf, 0)
	c.Assert(err, IsNil)

	for len(buf) > 0 {
		id := int(binary.LittleEndian.Uint32(buf[0:4]))
		buf = buf[4:]
		out = append(out, id)
	}
	return
}

type cryptTestBase struct {
	recoveryKey      []byte
	recoveryKeyAscii []string

	dir string

	passwordFile            string
	expectedTpmKeyFile      string
	expectedRecoveryKeyFile string

	mockSdAskPassword *testutil.MockCmd
	mockSdCryptsetup  *testutil.MockCmd

	possessesUserKeyringKeys bool
}

func (ctb *cryptTestBase) setUpSuiteBase(c *C) {
	ctb.recoveryKey = make([]byte, 16)
	rand.Read(ctb.recoveryKey)

	for i := 0; i < len(ctb.recoveryKey)/2; i++ {
		x := binary.LittleEndian.Uint16(ctb.recoveryKey[i*2:])
		ctb.recoveryKeyAscii = append(ctb.recoveryKeyAscii, fmt.Sprintf("%05d", x))
	}

	// These tests create keys in the user keyring that are only readable by a possessor. Reading these keys fails when running
	// the tests inside gnome-terminal in Ubuntu 18.04 because the gnome-terminal backend runs inside the systemd user session,
	// and inherits a private session keyring from the user session manager from which the user keyring isn't linked. This is
	// fixed in later releases by setting KeyringMode=inherit in /lib/systemd/system/user@.service, which causes the user
	// session manager to start without a session keyring attached (which the gnome-terminal backend inherits). In this case,
	// for the purposes of determing whether this process possesses a key, the kernel searches the user session keyring, from
	// which the user keyring is linked.
	userKeyringId, err := unix.KeyctlGetKeyringID(userKeyring, false)
	c.Assert(err, IsNil)
	keys := getKeyringKeys(c, sessionKeyring)
	for _, id := range keys {
		if id == userKeyringId {
			ctb.possessesUserKeyringKeys = true
			break
		}
	}
}

func (ctb *cryptTestBase) setUpTestBase(c *C, bt *testutil.BaseTest) {
	ctb.dir = c.MkDir()
	bt.AddCleanup(MockRunDir(ctb.dir))

	ctb.passwordFile = filepath.Join(ctb.dir, "password")
	ctb.expectedTpmKeyFile = filepath.Join(ctb.dir, "expectedtpmkey")
	ctb.expectedRecoveryKeyFile = filepath.Join(ctb.dir, "expectedrecoverykey")

	sdAskPasswordBottom := `
head -1 %[1]s
sed -i -e '1,1d' %[1]s
`
	ctb.mockSdAskPassword = testutil.MockCommand(c, "systemd-ask-password", fmt.Sprintf(sdAskPasswordBottom, ctb.passwordFile))
	bt.AddCleanup(ctb.mockSdAskPassword.Restore)

	sdCryptsetupBottom := `
if ! cmp -s "$4" "%[1]s"; then
	if ! cmp -s "$4" "%[2]s"; then
		exit 1
	fi
fi
`
	ctb.mockSdCryptsetup = testutil.MockCommand(c, c.MkDir()+"/systemd-cryptsetup", fmt.Sprintf(sdCryptsetupBottom, ctb.expectedTpmKeyFile, ctb.expectedRecoveryKeyFile))
	bt.AddCleanup(ctb.mockSdCryptsetup.Restore)
	bt.AddCleanup(MockSystemdCryptsetupPath(ctb.mockSdCryptsetup.Exe()))

	c.Assert(ioutil.WriteFile(ctb.expectedRecoveryKeyFile, ctb.recoveryKey, 0644), IsNil)

	startKeys := getKeyringKeys(c, userKeyring)

	bt.AddCleanup(func() {
		for kid := range getKeyringKeys(c, userKeyring) {
			found := false
			for skid := range startKeys {
				if skid == kid {
					found = true
					break
				}
			}
			if found {
				continue
			}
			_, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, kid, userKeyring, 0, 0)
			c.Check(err, IsNil)
		}
	})
}

func (ctb *cryptTestBase) checkRecoveryKeyKeyringEntry(c *C, reason RecoveryKeyUsageReason) {
	id, err := unix.KeyctlSearch(userKeyring, "user", fmt.Sprintf("%s:data:reason=%d", filepath.Base(os.Args[0]), reason), 0)
	c.Check(err, IsNil)

	// The previous tests should have all succeeded, but the following test will fail if the user keyring isn't reachable from
	// the session keyring.
	if !ctb.possessesUserKeyringKeys && !c.Failed() {
		c.ExpectFailure("Cannot possess user keys because the user keyring isn't reachable from the session keyring")
	}

	buf := make([]byte, 16)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
	c.Check(err, IsNil)
	c.Check(n, Equals, 16)
	c.Check(buf, DeepEquals, ctb.recoveryKey)
}

type cryptTPMTestBase struct {
	cryptTestBase

	tpmKey  []byte
	keyFile string
}

func (ctb *cryptTPMTestBase) setUpSuiteBase(c *C) {
	ctb.cryptTestBase.setUpSuiteBase(c)
	ctb.tpmKey = make([]byte, 32)
	rand.Read(ctb.tpmKey)
}

func (ctb *cryptTPMTestBase) setUpTestBase(c *C, ttb *tpmTestBase) {
	ctb.cryptTestBase.setUpTestBase(c, &ttb.BaseTest)

	c.Assert(ProvisionTPM(ttb.tpm, ProvisionModeFull, nil), IsNil)

	dir := c.MkDir()
	ctb.keyFile = dir + "/keydata"

	pinHandle := tpm2.Handle(0x0181fff0)
	c.Assert(SealKeyToTPM(ttb.tpm, ctb.tpmKey, ctb.keyFile, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PINHandle: pinHandle}), IsNil)
	pinIndex, err := ttb.tpm.CreateResourceContextFromTPM(pinHandle)
	c.Assert(err, IsNil)
	ttb.addCleanupNVSpace(c, ttb.tpm.OwnerHandleContext(), pinIndex)

	c.Assert(ioutil.WriteFile(ctb.expectedTpmKeyFile, ctb.tpmKey, 0644), IsNil)
}

type cryptTPMSuite struct {
	tpmTestBase
	cryptTPMTestBase
}

var _ = Suite(&cryptTPMSuite{})

func (s *cryptTPMSuite) SetUpSuite(c *C) {
	s.cryptTPMTestBase.setUpSuiteBase(c)
}

func (s *cryptTPMSuite) SetUpTest(c *C) {
	s.tpmTestBase.SetUpTest(c)
	s.cryptTPMTestBase.setUpTestBase(c, &s.tpmTestBase)
}

type testActivateVolumeWithTPMSealedKeyNo2FAData struct {
	volumeName       string
	sourceDevicePath string
	pinTries         int
	recoveryKeyTries int
	activateOptions  []string
}

func (s *cryptTPMSuite) testActivateVolumeWithTPMSealedKeyNo2FA(c *C, data *testActivateVolumeWithTPMSealedKeyNo2FAData) {
	options := ActivateWithTPMSealedKeyOptions{PINTries: data.pinTries, RecoveryKeyTries: data.recoveryKeyTries, ActivateOptions: data.activateOptions}
	success, err := ActivateVolumeWithTPMSealedKey(s.tpm, data.volumeName, data.sourceDevicePath, s.keyFile, nil, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, 0)
	c.Assert(len(s.mockSdCryptsetup.Calls()), Equals, 1)
	c.Assert(len(s.mockSdCryptsetup.Calls()[0]), Equals, 6)

	c.Check(s.mockSdCryptsetup.Calls()[0][0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", data.volumeName, data.sourceDevicePath})
	c.Check(s.mockSdCryptsetup.Calls()[0][4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]*")
	c.Check(s.mockSdCryptsetup.Calls()[0][5], Equals, strings.Join(append(data.activateOptions, "tries=1"), ","))
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyNo2FA1(c *C) {
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyNo2FA2(c *C) {
	// Test with a non-zero PINTries when a PIN isn't set.
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		pinTries:         1,
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyNo2FA3(c *C) {
	// Test with a non-zero RecoveryKeyTries.
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		recoveryKeyTries: 1,
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyNo2FA4(c *C) {
	// Test with extra options for systemd-cryptsetup.
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		activateOptions:  []string{"foo=bar", "baz"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyNo2FA5(c *C) {
	// Test with a different volume name / device path.
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "foo",
		sourceDevicePath: "/dev/vda2",
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyNo2FA6(c *C) {
	// Test that ActivateVolumeWithTPMSealedKey creates a SRK when it can, rather than fallback back to the recovery key.
	srk, err := s.tpm.CreateResourceContextFromTPM(SrkHandle)
	c.Assert(err, IsNil)
	_, err = s.tpm.EvictControl(s.tpm.OwnerHandleContext(), srk, srk.Handle(), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
	})
}

type testActivateVolumeWithTPMSealedKeyErrorHandlingData struct {
	pinTries           int
	recoveryKeyTries   int
	activateOptions    []string
	passphraseAttempts []string
	success            bool
	recoveryReason     RecoveryKeyUsageReason
	errChecker         Checker
	errCheckerArgs     []interface{}
}

func (s *cryptTPMSuite) testActivateVolumeWithTPMSealedKeyErrorHandling(c *C, data *testActivateVolumeWithTPMSealedKeyErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.passphraseAttempts, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithTPMSealedKeyOptions{PINTries: data.pinTries, RecoveryKeyTries: data.recoveryKeyTries, ActivateOptions: data.activateOptions}
	success, err := ActivateVolumeWithTPMSealedKey(s.tpm, "data", "/dev/sda1", s.keyFile, nil, &options)
	c.Check(err, data.errChecker, data.errCheckerArgs...)
	c.Check(success, Equals, data.success)

	if !data.success {
		return
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, data.recoveryReason)
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling1(c *C) {
	// Test with an invalid value for PINTries.
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		pinTries:       -1,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"invalid PINTries"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling2(c *C) {
	// Test with an invalid value for RecoveryKeyTries.
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: -1,
		errChecker:       ErrorMatches,
		errCheckerArgs:   []interface{}{"invalid RecoveryKeyTries"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling3(c *C) {
	// Test that adding "tries=" to ActivateOptions fails.
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		activateOptions: []string{"tries=2"},
		errChecker:      ErrorMatches,
		errCheckerArgs:  []interface{}{"cannot specify the \"tries=\" option for systemd-cryptsetup"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling4(c *C) {
	// Test that recovery fallback works with the TPM in DA lockout mode.
	c.Assert(s.tpm.DictionaryAttackParameters(s.tpm.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(ProvisionTPM(s.tpm, ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:   1,
		passphraseAttempts: []string{strings.Join(s.recoveryKeyAscii, "-")},
		success:            true,
		recoveryReason:     RecoveryKeyUsageReasonTPMLockout,
		errChecker:         ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling5(c *C) {
	// Test that recovery fallback works when there is no SRK and a new one can't be created.
	srk, err := s.tpm.CreateResourceContextFromTPM(SrkHandle)
	c.Assert(err, IsNil)
	_, err = s.tpm.EvictControl(s.tpm.OwnerHandleContext(), srk, srk.Handle(), nil)
	c.Assert(err, IsNil)
	s.setHierarchyAuth(c, tpm2.HandleOwner)
	s.tpm.OwnerHandleContext().SetAuthValue(nil)
	defer s.tpm.OwnerHandleContext().SetAuthValue(testAuth)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 2,
		passphraseAttempts: []string{
			"00000-00000-00000-00000-00000-00000-00000-00000",
			strings.Join(s.recoveryKeyAscii, "-"),
		},
		success:        true,
		recoveryReason: RecoveryKeyUsageReasonTPMProvisioningError,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is not correctly " +
			"provisioned\\) but activation with recovery key was successful"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling6(c *C) {
	// Test that recovery fallback works when the unsealed key is incorrect.
	incorrectKey := make([]byte, 32)
	rand.Read(incorrectKey)
	c.Assert(ioutil.WriteFile(s.expectedTpmKeyFile, incorrectKey, 0644), IsNil)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:   1,
		passphraseAttempts: []string{strings.Join(s.recoveryKeyAscii, "-")},
		success:            true,
		recoveryReason:     RecoveryKeyUsageReasonInvalidKeyFile,
		errChecker:         ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot activate volume: " + s.mockSdCryptsetup.Exe() +
			" failed: exit status 1\\) but activation with recovery key was successful"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling7(c *C) {
	// Test that activation fails if RecoveryKeyTries is zero.
	c.Assert(s.tpm.DictionaryAttackParameters(s.tpm.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(ProvisionTPM(s.tpm, ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		success:    false,
		errChecker: ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) " +
			"and activation with recovery key failed \\(no recovery key tries permitted\\)"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling8(c *C) {
	// Test that activation fails if the wrong recovery key is provided.
	c.Assert(s.tpm.DictionaryAttackParameters(s.tpm.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(ProvisionTPM(s.tpm, ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:   1,
		passphraseAttempts: []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		success:            false,
		errChecker:         ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) " +
			"and activation with recovery key failed \\(cannot activate volume: " + s.mockSdCryptsetup.Exe() + " failed: exit status 1\\)"},
	})
}

type cryptTPMSimulatorSuite struct {
	tpmSimulatorTestBase
	cryptTPMTestBase
}

var _ = Suite(&cryptTPMSimulatorSuite{})

func (s *cryptTPMSimulatorSuite) SetUpSuite(c *C) {
	s.cryptTPMTestBase.setUpSuiteBase(c)
}

func (s *cryptTPMSimulatorSuite) SetUpTest(c *C) {
	s.tpmSimulatorTestBase.SetUpTest(c)
	s.resetTPMSimulator(c)
	s.cryptTPMTestBase.setUpTestBase(c, &s.tpmTestBase)
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithTPMSealedKeyErrorHandling(c *C, data *testActivateVolumeWithTPMSealedKeyErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.passphraseAttempts, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithTPMSealedKeyOptions{PINTries: data.pinTries, RecoveryKeyTries: data.recoveryKeyTries, ActivateOptions: data.activateOptions}
	success, err := ActivateVolumeWithTPMSealedKey(s.tpm, "data", "/dev/sda1", s.keyFile, nil, &options)
	c.Check(err, data.errChecker, data.errCheckerArgs...)
	c.Check(success, Equals, data.success)

	if !data.success {
		return
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, data.recoveryReason)
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling1(c *C) {
	// Test that recovery fallback works when the sealed key authorization policy is wrong.
	_, err := s.tpm.PCREvent(s.tpm.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:   1,
		passphraseAttempts: []string{strings.Join(s.recoveryKeyAscii, "-")},
		success:            true,
		recoveryReason:     RecoveryKeyUsageReasonInvalidKeyFile,
		errChecker:         ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: invalid key data file: cannot complete " +
			"authorization policy assertions: cannot complete OR assertions: current session digest not found in policy data\\) but " +
			"activation with recovery key was successful"},
	})
}

type cryptSuite struct {
	testutil.BaseTest
	cryptTestBase
}

var _ = Suite(&cryptSuite{})

func (s *cryptSuite) SetUpSuite(c *C) {
	s.cryptTestBase.setUpSuiteBase(c)
}

func (s *cryptSuite) SetUpTest(c *C) {
	s.cryptTestBase.setUpTestBase(c, &s.BaseTest)
}

type testActivateVolumeWithRecoveryKeyData struct {
	volumeName                 string
	sourceDevicePath           string
	tries                      int
	activateOptions            []string
	recoveryPassphraseAttempts []string
	sdCryptsetupCalls          int
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKey(c *C, data *testActivateVolumeWithRecoveryKeyData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.recoveryPassphraseAttempts, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithRecoveryKeyOptions{Tries: data.tries, ActivateOptions: data.activateOptions}
	c.Assert(ActivateVolumeWithRecoveryKey(data.volumeName, data.sourceDevicePath, nil, &options), IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.recoveryPassphraseAttempts))

	c.Check(len(s.mockSdCryptsetup.Calls()), Equals, data.sdCryptsetupCalls)
	for _, call := range s.mockSdCryptsetup.Calls() {
		c.Assert(len(call), Equals, 6)
		c.Check(call[0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", data.volumeName, data.sourceDevicePath})
		c.Check(call[4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]*")
		c.Check(call[5], Equals, strings.Join(append(data.activateOptions, "tries=1"), ","))
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, RecoveryKeyUsageReasonRequested)
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey1(c *C) {
	// Test with a recovery key which is entered with a hyphen between each group of 5 digits.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		tries:            1,
		recoveryPassphraseAttempts: []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:          1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey2(c *C) {
	// Test with a recovery key which is entered without a hyphen between each group of 5 digits.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		tries:            1,
		recoveryPassphraseAttempts: []string{strings.Join(s.recoveryKeyAscii, "")},
		sdCryptsetupCalls:          1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey3(c *C) {
	// Test that activation succeeds when the correct recovery key is provided on the second attempt.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		tries:            2,
		recoveryPassphraseAttempts: []string{
			"00000-00000-00000-00000-00000-00000-00000-00000",
			strings.Join(s.recoveryKeyAscii, "-"),
		},
		sdCryptsetupCalls: 2,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey4(c *C) {
	// Test that activation succeeds when the correct recovery key is provided on the second attempt, and the first
	// attempt is badly formatted.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		tries:            2,
		recoveryPassphraseAttempts: []string{
			"1234",
			strings.Join(s.recoveryKeyAscii, "-"),
		},
		sdCryptsetupCalls: 1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey5(c *C) {
	// Test with additional options passed to systemd-cryptsetup.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:                 "data",
		sourceDevicePath:           "/dev/sda1",
		tries:                      1,
		activateOptions:            []string{"foo", "bar"},
		recoveryPassphraseAttempts: []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:          1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey6(c *C) {
	// Test with a different volume name / device path.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:       "foo",
		sourceDevicePath: "/dev/vdb2",
		tries:            1,
		recoveryPassphraseAttempts: []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:          1,
	})
}

type testActivateVolumeWithRecoveryKeyUsingKeyReaderData struct {
	tries                      int
	recoveryKeyFileContents    string
	recoveryPassphraseAttempts []string
	sdCryptsetupCalls          int
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKeyUsingKeyReader(c *C, data *testActivateVolumeWithRecoveryKeyUsingKeyReaderData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.recoveryPassphraseAttempts, "\n")+"\n"), 0644), IsNil)
	c.Assert(ioutil.WriteFile(filepath.Join(s.dir, "keyfile"), []byte(data.recoveryKeyFileContents), 0644), IsNil)

	r, err := os.Open(filepath.Join(s.dir, "keyfile"))
	c.Assert(err, IsNil)
	defer r.Close()

	options := ActivateWithRecoveryKeyOptions{Tries: data.tries}
	c.Assert(ActivateVolumeWithRecoveryKey("data", "/dev/sda1", r, &options), IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.recoveryPassphraseAttempts))

	c.Check(len(s.mockSdCryptsetup.Calls()), Equals, data.sdCryptsetupCalls)
	for _, call := range s.mockSdCryptsetup.Calls() {
		c.Assert(len(call), Equals, 6)
		c.Check(call[0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", "data", "/dev/sda1"})
		c.Check(call[4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]*")
		c.Check(call[5], Equals, "tries=1")
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, RecoveryKeyUsageReasonRequested)
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader1(c *C) {
	// Test with the correct recovery key supplied via a io.Reader, with a hyphen separating each group of 5 digits.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries: 1,
		recoveryKeyFileContents: strings.Join(s.recoveryKeyAscii, "-") + "\n",
		sdCryptsetupCalls:       1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader2(c *C) {
	// Test with the correct recovery key supplied via a io.Reader, without a hyphen separating each group of 5 digits.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries: 1,
		recoveryKeyFileContents: strings.Join(s.recoveryKeyAscii, "") + "\n",
		sdCryptsetupCalls:       1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader3(c *C) {
	// Test with the correct recovery key supplied via a io.Reader when the key doesn't end in a newline.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries: 1,
		recoveryKeyFileContents: strings.Join(s.recoveryKeyAscii, "-"),
		sdCryptsetupCalls:       1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader4(c *C) {
	// Test that falling back to requesting a recovery key works if the one provided by the io.Reader is incorrect.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries: 2,
		recoveryKeyFileContents:    "00000-00000-00000-00000-00000-00000-00000-00000\n",
		recoveryPassphraseAttempts: []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:          2,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader5(c *C) {
	// Test that falling back to requesting a recovery key works if the one provided by the io.Reader is badly formatted.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries: 2,
		recoveryKeyFileContents:    "5678\n",
		recoveryPassphraseAttempts: []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:          1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader6(c *C) {
	// Test that falling back to requesting a recovery key works if the provided io.Reader is backed by an empty buffer.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries: 1,
		recoveryPassphraseAttempts: []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:          1,
	})
}

type testActivateVolumeWithRecoveryKeyErrorHandlingData struct {
	tries                      int
	activateOptions            []string
	recoveryPassphraseAttempts []string
	errChecker                 Checker
	errCheckerArgs             []interface{}
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKeyErrorHandling(c *C, data *testActivateVolumeWithRecoveryKeyErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.recoveryPassphraseAttempts, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithRecoveryKeyOptions{Tries: data.tries, ActivateOptions: data.activateOptions}
	c.Check(ActivateVolumeWithRecoveryKey("data", "/dev/sda1", nil, &options), data.errChecker, data.errCheckerArgs...)
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling1(c *C) {
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:          -1,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"invalid Tries"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling2(c *C) {
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:          0,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"no recovery key tries permitted"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling3(c *C) {
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:           1,
		activateOptions: []string{"tries=2"},
		errChecker:      ErrorMatches,
		errCheckerArgs:  []interface{}{"cannot specify the \"tries=\" option for systemd-cryptsetup"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling4(c *C) {
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries: 1,
		recoveryPassphraseAttempts: []string{"00000-1234"},
		errChecker:                 ErrorMatches,
		errCheckerArgs:             []interface{}{"cannot decode recovery key: incorrectly formatted \\(insufficient characters\\)"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling5(c *C) {
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries: 1,
		recoveryPassphraseAttempts: []string{"00000-123bc"},
		errChecker:                 ErrorMatches,
		errCheckerArgs:             []interface{}{"cannot decode recovery key: incorrectly formatted \\(invalid base-10 number\\)"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling6(c *C) {
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries: 1,
		recoveryPassphraseAttempts: []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		errChecker:                 ErrorMatches,
		errCheckerArgs:             []interface{}{"cannot activate volume: " + s.mockSdCryptsetup.Exe() + " failed: exit status 1"},
	})
}
