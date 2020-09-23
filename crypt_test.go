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
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

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

type luks2ActivateCall struct {
	volumeName       string
	sourceDevicePath string
	options          []string
}

type cryptTestBase struct {
	base *snapd_testutil.BaseTest

	recoveryKey RecoveryKey

	passwordFile string // a newline delimited list of passwords for the mock systemd-ask-password to return

	mockSdAskPassword *snapd_testutil.MockCmd

	luks2ActivateCalls []*luks2ActivateCall
	mockKeyslots       [][]byte

	possessesUserKeyringKeys bool
}

func (ctb *cryptTestBase) setUpSuite(c *C, base *snapd_testutil.BaseTest) {
	ctb.base = base

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

func (ctb *cryptTestBase) setUpTest(c *C) {
	ctb.base.AddCleanup(testutil.MockRunDir(c.MkDir()))

	rand.Read(ctb.recoveryKey[:])

	ctb.passwordFile = filepath.Join(c.MkDir(), "password")

	sdAskPasswordBottom := `
head -1 %[1]s
sed -i -e '1,1d' %[1]s
`
	ctb.mockSdAskPassword = snapd_testutil.MockCommand(c, "systemd-ask-password", fmt.Sprintf(sdAskPasswordBottom, ctb.passwordFile))
	ctb.base.AddCleanup(ctb.mockSdAskPassword.Restore)

	ctb.luks2ActivateCalls = nil
	ctb.base.AddCleanup(MockLUKS2Activate(func(volumeName, sourceDevicePath string, key []byte, options []string) error {
		ctb.luks2ActivateCalls = append(ctb.luks2ActivateCalls, &luks2ActivateCall{volumeName, sourceDevicePath, options})
		for _, k := range ctb.mockKeyslots {
			if bytes.Equal(k, key) {
				return nil
			}
		}
		return &exec.ExitError{ProcessState: &os.ProcessState{}}
	}))

	ctb.mockKeyslots = [][]byte{ctb.recoveryKey[:]}

	startKeys := getKeyringKeys(c, userKeyring)

	ctb.base.AddCleanup(func() {
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

	cryptsetupWrapper := testutil.WrapCryptsetup(c)
	ctb.base.AddCleanup(cryptsetupWrapper.Restore)
}

func (ctb *cryptTestBase) createEmptyDiskImage(c *C) string {
	f, err := os.OpenFile(filepath.Join(c.MkDir(), "disk.img"), os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	c.Assert(f.Truncate(20*1024*1024), IsNil)
	return f.Name()
}

func (ctb *cryptTestBase) checkRecoveryKeyKeyringEntry(c *C, volumeName string, reason RecoveryKeyUsageReason) {
	id, err := unix.KeyctlSearch(userKeyring, "user", fmt.Sprintf("%s:%s:reason=%d", filepath.Base(os.Args[0]), volumeName, reason), 0)
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
	c.Check(buf, DeepEquals, ctb.recoveryKey[:])
}

type cryptTPMTestBase struct {
	cryptTestBase
	base *testutil.TPMTestBase

	tpmKey  []byte
	keyFile string
}

func (ctb *cryptTPMTestBase) setUpSuite(c *C, base *testutil.TPMTestBase) {
	ctb.cryptTestBase.setUpSuite(c, &base.BaseTest)
	ctb.base = base
}

func (ctb *cryptTPMTestBase) setUpTest(c *C) {
	ctb.cryptTestBase.setUpTest(c)

	ctb.tpmKey = make([]byte, 64)
	rand.Read(ctb.tpmKey)

	c.Assert(ProvisionTPM(ctb.base.TPM, ProvisionModeFull, nil), IsNil)

	dir := c.MkDir()
	ctb.keyFile = dir + "/keydata"

	pinHandle := tpm2.Handle(0x0181fff0)
	c.Assert(SealKeyToTPM(ctb.base.TPM, ctb.tpmKey, ctb.keyFile, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PINHandle: pinHandle}), IsNil)
	pinIndex, err := ctb.base.TPM.CreateResourceContextFromTPM(pinHandle)
	c.Assert(err, IsNil)
	ctb.base.AddCleanupNVSpace(c, ctb.base.TPM.OwnerHandleContext(), pinIndex)

	ctb.mockKeyslots = append(ctb.mockKeyslots, ctb.tpmKey)

	// Some tests may increment the DA lockout counter
	ctb.base.AddCleanup(func() {
		c.Check(ctb.base.TPM.DictionaryAttackLockReset(ctb.base.TPM.LockoutHandleContext(), nil), IsNil)
	})
}

type cryptTPMSuite struct {
	testutil.TPMTestBase
	cryptTPMTestBase
}

var _ = Suite(&cryptTPMSuite{})

func (s *cryptTPMSuite) SetUpSuite(c *C) {
	s.cryptTPMTestBase.setUpSuite(c, &s.TPMTestBase)
}

func (s *cryptTPMSuite) SetUpTest(c *C) {
	s.TPMTestBase.SetUpTest(c)
	s.cryptTPMTestBase.setUpTest(c)
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
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, data.volumeName, data.sourceDevicePath, s.keyFile, nil, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, 0)
	c.Assert(s.luks2ActivateCalls, HasLen, 1)
	c.Check(s.luks2ActivateCalls[0], DeepEquals, &luks2ActivateCall{data.volumeName, data.sourceDevicePath, data.activateOptions})
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
	srk, err := s.TPM.CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), srk, srk.Handle(), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
	})
}

type testActivateVolumeWithTPMSealedKeyAndPINData struct {
	pins     []string
	pinTries int
}

func (s *cryptTPMSuite) testActivateVolumeWithTPMSealedKeyAndPIN(c *C, data *testActivateVolumeWithTPMSealedKeyAndPINData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.pins, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithTPMSealedKeyOptions{PINTries: data.pinTries}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, "data", "/dev/sda1", s.keyFile, nil, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, len(data.pins))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the PIN for disk /dev/sda1:"})
	}

	c.Assert(s.luks2ActivateCalls, HasLen, 1)
	c.Check(s.luks2ActivateCalls[0], DeepEquals, &luks2ActivateCall{"data", "/dev/sda1", nil})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPIN1(c *C) {
	// Test with a single PIN attempt.
	k, err := ReadSealedKeyObjectFromFile(s.keyFile)
	c.Assert(err, IsNil)

	testPIN := "1234"
	c.Assert(k.ChangePIN(s.TPM, "", testPIN), IsNil)
	s.testActivateVolumeWithTPMSealedKeyAndPIN(c, &testActivateVolumeWithTPMSealedKeyAndPINData{
		pins:     []string{testPIN},
		pinTries: 1,
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPIN2(c *C) {
	// Test with 2 PIN attempts.
	k, err := ReadSealedKeyObjectFromFile(s.keyFile)
	c.Assert(err, IsNil)

	testPIN := "1234"
	c.Assert(k.ChangePIN(s.TPM, "", testPIN), IsNil)
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

func (s *cryptTPMSuite) testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c *C, data *testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.pins, "\n")+"\n"), 0644), IsNil)

	pinfile := filepath.Join(c.MkDir(), "pinfile")
	c.Assert(ioutil.WriteFile(pinfile, []byte(data.pinFileContents), 0644), IsNil)

	r, err := os.Open(pinfile)
	c.Assert(err, IsNil)
	defer r.Close()

	options := ActivateWithTPMSealedKeyOptions{PINTries: data.pinTries}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, "data", "/dev/sda1", s.keyFile, r, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, len(data.pins))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the PIN for disk /dev/sda1:"})
	}

	c.Assert(s.luks2ActivateCalls, HasLen, 1)
	c.Check(s.luks2ActivateCalls[0], DeepEquals, &luks2ActivateCall{"data", "/dev/sda1", nil})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader1(c *C) {
	// Test with the correct PIN provided via the io.Reader.
	k, err := ReadSealedKeyObjectFromFile(s.keyFile)
	c.Assert(err, IsNil)

	testPIN := "1234"
	c.Assert(k.ChangePIN(s.TPM, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pinFileContents: testPIN + "\n",
		pinTries:        1,
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader2(c *C) {
	// Test with the correct PIN provided via the io.Reader when the file doesn't end in a newline.
	k, err := ReadSealedKeyObjectFromFile(s.keyFile)
	c.Assert(err, IsNil)

	testPIN := "1234"
	c.Assert(k.ChangePIN(s.TPM, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pinFileContents: testPIN,
		pinTries:        1,
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader3(c *C) {
	// Test falling back to asking for a PIN if the wrong PIN is provided via the io.Reader.
	k, err := ReadSealedKeyObjectFromFile(s.keyFile)
	c.Assert(err, IsNil)

	testPIN := "1234"
	c.Assert(k.ChangePIN(s.TPM, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pins:            []string{testPIN},
		pinFileContents: "5678" + "\n",
		pinTries:        2,
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader4(c *C) {
	// Test falling back to asking for a PIN without using a try if the io.Reader has no contents.
	k, err := ReadSealedKeyObjectFromFile(s.keyFile)
	c.Assert(err, IsNil)

	testPIN := "1234"
	c.Assert(k.ChangePIN(s.TPM, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pins:     []string{testPIN},
		pinTries: 1,
	})
}

type testActivateVolumeWithTPMSealedKeyErrorHandlingData struct {
	pinTries         int
	recoveryKeyTries int
	activateOptions  []string
	passphrases      []string
	activateCalls    int
	success          bool
	recoveryReason   RecoveryKeyUsageReason
	errChecker       Checker
	errCheckerArgs   []interface{}
}

func (s *cryptTPMSuite) testActivateVolumeWithTPMSealedKeyErrorHandling(c *C, data *testActivateVolumeWithTPMSealedKeyErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.passphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithTPMSealedKeyOptions{PINTries: data.pinTries, RecoveryKeyTries: data.recoveryKeyTries, ActivateOptions: data.activateOptions}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, "data", "/dev/sda1", s.keyFile, nil, &options)
	c.Check(err, data.errChecker, data.errCheckerArgs...)
	c.Check(success, Equals, data.success)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, len(data.passphrases))
	for i, call := range s.mockSdAskPassword.Calls() {
		passphraseType := "PIN"
		if i >= data.pinTries {
			passphraseType = "recovery key"
		}
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the " + passphraseType + " for disk /dev/sda1:"})
	}

	c.Check(s.luks2ActivateCalls, HasLen, data.activateCalls)
	for _, call := range s.luks2ActivateCalls {
		c.Check(call, DeepEquals, &luks2ActivateCall{"data", "/dev/sda1", data.activateOptions})
	}

	if !data.success {
		return
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, "data", data.recoveryReason)
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
	// Test that recovery fallback works with the TPM in DA lockout mode.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(ProvisionTPM(s.TPM, ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateCalls:    1,
		success:          true,
		recoveryReason:   RecoveryKeyUsageReasonTPMLockout,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling4(c *C) {
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
		activateCalls:  2,
		success:        true,
		recoveryReason: RecoveryKeyUsageReasonTPMProvisioningError,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is not correctly " +
			"provisioned\\) but activation with recovery key was successful"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling5(c *C) {
	// Test that recovery fallback works when the unsealed key is incorrect.
	incorrectKey := make([]byte, 32)
	rand.Read(incorrectKey)
	s.mockKeyslots = [][]byte{s.recoveryKey[:], incorrectKey}

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateCalls:    2,
		success:          true,
		recoveryReason:   RecoveryKeyUsageReasonInvalidKeyFile,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot activate volume: exit status 0\\) but activation " +
			"with recovery key was successful"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling6(c *C) {
	// Test that activation fails if RecoveryKeyTries is zero.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(ProvisionTPM(s.TPM, ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		success:    false,
		errChecker: ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) " +
			"and activation with recovery key failed \\(no recovery key tries permitted\\)"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling7(c *C) {
	// Test that activation fails if the wrong recovery key is provided.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(ProvisionTPM(s.TPM, ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		activateCalls:    1,
		success:          false,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) " +
			"and activation with recovery key failed \\(cannot activate volume: exit status 0\\)"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling8(c *C) {
	// Test that recovery fallback works if the wrong PIN is supplied.
	k, err := ReadSealedKeyObjectFromFile(s.keyFile)
	c.Assert(err, IsNil)

	testPIN := "1234"
	c.Assert(k.ChangePIN(s.TPM, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		pinTries:         1,
		recoveryKeyTries: 1,
		passphrases: []string{
			"",
			s.recoveryKey.String(),
		},
		activateCalls:  1,
		success:        true,
		recoveryReason: RecoveryKeyUsageReasonPINFail,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the provided PIN is incorrect\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling9(c *C) {
	// Test that recovery fallback works if a PIN is set but no PIN attempts are permitted.
	k, err := ReadSealedKeyObjectFromFile(s.keyFile)
	c.Assert(err, IsNil)

	c.Assert(k.ChangePIN(s.TPM, "", "1234"), IsNil)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateCalls:    1,
		success:          true,
		recoveryReason:   RecoveryKeyUsageReasonPINFail,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(no PIN tries permitted when a PIN is required\\) but " +
			"activation with recovery key was successful"},
	})
}

type cryptTPMSimulatorSuite struct {
	testutil.TPMSimulatorTestBase
	cryptTPMTestBase
}

var _ = Suite(&cryptTPMSimulatorSuite{})

func (s *cryptTPMSimulatorSuite) SetUpSuite(c *C) {
	s.cryptTPMTestBase.setUpSuite(c, &s.TPMTestBase)
}

func (s *cryptTPMSimulatorSuite) SetUpTest(c *C) {
	s.TPMSimulatorTestBase.SetUpTest(c)
	s.ResetTPMSimulator(c)
	s.cryptTPMTestBase.setUpTest(c)
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithTPMSealedKeyErrorHandling(c *C, data *testActivateVolumeWithTPMSealedKeyErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.passphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithTPMSealedKeyOptions{PINTries: data.pinTries, RecoveryKeyTries: data.recoveryKeyTries, ActivateOptions: data.activateOptions}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, "data", "/dev/sda1", s.keyFile, nil, &options)
	c.Check(err, data.errChecker, data.errCheckerArgs...)
	c.Check(success, Equals, data.success)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, len(data.passphrases))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the recovery key for disk /dev/sda1:"})
	}
	c.Check(s.luks2ActivateCalls, HasLen, data.activateCalls)
	for _, call := range s.luks2ActivateCalls {
		c.Check(call, DeepEquals, &luks2ActivateCall{"data", "/dev/sda1", data.activateOptions})
	}

	if !data.success {
		return
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, "data", data.recoveryReason)
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling1(c *C) {
	// Test that recovery fallback works when the sealed key authorization policy is wrong.
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries: 1,
		passphrases:      []string{s.recoveryKey.String()},
		activateCalls:    1,
		success:          true,
		recoveryReason:   RecoveryKeyUsageReasonInvalidKeyFile,
		errChecker:       ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: invalid key data file: cannot complete " +
			"authorization policy assertions: cannot complete OR assertions: current session digest not found in policy data\\) but " +
			"activation with recovery key was successful"},
	})
}

type cryptSuite struct {
	snapd_testutil.BaseTest
	cryptTestBase
}

var _ = Suite(&cryptSuite{})

func (s *cryptSuite) SetUpSuite(c *C) {
	s.cryptTestBase.setUpSuite(c, &s.BaseTest)
}

func (s *cryptSuite) SetUpTest(c *C) {
	s.cryptTestBase.setUpTest(c)
}

type testActivateVolumeWithRecoveryKeyData struct {
	volumeName          string
	sourceDevicePath    string
	tries               int
	activateOptions     []string
	recoveryPassphrases []string
	activateCalls       int
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKey(c *C, data *testActivateVolumeWithRecoveryKeyData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.recoveryPassphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithRecoveryKeyOptions{Tries: data.tries, ActivateOptions: data.activateOptions}
	c.Assert(ActivateVolumeWithRecoveryKey(data.volumeName, data.sourceDevicePath, nil, &options), IsNil)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, len(data.recoveryPassphrases))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":" + data.sourceDevicePath, "Please enter the recovery key for disk " + data.sourceDevicePath + ":"})
	}

	c.Check(s.luks2ActivateCalls, HasLen, data.activateCalls)
	for _, call := range s.luks2ActivateCalls {
		c.Check(call, DeepEquals, &luks2ActivateCall{data.volumeName, data.sourceDevicePath, data.activateOptions})
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, data.volumeName, RecoveryKeyUsageReasonRequested)
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey1(c *C) {
	// Test with a recovery key which is entered with a hyphen between each group of 5 digits.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:          "data",
		sourceDevicePath:    "/dev/sda1",
		tries:               1,
		recoveryPassphrases: []string{s.recoveryKey.String()},
		activateCalls:       1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey2(c *C) {
	// Test with a recovery key which is entered without a hyphen between each group of 5 digits.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:          "data",
		sourceDevicePath:    "/dev/sda1",
		tries:               1,
		recoveryPassphrases: []string{strings.Replace(s.recoveryKey.String(), "-", "", -1)},
		activateCalls:       1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey3(c *C) {
	// Test that activation succeeds when the correct recovery key is provided on the second attempt.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		tries:            2,
		recoveryPassphrases: []string{
			"00000-00000-00000-00000-00000-00000-00000-00000",
			s.recoveryKey.String(),
		},
		activateCalls: 2,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey4(c *C) {
	// Test that activation succeeds when the correct recovery key is provided on the second attempt, and the first
	// attempt is badly formatted.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		tries:            2,
		recoveryPassphrases: []string{
			"1234",
			s.recoveryKey.String(),
		},
		activateCalls: 1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey5(c *C) {
	// Test with additional options passed to systemd-cryptsetup.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:          "data",
		sourceDevicePath:    "/dev/sda1",
		tries:               1,
		activateOptions:     []string{"foo", "bar"},
		recoveryPassphrases: []string{s.recoveryKey.String()},
		activateCalls:       1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey6(c *C) {
	// Test with a different volume name / device path.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:          "foo",
		sourceDevicePath:    "/dev/vdb2",
		tries:               1,
		recoveryPassphrases: []string{s.recoveryKey.String()},
		activateCalls:       1,
	})
}

type testActivateVolumeWithRecoveryKeyUsingKeyReaderData struct {
	tries                   int
	recoveryKeyFileContents string
	recoveryPassphrases     []string
	activateCalls           int
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKeyUsingKeyReader(c *C, data *testActivateVolumeWithRecoveryKeyUsingKeyReaderData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.recoveryPassphrases, "\n")+"\n"), 0644), IsNil)

	keyfile := filepath.Join(c.MkDir(), "keyfile")
	c.Assert(ioutil.WriteFile(keyfile, []byte(data.recoveryKeyFileContents), 0644), IsNil)

	r, err := os.Open(keyfile)
	c.Assert(err, IsNil)
	defer r.Close()

	options := ActivateWithRecoveryKeyOptions{Tries: data.tries}
	c.Assert(ActivateVolumeWithRecoveryKey("data", "/dev/sda1", r, &options), IsNil)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, len(data.recoveryPassphrases))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the recovery key for disk /dev/sda1:"})
	}

	c.Check(s.luks2ActivateCalls, HasLen, data.activateCalls)
	for _, call := range s.luks2ActivateCalls {
		c.Check(call, DeepEquals, &luks2ActivateCall{"data", "/dev/sda1", nil})
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, "data", RecoveryKeyUsageReasonRequested)
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader1(c *C) {
	// Test with the correct recovery key supplied via a io.Reader, with a hyphen separating each group of 5 digits.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:                   1,
		recoveryKeyFileContents: s.recoveryKey.String() + "\n",
		activateCalls:           1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader2(c *C) {
	// Test with the correct recovery key supplied via a io.Reader, without a hyphen separating each group of 5 digits.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:                   1,
		recoveryKeyFileContents: strings.Replace(s.recoveryKey.String(), "-", "", -1) + "\n",
		activateCalls:           1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader3(c *C) {
	// Test with the correct recovery key supplied via a io.Reader when the key doesn't end in a newline.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:                   1,
		recoveryKeyFileContents: s.recoveryKey.String(),
		activateCalls:           1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader4(c *C) {
	// Test that falling back to requesting a recovery key works if the one provided by the io.Reader is incorrect.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:                   2,
		recoveryKeyFileContents: "00000-00000-00000-00000-00000-00000-00000-00000\n",
		recoveryPassphrases:     []string{s.recoveryKey.String()},
		activateCalls:           2,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader5(c *C) {
	// Test that falling back to requesting a recovery key works if the one provided by the io.Reader is badly formatted.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:                   2,
		recoveryKeyFileContents: "5678\n",
		recoveryPassphrases:     []string{s.recoveryKey.String()},
		activateCalls:           1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader6(c *C) {
	// Test that falling back to requesting a recovery key works if the provided io.Reader is backed by an empty buffer,
	// without using up a try.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:               1,
		recoveryPassphrases: []string{s.recoveryKey.String()},
		activateCalls:       1,
	})
}

type testParseRecoveryKeyData struct {
	formatted string
	expected  []byte
}

func (s *cryptSuite) testParseRecoveryKey(c *C, data *testParseRecoveryKeyData) {
	k, err := ParseRecoveryKey(data.formatted)
	c.Check(err, IsNil)
	c.Check(k[:], DeepEquals, data.expected)
}

func (s *cryptSuite) TestParseRecoveryKey1(c *C) {
	s.testParseRecoveryKey(c, &testParseRecoveryKeyData{
		formatted: "00000-00000-00000-00000-00000-00000-00000-00000",
		expected:  testutil.DecodeHexString(c, "00000000000000000000000000000000"),
	})
}

func (s *cryptSuite) TestParseRecoveryKey2(c *C) {
	s.testParseRecoveryKey(c, &testParseRecoveryKeyData{
		formatted: "61665-00531-54469-09783-47273-19035-40077-28287",
		expected:  testutil.DecodeHexString(c, "e1f01302c5d43726a9b85b4a8d9c7f6e"),
	})
}

func (s *cryptSuite) TestParseRecoveryKey3(c *C) {
	s.testParseRecoveryKey(c, &testParseRecoveryKeyData{
		formatted: "6166500531544690978347273190354007728287",
		expected:  testutil.DecodeHexString(c, "e1f01302c5d43726a9b85b4a8d9c7f6e"),
	})
}

type testParseRecoveryKeyErrorHandlingData struct {
	formatted      string
	errChecker     Checker
	errCheckerArgs []interface{}
}

func (s *cryptSuite) testParseRecoveryKeyErrorHandling(c *C, data *testParseRecoveryKeyErrorHandlingData) {
	_, err := ParseRecoveryKey(data.formatted)
	c.Check(err, data.errChecker, data.errCheckerArgs...)
}

func (s *cryptSuite) TestParseRecoveryKeyErrorHandling1(c *C) {
	s.testParseRecoveryKeyErrorHandling(c, &testParseRecoveryKeyErrorHandlingData{
		formatted:      "00000-1234",
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"incorrectly formatted: insufficient characters"},
	})
}

func (s *cryptSuite) TestParseRecoveryKeyErrorHandling2(c *C) {
	s.testParseRecoveryKeyErrorHandling(c, &testParseRecoveryKeyErrorHandlingData{
		formatted:      "00000-123bc",
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"incorrectly formatted: strconv.ParseUint: parsing \"123bc\": invalid syntax"},
	})
}

func (s *cryptSuite) TestParseRecoveryKeyErrorHandling3(c *C) {
	s.testParseRecoveryKeyErrorHandling(c, &testParseRecoveryKeyErrorHandlingData{
		formatted:      "00000-00000-00000-00000-00000-00000-00000-00000-00000",
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"incorrectly formatted: too many characters"},
	})
}

func (s *cryptSuite) TestParseRecoveryKeyErrorHandling4(c *C) {
	s.testParseRecoveryKeyErrorHandling(c, &testParseRecoveryKeyErrorHandlingData{
		formatted:      "-00000-00000-00000-00000-00000-00000-00000-00000",
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"incorrectly formatted: strconv.ParseUint: parsing \"-0000\": invalid syntax"},
	})
}

func (s *cryptSuite) TestParseRecoveryKeyErrorHandling5(c *C) {
	s.testParseRecoveryKeyErrorHandling(c, &testParseRecoveryKeyErrorHandlingData{
		formatted:      "00000-00000-00000-00000-00000-00000-00000-00000-",
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"incorrectly formatted: too many characters"},
	})
}

type testRecoveryKeyStringifyData struct {
	key      []byte
	expected string
}

func (s *cryptSuite) testRecoveryKeyStringify(c *C, data *testRecoveryKeyStringifyData) {
	var key RecoveryKey
	copy(key[:], data.key)
	c.Check(key.String(), Equals, data.expected)
}

func (s *cryptSuite) TestRecoveryKeyStringify1(c *C) {
	s.testRecoveryKeyStringify(c, &testRecoveryKeyStringifyData{
		expected: "00000-00000-00000-00000-00000-00000-00000-00000",
	})
}

func (s *cryptSuite) TestRecoveryKeyStringify2(c *C) {
	s.testRecoveryKeyStringify(c, &testRecoveryKeyStringifyData{
		key:      testutil.DecodeHexString(c, "e1f01302c5d43726a9b85b4a8d9c7f6e"),
		expected: "61665-00531-54469-09783-47273-19035-40077-28287",
	})
}

type testActivateVolumeWithRecoveryKeyErrorHandlingData struct {
	tries               int
	activateOptions     []string
	recoveryPassphrases []string
	activateCalls       int
	errChecker          Checker
	errCheckerArgs      []interface{}
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKeyErrorHandling(c *C, data *testActivateVolumeWithRecoveryKeyErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.recoveryPassphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithRecoveryKeyOptions{Tries: data.tries, ActivateOptions: data.activateOptions}
	c.Check(ActivateVolumeWithRecoveryKey("data", "/dev/sda1", nil, &options), data.errChecker, data.errCheckerArgs...)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, len(data.recoveryPassphrases))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the recovery key for disk /dev/sda1:"})
	}

	c.Check(s.luks2ActivateCalls, HasLen, data.activateCalls)
	for _, call := range s.luks2ActivateCalls {
		c.Check(call, DeepEquals, &luks2ActivateCall{"data", "/dev/sda1", nil})
	}
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling1(c *C) {
	// Test with an invalid Tries value.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:          -1,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"invalid Tries"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling2(c *C) {
	// Test with Tries set to zero.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:          0,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"no recovery key tries permitted"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling3(c *C) {
	// Test with a badly formatted recovery key.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:               1,
		recoveryPassphrases: []string{"00000-1234"},
		errChecker:          ErrorMatches,
		errCheckerArgs:      []interface{}{"cannot decode recovery key: incorrectly formatted: insufficient characters"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling4(c *C) {
	// Test with a badly formatted recovery key.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:               1,
		recoveryPassphrases: []string{"00000-123bc"},
		errChecker:          ErrorMatches,
		errCheckerArgs:      []interface{}{"cannot decode recovery key: incorrectly formatted: strconv.ParseUint: parsing \"123bc\": invalid syntax"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling5(c *C) {
	// Test with the wrong recovery key.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:               1,
		recoveryPassphrases: []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		activateCalls:       1,
		errChecker:          ErrorMatches,
		errCheckerArgs:      []interface{}{"cannot activate volume: exit status 0"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling6(c *C) {
	// Test that the last error is returned when there are consecutive failures for different reasons.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:               2,
		recoveryPassphrases: []string{"00000-00000-00000-00000-00000-00000-00000-00000", "1234"},
		activateCalls:       1,
		errChecker:          ErrorMatches,
		errCheckerArgs:      []interface{}{"cannot decode recovery key: incorrectly formatted: insufficient characters"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling7(c *C) {
	// Test with a badly formatted recovery key.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:               1,
		recoveryPassphrases: []string{"00000-00000-00000-00000-00000-00000-00000-00000-00000"},
		errChecker:          ErrorMatches,
		errCheckerArgs:      []interface{}{"cannot decode recovery key: incorrectly formatted: too many characters"},
	})
}

type testInitializeLUKS2ContainerData struct {
	label string
	key   []byte
}

func (s *cryptSuite) testInitializeLUKS2Container(c *C, data *testInitializeLUKS2ContainerData) {
	devicePath := s.createEmptyDiskImage(c)

	c.Check(InitializeLUKS2Container(devicePath, data.label, data.key), IsNil)

	info, err := luks2.DecodeHdr(devicePath)
	c.Assert(err, IsNil)

	c.Check(info.Label, Equals, data.label)

	c.Check(info.Metadata.Keyslots, HasLen, 1)
	keyslot, ok := info.Metadata.Keyslots[0]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.KeySize, Equals, 64)
	c.Check(keyslot.Priority, Equals, 2)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, "argon2i")
	c.Check(keyslot.KDF.Time, Equals, 4)
	c.Check(keyslot.KDF.Memory, Equals, 32)

	c.Check(info.Metadata.Segments, HasLen, 1)
	segment, ok := info.Metadata.Segments[0]
	c.Assert(ok, Equals, true)
	c.Check(segment.Encryption, Equals, "aes-xts-plain64")

	c.Check(info.Metadata.Tokens, HasLen, 1)
	token, ok := info.Metadata.Tokens[0]
	c.Assert(ok, Equals, true)
	c.Check(token.Type, Equals, "secboot")
	c.Assert(token.Keyslots, HasLen, 1)
	c.Check(int(token.Keyslots[0]), Equals, 0)
	c.Check(token.Params["secboot-type"], Equals, "master-detached")

	c.Check(luks2.TestPassphrase(devicePath, -1, data.key), IsNil)
}

func (s *cryptSuite) TestInitializeLUKS2Container1(c *C) {
	key := make([]byte, 64)
	rand.Read(key)

	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		label: "data",
		key:   key,
	})
}

func (s *cryptSuite) TestInitializeLUKS2Container2(c *C) {
	key := make([]byte, 64)
	rand.Read(key)

	// Test with different args.
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		label: "test",
		key:   key,
	})
}

func (s *cryptSuite) TestInitializeLUKS2ContainerInvalidKeySize(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	devicePath := s.createEmptyDiskImage(c)
	c.Check(InitializeLUKS2Container(devicePath, "data", key), ErrorMatches, "cannot format device: expected a key length of 512-bits \\(got 256\\)")
}

func (s *cryptSuite) TestSetLUKS2ContainerRecoveryKey(c *C) {
	for i := 0; i < 2; i++ {
		key := make([]byte, 64)
		rand.Read(key)

		devicePath := s.createEmptyDiskImage(c)
		c.Assert(InitializeLUKS2Container(devicePath, "test", key), IsNil)

		var recoveryKey RecoveryKey
		rand.Read(recoveryKey[:])

		c.Check(SetLUKS2ContainerRecoveryKey(devicePath, key, recoveryKey), IsNil)

		info, err := luks2.DecodeHdr(devicePath)
		c.Assert(err, IsNil)

		c.Check(info.Metadata.Tokens, HasLen, 2)
		var token *luks2.Token
		for _, t := range info.Metadata.Tokens {
			if t.Type == "secboot" && t.Params["secboot-type"] == "recovery" {
				token = t
				break
			}
		}
		c.Assert(token, NotNil)
		c.Assert(token.Keyslots, HasLen, 1)
		keyslotId := token.Keyslots[0]

		c.Check(info.Metadata.Keyslots, HasLen, 2)
		keyslot, ok := info.Metadata.Keyslots[keyslotId]
		c.Assert(ok, Equals, true)
		c.Check(keyslot.KeySize, Equals, 64)
		c.Check(keyslot.Priority, Equals, 1)
		c.Assert(keyslot.KDF, NotNil)
		c.Check(keyslot.KDF.Type, Equals, "argon2i")

		c.Check(luks2.TestPassphrase(devicePath, -1, recoveryKey[:]), IsNil)
	}
}

func (s *cryptSuite) TestChangeLUKS2ContainerRecoveryKey(c *C) {
	key := make([]byte, 64)
	rand.Read(key)

	var recoveryKey RecoveryKey
	rand.Read(recoveryKey[:])

	devicePath := s.createEmptyDiskImage(c)
	c.Assert(InitializeLUKS2Container(devicePath, "test", key), IsNil)

	c.Assert(SetLUKS2ContainerRecoveryKey(devicePath, key, recoveryKey), IsNil)

	var recoveryKey2 RecoveryKey
	rand.Read(recoveryKey2[:])
	c.Check(SetLUKS2ContainerRecoveryKey(devicePath, recoveryKey[:], recoveryKey2), IsNil)

	info, err := luks2.DecodeHdr(devicePath)
	c.Assert(err, IsNil)

	c.Check(info.Metadata.Keyslots, HasLen, 2)

	c.Check(info.Metadata.Tokens, HasLen, 2)
	var token *luks2.Token
	for _, t := range info.Metadata.Tokens {
		if t.Type == "secboot" && t.Params["secboot-type"] == "recovery" {
			token = t
			break
		}
	}
	c.Assert(token, NotNil)
	c.Assert(token.Keyslots, HasLen, 1)
	keyslotId := token.Keyslots[0]

	keyslot, ok := info.Metadata.Keyslots[keyslotId]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.KeySize, Equals, 64)
	c.Check(keyslot.Priority, Equals, 1)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, "argon2i")

	c.Check(luks2.TestPassphrase(devicePath, -1, key), IsNil)
	c.Check(luks2.TestPassphrase(devicePath, -1, recoveryKey2[:]), IsNil)
}

func (s *cryptSuite) TestSetLUKS2ContainerMasterKey(c *C) {
	for i := 0; i < 2; i++ {
		initialKey := make([]byte, 64)
		rand.Read(initialKey)

		var recoveryKey RecoveryKey
		rand.Read(recoveryKey[:])

		devicePath := s.createEmptyDiskImage(c)
		c.Assert(InitializeLUKS2Container(devicePath, "test", initialKey), IsNil)
		c.Assert(SetLUKS2ContainerRecoveryKey(devicePath, initialKey, recoveryKey), IsNil)

		key := make([]byte, 64)
		rand.Read(key)

		c.Check(SetLUKS2ContainerMasterKey(devicePath, recoveryKey[:], key), IsNil)

		info, err := luks2.DecodeHdr(devicePath)
		c.Assert(err, IsNil)

		c.Check(info.Metadata.Tokens, HasLen, 2)
		var token *luks2.Token
		for _, t := range info.Metadata.Tokens {
			if t.Type == "secboot" && t.Params["secboot-type"] == "master-detached" {
				token = t
				break
			}
		}
		c.Assert(token, NotNil)
		c.Assert(token.Keyslots, HasLen, 1)
		keyslotId := token.Keyslots[0]

		c.Check(info.Metadata.Keyslots, HasLen, 2)
		keyslot, ok := info.Metadata.Keyslots[keyslotId]
		c.Assert(ok, Equals, true)
		c.Check(keyslot.KeySize, Equals, 64)
		c.Check(keyslot.Priority, Equals, 2)
		c.Assert(keyslot.KDF, NotNil)
		c.Check(keyslot.KDF.Type, Equals, "argon2i")
		c.Check(keyslot.KDF.Time, Equals, 4)
		c.Check(keyslot.KDF.Memory, Equals, 32)

		c.Check(luks2.TestPassphrase(devicePath, -1, key), IsNil)
	}
}

func (s *cryptSuite) TestChangeLUKS2ContainerMasterKey(c *C) {
	initialKey := make([]byte, 64)
	rand.Read(initialKey)

	devicePath := s.createEmptyDiskImage(c)
	c.Assert(InitializeLUKS2Container(devicePath, "test", initialKey), IsNil)

	newKey := make([]byte, 64)
	rand.Read(newKey)
	c.Check(SetLUKS2ContainerMasterKey(devicePath, initialKey, newKey), IsNil)

	info, err := luks2.DecodeHdr(devicePath)
	c.Assert(err, IsNil)

	c.Check(info.Metadata.Keyslots, HasLen, 1)

	c.Check(info.Metadata.Tokens, HasLen, 1)
	var token *luks2.Token
	for _, t := range info.Metadata.Tokens {
		if t.Type == "secboot" && t.Params["secboot-type"] == "master-detached" {
			token = t
			break
		}
	}
	c.Assert(token, NotNil)
	c.Assert(token.Keyslots, HasLen, 1)
	keyslotId := token.Keyslots[0]

	keyslot, ok := info.Metadata.Keyslots[keyslotId]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.KeySize, Equals, 64)
	c.Check(keyslot.Priority, Equals, 2)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, "argon2i")
	c.Check(keyslot.KDF.Time, Equals, 4)
	c.Check(keyslot.KDF.Memory, Equals, 32)

	c.Check(luks2.TestPassphrase(devicePath, -1, newKey), IsNil)
}
