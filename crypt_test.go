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
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
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

type cryptTestBase struct {
	recoveryKey      []byte
	recoveryKeyAscii []string

	tpmKey []byte

	dir string

	passwordFile                 string // a newline delimited list of passwords for the mock systemd-ask-password to return
	expectedTpmKeyFile           string // the TPM expected by the mock systemd-cryptsetup
	expectedRecoveryKeyFile      string // the recovery key expected by the mock systemd-cryptsetup
	cryptsetupInvocationCountDir string
	cryptsetupKey                string // The file in which the mock cryptsetup dumps the provided key
	cryptsetupNewkey             string // The file in which the mock cryptsetup dumps the provided new key

	mockSdAskPassword *snapd_testutil.MockCmd
	mockSdCryptsetup  *snapd_testutil.MockCmd
	mockCryptsetup    *snapd_testutil.MockCmd

	possessesUserKeyringKeys bool
}

func (ctb *cryptTestBase) setUpSuiteBase(c *C) {
	ctb.recoveryKey = make([]byte, 16)
	rand.Read(ctb.recoveryKey)

	for i := 0; i < len(ctb.recoveryKey)/2; i++ {
		x := binary.LittleEndian.Uint16(ctb.recoveryKey[i*2:])
		ctb.recoveryKeyAscii = append(ctb.recoveryKeyAscii, fmt.Sprintf("%05d", x))
	}

	ctb.tpmKey = make([]byte, 64)
	rand.Read(ctb.tpmKey)

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

func (ctb *cryptTestBase) setUpTestBase(c *C, bt *snapd_testutil.BaseTest) {
	ctb.dir = c.MkDir()
	bt.AddCleanup(testutil.MockRunDir(ctb.dir))

	ctb.passwordFile = filepath.Join(ctb.dir, "password")                       // passwords to be returned by the mock sd-ask-password
	ctb.expectedTpmKeyFile = filepath.Join(ctb.dir, "expectedtpmkey")           // TPM key expected by the mock systemd-cryptsetup
	ctb.expectedRecoveryKeyFile = filepath.Join(ctb.dir, "expectedrecoverykey") // Recovery key expected by the mock systemd-cryptsetup
	ctb.cryptsetupKey = filepath.Join(ctb.dir, "cryptsetupkey")                 // File in which the mock cryptsetup records the passed in key
	ctb.cryptsetupNewkey = filepath.Join(ctb.dir, "cryptsetupnewkey")           // File in which the mock cryptsetup records the passed in new key
	ctb.cryptsetupInvocationCountDir = c.MkDir()

	sdAskPasswordBottom := `
head -1 %[1]s
sed -i -e '1,1d' %[1]s
`
	ctb.mockSdAskPassword = snapd_testutil.MockCommand(c, "systemd-ask-password", fmt.Sprintf(sdAskPasswordBottom, ctb.passwordFile))
	bt.AddCleanup(ctb.mockSdAskPassword.Restore)

	sdCryptsetupBottom := `
key=$(xxd -p < "$4")
if [ ! -f "%[1]s" ] || [ "$key" != "$(xxd -p < "%[1]s")" ]; then
    if [ ! -f "%[2]s" ] || [ "$key" != "$(xxd -p < "%[2]s")" ]; then
	exit 1
    fi
fi
`
	ctb.mockSdCryptsetup = snapd_testutil.MockCommand(c, c.MkDir()+"/systemd-cryptsetup", fmt.Sprintf(sdCryptsetupBottom, ctb.expectedTpmKeyFile, ctb.expectedRecoveryKeyFile))
	bt.AddCleanup(ctb.mockSdCryptsetup.Restore)
	bt.AddCleanup(testutil.MockSystemdCryptsetupPath(ctb.mockSdCryptsetup.Exe()))

	cryptsetupBottom := `
keyfile=""
action=""

while [ $# -gt 0 ]; do
    case "$1" in
        --key-file)
            keyfile=$2
            shift 2
            ;;
        --type | --cipher | --key-size | --pbkdf | --pbkdf-force-iterations | --pbkdf-memory | --label | --priority | --key-slot | --iter-time)
            shift 2
            ;;
        -*)
            shift
            ;;
        *)
            if [ -z "$action" ]; then
                action=$1
                shift
            else
                break
            fi
    esac
done

new_keyfile=""
if [ "$action" = "luksAddKey" ]; then
    new_keyfile=$2
fi

invocation=$(find %[4]s | wc -l)
mktemp %[4]s/XXXX

dump_key()
{
    in=$1
    out=$2

    if [ -z "$in" ]; then
	touch "$out"
    elif [ "$in" == "-" ]; then
	cat /dev/stdin > "$out"
    else
	cat "$in" > "$out"
    fi
}

dump_key "$keyfile" "%[2]s.$invocation"
dump_key "$new_keyfile" "%[3]s.$invocation"
`

	ctb.mockCryptsetup = snapd_testutil.MockCommand(c, "cryptsetup", fmt.Sprintf(cryptsetupBottom, ctb.dir, ctb.cryptsetupKey, ctb.cryptsetupNewkey, ctb.cryptsetupInvocationCountDir))
	bt.AddCleanup(ctb.mockCryptsetup.Restore)

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

	keyFile string
}

func (ctb *cryptTPMTestBase) setUpTestBase(c *C, ttb *testutil.TPMTestBase) {
	ctb.cryptTestBase.setUpTestBase(c, &ttb.BaseTest)

	c.Assert(ProvisionTPM(ttb.TPM, ProvisionModeFull, nil), IsNil)

	dir := c.MkDir()
	ctb.keyFile = dir + "/keydata"

	pinHandle := tpm2.Handle(0x0181fff0)
	c.Assert(SealKeyToTPM(ttb.TPM, ctb.tpmKey, ctb.keyFile, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PINHandle: pinHandle}), IsNil)
	pinIndex, err := ttb.TPM.CreateResourceContextFromTPM(pinHandle)
	c.Assert(err, IsNil)
	ttb.AddCleanupNVSpace(c, ttb.TPM.OwnerHandleContext(), pinIndex)

	c.Assert(ioutil.WriteFile(ctb.expectedTpmKeyFile, ctb.tpmKey, 0644), IsNil)

	// Some tests may increment the DA lockout counter
	ttb.AddCleanup(func() {
		c.Check(ttb.TPM.DictionaryAttackLockReset(ttb.TPM.LockoutHandleContext(), nil), IsNil)
	})
}

type cryptTPMSuite struct {
	testutil.TPMTestBase
	cryptTPMTestBase
}

var _ = Suite(&cryptTPMSuite{})

func (s *cryptTPMSuite) SetUpSuite(c *C) {
	s.cryptTPMTestBase.setUpSuiteBase(c)
}

func (s *cryptTPMSuite) SetUpTest(c *C) {
	s.TPMTestBase.SetUpTest(c)
	s.cryptTPMTestBase.setUpTestBase(c, &s.TPMTestBase)
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

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, 0)
	c.Assert(len(s.mockSdCryptsetup.Calls()), Equals, 1)
	c.Assert(len(s.mockSdCryptsetup.Calls()[0]), Equals, 6)

	c.Check(s.mockSdCryptsetup.Calls()[0][0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", data.volumeName, data.sourceDevicePath})
	c.Check(s.mockSdCryptsetup.Calls()[0][4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
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

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.pins))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the PIN for disk /dev/sda1:"})
	}

	c.Assert(len(s.mockSdCryptsetup.Calls()), Equals, 1)
	c.Assert(len(s.mockSdCryptsetup.Calls()[0]), Equals, 6)

	c.Check(s.mockSdCryptsetup.Calls()[0][0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", "data", "/dev/sda1"})
	c.Check(s.mockSdCryptsetup.Calls()[0][4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
	c.Check(s.mockSdCryptsetup.Calls()[0][5], Equals, "tries=1")
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPIN1(c *C) {
	// Test with a single PIN attempt.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)
	s.testActivateVolumeWithTPMSealedKeyAndPIN(c, &testActivateVolumeWithTPMSealedKeyAndPINData{
		pins:     []string{testPIN},
		pinTries: 1,
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPIN2(c *C) {
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

func (s *cryptTPMSuite) testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c *C, data *testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.pins, "\n")+"\n"), 0644), IsNil)
	c.Assert(ioutil.WriteFile(filepath.Join(s.dir, "pinfile"), []byte(data.pinFileContents), 0644), IsNil)

	r, err := os.Open(filepath.Join(s.dir, "pinfile"))
	c.Assert(err, IsNil)
	defer r.Close()

	options := ActivateWithTPMSealedKeyOptions{PINTries: data.pinTries}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, "data", "/dev/sda1", s.keyFile, r, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.pins))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the PIN for disk /dev/sda1:"})
	}

	c.Assert(len(s.mockSdCryptsetup.Calls()), Equals, 1)
	c.Assert(len(s.mockSdCryptsetup.Calls()[0]), Equals, 6)

	c.Check(s.mockSdCryptsetup.Calls()[0][0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", "data", "/dev/sda1"})
	c.Check(s.mockSdCryptsetup.Calls()[0][4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
	c.Check(s.mockSdCryptsetup.Calls()[0][5], Equals, "tries=1")
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader1(c *C) {
	// Test with the correct PIN provided via the io.Reader.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pinFileContents: testPIN + "\n",
		pinTries:        1,
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader2(c *C) {
	// Test with the correct PIN provided via the io.Reader when the file doesn't end in a newline.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pinFileContents: testPIN,
		pinTries:        1,
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader3(c *C) {
	// Test falling back to asking for a PIN if the wrong PIN is provided via the io.Reader.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pins:            []string{testPIN},
		pinFileContents: "5678" + "\n",
		pinTries:        2,
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyAndPINUsingPINReader4(c *C) {
	// Test falling back to asking for a PIN without using a try if the io.Reader has no contents.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)

	s.testActivateVolumeWithTPMSealedKeyAndPINUsingPINReader(c, &testActivateVolumeWithTPMSealedKeyAndPINUsingPINReaderData{
		pins:     []string{testPIN},
		pinTries: 1,
	})
}

type testActivateVolumeWithTPMSealedKeyErrorHandlingData struct {
	pinTries          int
	recoveryKeyTries  int
	activateOptions   []string
	passphrases       []string
	sdCryptsetupCalls int
	success           bool
	recoveryReason    RecoveryKeyUsageReason
	errChecker        Checker
	errCheckerArgs    []interface{}
}

func (s *cryptTPMSuite) testActivateVolumeWithTPMSealedKeyErrorHandling(c *C, data *testActivateVolumeWithTPMSealedKeyErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.passphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithTPMSealedKeyOptions{PINTries: data.pinTries, RecoveryKeyTries: data.recoveryKeyTries, ActivateOptions: data.activateOptions}
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
	c.Check(len(s.mockSdCryptsetup.Calls()), Equals, data.sdCryptsetupCalls)
	for _, call := range s.mockSdCryptsetup.Calls() {
		c.Assert(len(call), Equals, 6)
		c.Check(call[0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", "data", "/dev/sda1"})
		c.Check(call[4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
		c.Check(call[5], Equals, strings.Join(append(data.activateOptions, "tries=1"), ","))
	}

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
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(ProvisionTPM(s.TPM, ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		recoveryReason:    RecoveryKeyUsageReasonTPMLockout,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling5(c *C) {
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
			strings.Join(s.recoveryKeyAscii, "-"),
		},
		sdCryptsetupCalls: 2,
		success:           true,
		recoveryReason:    RecoveryKeyUsageReasonTPMProvisioningError,
		errChecker:        ErrorMatches,
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
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 2,
		success:           true,
		recoveryReason:    RecoveryKeyUsageReasonInvalidKeyFile,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot activate volume: exit status 1\\) but activation " +
			"with recovery key was successful"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling7(c *C) {
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

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling8(c *C) {
	// Test that activation fails if the wrong recovery key is provided.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(ProvisionTPM(s.TPM, ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:  1,
		passphrases:       []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		sdCryptsetupCalls: 1,
		success:           false,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) " +
			"and activation with recovery key failed \\(cannot activate volume: exit status 1\\)"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling9(c *C) {
	// Test that recovery fallback works if the wrong PIN is supplied.
	testPIN := "1234"
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", testPIN), IsNil)
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		pinTries:         1,
		recoveryKeyTries: 1,
		passphrases: []string{
			"",
			strings.Join(s.recoveryKeyAscii, "-"),
		},
		sdCryptsetupCalls: 1,
		success:           true,
		recoveryReason:    RecoveryKeyUsageReasonPINFail,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the provided PIN is incorrect\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling10(c *C) {
	// Test that recovery fallback works if a PIN is set but no PIN attempts are permitted.
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", "1234"), IsNil)
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		recoveryReason:    RecoveryKeyUsageReasonPINFail,
		errChecker:        ErrorMatches,
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
	s.cryptTPMTestBase.setUpSuiteBase(c)
}

func (s *cryptTPMSimulatorSuite) SetUpTest(c *C) {
	s.TPMSimulatorTestBase.SetUpTest(c)
	s.ResetTPMSimulator(c)
	s.cryptTPMTestBase.setUpTestBase(c, &s.TPMTestBase)
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithTPMSealedKeyErrorHandling(c *C, data *testActivateVolumeWithTPMSealedKeyErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.passphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithTPMSealedKeyOptions{PINTries: data.pinTries, RecoveryKeyTries: data.recoveryKeyTries, ActivateOptions: data.activateOptions}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, "data", "/dev/sda1", s.keyFile, nil, &options)
	c.Check(err, data.errChecker, data.errCheckerArgs...)
	c.Check(success, Equals, data.success)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.passphrases))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the recovery key for disk /dev/sda1:"})
	}
	c.Check(len(s.mockSdCryptsetup.Calls()), Equals, data.sdCryptsetupCalls)
	for _, call := range s.mockSdCryptsetup.Calls() {
		c.Assert(len(call), Equals, 6)
		c.Check(call[0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", "data", "/dev/sda1"})
		c.Check(call[4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
		c.Check(call[5], Equals, strings.Join(append(data.activateOptions, "tries=1"), ","))
	}

	if !data.success {
		return
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, data.recoveryReason)
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling1(c *C) {
	// Test that recovery fallback works when the sealed key authorization policy is wrong.
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		recoveryReason:    RecoveryKeyUsageReasonInvalidKeyFile,
		errChecker:        ErrorMatches,
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
	s.cryptTestBase.setUpSuiteBase(c)
}

func (s *cryptSuite) SetUpTest(c *C) {
	s.cryptTestBase.setUpTestBase(c, &s.BaseTest)
}

type testActivateVolumeWithRecoveryKeyData struct {
	volumeName          string
	sourceDevicePath    string
	tries               int
	activateOptions     []string
	recoveryPassphrases []string
	sdCryptsetupCalls   int
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKey(c *C, data *testActivateVolumeWithRecoveryKeyData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.recoveryPassphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithRecoveryKeyOptions{Tries: data.tries, ActivateOptions: data.activateOptions}
	c.Assert(ActivateVolumeWithRecoveryKey(data.volumeName, data.sourceDevicePath, nil, &options), IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.recoveryPassphrases))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":" + data.sourceDevicePath, "Please enter the recovery key for disk " + data.sourceDevicePath + ":"})
	}

	c.Check(len(s.mockSdCryptsetup.Calls()), Equals, data.sdCryptsetupCalls)
	for _, call := range s.mockSdCryptsetup.Calls() {
		c.Assert(len(call), Equals, 6)
		c.Check(call[0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", data.volumeName, data.sourceDevicePath})
		c.Check(call[4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
		c.Check(call[5], Equals, strings.Join(append(data.activateOptions, "tries=1"), ","))
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, RecoveryKeyUsageReasonRequested)
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey1(c *C) {
	// Test with a recovery key which is entered with a hyphen between each group of 5 digits.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:          "data",
		sourceDevicePath:    "/dev/sda1",
		tries:               1,
		recoveryPassphrases: []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:   1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey2(c *C) {
	// Test with a recovery key which is entered without a hyphen between each group of 5 digits.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:          "data",
		sourceDevicePath:    "/dev/sda1",
		tries:               1,
		recoveryPassphrases: []string{strings.Join(s.recoveryKeyAscii, "")},
		sdCryptsetupCalls:   1,
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
		recoveryPassphrases: []string{
			"1234",
			strings.Join(s.recoveryKeyAscii, "-"),
		},
		sdCryptsetupCalls: 1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey5(c *C) {
	// Test with additional options passed to systemd-cryptsetup.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:          "data",
		sourceDevicePath:    "/dev/sda1",
		tries:               1,
		activateOptions:     []string{"foo", "bar"},
		recoveryPassphrases: []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:   1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey6(c *C) {
	// Test with a different volume name / device path.
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:          "foo",
		sourceDevicePath:    "/dev/vdb2",
		tries:               1,
		recoveryPassphrases: []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:   1,
	})
}

type testActivateVolumeWithRecoveryKeyUsingKeyReaderData struct {
	tries                   int
	recoveryKeyFileContents string
	recoveryPassphrases     []string
	sdCryptsetupCalls       int
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKeyUsingKeyReader(c *C, data *testActivateVolumeWithRecoveryKeyUsingKeyReaderData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.recoveryPassphrases, "\n")+"\n"), 0644), IsNil)
	c.Assert(ioutil.WriteFile(filepath.Join(s.dir, "keyfile"), []byte(data.recoveryKeyFileContents), 0644), IsNil)

	r, err := os.Open(filepath.Join(s.dir, "keyfile"))
	c.Assert(err, IsNil)
	defer r.Close()

	options := ActivateWithRecoveryKeyOptions{Tries: data.tries}
	c.Assert(ActivateVolumeWithRecoveryKey("data", "/dev/sda1", r, &options), IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.recoveryPassphrases))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the recovery key for disk /dev/sda1:"})
	}

	c.Check(len(s.mockSdCryptsetup.Calls()), Equals, data.sdCryptsetupCalls)
	for _, call := range s.mockSdCryptsetup.Calls() {
		c.Assert(len(call), Equals, 6)
		c.Check(call[0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", "data", "/dev/sda1"})
		c.Check(call[4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
		c.Check(call[5], Equals, "tries=1")
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyKeyringEntry(c, RecoveryKeyUsageReasonRequested)
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader1(c *C) {
	// Test with the correct recovery key supplied via a io.Reader, with a hyphen separating each group of 5 digits.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:                   1,
		recoveryKeyFileContents: strings.Join(s.recoveryKeyAscii, "-") + "\n",
		sdCryptsetupCalls:       1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader2(c *C) {
	// Test with the correct recovery key supplied via a io.Reader, without a hyphen separating each group of 5 digits.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:                   1,
		recoveryKeyFileContents: strings.Join(s.recoveryKeyAscii, "") + "\n",
		sdCryptsetupCalls:       1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader3(c *C) {
	// Test with the correct recovery key supplied via a io.Reader when the key doesn't end in a newline.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:                   1,
		recoveryKeyFileContents: strings.Join(s.recoveryKeyAscii, "-"),
		sdCryptsetupCalls:       1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader4(c *C) {
	// Test that falling back to requesting a recovery key works if the one provided by the io.Reader is incorrect.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:                   2,
		recoveryKeyFileContents: "00000-00000-00000-00000-00000-00000-00000-00000\n",
		recoveryPassphrases:     []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:       2,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader5(c *C) {
	// Test that falling back to requesting a recovery key works if the one provided by the io.Reader is badly formatted.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:                   2,
		recoveryKeyFileContents: "5678\n",
		recoveryPassphrases:     []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:       1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyUsingKeyReader6(c *C) {
	// Test that falling back to requesting a recovery key works if the provided io.Reader is backed by an empty buffer,
	// without using up a try.
	s.testActivateVolumeWithRecoveryKeyUsingKeyReader(c, &testActivateVolumeWithRecoveryKeyUsingKeyReaderData{
		tries:               1,
		recoveryPassphrases: []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls:   1,
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
	sdCryptsetupCalls   int
	errChecker          Checker
	errCheckerArgs      []interface{}
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKeyErrorHandling(c *C, data *testActivateVolumeWithRecoveryKeyErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.recoveryPassphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateWithRecoveryKeyOptions{Tries: data.tries, ActivateOptions: data.activateOptions}
	c.Check(ActivateVolumeWithRecoveryKey("data", "/dev/sda1", nil, &options), data.errChecker, data.errCheckerArgs...)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, len(data.recoveryPassphrases))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":/dev/sda1", "Please enter the recovery key for disk /dev/sda1:"})
	}

	c.Check(len(s.mockSdCryptsetup.Calls()), Equals, data.sdCryptsetupCalls)
	for _, call := range s.mockSdCryptsetup.Calls() {
		c.Assert(len(call), Equals, 6)
		c.Check(call[0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", "data", "/dev/sda1"})
		c.Check(call[4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
		c.Check(call[5], Equals, "tries=1")
		c.Check(call[5], Equals, strings.Join(append(data.activateOptions, "tries=1"), ","))
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
	// Test that adding "tries=" to ActivateOptions fails.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:           1,
		activateOptions: []string{"tries=2"},
		errChecker:      ErrorMatches,
		errCheckerArgs:  []interface{}{"cannot specify the \"tries=\" option for systemd-cryptsetup"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling4(c *C) {
	// Test with a badly formatted recovery key.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:               1,
		recoveryPassphrases: []string{"00000-1234"},
		errChecker:          ErrorMatches,
		errCheckerArgs:      []interface{}{"cannot decode recovery key: incorrectly formatted: insufficient characters"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling5(c *C) {
	// Test with a badly formatted recovery key.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:               1,
		recoveryPassphrases: []string{"00000-123bc"},
		errChecker:          ErrorMatches,
		errCheckerArgs:      []interface{}{"cannot decode recovery key: incorrectly formatted: strconv.ParseUint: parsing \"123bc\": invalid syntax"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling6(c *C) {
	// Test with the wrong recovery key.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:               1,
		recoveryPassphrases: []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		sdCryptsetupCalls:   1,
		errChecker:          ErrorMatches,
		errCheckerArgs:      []interface{}{"cannot activate volume: exit status 1"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling7(c *C) {
	// Test that the last error is returned when there are consecutive failures for different reasons.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:               2,
		recoveryPassphrases: []string{"00000-00000-00000-00000-00000-00000-00000-00000", "1234"},
		sdCryptsetupCalls:   1,
		errChecker:          ErrorMatches,
		errCheckerArgs:      []interface{}{"cannot decode recovery key: incorrectly formatted: insufficient characters"},
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling8(c *C) {
	// Test with a badly formatted recovery key.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:               1,
		recoveryPassphrases: []string{"00000-00000-00000-00000-00000-00000-00000-00000-00000"},
		errChecker:          ErrorMatches,
		errCheckerArgs:      []interface{}{"cannot decode recovery key: incorrectly formatted: too many characters"},
	})
}

type testInitializeLUKS2ContainerData struct {
	devicePath string
	label      string
	key        []byte
}

func (s *cryptSuite) testInitializeLUKS2Container(c *C, data *testInitializeLUKS2ContainerData) {
	c.Check(InitializeLUKS2Container(data.devicePath, data.label, data.key), IsNil)
	c.Check(s.mockCryptsetup.Calls(), DeepEquals, [][]string{
		{"cryptsetup", "-q", "luksFormat", "--type", "luks2", "--key-file", "-", "--cipher", "aes-xts-plain64", "--key-size", "512",
			"--pbkdf", "argon2i", "--pbkdf-force-iterations", "4", "--pbkdf-memory", "32", "--label", data.label, data.devicePath},
		{"cryptsetup", "config", "--priority", "prefer", "--key-slot", "0", data.devicePath}})
	key, err := ioutil.ReadFile(s.cryptsetupKey + ".1")
	c.Assert(err, IsNil)
	c.Check(key, DeepEquals, data.key)
}

func (s *cryptSuite) TestInitializeLUKS2Container1(c *C) {
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/sda1",
		label:      "data",
		key:        s.tpmKey,
	})
}

func (s *cryptSuite) TestInitializeLUKS2Container2(c *C) {
	// Test with different args.
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/vdc2",
		label:      "test",
		key:        s.tpmKey,
	})
}

func (s *cryptSuite) TestInitializeLUKS2Container(c *C) {
	// Test with a different key
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/vdc2",
		label:      "test",
		key:        make([]byte, 64),
	})
}

func (s *cryptSuite) TestInitializeLUKS2ContainerInvalidKeySize(c *C) {
	c.Check(InitializeLUKS2Container("/dev/sda1", "data", s.tpmKey[0:32]), ErrorMatches, "expected a key length of 512-bits \\(got 256\\)")
}

type testAddRecoveryKeyToLUKS2ContainerData struct {
	devicePath  string
	key         []byte
	recoveryKey []byte
}

func (s *cryptSuite) testAddRecoveryKeyToLUKS2Container(c *C, data *testAddRecoveryKeyToLUKS2ContainerData) {
	var recoveryKey [16]byte
	copy(recoveryKey[:], data.recoveryKey)

	c.Check(AddRecoveryKeyToLUKS2Container(data.devicePath, data.key, recoveryKey), IsNil)
	c.Assert(len(s.mockCryptsetup.Calls()), Equals, 1)

	call := s.mockCryptsetup.Calls()[0]
	c.Assert(len(call), Equals, 10)
	c.Check(call[0:3], DeepEquals, []string{"cryptsetup", "luksAddKey", "--key-file"})
	c.Check(call[3], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
	c.Check(call[4:10], DeepEquals, []string{"--pbkdf", "argon2i", "--iter-time", "5000", data.devicePath, "-"})

	key, err := ioutil.ReadFile(s.cryptsetupKey + ".1")
	c.Assert(err, IsNil)
	c.Check(key, DeepEquals, data.key)

	newKey, err := ioutil.ReadFile(s.cryptsetupNewkey + ".1")
	c.Assert(err, IsNil)
	c.Check(newKey, DeepEquals, data.recoveryKey)
}

func (s *cryptSuite) TestAddRecoveryKeyToLUKS2Container1(c *C) {
	s.testAddRecoveryKeyToLUKS2Container(c, &testAddRecoveryKeyToLUKS2ContainerData{
		devicePath:  "/dev/sda1",
		key:         s.tpmKey,
		recoveryKey: s.recoveryKey,
	})
}

func (s *cryptSuite) TestAddRecoveryKeyToLUKS2Container2(c *C) {
	// Test with different path.
	s.testAddRecoveryKeyToLUKS2Container(c, &testAddRecoveryKeyToLUKS2ContainerData{
		devicePath:  "/dev/vdb2",
		key:         s.tpmKey,
		recoveryKey: s.recoveryKey,
	})
}

func (s *cryptSuite) TestAddRecoveryKeyToLUKS2Container3(c *C) {
	// Test with different key.
	s.testAddRecoveryKeyToLUKS2Container(c, &testAddRecoveryKeyToLUKS2ContainerData{
		devicePath:  "/dev/vdb2",
		key:         make([]byte, 64),
		recoveryKey: s.recoveryKey,
	})
}

func (s *cryptSuite) TestAddRecoveryKeyToLUKS2Container4(c *C) {
	// Test with different recovery key.
	s.testAddRecoveryKeyToLUKS2Container(c, &testAddRecoveryKeyToLUKS2ContainerData{
		devicePath:  "/dev/vdb2",
		key:         s.tpmKey,
		recoveryKey: make([]byte, 16),
	})
}

type testChangeLUKS2KeyUsingRecoveryKeyData struct {
	devicePath  string
	recoveryKey []byte
	key         []byte
}

func (s *cryptSuite) testChangeLUKS2KeyUsingRecoveryKey(c *C, data *testChangeLUKS2KeyUsingRecoveryKeyData) {
	var recoveryKey [16]byte
	copy(recoveryKey[:], data.recoveryKey)

	c.Check(ChangeLUKS2KeyUsingRecoveryKey(data.devicePath, recoveryKey, data.key), IsNil)
	c.Assert(len(s.mockCryptsetup.Calls()), Equals, 3)
	c.Check(s.mockCryptsetup.Calls()[0], DeepEquals, []string{"cryptsetup", "luksKillSlot", "--key-file", "-", data.devicePath, "0"})

	call := s.mockCryptsetup.Calls()[1]
	c.Assert(len(call), Equals, 14)
	c.Check(call[0:3], DeepEquals, []string{"cryptsetup", "luksAddKey", "--key-file"})
	c.Check(call[3], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
	c.Check(call[4:14], DeepEquals, []string{"--pbkdf", "argon2i", "--pbkdf-force-iterations", "4", "--pbkdf-memory", "32", "--key-slot", "0", data.devicePath, "-"})

	c.Check(s.mockCryptsetup.Calls()[2], DeepEquals, []string{"cryptsetup", "config", "--priority", "prefer", "--key-slot", "0", data.devicePath})

	key, err := ioutil.ReadFile(s.cryptsetupKey + ".1")
	c.Assert(err, IsNil)
	c.Check(key, DeepEquals, data.recoveryKey)

	key, err = ioutil.ReadFile(s.cryptsetupKey + ".2")
	c.Assert(err, IsNil)
	c.Check(key, DeepEquals, data.recoveryKey)

	key, err = ioutil.ReadFile(s.cryptsetupNewkey + ".2")
	c.Assert(err, IsNil)
	c.Check(key, DeepEquals, data.key)
}

func (s *cryptSuite) TestChangeLUKS2KeyUsingRecoveryKey1(c *C) {
	s.testChangeLUKS2KeyUsingRecoveryKey(c, &testChangeLUKS2KeyUsingRecoveryKeyData{
		devicePath:  "/dev/sda1",
		recoveryKey: s.recoveryKey,
		key:         s.tpmKey,
	})
}

func (s *cryptSuite) TestChangeLUKS2KeyUsingRecoveryKey2(c *C) {
	s.testChangeLUKS2KeyUsingRecoveryKey(c, &testChangeLUKS2KeyUsingRecoveryKeyData{
		devicePath:  "/dev/vdc1",
		recoveryKey: s.recoveryKey,
		key:         s.tpmKey,
	})
}

func (s *cryptSuite) TestChangeLUKS2KeyUsingRecoveryKey3(c *C) {
	s.testChangeLUKS2KeyUsingRecoveryKey(c, &testChangeLUKS2KeyUsingRecoveryKeyData{
		devicePath:  "/dev/sda1",
		recoveryKey: make([]byte, 16),
		key:         s.tpmKey,
	})
}

func (s *cryptSuite) TestChangeLUKS2KeyUsingRecoveryKey4(c *C) {
	s.testChangeLUKS2KeyUsingRecoveryKey(c, &testChangeLUKS2KeyUsingRecoveryKeyData{
		devicePath:  "/dev/vdc1",
		recoveryKey: s.recoveryKey,
		key:         make([]byte, 64),
	})
}
