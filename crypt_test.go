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

	passwordFile string // a newline delimited list of passwords for the mock systemd-ask-password to return

	mockKeyslotsDir   string
	mockKeyslotsCount int

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
	bt.AddCleanup(MockRunDir(ctb.dir))

	ctb.passwordFile = filepath.Join(ctb.dir, "password") // passwords to be returned by the mock sd-ask-password

	ctb.mockKeyslotsCount = 0
	ctb.mockKeyslotsDir = c.MkDir()

	ctb.cryptsetupKey = filepath.Join(ctb.dir, "cryptsetupkey")       // File in which the mock cryptsetup records the passed in key
	ctb.cryptsetupNewkey = filepath.Join(ctb.dir, "cryptsetupnewkey") // File in which the mock cryptsetup records the passed in new key
	ctb.cryptsetupInvocationCountDir = c.MkDir()

	sdAskPasswordBottom := `
head -1 %[1]s
sed -i -e '1,1d' %[1]s
`
	ctb.mockSdAskPassword = snapd_testutil.MockCommand(c, "systemd-ask-password", fmt.Sprintf(sdAskPasswordBottom, ctb.passwordFile))
	bt.AddCleanup(ctb.mockSdAskPassword.Restore)

	sdCryptsetupBottom := `
key=$(xxd -p < "$4")
for f in "%[1]s"/*; do
    if [ "$key" == "$(xxd -p < "$f")" ]; then
	exit 0
    fi
done

# use a specific error code to differentiate from arbitrary exit 1 elsewhere
exit 5
`
	ctb.mockSdCryptsetup = snapd_testutil.MockCommand(c, c.MkDir()+"/systemd-cryptsetup", fmt.Sprintf(sdCryptsetupBottom, ctb.mockKeyslotsDir))
	bt.AddCleanup(ctb.mockSdCryptsetup.Restore)
	bt.AddCleanup(MockSystemdCryptsetupPath(ctb.mockSdCryptsetup.Exe()))

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

	ctb.addMockKeyslot(c, ctb.recoveryKey)

	startKeys := getKeyringKeys(c, userKeyring)

	bt.AddCleanup(func() {
		for _, id1 := range getKeyringKeys(c, userKeyring) {
			found := false
			for _, id2 := range startKeys {
				if id1 == id2 {
					found = true
					break
				}
			}
			if found {
				continue
			}
			_, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, id1, userKeyring, 0, 0)
			c.Check(err, IsNil)
		}
	})
}

func (ctb *cryptTestBase) addMockKeyslot(c *C, key []byte) {
	c.Assert(ioutil.WriteFile(filepath.Join(ctb.mockKeyslotsDir, fmt.Sprintf("%d", ctb.mockKeyslotsCount)), key, 0644), IsNil)
	ctb.mockKeyslotsCount++
}

func (ctb *cryptTestBase) checkRecoveryActivationData(c *C, prefix, path string, requested bool, errors []KeyErrorCode) {
	// The previous tests should have all succeeded, but the following test will fail if the user keyring isn't reachable from
	// the session keyring.
	if !ctb.possessesUserKeyringKeys && !c.Failed() {
		c.ExpectFailure("Cannot possess user keys because the user keyring isn't reachable from the session keyring")
	}

	data, err := GetActivationDataFromKernel(prefix, path, false)
	c.Assert(err, IsNil)
	recoveryData, ok := data.(*RecoveryActivationData)
	c.Assert(ok, Equals, true)
	c.Check(recoveryData.Key[:], DeepEquals, ctb.recoveryKey)
	c.Check(recoveryData.Requested, Equals, requested)
	c.Check(recoveryData.ErrorCodes, DeepEquals, errors)

	data, err = GetActivationDataFromKernel(prefix, path, true)
	c.Check(err, IsNil)
	c.Check(data, NotNil)
	_, err = GetActivationDataFromKernel(prefix, path, true)
	c.Check(err, Equals, ErrNoActivationData)
}

type cryptTPMSimulatorSuite struct {
	testutil.TPMSimulatorTestBase
	cryptTestBase

	keyFile        string
	authPrivateKey TPMPolicyAuthKey
}

var _ = Suite(&cryptTPMSimulatorSuite{})

func (s *cryptTPMSimulatorSuite) SetUpSuite(c *C) {
	s.cryptTestBase.setUpSuiteBase(c)
}

func (s *cryptTPMSimulatorSuite) SetUpTest(c *C) {
	s.TPMSimulatorTestBase.SetUpTest(c)
	s.cryptTestBase.setUpTestBase(c, &s.BaseTest)

	c.Assert(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	s.ResetTPMSimulator(c)

	dir := c.MkDir()
	s.keyFile = dir + "/keydata"

	pcrPolicyCounterHandle := tpm2.Handle(0x0181fff0)
	authPrivateKey, err := SealKeyToTPM(s.TPM, s.tpmKey, s.keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: pcrPolicyCounterHandle})
	c.Assert(err, IsNil)
	s.authPrivateKey = authPrivateKey
	pcrPolicyCounter, err := s.TPM.CreateResourceContextFromTPM(pcrPolicyCounterHandle)
	c.Assert(err, IsNil)
	s.AddCleanupNVSpace(c, s.TPM.OwnerHandleContext(), pcrPolicyCounter)

	s.addMockKeyslot(c, s.tpmKey)

	// Some tests may increment the DA lockout counter
	s.AddCleanup(func() {
		c.Check(s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil), IsNil)
	})
}

func (s *cryptTPMSimulatorSuite) checkTPMPolicyAuthKey(c *C, prefix, path string, key TPMPolicyAuthKey) {
	// The previous tests should have all succeeded, but the following test will fail if the user keyring isn't reachable from
	// the session keyring.
	if !s.possessesUserKeyringKeys && !c.Failed() {
		c.ExpectFailure("Cannot possess user keys because the user keyring isn't reachable from the session keyring")
	}

	data, err := GetActivationDataFromKernel(prefix, path, false)
	c.Assert(err, IsNil)
	authKey, ok := data.(TPMPolicyAuthKey)
	c.Check(ok, Equals, true)
	c.Check(authKey, DeepEquals, key)

	data, err = GetActivationDataFromKernel(prefix, path, true)
	c.Check(err, IsNil)
	c.Check(data, NotNil)
	_, err = GetActivationDataFromKernel(prefix, path, true)
	c.Check(err, Equals, ErrNoActivationData)
}

type testActivateVolumeWithMultipleTPMSealedKeysData struct {
	volumeName        string
	sourceDevicePath  string
	keyFiles          []string
	pinTries          int
	recoveryKeyTries  int
	activateOptions   []string
	keyringPrefix     string
	sdCryptsetupCalls int
	pins              []string
	authPrivateKey    TPMPolicyAuthKey
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithMultipleTPMSealedKeys(c *C, data *testActivateVolumeWithMultipleTPMSealedKeysData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.pins, "\n")+"\n"), 0644), IsNil)

	options := ActivateVolumeOptions{
		PassphraseTries:  data.pinTries,
		RecoveryKeyTries: data.recoveryKeyTries,
		ActivateOptions:  data.activateOptions,
		KeyringPrefix:    data.keyringPrefix}
	success, err := ActivateVolumeWithMultipleTPMSealedKeys(s.TPM, data.volumeName, data.sourceDevicePath, data.keyFiles, nil, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, len(data.pins))
	for _, call := range s.mockSdAskPassword.Calls() {
		c.Check(call, DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk", "--id",
			filepath.Base(os.Args[0]) + ":" + data.sourceDevicePath, "Please enter the PIN for disk " + data.sourceDevicePath + ":"})
	}

	c.Check(len(s.mockSdCryptsetup.Calls()), Equals, data.sdCryptsetupCalls)
	for _, call := range s.mockSdCryptsetup.Calls() {
		c.Assert(call, HasLen, 6)
		c.Check(call[0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", data.volumeName, data.sourceDevicePath})
		c.Check(call[4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
		c.Check(call[5], Equals, strings.Join(append(data.activateOptions, "tries=1"), ","))
	}

	s.checkTPMPolicyAuthKey(c, data.keyringPrefix, data.sourceDevicePath, data.authPrivateKey)
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys1(c *C) {
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:        "data",
		sourceDevicePath:  "/dev/sda1",
		keyFiles:          []string{s.keyFile, keyFile},
		sdCryptsetupCalls: 1,
		authPrivateKey:    s.authPrivateKey})
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
		volumeName:        "foo",
		sourceDevicePath:  "/dev/vda2",
		keyFiles:          []string{s.keyFile, keyFile},
		sdCryptsetupCalls: 1,
		authPrivateKey:    s.authPrivateKey})
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
		volumeName:        "data",
		sourceDevicePath:  "/dev/sda1",
		keyFiles:          []string{keyFile, s.keyFile},
		sdCryptsetupCalls: 1,
		authPrivateKey:    authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys4(c *C) {
	// Test with extra options for systemd-cryptsetup.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:        "data",
		sourceDevicePath:  "/dev/sda1",
		keyFiles:          []string{s.keyFile, keyFile},
		activateOptions:   []string{"foo=bar", "baz"},
		sdCryptsetupCalls: 1,
		authPrivateKey:    s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys5(c *C) {
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
		volumeName:        "data",
		sourceDevicePath:  "/dev/sda1",
		keyFiles:          []string{s.keyFile, keyFile},
		sdCryptsetupCalls: 1,
		authPrivateKey:    s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys6(c *C) {
	// Test with 1 invalid and 1 valid key, with the invalid key being tried first.
	key := make([]byte, 64)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	pcrProfile := NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).ExtendPCR(tpm2.HashAlgorithmSHA256, 7, make([]byte, 32))
	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: pcrProfile, PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeys(c, &testActivateVolumeWithMultipleTPMSealedKeysData{
		volumeName:        "data",
		sourceDevicePath:  "/dev/sda1",
		keyFiles:          []string{keyFile, s.keyFile},
		sdCryptsetupCalls: 1,
		authPrivateKey:    s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys7(c *C) {
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
		volumeName:        "data",
		sourceDevicePath:  "/dev/sda1",
		keyFiles:          []string{keyFile, s.keyFile},
		sdCryptsetupCalls: 1,
		authPrivateKey:    s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys8(c *C) {
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
		volumeName:        "data",
		sourceDevicePath:  "/dev/sda1",
		keyFiles:          []string{s.keyFile, keyFile},
		pinTries:          1,
		sdCryptsetupCalls: 1,
		pins:              []string{"1234"},
		authPrivateKey:    s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys9(c *C) {
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
		volumeName:        "data",
		sourceDevicePath:  "/dev/sda1",
		keyFiles:          []string{s.keyFile, keyFile},
		pinTries:          1,
		sdCryptsetupCalls: 1,
		pins:              []string{"foo", "1234"},
		authPrivateKey:    authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys10(c *C) {
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
		volumeName:        "data",
		sourceDevicePath:  "/dev/sda1",
		keyFiles:          []string{s.keyFile, keyFile},
		pinTries:          2,
		sdCryptsetupCalls: 1,
		pins:              []string{"foo", "1234"},
		authPrivateKey:    s.authPrivateKey})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithMultipleTPMSealedKeys11(c *C) {
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
		volumeName:        "data",
		sourceDevicePath:  "/dev/sda1",
		keyFiles:          []string{keyFile, s.keyFile},
		pinTries:          1,
		sdCryptsetupCalls: 1,
		pins:              []string{"1234"},
		authPrivateKey:    s.authPrivateKey})
}

type testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData struct {
	keyFiles          []string
	pinTries          int
	recoveryKeyTries  int
	activateOptions   []string
	keyringPrefix     string
	passphrases       []string
	sdCryptsetupCalls int
	success           bool
	errCodes          []KeyErrorCode
	errChecker        Checker
	errCheckerArgs    []interface{}
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c *C, data *testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.passphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateVolumeOptions{
		PassphraseTries:  data.pinTries,
		RecoveryKeyTries: data.recoveryKeyTries,
		ActivateOptions:  data.activateOptions,
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
	s.checkRecoveryActivationData(c, data.keyringPrefix, "/dev/sda1", false, data.errCodes)
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
		keyFiles:          []string{s.keyFile, keyFile},
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		errCodes:          []KeyErrorCode{KeyErrorTPMLockout, KeyErrorTPMLockout},
		errChecker:        ErrorMatches,
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
		keyFiles:          []string{s.keyFile, keyFile},
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		errCodes:          []KeyErrorCode{KeyErrorTPMProvisioning, KeyErrorTPMProvisioning},
		errChecker:        ErrorMatches,
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
	c.Assert(os.RemoveAll(filepath.Join(s.mockKeyslotsDir, "1")), IsNil)
	s.addMockKeyslot(c, incorrectKey)

	keyFile := filepath.Join(c.MkDir(), "keydata2")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, IsNil)

	s.testActivateVolumeWithMultipleTPMSealedKeysErrorHandling(c, &testActivateVolumeWithMultipleTPMSealedKeysErrorHandlingData{
		keyFiles:          []string{s.keyFile, keyFile},
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 3,
		success:           true,
		errCodes:          []KeyErrorCode{KeyErrorInvalidFile, KeyErrorInvalidFile},
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot activate volume: " + s.mockSdCryptsetup.Exe() + " failed: exit status 5" +
			"\n- .*/keydata2: cannot activate volume: " + s.mockSdCryptsetup.Exe() + " failed: exit status 5" +
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
		errCodes:   []KeyErrorCode{KeyErrorTPMLockout, KeyErrorTPMLockout},
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
		keyFiles:          []string{s.keyFile, keyFile},
		sdCryptsetupCalls: 1,
		recoveryKeyTries:  1,
		passphrases:       []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		errCodes:          []KeyErrorCode{KeyErrorTPMLockout, KeyErrorTPMLockout},
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"(?sm)cannot activate with TPM sealed keys:" +
			"\n- .*/keydata: cannot unseal key: the TPM is in DA lockout mode" +
			"\n- .*/keydata2: cannot unseal key: the TPM is in DA lockout mode" +
			"\nand activation with recovery key failed: " +
			"cannot activate volume: " + s.mockSdCryptsetup.Exe() + " failed: exit status 5"},
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
		keyFiles:          []string{s.keyFile, keyFile},
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		errCodes:          []KeyErrorCode{KeyErrorPassphraseFail, KeyErrorPassphraseFail},
		errChecker:        ErrorMatches,
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
		keyFiles:          []string{s.keyFile, keyFile},
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		errCodes:          []KeyErrorCode{KeyErrorInvalidFile, KeyErrorInvalidFile},
		errChecker:        ErrorMatches,
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
		keyFiles:          []string{s.keyFile, keyFile},
		pinTries:          1,
		recoveryKeyTries:  1,
		passphrases:       []string{"foo", strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		errCodes:          []KeyErrorCode{KeyErrorPassphraseFail, KeyErrorInvalidFile},
		errChecker:        ErrorMatches,
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
			strings.Join(s.recoveryKeyAscii, "-"),
		},
		sdCryptsetupCalls: 2,
		success:           true,
		errCodes:          []KeyErrorCode{KeyErrorTPMLockout, KeyErrorTPMLockout},
		errChecker:        ErrorMatches,
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
	activateOptions  []string
	keyringPrefix    string
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithTPMSealedKeyNo2FA(c *C, data *testActivateVolumeWithTPMSealedKeyNo2FAData) {
	options := ActivateVolumeOptions{
		PassphraseTries:  data.pinTries,
		RecoveryKeyTries: data.recoveryKeyTries,
		ActivateOptions:  data.activateOptions,
		KeyringPrefix:    data.keyringPrefix}
	success, err := ActivateVolumeWithTPMSealedKey(s.TPM, data.volumeName, data.sourceDevicePath, s.keyFile, nil, &options)
	c.Check(success, Equals, true)
	c.Check(err, IsNil)

	c.Check(len(s.mockSdAskPassword.Calls()), Equals, 0)
	c.Assert(len(s.mockSdCryptsetup.Calls()), Equals, 1)
	c.Assert(len(s.mockSdCryptsetup.Calls()[0]), Equals, 6)

	c.Check(s.mockSdCryptsetup.Calls()[0][0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", data.volumeName, data.sourceDevicePath})
	c.Check(s.mockSdCryptsetup.Calls()[0][4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
	c.Check(s.mockSdCryptsetup.Calls()[0][5], Equals, strings.Join(append(data.activateOptions, "tries=1"), ","))

	s.checkTPMPolicyAuthKey(c, data.keyringPrefix, data.sourceDevicePath, s.authPrivateKey)
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
	// Test with extra options for systemd-cryptsetup.
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		activateOptions:  []string{"foo=bar", "baz"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyNo2FA5(c *C) {
	// Test with a different volume name / device path.
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "foo",
		sourceDevicePath: "/dev/vda2",
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyNo2FA6(c *C) {
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

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyNo2FA7(c *C) {
	s.testActivateVolumeWithTPMSealedKeyNo2FA(c, &testActivateVolumeWithTPMSealedKeyNo2FAData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		keyringPrefix:    "test",
	})
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

	c.Assert(len(s.mockSdCryptsetup.Calls()), Equals, 1)
	c.Assert(len(s.mockSdCryptsetup.Calls()[0]), Equals, 6)

	c.Check(s.mockSdCryptsetup.Calls()[0][0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", "data", "/dev/sda1"})
	c.Check(s.mockSdCryptsetup.Calls()[0][4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
	c.Check(s.mockSdCryptsetup.Calls()[0][5], Equals, "tries=1")

	s.checkTPMPolicyAuthKey(c, "", "/dev/sda1", s.authPrivateKey)
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

	c.Assert(len(s.mockSdCryptsetup.Calls()), Equals, 1)
	c.Assert(len(s.mockSdCryptsetup.Calls()[0]), Equals, 6)

	c.Check(s.mockSdCryptsetup.Calls()[0][0:4], DeepEquals, []string{"systemd-cryptsetup", "attach", "data", "/dev/sda1"})
	c.Check(s.mockSdCryptsetup.Calls()[0][4], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
	c.Check(s.mockSdCryptsetup.Calls()[0][5], Equals, "tries=1")

	s.checkTPMPolicyAuthKey(c, "", "/dev/sda1", s.authPrivateKey)
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
	pinTries          int
	recoveryKeyTries  int
	activateOptions   []string
	keyringPrefix     string
	passphrases       []string
	sdCryptsetupCalls int
	success           bool
	recoveryReason    KeyErrorCode
	errChecker        Checker
	errCheckerArgs    []interface{}
}

func (s *cryptTPMSimulatorSuite) testActivateVolumeWithTPMSealedKeyErrorHandling(c *C, data *testActivateVolumeWithTPMSealedKeyErrorHandlingData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.passphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateVolumeOptions{
		PassphraseTries:  data.pinTries,
		RecoveryKeyTries: data.recoveryKeyTries,
		ActivateOptions:  data.activateOptions,
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
	s.checkRecoveryActivationData(c, data.keyringPrefix, "/dev/sda1", false, []KeyErrorCode{data.recoveryReason})
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
	// Test that adding "tries=" to ActivateOptions fails.
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		activateOptions: []string{"tries=2"},
		errChecker:      ErrorMatches,
		errCheckerArgs:  []interface{}{"cannot specify the \"tries=\" option for systemd-cryptsetup"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling4(c *C) {
	// Test that recovery fallback works with the TPM in DA lockout mode.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		recoveryReason:    KeyErrorTPMLockout,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling5(c *C) {
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
		recoveryReason:    KeyErrorTPMProvisioning,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is not correctly " +
			"provisioned\\) but activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling6(c *C) {
	// Test that recovery fallback works when the unsealed key is incorrect.
	incorrectKey := make([]byte, 32)
	rand.Read(incorrectKey)
	c.Assert(os.RemoveAll(filepath.Join(s.mockKeyslotsDir, "1")), IsNil)
	s.addMockKeyslot(c, incorrectKey)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 2,
		success:           true,
		recoveryReason:    KeyErrorInvalidFile,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot activate volume: " + s.mockSdCryptsetup.Exe() +
			" failed: exit status 5\\) but activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling7(c *C) {
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

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling8(c *C) {
	// Test that activation fails if the wrong recovery key is provided.
	c.Assert(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	defer func() {
		c.Check(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)
	}()

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:  1,
		passphrases:       []string{"00000-00000-00000-00000-00000-00000-00000-00000"},
		sdCryptsetupCalls: 1,
		success:           false,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the TPM is in DA lockout mode\\) " +
			"and activation with recovery key failed \\(cannot activate volume: " + s.mockSdCryptsetup.Exe() + " failed: exit status 5\\)"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling9(c *C) {
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
		recoveryReason:    KeyErrorPassphraseFail,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: the provided PIN is incorrect\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling10(c *C) {
	// Test that recovery fallback works if a PIN is set but no PIN attempts are permitted.
	c.Assert(ChangePIN(s.TPM, s.keyFile, "", "1234"), IsNil)
	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		recoveryReason:    KeyErrorPassphraseFail,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(no PIN tries permitted when a PIN is required\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling11(c *C) {
	// Test that recovery fallback works when the sealed key authorization policy is wrong.
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:  1,
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		recoveryReason:    KeyErrorInvalidFile,
		errChecker:        ErrorMatches,
		errCheckerArgs: []interface{}{"cannot activate with TPM sealed key \\(cannot unseal key: invalid key data file: cannot complete " +
			"authorization policy assertions: cannot complete OR assertions: current session digest not found in policy data\\) but " +
			"activation with recovery key was successful"},
	})
}

func (s *cryptTPMSimulatorSuite) TestActivateVolumeWithTPMSealedKeyErrorHandling12(c *C) {
	// Test that recovery fallback works when the sealed key authorization policy is wrong, and make sure that
	// the recovery key is added to the keyring with our specified prefix
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(7), []byte("foo"), nil)
	c.Assert(err, IsNil)

	s.testActivateVolumeWithTPMSealedKeyErrorHandling(c, &testActivateVolumeWithTPMSealedKeyErrorHandlingData{
		recoveryKeyTries:  1,
		keyringPrefix:     "test",
		passphrases:       []string{strings.Join(s.recoveryKeyAscii, "-")},
		sdCryptsetupCalls: 1,
		success:           true,
		recoveryReason:    KeyErrorInvalidFile,
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
	keyringPrefix       string
	recoveryPassphrases []string
	sdCryptsetupCalls   int
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKey(c *C, data *testActivateVolumeWithRecoveryKeyData) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(strings.Join(data.recoveryPassphrases, "\n")+"\n"), 0644), IsNil)

	options := ActivateVolumeOptions{RecoveryKeyTries: data.tries, ActivateOptions: data.activateOptions, KeyringPrefix: data.keyringPrefix}
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
	s.checkRecoveryActivationData(c, data.keyringPrefix, data.sourceDevicePath, true, nil)
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

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey7(c *C) {
	// Test with a different keyring prefix
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		volumeName:          "data",
		sourceDevicePath:    "/dev/sda1",
		tries:               1,
		keyringPrefix:       "test",
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

	options := ActivateVolumeOptions{RecoveryKeyTries: data.tries}
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
	s.checkRecoveryActivationData(c, "", "/dev/sda1", true, nil)
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

	options := ActivateVolumeOptions{RecoveryKeyTries: data.tries, ActivateOptions: data.activateOptions}
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
	// Test with an invalid RecoveryKeyTries value.
	s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:          -1,
		errChecker:     ErrorMatches,
		errCheckerArgs: []interface{}{"invalid RecoveryKeyTries"},
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
		errCheckerArgs:      []interface{}{"cannot activate volume: " + s.mockSdCryptsetup.Exe() + " failed: exit status 5"},
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

type testActivateVolumeWithKeyData struct {
	activateOptions []string
	keyData         []byte
	expectedKeyData []byte
	errMatch        string
	cmdCalled       bool
}

func (s *cryptSuite) testActivateVolumeWithKey(c *C, data *testActivateVolumeWithKeyData) {
	c.Assert(data.keyData, NotNil)

	expectedKeyData := data.expectedKeyData
	if expectedKeyData == nil {
		expectedKeyData = data.keyData
	}
	s.addMockKeyslot(c, expectedKeyData)

	options := ActivateVolumeOptions{
		ActivateOptions: data.activateOptions,
	}
	err := ActivateVolumeWithKey("luks-volume", "/dev/sda1", data.keyData, &options)
	if data.errMatch == "" {
		c.Check(err, IsNil)
	} else {
		c.Check(err, ErrorMatches, data.errMatch)
	}

	if data.cmdCalled {
		c.Check(len(s.mockSdAskPassword.Calls()), Equals, 0)
		c.Assert(len(s.mockSdCryptsetup.Calls()), Equals, 1)
		c.Assert(len(s.mockSdCryptsetup.Calls()[0]), Equals, 6)

		c.Check(s.mockSdCryptsetup.Calls()[0][0:4], DeepEquals, []string{
			"systemd-cryptsetup", "attach", "luks-volume", "/dev/sda1",
		})
		c.Check(s.mockSdCryptsetup.Calls()[0][4], Matches,
			filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
		c.Check(s.mockSdCryptsetup.Calls()[0][5], Equals,
			strings.Join(append(data.activateOptions, "tries=1"), ","))
	} else {
		c.Check(len(s.mockSdAskPassword.Calls()), Equals, 0)
		c.Assert(len(s.mockSdCryptsetup.Calls()), Equals, 0)
	}
}

func (s *cryptSuite) TestActivateVolumeWithKeyNoOptions(c *C) {
	s.testActivateVolumeWithKey(c, &testActivateVolumeWithKeyData{
		activateOptions: nil,
		keyData:         []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		cmdCalled:       true,
	})
}

func (s *cryptSuite) TestActivateVolumeWithKeyWithOptions(c *C) {
	s.testActivateVolumeWithKey(c, &testActivateVolumeWithKeyData{
		activateOptions: []string{"--option"},
		keyData:         []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		cmdCalled:       true,
	})
}

func (s *cryptSuite) TestActivateVolumeWithKeyMismatchErr(c *C) {
	s.testActivateVolumeWithKey(c, &testActivateVolumeWithKeyData{
		activateOptions: []string{"--option"},
		keyData:         []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		expectedKeyData: []byte{0, 0, 0, 0, 1},
		errMatch:        ".*/systemd-cryptsetup failed: exit status 5",
		cmdCalled:       true,
	})
}

func (s *cryptSuite) TestActivateVolumeWithKeyTriesErr(c *C) {
	s.testActivateVolumeWithKey(c, &testActivateVolumeWithKeyData{
		activateOptions: []string{"tries=123"},
		keyData:         []byte{0, 0, 0, 0, 1},
		errMatch:        `cannot specify the "tries=" option for systemd-cryptsetup`,
		cmdCalled:       false,
	})
}

type testInitializeLUKS2ContainerData struct {
	devicePath string
	label      string
	key        []byte
	opts       *InitializeLUKS2ContainerOptions
	formatArgs []string
}

func (s *cryptSuite) testInitializeLUKS2Container(c *C, data *testInitializeLUKS2ContainerData) {
	c.Check(InitializeLUKS2Container(data.devicePath, data.label, data.key, data.opts), IsNil)
	formatArgs := []string{"cryptsetup",
		"-q", "luksFormat", "--type", "luks2",
		"--key-file", "-", "--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--pbkdf", "argon2i", "--iter-time", "100",
		"--label", data.label, data.devicePath,
	}
	if data.formatArgs != nil {
		formatArgs = data.formatArgs
	}
	c.Check(s.mockCryptsetup.Calls(), DeepEquals, [][]string{
		formatArgs,
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

func (s *cryptSuite) TestInitializeLUKS2ContainerWithOptions(c *C) {
	// Test with a different key
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/vdc2",
		label:      "test",
		key:        s.tpmKey,
		opts: &InitializeLUKS2ContainerOptions{
			MetadataKiBSize:     2 * 1024, // 2MiB
			KeyslotsAreaKiBSize: 3 * 1024, // 3MiB

		},
		formatArgs: []string{"cryptsetup",
			"-q", "luksFormat", "--type", "luks2",
			"--key-file", "-", "--cipher", "aes-xts-plain64",
			"--key-size", "512",
			"--pbkdf", "argon2i", "--iter-time", "100",
			"--label", "test",
			"--luks2-metadata-size", "2048k",
			"--luks2-keyslots-size", "3072k",
			"/dev/vdc2",
		},
	})
}

func (s *cryptSuite) TestInitializeLUKS2ContainerInvalidKeySize(c *C) {
	c.Check(InitializeLUKS2Container("/dev/sda1", "data", s.tpmKey[0:16], nil), ErrorMatches, "expected a key length of at least 256-bits \\(got 128\\)")
}

func (s *cryptSuite) TestInitializeLUKS2ContainerMetadataKiBSize(c *C) {
	key := make([]byte, 64)
	for _, validSz := range []int{0, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096} {
		opts := InitializeLUKS2ContainerOptions{
			MetadataKiBSize: validSz,
		}
		c.Check(InitializeLUKS2Container("/dev/sda1", "data", key, &opts), IsNil)
	}

	for _, invalidSz := range []int{1, 16 + 3, 8192, 500} {
		opts := InitializeLUKS2ContainerOptions{
			MetadataKiBSize: invalidSz,
		}
		c.Check(InitializeLUKS2Container("/dev/sda1", "data", key, &opts), ErrorMatches,
			fmt.Sprintf("cannot set metadata size to %v KiB", invalidSz))
	}
}

func (s *cryptSuite) TestInitializeLUKS2ContainerKeyslotsSize(c *C) {
	key := make([]byte, 64)
	for _, validSz := range []int{0, 4,
		128 * 1024,
		8 * 1024,
		16,
		256,
	} {
		opts := InitializeLUKS2ContainerOptions{
			KeyslotsAreaKiBSize: validSz,
		}
		c.Check(InitializeLUKS2Container("/dev/sda1", "data", key, &opts), IsNil)
	}

	for _, invalidSz := range []int{
		// smaller than 4096 (4KiB)
		1, 3,
		// misaligned
		40 + 1,
		// larger than 128MB
		128*1024 + 4,
	} {
		opts := InitializeLUKS2ContainerOptions{
			KeyslotsAreaKiBSize: invalidSz,
		}
		c.Check(InitializeLUKS2Container("/dev/sda1", "data", key, &opts), ErrorMatches,
			fmt.Sprintf("cannot set keyslots area size to %v KiB", invalidSz))
	}
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
	c.Assert(len(call), Equals, 12)
	c.Check(call[0:3], DeepEquals, []string{"cryptsetup", "luksAddKey", "--key-file"})
	c.Check(call[3], Matches, filepath.Join(s.dir, filepath.Base(os.Args[0]))+"\\.[0-9]+/fifo")
	c.Check(call[4:12], DeepEquals, []string{"--pbkdf", "argon2i", "--iter-time", "100", "--key-slot", "0", data.devicePath, "-"})

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
