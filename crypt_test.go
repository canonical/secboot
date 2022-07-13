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
	"crypto"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"time"

	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luks2/luks2test"
	"github.com/snapcore/secboot/internal/paths/pathstest"
	"github.com/snapcore/secboot/internal/testutil"
)

type cryptTestBase struct{}

func (ctb *cryptTestBase) newPrimaryKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func (ctb *cryptTestBase) newRecoveryKey() RecoveryKey {
	var key RecoveryKey
	rand.Read(key[:])
	return key
}

type mockAuthRequestor struct {
	passphraseResponses []interface{}
	passphraseRequests  []struct {
		volumeName       string
		sourceDevicePath string
	}

	recoveryKeyResponses []interface{}
	recoveryKeyRequests  []struct {
		volumeName       string
		sourceDevicePath string
	}
}

func (r *mockAuthRequestor) RequestPassphrase(volumeName, sourceDevicePath string) (string, error) {
	r.passphraseRequests = append(r.passphraseRequests, struct {
		volumeName       string
		sourceDevicePath string
	}{
		volumeName:       volumeName,
		sourceDevicePath: sourceDevicePath,
	})

	if len(r.passphraseResponses) == 0 {
		return "", errors.New("empty response")
	}
	response := r.passphraseResponses[0]
	r.passphraseResponses = r.passphraseResponses[1:]

	switch rsp := response.(type) {
	case string:
		return rsp, nil
	case error:
		return "", rsp
	default:
		panic("invalid type")
	}
}

func (r *mockAuthRequestor) RequestRecoveryKey(volumeName, sourceDevicePath string) (RecoveryKey, error) {
	r.recoveryKeyRequests = append(r.recoveryKeyRequests, struct {
		volumeName       string
		sourceDevicePath string
	}{
		volumeName:       volumeName,
		sourceDevicePath: sourceDevicePath,
	})

	if len(r.recoveryKeyResponses) == 0 {
		return RecoveryKey{}, errors.New("empty response")
	}
	response := r.recoveryKeyResponses[0]
	r.recoveryKeyResponses = r.recoveryKeyResponses[1:]

	switch rsp := response.(type) {
	case RecoveryKey:
		return rsp, nil
	case error:
		return RecoveryKey{}, rsp
	default:
		panic("invalid type")
	}
}

// mockLUKS2Container represents a LUKS2 container and its associated state
type mockLUKS2Container struct {
	keyslots map[int][]byte
}

func (c *mockLUKS2Container) nextFreeSlot() (slot int) {
	var slots []int
	for i := range c.keyslots {
		slots = append(slots, i)
	}
	sort.Ints(slots)
	for _, i := range slots {
		if i != slot {
			break
		}
		slot++
	}
	return slot
}

// mockLUKS2 mocks a device's global LUKS2 state. It provides mock
// implementations of the various LUKS2 operations.
type mockLUKS2 struct {
	operations []string                       // A log of LUKS2 operations recorded during a test
	devices    map[string]*mockLUKS2Container // A map of device paths to mocked containers
	activated  map[string]string              // A map of volume names to device paths for activated containers.
}

func (l *mockLUKS2) activate(volumeName, sourceDevicePath string, key []byte) error {
	l.operations = append(l.operations, "Activate("+volumeName+","+sourceDevicePath+")")

	if _, exists := l.activated[volumeName]; exists {
		return errors.New("systemd-cryptsetup failed with: exit status 1")
	}

	dev, ok := l.devices[sourceDevicePath]
	if !ok {
		return errors.New("systemd-cryptsetup failed with: exit status 1")
	}

	for _, k := range dev.keyslots {
		if bytes.Equal(k, key) {
			l.activated[volumeName] = sourceDevicePath
			return nil
		}
	}

	return errors.New("systemd-cryptsetup failed with: exit status 1")
}

func (l *mockLUKS2) addKey(devicePath string, existingKey, key []byte, options *luks2.AddKeyOptions) error {
	l.operations = append(l.operations, fmt.Sprint("AddKey(", devicePath, ",", options, ")"))

	if options == nil {
		options = &luks2.AddKeyOptions{Slot: luks2.AnySlot}
	}

	dev, ok := l.devices[devicePath]
	if !ok {
		return errors.New("no container")
	}

	var slot int
	switch {
	case options.Slot == luks2.AnySlot:
		slot = dev.nextFreeSlot()
	case options.Slot < 0:
		return errors.New("invalid slot")
	default:
		if _, exists := dev.keyslots[options.Slot]; exists {
			return errors.New("slot already in use")
		}
		slot = options.Slot
	}

	found := false
	for _, k := range dev.keyslots {
		if bytes.Equal(k, existingKey) {
			found = true
			break
		}
	}
	if !found {
		return errors.New("invalid key")
	}

	dev.keyslots[slot] = key
	return nil
}

func (l *mockLUKS2) deactivate(volumeName string) error {
	l.operations = append(l.operations, "Deactivate("+volumeName+")")

	if _, exists := l.activated[volumeName]; !exists {
		return errors.New("systemd-cryptsetup failed with: exit status 1")
	}

	delete(l.activated, volumeName)
	return nil
}

func (l *mockLUKS2) format(devicePath, label string, key []byte, options *luks2.FormatOptions) error {
	l.operations = append(l.operations, fmt.Sprint("Format(", devicePath, ",", label, ",", options, ")"))

	l.devices[devicePath] = &mockLUKS2Container{keyslots: map[int][]byte{0: key}}
	return nil
}

func (l *mockLUKS2) killSlot(devicePath string, slot int, key []byte) error {
	l.operations = append(l.operations, fmt.Sprint("KillSlot(", devicePath, ",", slot, ")"))

	if slot < 0 {
		return errors.New("invalid slot")
	}

	dev, ok := l.devices[devicePath]
	if !ok {
		return errors.New("no container")
	}

	if _, exists := dev.keyslots[slot]; !exists {
		return errors.New("no slot")
	}

	if len(dev.keyslots) == 1 {
		if !bytes.Equal(key, dev.keyslots[slot]) {
			return errors.New("invalid key")
		}
	} else {
		found := false
		for _, k := range dev.keyslots {
			if bytes.Equal(key, k) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("invalid key")
		}
	}

	delete(dev.keyslots, slot)
	return nil
}

func (l *mockLUKS2) setSlotPriority(devicePath string, slot int, priority luks2.SlotPriority) error {
	l.operations = append(l.operations, fmt.Sprint("SetSlotPriority(", devicePath, ",", slot, ",", priority, ")"))

	if _, ok := l.devices[devicePath]; !ok {
		return errors.New("no container")
	}
	return nil
}

type cryptSuite struct {
	cryptTestBase
	keyDataTestBase
	testutil.KeyringTestBase

	luks2 *mockLUKS2
}

var _ = Suite(&cryptSuite{})

func (s *cryptSuite) SetUpSuite(c *C) {
	s.keyDataTestBase.SetUpSuite(c)
	s.KeyringTestBase.SetUpSuite(c)
}

func (s *cryptSuite) SetUpTest(c *C) {
	s.keyDataTestBase.SetUpTest(c)
	s.KeyringTestBase.SetUpTest(c)

	s.handler.passphraseSupport = true

	s.AddCleanup(pathstest.MockRunDir(c.MkDir()))

	s.luks2 = &mockLUKS2{
		devices:   make(map[string]*mockLUKS2Container),
		activated: make(map[string]string)}

	restore := MockLUKS2Activate(s.luks2.activate)
	s.AddCleanup(restore)
	restore = MockLUKS2AddKey(s.luks2.addKey)
	s.AddCleanup(restore)
	restore = MockLUKS2Deactivate(s.luks2.deactivate)
	s.AddCleanup(restore)
	restore = MockLUKS2Format(s.luks2.format)
	s.AddCleanup(restore)
	restore = MockLUKS2KillSlot(s.luks2.killSlot)
	s.AddCleanup(restore)
	restore = MockLUKS2SetSlotPriority(s.luks2.setSlotPriority)
	s.AddCleanup(restore)
}

func (s *cryptSuite) addMockKeyslot(path string, key []byte) {
	dev, ok := s.luks2.devices[path]
	if !ok {
		dev = &mockLUKS2Container{keyslots: make(map[int][]byte)}
		s.luks2.devices[path] = dev
	}
	dev.keyslots[dev.nextFreeSlot()] = key
}

func (s *cryptSuite) checkRecoveryKeyInKeyring(c *C, prefix, path string, expected RecoveryKey) {
	// The following test will fail if the user keyring isn't reachable from the session keyring. If the test have succeeded
	// so far, mark the current test as expected to fail.
	if !s.ProcessPossessesUserKeyringKeys && !c.Failed() {
		c.ExpectFailure("Cannot possess user keys because the user keyring isn't reachable from the session keyring")
	}

	key, err := GetDiskUnlockKeyFromKernel(prefix, path, false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, DiskUnlockKey(expected[:]))
}

func (s *cryptSuite) checkKeyDataKeysInKeyring(c *C, prefix, path string, expectedKey DiskUnlockKey, expectedAuxKey AuxiliaryKey) {
	// The following test will fail if the user keyring isn't reachable from the session keyring. If the test have succeeded
	// so far, mark the current test as expected to fail.
	if !s.ProcessPossessesUserKeyringKeys && !c.Failed() {
		c.ExpectFailure("Cannot possess user keys because the user keyring isn't reachable from the session keyring")
	}

	key, err := GetDiskUnlockKeyFromKernel(prefix, path, false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, expectedKey)

	auxKey, err := GetAuxiliaryKeyFromKernel(prefix, path, false)
	c.Check(err, IsNil)
	c.Check(auxKey, DeepEquals, expectedAuxKey)
}

func (s *cryptSuite) newMultipleNamedKeyData(c *C, names ...string) (keyData []*KeyData, keys []DiskUnlockKey, auxKeys []AuxiliaryKey) {
	for _, name := range names {
		key, auxKey := s.newKeyDataKeys(c, 32, 32)
		protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

		kd, err := NewKeyData(protected)
		c.Assert(err, IsNil)

		w := makeMockKeyDataWriter()
		c.Check(kd.WriteAtomic(w), IsNil)

		r := &mockKeyDataReader{name, w.Reader()}
		kd, err = ReadKeyData(r)
		c.Assert(err, IsNil)

		keyData = append(keyData, kd)
		keys = append(keys, key)
		auxKeys = append(auxKeys, auxKey)
	}

	return keyData, keys, auxKeys
}

func (s *cryptSuite) newNamedKeyData(c *C, name string) (*KeyData, DiskUnlockKey, AuxiliaryKey) {
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, name)
	return keyData[0], keys[0], auxKeys[0]
}

type testActivateVolumeWithRecoveryKeyData struct {
	recoveryKey      RecoveryKey
	volumeName       string
	sourceDevicePath string
	tries            int
	keyringPrefix    string
	authResponses    []interface{}
	activateTries    int
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKey(c *C, data *testActivateVolumeWithRecoveryKeyData) {
	s.addMockKeyslot(data.sourceDevicePath, data.recoveryKey[:])

	authRequestor := &mockAuthRequestor{recoveryKeyResponses: data.authResponses}
	options := ActivateVolumeOptions{RecoveryKeyTries: data.tries, KeyringPrefix: data.keyringPrefix}

	c.Assert(ActivateVolumeWithRecoveryKey(data.volumeName, data.sourceDevicePath, authRequestor, &options), IsNil)

	c.Check(authRequestor.recoveryKeyRequests, HasLen, len(data.authResponses))
	for _, rsp := range authRequestor.recoveryKeyRequests {
		c.Check(rsp.volumeName, Equals, data.volumeName)
		c.Check(rsp.sourceDevicePath, Equals, data.sourceDevicePath)
	}

	c.Assert(s.luks2.operations, HasLen, data.activateTries)
	for _, op := range s.luks2.operations {
		c.Check(op, Equals, "Activate("+data.volumeName+","+data.sourceDevicePath+")")
	}

	// This should be done last because it may fail in some circumstances.
	s.checkRecoveryKeyInKeyring(c, data.keyringPrefix, data.sourceDevicePath, data.recoveryKey)
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey1(c *C) {
	// Test with the correct recovery key.
	recoveryKey := s.newRecoveryKey()
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		recoveryKey:      recoveryKey,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		tries:            1,
		authResponses:    []interface{}{recoveryKey},
		activateTries:    1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey2(c *C) {
	// Test that activation succeeds when the correct recovery key is provided on the second attempt.
	recoveryKey := s.newRecoveryKey()
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		recoveryKey:      recoveryKey,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		tries:            2,
		authResponses:    []interface{}{RecoveryKey{}, recoveryKey},
		activateTries:    2,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey3(c *C) {
	// Test that activation succeeds when the correct recovery key is provided on the second attempt, and the first
	// attempt is an error.
	recoveryKey := s.newRecoveryKey()
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		recoveryKey:      recoveryKey,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		tries:            2,
		authResponses:    []interface{}{errors.New(""), recoveryKey},
		activateTries:    1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey4(c *C) {
	// Test with a different volume name / device path.
	recoveryKey := s.newRecoveryKey()
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		recoveryKey:      recoveryKey,
		volumeName:       "foo",
		sourceDevicePath: "/dev/vdb2",
		tries:            1,
		authResponses:    []interface{}{recoveryKey},
		activateTries:    1,
	})
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKey5(c *C) {
	// Test with a different keyring prefix
	recoveryKey := s.newRecoveryKey()
	s.testActivateVolumeWithRecoveryKey(c, &testActivateVolumeWithRecoveryKeyData{
		recoveryKey:      recoveryKey,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		tries:            1,
		keyringPrefix:    "test",
		authResponses:    []interface{}{recoveryKey},
		activateTries:    1,
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
	tries         int
	authRequestor *mockAuthRequestor
	activateTries int
}

func (s *cryptSuite) testActivateVolumeWithRecoveryKeyErrorHandling(c *C, data *testActivateVolumeWithRecoveryKeyErrorHandlingData) error {
	recoveryKey := s.newRecoveryKey()
	s.addMockKeyslot("/dev/sda1", recoveryKey[:])

	var authRequestor AuthRequestor
	var numResponses int
	if data.authRequestor != nil {
		authRequestor = data.authRequestor
		numResponses = len(data.authRequestor.recoveryKeyResponses)
	}

	options := ActivateVolumeOptions{RecoveryKeyTries: data.tries}
	err := ActivateVolumeWithRecoveryKey("data", "/dev/sda1", authRequestor, &options)

	if data.authRequestor != nil {
		c.Check(data.authRequestor.recoveryKeyRequests, HasLen, numResponses)
		for _, rsp := range data.authRequestor.recoveryKeyRequests {
			c.Check(rsp.volumeName, Equals, "data")
			c.Check(rsp.sourceDevicePath, Equals, "/dev/sda1")
		}
	}

	c.Assert(s.luks2.operations, HasLen, data.activateTries)
	for _, op := range s.luks2.operations {
		c.Check(op, Equals, "Activate(data,/dev/sda1)")
	}

	return err
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling1(c *C) {
	// Test with an invalid RecoveryKeyTries value.
	c.Check(s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:         -1,
		authRequestor: &mockAuthRequestor{},
	}), ErrorMatches, "invalid RecoveryKeyTries")
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling2(c *C) {
	// Test with Tries set to zero.
	c.Check(s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:         0,
		authRequestor: &mockAuthRequestor{},
	}), ErrorMatches, "no recovery key tries permitted")
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling3(c *C) {
	// Test with no auth requestor
	c.Check(s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries: 1,
	}), ErrorMatches, "nil authRequestor")
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling4(c *C) {
	// Test with the auth requestor returning an error.
	c.Check(s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:         1,
		authRequestor: &mockAuthRequestor{recoveryKeyResponses: []interface{}{errors.New("some error")}},
	}), ErrorMatches, "cannot obtain recovery key: some error")
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling5(c *C) {
	// Test with the wrong recovery key.
	c.Check(s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:         1,
		authRequestor: &mockAuthRequestor{recoveryKeyResponses: []interface{}{RecoveryKey{}}},
		activateTries: 1,
	}), ErrorMatches, "cannot activate volume: systemd-cryptsetup failed with: exit status 1")
}

func (s *cryptSuite) TestActivateVolumeWithRecoveryKeyErrorHandling6(c *C) {
	// Test that the last error is returned when there are consecutive failures for different reasons.
	c.Check(s.testActivateVolumeWithRecoveryKeyErrorHandling(c, &testActivateVolumeWithRecoveryKeyErrorHandlingData{
		tries:         2,
		authRequestor: &mockAuthRequestor{recoveryKeyResponses: []interface{}{errors.New("some error"), errors.New("another error")}},
		activateTries: 0,
	}), ErrorMatches, "cannot obtain recovery key: another error")
}

type testActivateVolumeWithKeyDataData struct {
	authorizedModels []SnapModel
	passphrase       string
	volumeName       string
	sourceDevicePath string
	passphraseTries  int
	keyringPrefix    string
	authResponses    []interface{}
	model            SnapModel
}

func (s *cryptSuite) testActivateVolumeWithKeyData(c *C, data *testActivateVolumeWithKeyDataData) {
	keyData, key, auxKey := s.newNamedKeyData(c, "")
	s.addMockKeyslot(data.sourceDevicePath, key)

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, data.authorizedModels...), IsNil)

	authRequestor := &mockAuthRequestor{passphraseResponses: data.authResponses}

	var kdf mockKDF
	if data.passphrase != "" {
		c.Check(keyData.SetPassphrase(data.passphrase, nil, &kdf), IsNil)
	}

	options := &ActivateVolumeOptions{
		PassphraseTries: data.passphraseTries,
		KeyringPrefix:   data.keyringPrefix,
		Model:           data.model}
	err := ActivateVolumeWithKeyData(data.volumeName, data.sourceDevicePath, keyData, authRequestor, &kdf, options)
	c.Assert(err, IsNil)

	c.Check(s.luks2.operations, DeepEquals, []string{"Activate(" + data.volumeName + "," + data.sourceDevicePath + ")"})

	c.Check(authRequestor.passphraseRequests, HasLen, len(data.authResponses))
	for _, rsp := range authRequestor.passphraseRequests {
		c.Check(rsp.volumeName, Equals, data.volumeName)
		c.Check(rsp.sourceDevicePath, Equals, data.sourceDevicePath)
	}

	// This should be done last because it may fail in some circumstances.
	s.checkKeyDataKeysInKeyring(c, data.keyringPrefix, data.sourceDevicePath, key, auxKey)
}

func (s *cryptSuite) TestActivateVolumeWithKeyData1(c *C) {
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	s.testActivateVolumeWithKeyData(c, &testActivateVolumeWithKeyDataData{
		authorizedModels: models,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		model:            models[0]})
}

func (s *cryptSuite) TestActivateVolumeWithKeyData2(c *C) {
	// Test with different volumeName / sourceDevicePath
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	s.testActivateVolumeWithKeyData(c, &testActivateVolumeWithKeyDataData{
		authorizedModels: models,
		volumeName:       "foo",
		sourceDevicePath: "/dev/vda2",
		model:            models[0]})
}

func (s *cryptSuite) TestActivateVolumeWithKeyData3(c *C) {
	// Test with different authorized models
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	s.testActivateVolumeWithKeyData(c, &testActivateVolumeWithKeyDataData{
		authorizedModels: models,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		model:            models[0]})
}

func (s *cryptSuite) TestActivateVolumeWithKeyData4(c *C) {
	// Test that skipping the snap model check works
	s.testActivateVolumeWithKeyData(c, &testActivateVolumeWithKeyDataData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		model:            SkipSnapModelCheck})
}

func (s *cryptSuite) TestActivateVolumeWithKeyData5(c *C) {
	// Test with passphrase
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	s.testActivateVolumeWithKeyData(c, &testActivateVolumeWithKeyDataData{
		passphrase:       "1234",
		authorizedModels: models,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		passphraseTries:  1,
		authResponses:    []interface{}{"1234"},
		model:            models[0]})
}

func (s *cryptSuite) TestActivateVolumeWithKeyData6(c *C) {
	// Test with passphrase using multiple tries
	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	s.testActivateVolumeWithKeyData(c, &testActivateVolumeWithKeyDataData{
		passphrase:       "1234",
		authorizedModels: models,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		passphraseTries:  3,
		authResponses:    []interface{}{"incorrect", "1234"},
		model:            models[0]})
}

type testActivateVolumeWithKeyDataErrorHandlingData struct {
	primaryKey  DiskUnlockKey
	recoveryKey RecoveryKey

	authRequestor *mockAuthRequestor

	passphraseTries  int
	recoveryKeyTries int
	keyringPrefix    string
	kdf              KDF

	keyData *KeyData

	model SnapModel

	activateTries int
}

func (s *cryptSuite) testActivateVolumeWithKeyDataErrorHandling(c *C, data *testActivateVolumeWithKeyDataErrorHandlingData) error {
	s.addMockKeyslot("/dev/sda1", data.primaryKey)
	s.addMockKeyslot("/dev/sda1", data.recoveryKey[:])

	var authRequestor AuthRequestor
	var numPassphraseResponses int
	var numRecoveryResponses int
	if data.authRequestor != nil {
		authRequestor = data.authRequestor
		numPassphraseResponses = len(data.authRequestor.passphraseResponses)
		numRecoveryResponses = len(data.authRequestor.recoveryKeyResponses)
	}

	options := &ActivateVolumeOptions{
		PassphraseTries:  data.passphraseTries,
		RecoveryKeyTries: data.recoveryKeyTries,
		KeyringPrefix:    data.keyringPrefix,
		Model:            data.model}
	err := ActivateVolumeWithKeyData("data", "/dev/sda1", data.keyData, authRequestor, data.kdf, options)

	if data.authRequestor != nil {
		c.Check(data.authRequestor.passphraseRequests, HasLen, numPassphraseResponses)
		for _, rsp := range data.authRequestor.passphraseRequests {
			c.Check(rsp.volumeName, Equals, "data")
			c.Check(rsp.sourceDevicePath, Equals, "/dev/sda1")
		}

		c.Check(data.authRequestor.recoveryKeyRequests, HasLen, numRecoveryResponses)
		for _, rsp := range data.authRequestor.recoveryKeyRequests {
			c.Check(rsp.volumeName, Equals, "data")
			c.Check(rsp.sourceDevicePath, Equals, "/dev/sda1")
		}
	}

	c.Assert(s.luks2.operations, HasLen, data.activateTries)
	for _, op := range s.luks2.operations {
		c.Check(op, Equals, "Activate(data,/dev/sda1)")
	}

	if err == ErrRecoveryKeyUsed {
		// This should be done last because it may fail in some circumstances.
		s.checkRecoveryKeyInKeyring(c, data.keyringPrefix, "/dev/sda1", data.recoveryKey)
	}

	return err
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling1(c *C) {
	// Test with an invalid value for RecoveryKeyTries.
	keyData, _, _ := s.newNamedKeyData(c, "")

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		recoveryKeyTries: -1,
		keyData:          keyData,
	}), ErrorMatches, "invalid RecoveryKeyTries")
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling2(c *C) {
	// Test that recovery fallback works with the platform is unavailable
	keyData, key, _ := s.newNamedKeyData(c, "")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUnavailable

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		primaryKey:       key,
		recoveryKey:      recoveryKey,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{recoveryKey}},
		recoveryKeyTries: 1,
		keyData:          keyData,
		model:            SkipSnapModelCheck,
		activateTries:    1,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling3(c *C) {
	// Test that recovery fallback works when the platform device isn't properly initialized
	keyData, key, _ := s.newNamedKeyData(c, "")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUninitialized

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		primaryKey:       key,
		recoveryKey:      recoveryKey,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{recoveryKey}},
		recoveryKeyTries: 1,
		keyData:          keyData,
		model:            SkipSnapModelCheck,
		activateTries:    1,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling4(c *C) {
	// Test that recovery fallback works when the recovered key is incorrect
	keyData, _, _ := s.newNamedKeyData(c, "")
	recoveryKey := s.newRecoveryKey()

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		recoveryKey:      recoveryKey,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{recoveryKey}},
		recoveryKeyTries: 1,
		keyData:          keyData,
		model:            SkipSnapModelCheck,
		activateTries:    2,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling5(c *C) {
	// Test that activation fails if RecoveryKeyTries is zero.
	keyData, key, _ := s.newNamedKeyData(c, "foo")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUnavailable

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		primaryKey:       key,
		recoveryKey:      recoveryKey,
		recoveryKeyTries: 0,
		keyData:          keyData,
		model:            SkipSnapModelCheck,
		activateTries:    0,
	}), ErrorMatches,
		"cannot activate with platform protected keys:\n"+
			"- foo: cannot recover key: the platform's secure device is unavailable: the "+
			"platform device is unavailable\n"+
			"and activation with recovery key failed: no recovery key tries permitted")
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling6(c *C) {
	// Test that activation fails if the supplied recovery key is incorrect
	keyData, key, _ := s.newNamedKeyData(c, "bar")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUnavailable

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		primaryKey:       key,
		recoveryKey:      recoveryKey,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{RecoveryKey{}}},
		recoveryKeyTries: 1,
		keyData:          keyData,
		model:            SkipSnapModelCheck,
		activateTries:    1,
	}), ErrorMatches,
		"cannot activate with platform protected keys:\n"+
			"- bar: cannot recover key: the platform's secure device is unavailable: the "+
			"platform device is unavailable\n"+
			"and activation with recovery key failed: cannot activate volume: "+
			"systemd-cryptsetup failed with: exit status 1")
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling7(c *C) {
	// Test that recovery fallback works if the correct key is eventually supplied
	keyData, key, _ := s.newNamedKeyData(c, "")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUnavailable

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		primaryKey:       key,
		recoveryKey:      recoveryKey,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{RecoveryKey{}, recoveryKey}},
		recoveryKeyTries: 2,
		keyData:          keyData,
		model:            SkipSnapModelCheck,
		activateTries:    2,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling8(c *C) {
	// Test that recovery fallback works if the correct key is eventually supplied
	keyData, key, _ := s.newNamedKeyData(c, "")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUnavailable

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		primaryKey:       key,
		recoveryKey:      recoveryKey,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{errors.New("some error"), recoveryKey}},
		recoveryKeyTries: 2,
		keyData:          keyData,
		model:            SkipSnapModelCheck,
		activateTries:    1,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling9(c *C) {
	// Test that we get an error if no AuthRequestor is supplied but recovery key
	// tries are permitted.
	keyData, _, _ := s.newNamedKeyData(c, "")

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		recoveryKeyTries: 1,
		keyData:          keyData,
		model:            SkipSnapModelCheck,
	}), ErrorMatches, "nil authRequestor")
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling10(c *C) {
	// Test that recovery key fallback works if the wrong passphrase is supplied.
	keyData, key, _ := s.newNamedKeyData(c, "foo")
	recoveryKey := s.newRecoveryKey()

	var kdf mockKDF
	c.Check(keyData.SetPassphrase("1234", nil, &kdf), IsNil)

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		primaryKey:  key,
		recoveryKey: recoveryKey,
		authRequestor: &mockAuthRequestor{
			passphraseResponses:  []interface{}{"incorrect", "invalid"},
			recoveryKeyResponses: []interface{}{recoveryKey}},
		passphraseTries:  2,
		recoveryKeyTries: 2,
		kdf:              &kdf,
		keyData:          keyData,
		model:            SkipSnapModelCheck,
		activateTries:    1,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling11(c *C) {
	// Test that we get an error if no AuthRequestor is supplied but passphrase
	// tries are permitted.
	keyData, _, _ := s.newNamedKeyData(c, "")

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		passphraseTries: 1,
		keyData:         keyData,
		model:           SkipSnapModelCheck,
	}), ErrorMatches, "nil authRequestor")
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling12(c *C) {
	// Test that we get an error if no KDF is supplied but passphrase tries
	// are permitted.
	keyData, _, _ := s.newNamedKeyData(c, "")

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		passphraseTries: 1,
		keyData:         keyData,
		model:           SkipSnapModelCheck,
		authRequestor:   &mockAuthRequestor{},
	}), ErrorMatches, "nil kdf")
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling13(c *C) {
	// Test that activation fails if the supplied passphrase and recovery key are incorrect
	keyData, key, _ := s.newNamedKeyData(c, "bar")
	recoveryKey := s.newRecoveryKey()

	var kdf mockKDF
	c.Check(keyData.SetPassphrase("1234", nil, &kdf), IsNil)

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		primaryKey:  key,
		recoveryKey: recoveryKey,
		authRequestor: &mockAuthRequestor{
			passphraseResponses:  []interface{}{""},
			recoveryKeyResponses: []interface{}{RecoveryKey{}}},
		passphraseTries:  1,
		recoveryKeyTries: 1,
		kdf:              &kdf,
		keyData:          keyData,
		model:            SkipSnapModelCheck,
		activateTries:    1,
	}), ErrorMatches, "cannot activate with platform protected keys:\n"+
		"- bar: cannot recover key: the supplied passphrase is incorrect\n"+
		"and activation with recovery key failed: cannot activate volume: "+
		"systemd-cryptsetup failed with: exit status 1")
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling14(c *C) {
	// Test with an invalid value for SnapModel
	keyData, _, _ := s.newNamedKeyData(c, "")

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		keyData: keyData,
	}), ErrorMatches, "nil Model")
}

func (s *cryptSuite) TestActivateVolumeWithKeyDataErrorHandling15(c *C) {
	// Test that activation fails if the supplied model is not authorized
	keyData, key, _ := s.newNamedKeyData(c, "foo")
	recoveryKey := s.newRecoveryKey()

	c.Check(s.testActivateVolumeWithKeyDataErrorHandling(c, &testActivateVolumeWithKeyDataErrorHandlingData{
		primaryKey:       key,
		recoveryKey:      recoveryKey,
		recoveryKeyTries: 0,
		keyData:          keyData,
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		activateTries: 0,
	}), ErrorMatches, "cannot activate with platform protected keys:\n"+
		"- foo: snap model is not authorized\n"+
		"and activation with recovery key failed: no recovery key tries permitted")
}

type testActivateVolumeWithMultipleKeyDataData struct {
	keys    []DiskUnlockKey
	keyData []*KeyData

	volumeName       string
	sourceDevicePath string
	passphraseTries  int
	keyringPrefix    string

	model SnapModel

	authResponses []interface{}

	activateTries int

	key    DiskUnlockKey
	auxKey AuxiliaryKey
}

func (s *cryptSuite) testActivateVolumeWithMultipleKeyData(c *C, data *testActivateVolumeWithMultipleKeyDataData) {
	for _, k := range data.keys {
		s.addMockKeyslot(data.sourceDevicePath, k)
	}

	authRequestor := &mockAuthRequestor{passphraseResponses: data.authResponses}

	var kdf mockKDF
	options := &ActivateVolumeOptions{
		PassphraseTries: data.passphraseTries,
		KeyringPrefix:   data.keyringPrefix,
		Model:           data.model}
	err := ActivateVolumeWithMultipleKeyData(data.volumeName, data.sourceDevicePath, data.keyData, authRequestor, &kdf, options)
	c.Assert(err, IsNil)

	c.Check(authRequestor.passphraseRequests, HasLen, len(data.authResponses))
	for _, rsp := range authRequestor.passphraseRequests {
		c.Check(rsp.volumeName, Equals, data.volumeName)
		c.Check(rsp.sourceDevicePath, Equals, data.sourceDevicePath)
	}

	c.Assert(s.luks2.operations, HasLen, data.activateTries)
	for _, op := range s.luks2.operations {
		c.Check(op, Equals, "Activate("+data.volumeName+","+data.sourceDevicePath+")")
	}

	// This should be done last because it may fail in some circumstances.
	s.checkKeyDataKeysInKeyring(c, data.keyringPrefix, data.sourceDevicePath, data.key, data.auxKey)
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyData1(c *C) {
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, "", "")

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	c.Check(keyData[0].SetAuthorizedSnapModels(auxKeys[0], models...), IsNil)
	c.Check(keyData[1].SetAuthorizedSnapModels(auxKeys[1], models...), IsNil)

	s.testActivateVolumeWithMultipleKeyData(c, &testActivateVolumeWithMultipleKeyDataData{
		keys:             keys,
		keyData:          keyData,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		model:            models[0],
		activateTries:    1,
		key:              keys[0],
		auxKey:           auxKeys[0]})
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyData2(c *C) {
	// Test with a different volumeName / sourceDevicePath
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, "", "")

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	c.Check(keyData[0].SetAuthorizedSnapModels(auxKeys[0], models...), IsNil)
	c.Check(keyData[1].SetAuthorizedSnapModels(auxKeys[1], models...), IsNil)

	s.testActivateVolumeWithMultipleKeyData(c, &testActivateVolumeWithMultipleKeyDataData{
		keys:             keys,
		keyData:          keyData,
		volumeName:       "foo",
		sourceDevicePath: "/dev/vda2",
		model:            models[0],
		activateTries:    1,
		key:              keys[0],
		auxKey:           auxKeys[0]})
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyData3(c *C) {
	// Try with an invalid first key - the second key should be used for activation.
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, "", "")

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	c.Check(keyData[0].SetAuthorizedSnapModels(auxKeys[0], models...), IsNil)
	c.Check(keyData[1].SetAuthorizedSnapModels(auxKeys[1], models...), IsNil)

	s.testActivateVolumeWithMultipleKeyData(c, &testActivateVolumeWithMultipleKeyDataData{
		keys:             keys[1:],
		keyData:          keyData,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		model:            models[0],
		activateTries:    2,
		key:              keys[1],
		auxKey:           auxKeys[1]})
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyData4(c *C) {
	// Test with 2 keys that have a passphrase set, using the first key for activation.
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, "", "")

	var kdf mockKDF
	c.Check(keyData[0].SetPassphrase("1234", nil, &kdf), IsNil)
	c.Check(keyData[1].SetPassphrase("5678", nil, &kdf), IsNil)

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	c.Check(keyData[0].SetAuthorizedSnapModels(auxKeys[0], models...), IsNil)
	c.Check(keyData[1].SetAuthorizedSnapModels(auxKeys[1], models...), IsNil)

	s.testActivateVolumeWithMultipleKeyData(c, &testActivateVolumeWithMultipleKeyDataData{
		keys:             keys,
		keyData:          keyData,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		passphraseTries:  1,
		authResponses:    []interface{}{"1234"},
		model:            models[0],
		activateTries:    1,
		key:              keys[0],
		auxKey:           auxKeys[0]})
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyData5(c *C) {
	// Test with 2 keys that have a passphrase set, using the second key for activation.
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, "", "")

	var kdf mockKDF
	c.Check(keyData[0].SetPassphrase("1234", nil, &kdf), IsNil)
	c.Check(keyData[1].SetPassphrase("5678", nil, &kdf), IsNil)

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	c.Check(keyData[0].SetAuthorizedSnapModels(auxKeys[0], models...), IsNil)
	c.Check(keyData[1].SetAuthorizedSnapModels(auxKeys[1], models...), IsNil)

	s.testActivateVolumeWithMultipleKeyData(c, &testActivateVolumeWithMultipleKeyDataData{
		keys:             keys,
		keyData:          keyData,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		passphraseTries:  1,
		authResponses:    []interface{}{"5678"},
		model:            models[0],
		activateTries:    1,
		key:              keys[1],
		auxKey:           auxKeys[1]})
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyData6(c *C) {
	// Test with 2 keys where one has a passphrase set. The one without the passphrase
	// should be used first.
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, "", "")

	var kdf mockKDF
	c.Check(keyData[0].SetPassphrase("1234", nil, &kdf), IsNil)

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	c.Check(keyData[0].SetAuthorizedSnapModels(auxKeys[0], models...), IsNil)
	c.Check(keyData[1].SetAuthorizedSnapModels(auxKeys[1], models...), IsNil)

	s.testActivateVolumeWithMultipleKeyData(c, &testActivateVolumeWithMultipleKeyDataData{
		keys:             keys,
		keyData:          keyData,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		passphraseTries:  1,
		model:            models[0],
		activateTries:    1,
		key:              keys[1],
		auxKey:           auxKeys[1]})
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyData7(c *C) {
	// Test with 2 keys that have a passphrase set, using the second key for activation
	// after more than one attempt.
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, "", "")

	var kdf mockKDF
	c.Check(keyData[0].SetPassphrase("1234", nil, &kdf), IsNil)
	c.Check(keyData[1].SetPassphrase("5678", nil, &kdf), IsNil)

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	c.Check(keyData[0].SetAuthorizedSnapModels(auxKeys[0], models...), IsNil)
	c.Check(keyData[1].SetAuthorizedSnapModels(auxKeys[1], models...), IsNil)

	s.testActivateVolumeWithMultipleKeyData(c, &testActivateVolumeWithMultipleKeyDataData{
		keys:             keys,
		keyData:          keyData,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		passphraseTries:  3,
		authResponses:    []interface{}{"incorrect", "5678"},
		model:            models[0],
		activateTries:    1,
		key:              keys[1],
		auxKey:           auxKeys[1]})
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyData8(c *C) {
	// Test with 2 keys where one has a passphrase set. Activation fails with
	// the key that doesn't have a passphrase set, so activation should happen
	// with the key that has a passphrase set.
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, "", "")

	var kdf mockKDF
	c.Check(keyData[1].SetPassphrase("5678", nil, &kdf), IsNil)

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	c.Check(keyData[0].SetAuthorizedSnapModels(auxKeys[0], models...), IsNil)
	c.Check(keyData[1].SetAuthorizedSnapModels(auxKeys[1], models...), IsNil)

	s.testActivateVolumeWithMultipleKeyData(c, &testActivateVolumeWithMultipleKeyDataData{
		keys:             keys[1:],
		keyData:          keyData,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		passphraseTries:  1,
		authResponses:    []interface{}{"5678"},
		model:            models[0],
		activateTries:    2,
		key:              keys[1],
		auxKey:           auxKeys[1]})
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyData9(c *C) {
	// Try where the supplied model cannot be authorized via the first key - the
	// second key should be used for activation.
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, "", "")

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
	}
	c.Check(keyData[0].SetAuthorizedSnapModels(auxKeys[0], models[0]), IsNil)
	c.Check(keyData[1].SetAuthorizedSnapModels(auxKeys[1], models[1]), IsNil)

	s.testActivateVolumeWithMultipleKeyData(c, &testActivateVolumeWithMultipleKeyDataData{
		keys:             keys,
		keyData:          keyData,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		model:            models[1],
		activateTries:    1,
		key:              keys[1],
		auxKey:           auxKeys[1]})
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyData10(c *C) {
	keyData, keys, auxKeys := s.newMultipleNamedKeyData(c, "", "")

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	c.Check(keyData[0].SetAuthorizedSnapModels(auxKeys[0], models...), IsNil)
	c.Check(keyData[1].SetAuthorizedSnapModels(auxKeys[1], models...), IsNil)

	s.testActivateVolumeWithMultipleKeyData(c, &testActivateVolumeWithMultipleKeyDataData{
		keys:             keys,
		keyData:          keyData,
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		model:            SkipSnapModelCheck,
		activateTries:    1,
		key:              keys[0],
		auxKey:           auxKeys[0]})
}

type testActivateVolumeWithMultipleKeyDataErrorHandlingData struct {
	keys        []DiskUnlockKey
	recoveryKey RecoveryKey
	keyData     []*KeyData

	authRequestor *mockAuthRequestor
	kdf           KDF

	passphraseTries  int
	recoveryKeyTries int
	keyringPrefix    string

	model SnapModel

	activateTries int
}

func (s *cryptSuite) testActivateVolumeWithMultipleKeyDataErrorHandling(c *C, data *testActivateVolumeWithMultipleKeyDataErrorHandlingData) error {
	for _, key := range data.keys {
		s.addMockKeyslot("/dev/sda1", key)
	}
	s.addMockKeyslot("/dev/sda1", data.recoveryKey[:])

	var authRequestor AuthRequestor
	var numPassphraseResponses int
	var numRecoveryResponses int
	if data.authRequestor != nil {
		authRequestor = data.authRequestor
		numPassphraseResponses = len(data.authRequestor.passphraseResponses)
		numRecoveryResponses = len(data.authRequestor.recoveryKeyResponses)
	}

	options := &ActivateVolumeOptions{
		PassphraseTries:  data.passphraseTries,
		RecoveryKeyTries: data.recoveryKeyTries,
		KeyringPrefix:    data.keyringPrefix,
		Model:            data.model}
	err := ActivateVolumeWithMultipleKeyData("data", "/dev/sda1", data.keyData, authRequestor, data.kdf, options)

	if data.authRequestor != nil {
		c.Check(data.authRequestor.passphraseRequests, HasLen, numPassphraseResponses)
		for _, rsp := range data.authRequestor.passphraseRequests {
			c.Check(rsp.volumeName, Equals, "data")
			c.Check(rsp.sourceDevicePath, Equals, "/dev/sda1")
		}

		c.Check(data.authRequestor.recoveryKeyRequests, HasLen, numRecoveryResponses)
		for _, rsp := range data.authRequestor.recoveryKeyRequests {
			c.Check(rsp.volumeName, Equals, "data")
			c.Check(rsp.sourceDevicePath, Equals, "/dev/sda1")
		}
	}

	c.Assert(s.luks2.operations, HasLen, data.activateTries)
	for _, op := range s.luks2.operations {
		c.Check(op, Equals, "Activate(data,/dev/sda1)")
	}

	if err == ErrRecoveryKeyUsed {
		// This should be done last because it may fail in some circumstances.
		s.checkRecoveryKeyInKeyring(c, data.keyringPrefix, "/dev/sda1", data.recoveryKey)
	}

	return err
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling1(c *C) {
	// Test with an invalid value for RecoveryKeyTries.
	keyData, _, _ := s.newMultipleNamedKeyData(c, "", "")

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keyData:          keyData,
		recoveryKeyTries: -1,
	}), ErrorMatches, "invalid RecoveryKeyTries")
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling2(c *C) {
	// Test that recovery fallback works with the platform is unavailable
	keyData, keys, _ := s.newMultipleNamedKeyData(c, "", "")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUnavailable

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keys:             keys,
		recoveryKey:      recoveryKey,
		keyData:          keyData,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{recoveryKey}},
		model:            SkipSnapModelCheck,
		recoveryKeyTries: 1,
		activateTries:    1,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling3(c *C) {
	// Test that recovery fallback works when the platform device isn't properly initialized
	keyData, keys, _ := s.newMultipleNamedKeyData(c, "", "")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUninitialized

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keys:             keys,
		recoveryKey:      recoveryKey,
		keyData:          keyData,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{recoveryKey}},
		model:            SkipSnapModelCheck,
		recoveryKeyTries: 1,
		activateTries:    1,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling4(c *C) {
	// Test that recovery fallback works when the recovered key is incorrect
	keyData, _, _ := s.newMultipleNamedKeyData(c, "", "")
	recoveryKey := s.newRecoveryKey()

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		recoveryKey:      recoveryKey,
		keyData:          keyData,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{recoveryKey}},
		model:            SkipSnapModelCheck,
		recoveryKeyTries: 1,
		activateTries:    3,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling5(c *C) {
	// Test that activation fails if RecoveryKeyTries is zero.
	keyData, keys, _ := s.newMultipleNamedKeyData(c, "foo", "bar")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUnavailable

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keys:             keys,
		recoveryKey:      recoveryKey,
		keyData:          keyData,
		recoveryKeyTries: 0,
		model:            SkipSnapModelCheck,
		activateTries:    0,
	}), ErrorMatches,
		"cannot activate with platform protected keys:\n"+
			"- foo: cannot recover key: the platform's secure device is unavailable: the "+
			"platform device is unavailable\n"+
			"- bar: cannot recover key: the platform's secure device is unavailable: the "+
			"platform device is unavailable\n"+
			"and activation with recovery key failed: no recovery key tries permitted")
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling6(c *C) {
	// Test that activation fails if the supplied recovery key is incorrect
	keyData, keys, _ := s.newMultipleNamedKeyData(c, "bar", "foo")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUnavailable

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keys:             keys,
		recoveryKey:      recoveryKey,
		keyData:          keyData,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{RecoveryKey{}}},
		recoveryKeyTries: 1,
		model:            SkipSnapModelCheck,
		activateTries:    1,
	}), ErrorMatches,
		"cannot activate with platform protected keys:\n"+
			"- bar: cannot recover key: the platform's secure device is unavailable: the "+
			"platform device is unavailable\n"+
			"- foo: cannot recover key: the platform's secure device is unavailable: the "+
			"platform device is unavailable\n"+
			"and activation with recovery key failed: cannot activate volume: "+
			"systemd-cryptsetup failed with: exit status 1")
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling7(c *C) {
	// Test that recovery fallback works if the correct key is eventually supplied
	keyData, keys, _ := s.newMultipleNamedKeyData(c, "", "")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUnavailable

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keys:             keys,
		recoveryKey:      recoveryKey,
		keyData:          keyData,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{RecoveryKey{}, recoveryKey}},
		model:            SkipSnapModelCheck,
		recoveryKeyTries: 2,
		activateTries:    2,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling8(c *C) {
	// Test that recovery fallback works if the correct key is eventually supplied
	keyData, keys, _ := s.newMultipleNamedKeyData(c, "", "")
	recoveryKey := s.newRecoveryKey()

	s.handler.state = mockPlatformDeviceStateUnavailable

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keys:             keys,
		recoveryKey:      recoveryKey,
		keyData:          keyData,
		authRequestor:    &mockAuthRequestor{recoveryKeyResponses: []interface{}{errors.New("some error"), recoveryKey}},
		model:            SkipSnapModelCheck,
		recoveryKeyTries: 2,
		activateTries:    1,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling9(c *C) {
	// Test that we get an error if no AuthRequestor is supplied when
	// RecoveryKeyTries is non-zero.
	keyData, _, _ := s.newMultipleNamedKeyData(c, "", "")

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keyData:          keyData,
		recoveryKeyTries: 1,
		model:            SkipSnapModelCheck,
	}), ErrorMatches, "nil authRequestor")
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling10(c *C) {
	// Test that recovery key fallback works if the wrong passphrase is supplied.
	keyData, keys, _ := s.newMultipleNamedKeyData(c, "foo", "bar")
	recoveryKey := s.newRecoveryKey()

	var kdf mockKDF
	c.Check(keyData[0].SetPassphrase("1234", nil, &kdf), IsNil)
	c.Check(keyData[1].SetPassphrase("1234", nil, &kdf), IsNil)

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keys:        keys,
		recoveryKey: recoveryKey,
		keyData:     keyData,
		authRequestor: &mockAuthRequestor{
			passphraseResponses:  []interface{}{"incorrect", "invalid"},
			recoveryKeyResponses: []interface{}{recoveryKey}},
		kdf:              &kdf,
		passphraseTries:  2,
		recoveryKeyTries: 1,
		model:            SkipSnapModelCheck,
		activateTries:    1,
	}), Equals, ErrRecoveryKeyUsed)
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling11(c *C) {
	// Test that we get an error if no AuthRequestor is supplied when
	// PassphraseTries is non-zero.
	keyData, _, _ := s.newMultipleNamedKeyData(c, "", "")

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keyData:         keyData,
		passphraseTries: 1,
		model:           SkipSnapModelCheck,
	}), ErrorMatches, "nil authRequestor")
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling12(c *C) {
	// Test that we get an error if no KDF is supplied when
	// PassphraseTries is non-zero.
	keyData, _, _ := s.newMultipleNamedKeyData(c, "", "")

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keyData:         keyData,
		authRequestor:   &mockAuthRequestor{},
		passphraseTries: 1,
		model:           SkipSnapModelCheck,
	}), ErrorMatches, "nil kdf")
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling13(c *C) {
	// Test that activation fails if the supplied passphrase and recovery key are incorrect
	keyData, keys, _ := s.newMultipleNamedKeyData(c, "foo", "bar")
	recoveryKey := s.newRecoveryKey()

	var kdf mockKDF
	c.Check(keyData[0].SetPassphrase("1234", nil, &kdf), IsNil)
	c.Check(keyData[1].SetPassphrase("1234", nil, &kdf), IsNil)

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keys:        keys,
		recoveryKey: recoveryKey,
		keyData:     keyData,
		authRequestor: &mockAuthRequestor{
			passphraseResponses:  []interface{}{""},
			recoveryKeyResponses: []interface{}{RecoveryKey{}}},
		kdf:              &kdf,
		passphraseTries:  1,
		recoveryKeyTries: 1,
		model:            SkipSnapModelCheck,
		activateTries:    1,
	}), ErrorMatches, "cannot activate with platform protected keys:\n"+
		"- foo: cannot recover key: the supplied passphrase is incorrect\n"+
		"- bar: cannot recover key: the supplied passphrase is incorrect\n"+
		"and activation with recovery key failed: cannot activate volume: "+
		"systemd-cryptsetup failed with: exit status 1")
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling14(c *C) {
	// Test with an invalid value for SnapModel.
	keyData, _, _ := s.newMultipleNamedKeyData(c, "", "")

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keyData: keyData,
	}), ErrorMatches, "nil Model")
}

func (s *cryptSuite) TestActivateVolumeWithMultipleKeyDataErrorHandling15(c *C) {
	// Test with an unauthorized snap model.
	keyData, keys, _ := s.newMultipleNamedKeyData(c, "foo", "bar")
	recoveryKey := s.newRecoveryKey()

	c.Check(s.testActivateVolumeWithMultipleKeyDataErrorHandling(c, &testActivateVolumeWithMultipleKeyDataErrorHandlingData{
		keys:             keys,
		recoveryKey:      recoveryKey,
		keyData:          keyData,
		recoveryKeyTries: 0,
		model: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		activateTries: 0,
	}), ErrorMatches, "cannot activate with platform protected keys:\n"+
		"- foo: snap model is not authorized\n"+
		"- bar: snap model is not authorized\n"+
		"and activation with recovery key failed: no recovery key tries permitted")
}

type testActivateVolumeWithKeyData struct {
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
	s.addMockKeyslot("/dev/sda1", expectedKeyData)

	options := ActivateVolumeOptions{}
	err := ActivateVolumeWithKey("luks-volume", "/dev/sda1", data.keyData, &options)
	if data.errMatch == "" {
		c.Check(err, IsNil)
	} else {
		c.Check(err, ErrorMatches, data.errMatch)
	}

	if data.cmdCalled {
		c.Check(s.luks2.operations, DeepEquals, []string{"Activate(luks-volume,/dev/sda1)"})
	} else {
		c.Check(s.luks2.operations, HasLen, 0)
	}
}

func (s *cryptSuite) TestActivateVolumeWithKey(c *C) {
	s.testActivateVolumeWithKey(c, &testActivateVolumeWithKeyData{
		keyData:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		cmdCalled: true,
	})
}

func (s *cryptSuite) TestActivateVolumeWithKeyMismatchErr(c *C) {
	s.testActivateVolumeWithKey(c, &testActivateVolumeWithKeyData{
		keyData:         []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		expectedKeyData: []byte{0, 0, 0, 0, 1},
		errMatch:        "systemd-cryptsetup failed with: exit status 1",
		cmdCalled:       true,
	})
}

func (s *cryptSuite) TestDeactivateVolume(c *C) {
	s.luks2.activated["luks-volume"] = "/dev/sda1"
	err := DeactivateVolume("luks-volume")
	c.Assert(err, IsNil)
	c.Check(s.luks2.operations, DeepEquals, []string{"Deactivate(luks-volume)"})
}

func (s *cryptSuite) TestDeactivateVolumeErr(c *C) {
	err := DeactivateVolume("bad-volume")
	c.Assert(err, ErrorMatches, `systemd-cryptsetup failed with: exit status 1`)
	c.Check(s.luks2.operations, DeepEquals, []string{"Deactivate(bad-volume)"})
}

type testInitializeLUKS2ContainerData struct {
	devicePath string
	label      string
	key        []byte
	opts       *InitializeLUKS2ContainerOptions

	fmtOpts *luks2.FormatOptions
}

func (s *cryptSuite) testInitializeLUKS2Container(c *C, data *testInitializeLUKS2ContainerData) {
	c.Check(InitializeLUKS2Container(data.devicePath, data.label, data.key, data.opts), IsNil)

	c.Check(s.luks2.operations, DeepEquals, []string{
		fmt.Sprint("Format(", data.devicePath, ",", data.label, ",", data.fmtOpts, ")"),
		"SetSlotPriority(" + data.devicePath + ",0,prefer)"})

	dev, ok := s.luks2.devices[data.devicePath]
	c.Assert(ok, testutil.IsTrue)

	key, ok := dev.keyslots[0]
	c.Check(ok, testutil.IsTrue)
	c.Check(key, DeepEquals, data.key)
}

func (s *cryptSuite) TestInitializeLUKS2Container(c *C) {
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/sda1",
		label:      "data",
		key:        s.newPrimaryKey(),
		fmtOpts:    &luks2.FormatOptions{KDFOptions: luks2.KDFOptions{ForceIterations: 4, MemoryKiB: 32}},
	})
}

func (s *cryptSuite) TestInitializeLUKS2ContainerDifferentArgs(c *C) {
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/vdc2",
		label:      "test",
		key:        s.newPrimaryKey(),
		fmtOpts:    &luks2.FormatOptions{KDFOptions: luks2.KDFOptions{ForceIterations: 4, MemoryKiB: 32}},
	})
}

func (s *cryptSuite) TestInitializeLUKS2ContainerWithOptions(c *C) {
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/sda1",
		label:      "data",
		key:        s.newPrimaryKey(),
		opts:       &InitializeLUKS2ContainerOptions{},
		fmtOpts:    &luks2.FormatOptions{KDFOptions: luks2.KDFOptions{ForceIterations: 4, MemoryKiB: 32}},
	})
}

func (s *cryptSuite) TestInitializeLUKS2ContainerWithCustomMetadataSize(c *C) {
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/sda1",
		label:      "data",
		key:        s.newPrimaryKey(),
		opts: &InitializeLUKS2ContainerOptions{
			MetadataKiBSize:     2 * 1024, // 2MiB
			KeyslotsAreaKiBSize: 3 * 1024, // 3MiB
		},
		fmtOpts: &luks2.FormatOptions{
			MetadataKiBSize:     2 * 1024,
			KeyslotsAreaKiBSize: 3 * 1024,
			KDFOptions:          luks2.KDFOptions{ForceIterations: 4, MemoryKiB: 32},
		},
	})
}

func (s *cryptSuite) TestInitializeLUKS2ContainerWithCustomKDFTime(c *C) {
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/sda1",
		label:      "data",
		key:        s.newPrimaryKey(),
		opts: &InitializeLUKS2ContainerOptions{
			KDFOptions: &KDFOptions{TargetDuration: 100 * time.Millisecond},
		},
		fmtOpts: &luks2.FormatOptions{KDFOptions: luks2.KDFOptions{TargetDuration: 100 * time.Millisecond}},
	})
}

func (s *cryptSuite) TestInitializeLUKS2ContainerWithCustomKDFMemory(c *C) {
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/sda1",
		label:      "data",
		key:        s.newPrimaryKey(),
		opts: &InitializeLUKS2ContainerOptions{
			KDFOptions: &KDFOptions{MemoryKiB: 128},
		},
		fmtOpts: &luks2.FormatOptions{KDFOptions: luks2.KDFOptions{MemoryKiB: 128}},
	})
}

func (s *cryptSuite) TestInitializeLUKS2ContainerWithCustomKDFIterations(c *C) {
	s.testInitializeLUKS2Container(c, &testInitializeLUKS2ContainerData{
		devicePath: "/dev/sda1",
		label:      "data",
		key:        s.newPrimaryKey(),
		opts: &InitializeLUKS2ContainerOptions{
			KDFOptions: &KDFOptions{ForceIterations: 10},
		},
		fmtOpts: &luks2.FormatOptions{KDFOptions: luks2.KDFOptions{ForceIterations: 10}},
	})
}

func (s *cryptSuite) TestInitializeLUKS2ContainerInvalidKeySize(c *C) {
	c.Check(InitializeLUKS2Container("/dev/sda1", "data", s.newPrimaryKey()[0:16], nil), ErrorMatches, "expected a key length of at least 256-bits \\(got 128\\)")
}

type testAddRecoveryKeyToLUKS2ContainerData struct {
	devicePath  string
	key         []byte
	recoveryKey RecoveryKey
}

func (s *cryptSuite) testAddRecoveryKeyToLUKS2Container(c *C, data *testAddRecoveryKeyToLUKS2ContainerData) {
	s.addMockKeyslot(data.devicePath, data.key)

	c.Check(AddRecoveryKeyToLUKS2Container(data.devicePath, data.key, data.recoveryKey, nil), IsNil)

	c.Check(s.luks2.operations, DeepEquals, []string{fmt.Sprint("AddKey(", data.devicePath, ",", &luks2.AddKeyOptions{Slot: luks2.AnySlot}, ")")})

	dev, ok := s.luks2.devices[data.devicePath]
	c.Assert(ok, testutil.IsTrue)

	key, ok := dev.keyslots[1]
	c.Check(ok, testutil.IsTrue)
	c.Check(key, DeepEquals, []byte(data.recoveryKey[:]))
}

func (s *cryptSuite) TestAddRecoveryKeyToLUKS2Container1(c *C) {
	s.testAddRecoveryKeyToLUKS2Container(c, &testAddRecoveryKeyToLUKS2ContainerData{
		devicePath:  "/dev/sda1",
		key:         s.newPrimaryKey(),
		recoveryKey: s.newRecoveryKey(),
	})
}

func (s *cryptSuite) TestAddRecoveryKeyToLUKS2Container2(c *C) {
	// Test with different path.
	s.testAddRecoveryKeyToLUKS2Container(c, &testAddRecoveryKeyToLUKS2ContainerData{
		devicePath:  "/dev/vdb2",
		key:         s.newPrimaryKey(),
		recoveryKey: s.newRecoveryKey(),
	})
}

func (s *cryptSuite) TestAddRecoveryKeyToLUKS2Container3(c *C) {
	// Test with different key.
	s.testAddRecoveryKeyToLUKS2Container(c, &testAddRecoveryKeyToLUKS2ContainerData{
		devicePath:  "/dev/vdb2",
		key:         make([]byte, 32),
		recoveryKey: s.newRecoveryKey(),
	})
}

func (s *cryptSuite) TestAddRecoveryKeyToLUKS2Container4(c *C) {
	// Test with different recovery key.
	s.testAddRecoveryKeyToLUKS2Container(c, &testAddRecoveryKeyToLUKS2ContainerData{
		devicePath: "/dev/vdb2",
		key:        s.newPrimaryKey(),
	})
}

type testChangeLUKS2KeyUsingRecoveryKeyData struct {
	devicePath  string
	recoveryKey RecoveryKey
	key         []byte
}

func (s *cryptSuite) testChangeLUKS2KeyUsingRecoveryKey(c *C, data *testChangeLUKS2KeyUsingRecoveryKeyData) {
	s.addMockKeyslot(data.devicePath, nil)
	s.addMockKeyslot(data.devicePath, data.recoveryKey[:])

	c.Check(ChangeLUKS2KeyUsingRecoveryKey(data.devicePath, data.recoveryKey, data.key), IsNil)

	c.Check(s.luks2.operations, DeepEquals, []string{
		"KillSlot(" + data.devicePath + ",0)",
		fmt.Sprint("AddKey(", data.devicePath, ",", &luks2.AddKeyOptions{KDFOptions: luks2.KDFOptions{ForceIterations: 4, MemoryKiB: 32}}, ")"),
		"SetSlotPriority(" + data.devicePath + ",0,prefer)",
	})

	dev, ok := s.luks2.devices[data.devicePath]
	c.Assert(ok, testutil.IsTrue)

	key, ok := dev.keyslots[0]
	c.Check(ok, testutil.IsTrue)
	c.Check(key, DeepEquals, data.key)
}

func (s *cryptSuite) TestChangeLUKS2KeyUsingRecoveryKey1(c *C) {
	s.testChangeLUKS2KeyUsingRecoveryKey(c, &testChangeLUKS2KeyUsingRecoveryKeyData{
		devicePath:  "/dev/sda1",
		recoveryKey: s.newRecoveryKey(),
		key:         s.newPrimaryKey(),
	})
}

func (s *cryptSuite) TestChangeLUKS2KeyUsingRecoveryKey2(c *C) {
	s.testChangeLUKS2KeyUsingRecoveryKey(c, &testChangeLUKS2KeyUsingRecoveryKeyData{
		devicePath:  "/dev/vdc1",
		recoveryKey: s.newRecoveryKey(),
		key:         s.newPrimaryKey(),
	})
}

func (s *cryptSuite) TestChangeLUKS2KeyUsingRecoveryKey3(c *C) {
	s.testChangeLUKS2KeyUsingRecoveryKey(c, &testChangeLUKS2KeyUsingRecoveryKeyData{
		devicePath: "/dev/sda1",
		key:        s.newPrimaryKey(),
	})
}

func (s *cryptSuite) TestChangeLUKS2KeyUsingRecoveryKey4(c *C) {
	s.testChangeLUKS2KeyUsingRecoveryKey(c, &testChangeLUKS2KeyUsingRecoveryKeyData{
		devicePath:  "/dev/vdc1",
		recoveryKey: s.newRecoveryKey(),
		key:         make([]byte, 32),
	})
}

type cryptSuiteUnmockedBase struct {
	snapd_testutil.BaseTest
	cryptTestBase
}

func (s *cryptSuiteUnmockedBase) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.AddCleanup(pathstest.MockRunDir(c.MkDir()))
	s.AddCleanup(luks2test.WrapCryptsetup(c))
}

type cryptSuiteUnmocked struct {
	cryptSuiteUnmockedBase
}

type cryptSuiteUnmockedExpensive struct {
	cryptSuiteUnmockedBase
}

func (s *cryptSuiteUnmockedExpensive) SetUpSuite(c *C) {
	if _, exists := os.LookupEnv("NO_EXPENSIVE_CRYPTSETUP_TESTS"); exists {
		c.Skip("skipping expensive cryptsetup tests")
	}
}

var _ = Suite(&cryptSuiteUnmocked{})
var _ = Suite(&cryptSuiteUnmockedExpensive{})

func (s *cryptSuiteUnmockedBase) testInitializeLUKS2Container(c *C, options *InitializeLUKS2ContainerOptions) {
	key := s.newPrimaryKey()
	path := luks2test.CreateEmptyDiskImage(c, 20)

	c.Check(InitializeLUKS2Container(path, "data", key, options), IsNil)

	switch {
	case options == nil:
		options = &InitializeLUKS2ContainerOptions{KDFOptions: &KDFOptions{MemoryKiB: 32, ForceIterations: 4}}
	case options.KDFOptions == nil:
		options.KDFOptions = &KDFOptions{MemoryKiB: 32, ForceIterations: 4}
	}

	info, err := luks2.ReadHeader(path, luks2.LockModeBlocking)
	c.Assert(err, IsNil)

	c.Check(info.Label, Equals, "data")

	c.Check(info.Metadata.Keyslots, HasLen, 1)
	keyslot, ok := info.Metadata.Keyslots[0]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.Priority, Equals, luks2.SlotPriorityHigh)

	c.Check(info.Metadata.Tokens, HasLen, 0)

	expectedMetadataSize := uint64(16 * 1024)
	if options.MetadataKiBSize > 0 {
		expectedMetadataSize = uint64(options.MetadataKiBSize * 1024)
	}
	expectedKeyslotsSize := uint64(16*1024*1024) - (2 * expectedMetadataSize)
	if options.KeyslotsAreaKiBSize > 0 {
		expectedKeyslotsSize = uint64(options.KeyslotsAreaKiBSize * 1024)
	}

	c.Check(info.Metadata.Config.JSONSize, Equals, expectedMetadataSize-uint64(4*1024))
	c.Check(info.Metadata.Config.KeyslotsSize, Equals, expectedKeyslotsSize)

	expectedMemoryKiB := 1 * 1024 * 1024
	if options.KDFOptions.MemoryKiB > 0 {
		expectedMemoryKiB = options.KDFOptions.MemoryKiB
	}

	if options.KDFOptions.ForceIterations > 0 {
		c.Check(keyslot.KDF.Time, Equals, options.KDFOptions.ForceIterations)
		c.Check(keyslot.KDF.Memory, Equals, expectedMemoryKiB)
	} else {
		expectedKDFTime := 2 * time.Second
		if options.KDFOptions.TargetDuration > 0 {
			expectedKDFTime = options.KDFOptions.TargetDuration
		}

		c.Check(keyslot.KDF.Memory, snapd_testutil.IntLessEqual, expectedMemoryKiB)

		start := time.Now()
		luks2test.CheckLUKS2Passphrase(c, path, key)
		elapsed := time.Now().Sub(start)

		// Check KDF time here with +/-20% tolerance and additional 500ms for cryptsetup exec and other activities
		c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntGreaterThan, int(float64(expectedKDFTime/time.Millisecond)*0.8))
		c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntLessThan, int(float64(expectedKDFTime/time.Millisecond)*1.2)+500)
	}
}

func (s *cryptSuiteUnmocked) TestInitializeLUKS2Container(c *C) {
	s.testInitializeLUKS2Container(c, nil)
}

func (s *cryptSuiteUnmocked) TestInitializeLUKS2ContainerWithOptions(c *C) {
	if luks2.DetectCryptsetupFeatures()&luks2.FeatureHeaderSizeSetting == 0 {
		c.Skip("cryptsetup doesn't support --luks2-metadata-size or --luks2-keyslots-size")
	}

	s.testInitializeLUKS2Container(c, &InitializeLUKS2ContainerOptions{
		MetadataKiBSize:     2 * 1024, // 2MiB
		KeyslotsAreaKiBSize: 3 * 1024, // 3MiB
	})
}

func (s *cryptSuiteUnmockedExpensive) TestInitializeLUKS2ContainerWithCustomKDFTime(c *C) {
	s.testInitializeLUKS2Container(c, &InitializeLUKS2ContainerOptions{
		KDFOptions: &KDFOptions{TargetDuration: 100 * time.Millisecond}})
}

func (s *cryptSuiteUnmockedExpensive) TestInitializeLUKS2ContainerWithCustomKDFMemory(c *C) {
	s.testInitializeLUKS2Container(c, &InitializeLUKS2ContainerOptions{
		KDFOptions: &KDFOptions{TargetDuration: 100 * time.Millisecond, MemoryKiB: 64}})
}

func (s *cryptSuiteUnmocked) TestInitializeLUKS2ContainerWithCustomKDFIterations(c *C) {
	s.testInitializeLUKS2Container(c, &InitializeLUKS2ContainerOptions{
		KDFOptions: &KDFOptions{ForceIterations: 8}})
}

func (s *cryptSuiteUnmockedExpensive) TestAddRecoveryKeyToLUKS2Container(c *C) {
	key := s.newPrimaryKey()
	path := luks2test.CreateEmptyDiskImage(c, 20)

	c.Check(InitializeLUKS2Container(path, "", key, nil), IsNil)

	startInfo, err := luks2.ReadHeader(path, luks2.LockModeBlocking)
	c.Assert(err, IsNil)

	recoveryKey := s.newRecoveryKey()
	c.Check(AddRecoveryKeyToLUKS2Container(path, key, recoveryKey, nil), IsNil)

	endInfo, err := luks2.ReadHeader(path, luks2.LockModeBlocking)
	c.Assert(err, IsNil)

	newSlotId := -1
	for s := range endInfo.Metadata.Keyslots {
		if _, ok := startInfo.Metadata.Keyslots[s]; !ok {
			newSlotId = int(s)
			break
		}
	}

	c.Assert(newSlotId, snapd_testutil.IntGreaterThan, -1)

	c.Check(endInfo.Metadata.Keyslots, HasLen, 2)
	keyslot, ok := endInfo.Metadata.Keyslots[newSlotId]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.Priority, Equals, luks2.SlotPriorityNormal)

	expectedKDFTime := 2000 * time.Millisecond

	start := time.Now()
	luks2test.CheckLUKS2Passphrase(c, path, recoveryKey[:])
	elapsed := time.Now().Sub(start)

	// Check KDF time here with +/-20% tolerance and additional 500ms for cryptsetup exec and other activities
	c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntGreaterThan, int(float64(expectedKDFTime/time.Millisecond)*0.8))
	c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntLessThan, int(float64(expectedKDFTime/time.Millisecond)*1.2)+500)
}

func (s *cryptSuiteUnmocked) ChangeLUKS2KeyUsingRecoveryKey(c *C) {
	key := s.newPrimaryKey()
	recoveryKey := s.newRecoveryKey()
	path := luks2test.CreateEmptyDiskImage(c, 20)

	c.Check(InitializeLUKS2Container(path, "", key, nil), IsNil)
	c.Check(AddRecoveryKeyToLUKS2Container(path, key, recoveryKey, nil), IsNil)

	newKey := s.newPrimaryKey()
	c.Check(ChangeLUKS2KeyUsingRecoveryKey(path, recoveryKey, newKey), IsNil)

	luks2test.CheckLUKS2Passphrase(c, path, recoveryKey[:])
	// XXX: There's no checking of the configured KDF values here. The function
	//  being tested here is going away in another PR anyway.
}
