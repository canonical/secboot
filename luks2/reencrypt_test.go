// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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

package luks2_test

import (
	"context"
	"fmt"

	"github.com/snapcore/secboot"
	internal_luks2 "github.com/snapcore/secboot/internal/luks2"
	. "github.com/snapcore/secboot/luks2"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	. "gopkg.in/check.v1"
)

type reencryptSuite struct {
	snapd_testutil.BaseTest

	containerData map[string]*mockContainerData
}

func (s *reencryptSuite) SetUpTest(c *C) {
	restore := MockNewLuksView(func(ctx context.Context, path string) (LuksView, error) {
		data, exists := s.containerData[path]
		if !exists {
			return nil, fmt.Errorf("error with binary header: %w", internal_luks2.ErrInvalidMagic)
		}
		return newMockLuksView(data), nil
	})
	s.AddCleanup(restore)

	s.containerData = make(map[string]*mockContainerData)
}

var _ = Suite(&reencryptSuite{})

func (s *reencryptSuite) TestStatusNone(c *C) {
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", "echo bla-bla")
	defer mockCryptsetup.Restore()

	reencryption := ReencryptionImpl{}
	status, err := reencryption.Status()

	c.Assert(err, IsNil)
	c.Assert(status, NotNil)
	c.Check(*status, Equals, secboot.ReencryptionStatusNone)
}

func (s *reencryptSuite) TestStatusInProgress(c *C) {
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", "echo reencryption: in-progress")
	defer mockCryptsetup.Restore()

	reencryption := ReencryptionImpl{}
	status, err := reencryption.Status()

	c.Assert(err, IsNil)
	c.Assert(status, NotNil)
	c.Check(*status, Equals, secboot.ReencryptionStatusInitialized)
}

func (s *reencryptSuite) TestStatusError1(c *C) {
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", "echo reencryption: some-unsupported-value")
	defer mockCryptsetup.Restore()

	reencryption := ReencryptionImpl{}
	status, err := reencryption.Status()

	c.Assert(err, NotNil)
	c.Assert(status, IsNil)
	c.Check(err, ErrorMatches, "unkown reencryption status: some-unsupported-value")
}

func (s *reencryptSuite) TestStatusError2(c *C) {
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", "exit 1")
	defer mockCryptsetup.Restore()

	reencryption := ReencryptionImpl{}
	status, err := reencryption.Status()

	c.Assert(err, NotNil)
	c.Assert(status, IsNil)
	c.Check(err, ErrorMatches, ".*cryptsetup failed with: exit status 1")
}

func (s *reencryptSuite) TestInitialize(c *C) {
	s.containerData["/dev/sda1"] = newMockContainerData()
	s.containerData["/dev/sda1"].recoveryKeyslots["default-recovery"] = 22
	s.containerData["/dev/sda1"].platformKeyslots["default"] = nil
	s.containerData["/dev/sda1"].platformKeyslots["default-fallback"] = nil

	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", "echo")
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")
	unlockKeys := make(map[string][]byte)
	unlockKeys["default-recovery"] = []byte{3, 3, 3}
	unlockKeys["default"] = []byte{4, 4, 4, 4}
	unlockKeys["default-fallback"] = []byte{2, 2}

	err := reencryption.Initialize(context.Background(), unlockKeys)
	c.Assert(err, IsNil)

	c.Assert(mockCryptsetup.Calls(), HasLen, 1)
	c.Check(mockCryptsetup.Calls()[0], DeepEquals, []string{
		"cryptsetup", "reencrypt", "--type", "luks2", "--keys-from-stdin-sizes", "3,4,2",
		"--batch-mode", "--init-only", "--active-name", "some-active-name"})
}

func (s *reencryptSuite) TestInitializeErrNumberOfKeys(c *C) {
	s.containerData["/dev/sda1"] = newMockContainerData()
	s.containerData["/dev/sda1"].recoveryKeyslots["default-recovery"] = 22
	s.containerData["/dev/sda1"].platformKeyslots["default"] = nil
	s.containerData["/dev/sda1"].platformKeyslots["default-fallback"] = nil

	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", "echo some-text")
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")
	var unlockKeys map[string][]byte
	err := reencryption.Initialize(context.Background(), unlockKeys)

	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "provided number of unlock keys \\(0\\) does not match with tokens of the LUKS header \\(3\\)")
}

func (s *reencryptSuite) TestInitializeErrMissingKey(c *C) {
	s.containerData["/dev/sda1"] = newMockContainerData()
	s.containerData["/dev/sda1"].recoveryKeyslots["default-recovery"] = 22
	s.containerData["/dev/sda1"].platformKeyslots["default"] = nil
	s.containerData["/dev/sda1"].platformKeyslots["default-fallback"] = nil

	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", "exit 1")
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")
	unlockKeys := make(map[string][]byte)
	unlockKeys["token-name-1"] = []byte{3, 3, 3}
	unlockKeys["token-name-2"] = []byte{3, 3, 3}
	unlockKeys["token-name-3"] = []byte{3, 3, 3}
	err := reencryption.Initialize(context.Background(), unlockKeys)

	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "missing unlock key for token \"default-recovery\"")
}

func (s *reencryptSuite) TestInitializeErrNoToken(c *C) {
	s.containerData["/dev/sda1"] = nil

	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", "exit 1")
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")
	unlockKeys := make(map[string][]byte)
	err := reencryption.Initialize(context.Background(), unlockKeys)

	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "cannot get any token name")
}

func (s *reencryptSuite) TestInitializeErrExtraToken(c *C) {
	s.containerData["/dev/sda1"] = newMockContainerData()
	s.containerData["/dev/sda1"].recoveryKeyslots["default-recovery"] = 22
	s.containerData["/dev/sda1"].platformKeyslots["default"] = nil
	s.containerData["/dev/sda1"].platformKeyslots["default-fallback"] = nil

	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", "exit 1")
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")
	unlockKeys := make(map[string][]byte)
	unlockKeys["default-recovery"] = []byte{3, 3, 3}
	unlockKeys["default"] = []byte{4, 4, 4, 4}
	unlockKeys["default-fallback"] = []byte{2, 2}
	unlockKeys["extra-token"] = []byte{5, 5, 5, 5, 5}

	err := reencryption.Initialize(context.Background(), unlockKeys)

	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "provided number of unlock keys \\(4\\) does not match with tokens of the LUKS header \\(3\\)")
}

func (s *reencryptSuite) TestResume(c *C) {
	scriptMockCryptsetup := `cat << EOF
{"device":"/dev/sda1","device_bytes":"0","device_size":"192937984","speed":"0","eta_ms":"0","time_ms":"2392"}
{"device":"/dev/sda1","device_bytes":"31457280","device_size":"192937984","speed":"6549296","eta_ms":"24656","time_ms":"4803"}
{"device":"/dev/sda1","device_bytes":"62914560","device_size":"192937984","speed":"8777239","eta_ms":"14813","time_ms":"7167"}
{"device":"/dev/sda1","device_bytes":"94371840","device_size":"192937984","speed":"9857500","eta_ms":"9999","time_ms":"9573"}
EOF`
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", scriptMockCryptsetup)
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")

	progress, err := reencryption.Resume(context.Background(), []byte{3, 3, 3})
	c.Assert(err, IsNil)

	messages := []secboot.ReencryptionProgressEvent{}
	var msg secboot.ReencryptionProgressEvent
	for msg = range progress {
		messages = append(messages, msg)
		if msg.Type == secboot.ReencryptionProgressCompleted {
			break
		}
		if msg.Type == secboot.ReencryptionProgressError {
			break
		}
	}

	c.Check(messages, HasLen, 6)

	c.Check(messages[0].Type, Equals, secboot.ReencryptionProgressStarted)

	c.Check(messages[1].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[1].Details, DeepEquals, secboot.ReencryptionProgressDetails{
		BytesReencryptedSoFar:    "0",
		DeviceSize:               "192937984",
		CalculatedSpeed:          "0",
		EstimatedTimeRemainingMs: "0",
		TotalTimeSoFarMs:         "2392",
	})
	c.Check(messages[1].Error, IsNil)

	c.Check(messages[2].Type, Equals, secboot.ReencryptionProgressRunning)

	c.Check(messages[3].Type, Equals, secboot.ReencryptionProgressRunning)

	c.Check(messages[4].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[4].Details, DeepEquals, secboot.ReencryptionProgressDetails{
		BytesReencryptedSoFar:    "94371840",
		DeviceSize:               "192937984",
		CalculatedSpeed:          "9857500",
		EstimatedTimeRemainingMs: "9999",
		TotalTimeSoFarMs:         "9573",
	})
	c.Check(messages[4].Error, IsNil)

	c.Check(messages[5].Type, Equals, secboot.ReencryptionProgressCompleted)
}

func (s *reencryptSuite) TestResumeMissingAndExtraFields(c *C) {
	scriptMockCryptsetup := `cat << EOF
{"device":"/dev/sda1", "example-other":"example-value"}
{"device":"/dev/sda1","device_bytes":"62914560"}
EOF`
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", scriptMockCryptsetup)
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")

	progress, err := reencryption.Resume(context.Background(), []byte{3, 3, 3})
	c.Assert(err, IsNil)

	messages := []secboot.ReencryptionProgressEvent{}
	var msg secboot.ReencryptionProgressEvent
	for msg = range progress {
		messages = append(messages, msg)
		if msg.Type == secboot.ReencryptionProgressCompleted {
			break
		}
		if msg.Type == secboot.ReencryptionProgressError {
			break
		}
	}

	c.Check(messages, HasLen, 4)

	c.Check(messages[0].Type, Equals, secboot.ReencryptionProgressStarted)

	c.Check(messages[1].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[1].Details, DeepEquals, secboot.ReencryptionProgressDetails{})
	c.Check(messages[1].Error, IsNil)

	c.Check(messages[2].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[2].Details, DeepEquals, secboot.ReencryptionProgressDetails{
		BytesReencryptedSoFar:    "62914560",
		DeviceSize:               "",
		CalculatedSpeed:          "",
		EstimatedTimeRemainingMs: "",
		TotalTimeSoFarMs:         "",
	})
	c.Check(messages[2].Error, IsNil)

	c.Check(messages[3].Type, Equals, secboot.ReencryptionProgressCompleted)
}

func (s *reencryptSuite) TestResumeLatency(c *C) {
	scriptMockCryptsetup := `sleep 1
	echo '{"device":"/dev/sda1"}'
	sleep 1
	echo '{"device":"/dev/sda1","device_bytes":"31457280"}'
	`
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", scriptMockCryptsetup)
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")

	progress, err := reencryption.Resume(context.Background(), []byte{3, 3, 3})
	c.Assert(err, IsNil)

	messages := []secboot.ReencryptionProgressEvent{}
	var msg secboot.ReencryptionProgressEvent
	for msg = range progress {
		messages = append(messages, msg)
		if msg.Type == secboot.ReencryptionProgressCompleted {
			break
		}
		if msg.Type == secboot.ReencryptionProgressError {
			break
		}
	}

	c.Assert(messages, HasLen, 4)

	c.Check(messages[0].Type, Equals, secboot.ReencryptionProgressStarted)

	c.Check(messages[1].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[1].Details, DeepEquals, secboot.ReencryptionProgressDetails{})
	c.Check(messages[1].Error, IsNil)

	c.Check(messages[2].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[2].Details, DeepEquals, secboot.ReencryptionProgressDetails{
		BytesReencryptedSoFar:    "31457280",
		DeviceSize:               "",
		CalculatedSpeed:          "",
		EstimatedTimeRemainingMs: "",
		TotalTimeSoFarMs:         "",
	})
	c.Check(messages[2].Error, IsNil)

	c.Check(messages[3].Type, Equals, secboot.ReencryptionProgressCompleted)
}

func (s *reencryptSuite) TestResumeErrJson(c *C) {
	scriptMockCryptsetup := `cat << EOF
{"device":"/dev/sda1","device_bytes":"0","device_size":"192937984","speed":"0","eta_ms":"0","time_ms":"2392"
invalid json 888

{"device":"/dev/sda1","device_bytes":"31457280","device_size":"192937984","speed":"6549296","eta_ms":"24656","time_ms":"4803"}
EOF
	`
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", scriptMockCryptsetup)
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")

	progress, err := reencryption.Resume(context.Background(), []byte{3, 3, 3})
	c.Assert(err, IsNil)

	messages := []secboot.ReencryptionProgressEvent{}
	var msg secboot.ReencryptionProgressEvent
	for msg = range progress {
		messages = append(messages, msg)
		if msg.Type == secboot.ReencryptionProgressCompleted {
			break
		}
		if msg.Type == secboot.ReencryptionProgressError {
			break
		}
	}

	c.Check(messages, HasLen, 6)

	c.Check(messages[0].Type, Equals, secboot.ReencryptionProgressStarted)

	c.Check(messages[1].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[1].Details, DeepEquals, secboot.ReencryptionProgressDetails{})
	c.Check(messages[1].Error, ErrorMatches, "cannot decode JSON: .*")

	c.Check(messages[2].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[2].Details, DeepEquals, secboot.ReencryptionProgressDetails{})
	c.Check(messages[2].Error, ErrorMatches, "cryptsetup error: invalid json 888")

	c.Check(messages[3].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[3].Details, DeepEquals, secboot.ReencryptionProgressDetails{})
	c.Check(messages[3].Error, ErrorMatches, "empty*")

	c.Check(messages[4].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[4].Details, DeepEquals, secboot.ReencryptionProgressDetails{
		BytesReencryptedSoFar:    "31457280",
		DeviceSize:               "192937984",
		CalculatedSpeed:          "6549296",
		EstimatedTimeRemainingMs: "24656",
		TotalTimeSoFarMs:         "4803",
	})
	c.Check(messages[4].Error, IsNil)

	c.Check(messages[5].Type, Equals, secboot.ReencryptionProgressCompleted)
}

func (s *reencryptSuite) TestResumeErrExit2(c *C) {
	scriptMockCryptsetup := `cat << EOF
{"device":"/dev/sda1","device_bytes":"0","device_size":"192937984","speed":"0","eta_ms":"0","time_ms":"2392"}
{"device":"/dev/sda1","device_bytes":"31457280","device_size":"192937984","speed":"6549296","eta_ms":"24656","time_ms":"4803"}
{"device":"/dev/sda1","device_bytes":"62914560","device_size":"192937984","speed":"8777239","eta_ms":"14813","time_ms":"7167"}
{"device":"/dev/sda1","device_bytes":"94371840","device_size":"192937984","speed":"9857500","eta_ms":"9999","time_ms":"9573"}
EOF
	exit 2
	`
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", scriptMockCryptsetup)
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")

	progress, err := reencryption.Resume(context.Background(), []byte{3, 3, 3})
	c.Assert(err, IsNil)

	messages := []secboot.ReencryptionProgressEvent{}
	var msg secboot.ReencryptionProgressEvent
	for msg = range progress {
		messages = append(messages, msg)
		if msg.Type == secboot.ReencryptionProgressCompleted {
			break
		}
		if msg.Type == secboot.ReencryptionProgressError {
			break
		}
	}

	c.Check(messages, HasLen, 6)

	c.Check(messages[0].Type, Equals, secboot.ReencryptionProgressStarted)

	c.Check(messages[1].Type, Equals, secboot.ReencryptionProgressRunning)

	c.Check(messages[2].Type, Equals, secboot.ReencryptionProgressRunning)

	c.Check(messages[3].Type, Equals, secboot.ReencryptionProgressRunning)

	c.Check(messages[4].Type, Equals, secboot.ReencryptionProgressRunning)
	c.Check(messages[4].Details, DeepEquals, secboot.ReencryptionProgressDetails{
		BytesReencryptedSoFar:    "94371840",
		DeviceSize:               "192937984",
		CalculatedSpeed:          "9857500",
		EstimatedTimeRemainingMs: "9999",
		TotalTimeSoFarMs:         "9573",
	})
	c.Check(messages[4].Error, IsNil)

	c.Check(messages[5].Type, Equals, secboot.ReencryptionProgressError)
	c.Check(messages[5].Error, ErrorMatches, "exit status 2")
}

func (s *reencryptSuite) TestResumeErrKillSelf(c *C) {
	scriptMockCryptsetup := `echo '{"device":"/dev/sda1"}'; kill -KILL $$`
	mockCryptsetup := snapd_testutil.MockCommand(c, "cryptsetup", scriptMockCryptsetup)
	defer mockCryptsetup.Restore()

	reencryption := NewReencryptionImpl("/dev/sda1", "some-active-name")

	progress, err := reencryption.Resume(context.Background(), []byte{3, 3, 3})
	c.Assert(err, IsNil)

	messages := []secboot.ReencryptionProgressEvent{}
	var msg secboot.ReencryptionProgressEvent
	for msg = range progress {
		messages = append(messages, msg)
		if msg.Type == secboot.ReencryptionProgressCompleted {
			break
		}
		if msg.Type == secboot.ReencryptionProgressError {
			break
		}
	}

	c.Check(messages, HasLen, 3)

	c.Check(messages[0].Type, Equals, secboot.ReencryptionProgressStarted)

	c.Check(messages[1].Type, Equals, secboot.ReencryptionProgressRunning)

	c.Check(messages[2].Type, Equals, secboot.ReencryptionProgressError)
	c.Check(messages[2].Error, ErrorMatches, "signal: killed")
}
