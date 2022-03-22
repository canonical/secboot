// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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
	"fmt"
	"io/ioutil"
	"math/rand"
	"path/filepath"

	. "github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/paths/pathstest"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"
)

type activateSuite struct {
	snapd_testutil.BaseTest

	runDir string

	mockKeyslotsDir   string
	mockKeyslotsCount int

	mockSdCryptsetup *snapd_testutil.MockCmd
}

func (s *activateSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.runDir = c.MkDir()
	s.AddCleanup(pathstest.MockRunDir(s.runDir))

	s.mockKeyslotsDir = c.MkDir()
	s.mockKeyslotsCount = 0

	sdCryptsetupBottom := `
if [ "$1" = "detach" ]; then
    if [ "$2" = "bad-volume" ]; then
        exit 7
    fi
    exit 0
fi
key=$(xxd -p < "$4")
for f in "%[1]s"/*; do
    if [ "$key" == "$(xxd -p < "$f")" ]; then
	exit 0
    fi
done

# use a specific error code to differentiate from arbitrary exit 1 elsewhere
exit 5
`
	s.mockSdCryptsetup = snapd_testutil.MockCommand(c, filepath.Join(c.MkDir(), "systemd-cryptsetup"), fmt.Sprintf(sdCryptsetupBottom, s.mockKeyslotsDir))
	s.AddCleanup(s.mockSdCryptsetup.Restore)
	s.AddCleanup(MockSystemdCryptsetupPath(s.mockSdCryptsetup.Exe()))
}

func (s *activateSuite) addMockKeyslot(c *C, key []byte) {
	c.Assert(ioutil.WriteFile(filepath.Join(s.mockKeyslotsDir, fmt.Sprintf("%d", s.mockKeyslotsCount)), key, 0644), IsNil)
	s.mockKeyslotsCount++
}

var _ = Suite(&activateSuite{})

type testActivateData struct {
	volumeName       string
	sourceDevicePath string
	slot             int
}

func (s *activateSuite) testActivate(c *C, data *testActivateData) {
	key := make([]byte, 32)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	c.Check(Activate(data.volumeName, data.sourceDevicePath, key, data.slot), IsNil)

	c.Assert(s.mockSdCryptsetup.Calls(), HasLen, 1)
	c.Assert(s.mockSdCryptsetup.Calls()[0], HasLen, 6)
	c.Check(s.mockSdCryptsetup.Calls()[0], DeepEquals, []string{"systemd-cryptsetup", "attach", data.volumeName, data.sourceDevicePath, "/dev/stdin", fmt.Sprintf("luks,keyslot=%d,tries=1", data.slot)})
}

func (s *activateSuite) TestActivate1(c *C) {
	s.testActivate(c, &testActivateData{
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1"})
}

func (s *activateSuite) TestActivate2(c *C) {
	s.testActivate(c, &testActivateData{
		volumeName:       "test",
		sourceDevicePath: "/dev/sda1"})
}

func (s *activateSuite) TestActivate3(c *C) {
	s.testActivate(c, &testActivateData{
		volumeName:       "data",
		sourceDevicePath: "/dev/vda2"})
}

func (s *activateSuite) TestActivateWrongKey(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.addMockKeyslot(c, key)

	c.Check(Activate("data", "/dev/sda1", nil, AnySlot), ErrorMatches, `systemd-cryptsetup failed with: exit status 5`)

	c.Assert(s.mockSdCryptsetup.Calls(), HasLen, 1)
	c.Assert(s.mockSdCryptsetup.Calls()[0], HasLen, 6)
	c.Check(s.mockSdCryptsetup.Calls()[0], DeepEquals, []string{"systemd-cryptsetup", "attach", "data", "/dev/sda1", "/dev/stdin", "luks,keyslot=-1,tries=1"})
}

func (s *activateSuite) TestDeactivate(c *C) {
	c.Assert(Deactivate("data"), IsNil)
	c.Assert(s.mockSdCryptsetup.Calls(), HasLen, 1)
	c.Check(s.mockSdCryptsetup.Calls()[0], DeepEquals, []string{
		"systemd-cryptsetup", "detach", "data",
	})
}

func (s *activateSuite) TestDeactivateErr(c *C) {
	c.Assert(Deactivate("bad-volume"), ErrorMatches, `systemd-cryptsetup failed with: exit status 7`)
	c.Assert(s.mockSdCryptsetup.Calls(), HasLen, 1)
	c.Check(s.mockSdCryptsetup.Calls()[0], DeepEquals, []string{
		"systemd-cryptsetup", "detach", "bad-volume",
	})
}
