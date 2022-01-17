// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
)

type authRequestorSystemdSuite struct {
	snapd_testutil.BaseTest

	passwordFile      string
	mockSdAskPassword *snapd_testutil.MockCmd
}

func (s *authRequestorSystemdSuite) SetUpTest(c *C) {
	dir := c.MkDir()
	s.passwordFile = filepath.Join(dir, "password") // password to be returned by the mock sd-ask-password

	sdAskPasswordBottom := `cat %[1]s`
	s.mockSdAskPassword = snapd_testutil.MockCommand(c, "systemd-ask-password", fmt.Sprintf(sdAskPasswordBottom, s.passwordFile))
	s.AddCleanup(s.mockSdAskPassword.Restore)
}

func (s *authRequestorSystemdSuite) setPassphrase(c *C, passphrase string) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(passphrase+"\n"), 0600), IsNil)
}

var _ = Suite(&authRequestorSystemdSuite{})

type testRequestPassphraseData struct {
	passphrase string

	tmpl string

	volumeName       string
	sourceDevicePath string

	expectedMsg string
}

func (s *authRequestorSystemdSuite) testRequestPassphrase(c *C, data *testRequestPassphraseData) {
	s.setPassphrase(c, data.passphrase)

	requestor, err := NewSystemdAuthRequestor(data.tmpl, "")
	c.Assert(err, IsNil)

	passphrase, err := requestor.RequestPassphrase(data.volumeName, data.sourceDevicePath)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, data.passphrase)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, 1)
	c.Check(s.mockSdAskPassword.Calls()[0], DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk",
		"--id", filepath.Base(os.Args[0]) + ":" + data.sourceDevicePath, data.expectedMsg})
}

func (s *authRequestorSystemdSuite) TestRequestPassphrase(c *C) {
	s.testRequestPassphrase(c, &testRequestPassphraseData{
		passphrase:       "password",
		tmpl:             "Enter passphrase for {{.SourceDevicePath}}:",
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		expectedMsg:      "Enter passphrase for /dev/sda1:"})
}

func (s *authRequestorSystemdSuite) TestRequestPassphraseDifferentPassphrase(c *C) {
	s.testRequestPassphrase(c, &testRequestPassphraseData{
		passphrase:       "1234",
		tmpl:             "Enter passphrase for {{.SourceDevicePath}}:",
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		expectedMsg:      "Enter passphrase for /dev/sda1:"})
}

func (s *authRequestorSystemdSuite) TestRequestPassphraseDifferentSourceDevice(c *C) {
	s.testRequestPassphrase(c, &testRequestPassphraseData{
		passphrase:       "password",
		tmpl:             "Enter passphrase for {{.SourceDevicePath}}:",
		volumeName:       "data",
		sourceDevicePath: "/dev/nvme0n1p1",
		expectedMsg:      "Enter passphrase for /dev/nvme0n1p1:"})
}

func (s *authRequestorSystemdSuite) TestRequestPassphraseDifferentMsg(c *C) {
	s.testRequestPassphrase(c, &testRequestPassphraseData{
		passphrase:       "password",
		tmpl:             "Enter passphrase for {{.VolumeName}}:",
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		expectedMsg:      "Enter passphrase for data:"})
}

func (s *authRequestorSystemdSuite) TestRequestPassphraseDifferentVolumeName(c *C) {
	s.testRequestPassphrase(c, &testRequestPassphraseData{
		passphrase:       "password",
		tmpl:             "Enter passphrase for {{.VolumeName}}:",
		volumeName:       "foo",
		sourceDevicePath: "/dev/sda1",
		expectedMsg:      "Enter passphrase for foo:"})
}

func (s *authRequestorSystemdSuite) TestRequestPassphraseInvalidResponse(c *C) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte("foo"), 0600), IsNil)

	requestor, err := NewSystemdAuthRequestor("", "")
	c.Assert(err, IsNil)

	_, err = requestor.RequestPassphrase("data", "/dev/sda1")
	c.Check(err, ErrorMatches, "systemd-ask-password output is missing terminating newline")
}

func (s *authRequestorSystemdSuite) TestRequestPassphraseFailure(c *C) {
	requestor, err := NewSystemdAuthRequestor("", "")
	c.Assert(err, IsNil)

	_, err = requestor.RequestPassphrase("data", "/dev/sda1")
	c.Check(err, ErrorMatches, "cannot execute systemd-ask-password: exit status 1")
}

type testRequestRecoveryKeyData struct {
	passphrase string

	tmpl string

	volumeName       string
	sourceDevicePath string

	expectedKey RecoveryKey
	expectedMsg string
}

func (s *authRequestorSystemdSuite) testRequestRecoveryKey(c *C, data *testRequestRecoveryKeyData) {
	s.setPassphrase(c, data.passphrase)

	requestor, err := NewSystemdAuthRequestor("", data.tmpl)
	c.Assert(err, IsNil)

	key, err := requestor.RequestRecoveryKey(data.volumeName, data.sourceDevicePath)
	c.Check(err, IsNil)
	c.Check(key, Equals, data.expectedKey)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, 1)
	c.Check(s.mockSdAskPassword.Calls()[0], DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk",
		"--id", filepath.Base(os.Args[0]) + ":" + data.sourceDevicePath, data.expectedMsg})
}

func (s *authRequestorSystemdSuite) TestRequestRecoveryKey(c *C) {
	var key RecoveryKey
	{
		k := testutil.DecodeHexString(c, "e73232a995f8c96988fbd4b4824e34f4")
		copy(key[:], k)
	}

	s.testRequestRecoveryKey(c, &testRequestRecoveryKeyData{
		passphrase:       key.String(),
		tmpl:             "Enter recovery key for {{.SourceDevicePath}}:",
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		expectedKey:      key,
		expectedMsg:      "Enter recovery key for /dev/sda1:"})
}

func (s *authRequestorSystemdSuite) TestRequestRecoveryKeyDifferentKey(c *C) {
	var key RecoveryKey
	{
		k := testutil.DecodeHexString(c, "8e67b1865e3d219bab10850cbd2c4dbe")
		copy(key[:], k)
	}

	s.testRequestRecoveryKey(c, &testRequestRecoveryKeyData{
		passphrase:       key.String(),
		tmpl:             "Enter recovery key for {{.SourceDevicePath}}:",
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		expectedKey:      key,
		expectedMsg:      "Enter recovery key for /dev/sda1:"})
}

func (s *authRequestorSystemdSuite) TestRequestRecoveryKeyDifferentSourceDevice(c *C) {
	var key RecoveryKey
	{
		k := testutil.DecodeHexString(c, "e73232a995f8c96988fbd4b4824e34f4")
		copy(key[:], k)
	}

	s.testRequestRecoveryKey(c, &testRequestRecoveryKeyData{
		passphrase:       key.String(),
		tmpl:             "Enter recovery key for {{.SourceDevicePath}}:",
		volumeName:       "data",
		sourceDevicePath: "/dev/vdb1",
		expectedKey:      key,
		expectedMsg:      "Enter recovery key for /dev/vdb1:"})
}

func (s *authRequestorSystemdSuite) TestRequestRecoveryKeyDifferentMsg(c *C) {
	var key RecoveryKey
	{
		k := testutil.DecodeHexString(c, "e73232a995f8c96988fbd4b4824e34f4")
		copy(key[:], k)
	}

	s.testRequestRecoveryKey(c, &testRequestRecoveryKeyData{
		passphrase:       key.String(),
		tmpl:             "Enter recovery key for {{.VolumeName}}:",
		volumeName:       "data",
		sourceDevicePath: "/dev/sda1",
		expectedKey:      key,
		expectedMsg:      "Enter recovery key for data:"})
}

func (s *authRequestorSystemdSuite) TestRequestRecoveryKeyDifferentVolumeName(c *C) {
	var key RecoveryKey
	{
		k := testutil.DecodeHexString(c, "e73232a995f8c96988fbd4b4824e34f4")
		copy(key[:], k)
	}

	s.testRequestRecoveryKey(c, &testRequestRecoveryKeyData{
		passphrase:       key.String(),
		tmpl:             "Enter recovery key for {{.VolumeName}}:",
		volumeName:       "bar",
		sourceDevicePath: "/dev/sda1",
		expectedKey:      key,
		expectedMsg:      "Enter recovery key for bar:"})
}

func (s *authRequestorSystemdSuite) TestRequestRecoveryKeyInvalidResponse(c *C) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte("foo"), 0600), IsNil)

	requestor, err := NewSystemdAuthRequestor("", "")
	c.Assert(err, IsNil)

	_, err = requestor.RequestRecoveryKey("data", "/dev/sda1")
	c.Check(err, ErrorMatches, "systemd-ask-password output is missing terminating newline")
}

func (s *authRequestorSystemdSuite) TestRequestRecoveryKeyInvalidFormat(c *C) {
	s.setPassphrase(c, "foo")

	requestor, err := NewSystemdAuthRequestor("", "")
	c.Assert(err, IsNil)

	_, err = requestor.RequestRecoveryKey("data", "/dev/sda1")
	c.Check(err, ErrorMatches, "cannot parse recovery key: incorrectly formatted: insufficient characters")
}

func (s *authRequestorSystemdSuite) TestRequestRecoveryKeyFailure(c *C) {
	requestor, err := NewSystemdAuthRequestor("", "")
	c.Assert(err, IsNil)

	_, err = requestor.RequestRecoveryKey("data", "/dev/sda1")
	c.Check(err, ErrorMatches, "cannot execute systemd-ask-password: exit status 1")
}
