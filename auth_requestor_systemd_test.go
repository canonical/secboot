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
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
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

type testRequestUserCredentialParams struct {
	passphrase string

	ctx       context.Context
	name      string
	path      string
	authTypes UserAuthType

	expectedMsg string
}

func (s *authRequestorSystemdSuite) testRequestUserCredential(c *C, params *testRequestUserCredentialParams) {
	s.setPassphrase(c, params.passphrase)

	requestor := NewSystemdAuthRequestor(map[UserAuthType]string{
		UserAuthTypePassphrase:                                             "Enter passphrase for %[1]s (%[2]s):",
		UserAuthTypePIN:                                                    "Enter PIN for %[1]s (%[2]s):",
		UserAuthTypeRecoveryKey:                                            "Enter recovery key for %[1]s (%[2]s):",
		UserAuthTypePassphrase | UserAuthTypePIN:                           "Enter passphrase or PIN for %[1]s (%[2]s):",
		UserAuthTypePassphrase | UserAuthTypeRecoveryKey:                   "Enter passphrase or recovery key for %[1]s (%[2]s):",
		UserAuthTypePIN | UserAuthTypeRecoveryKey:                          "Enter PIN or recovery key for %[1]s (%[2]s):",
		UserAuthTypePassphrase | UserAuthTypePIN | UserAuthTypeRecoveryKey: "Enter passphrase, PIN or recovery key for %[1]s (%[2]s):",
	})

	passphrase, err := requestor.RequestUserCredential(params.ctx, params.name, params.path, params.authTypes)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, params.passphrase)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, 1)
	c.Check(s.mockSdAskPassword.Calls()[0], DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk",
		"--id", filepath.Base(os.Args[0]) + ":" + params.path, params.expectedMsg})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphrase(c *C) {
	s.testRequestUserCredential(c, &testRequestUserCredentialParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphraseDifferentPassphrase(c *C) {
	s.testRequestUserCredential(c, &testRequestUserCredentialParams{
		passphrase:  "1234",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialDifferentPath(c *C) {
	s.testRequestUserCredential(c, &testRequestUserCredentialParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/nvme0n1p1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for data (/dev/nvme0n1p1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphraseDifferentName(c *C) {
	s.testRequestUserCredential(c, &testRequestUserCredentialParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "foo",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for foo (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPIN(c *C) {
	s.testRequestUserCredential(c, &testRequestUserCredentialParams{
		passphrase:  "1234",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePIN,
		expectedMsg: "Enter PIN for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testRequestUserCredentialParams{
		passphrase:  "00000-11111-22222-33333-44444-55555-00000-11111",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypeRecoveryKey,
		expectedMsg: "Enter recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphraseOrPIN(c *C) {
	s.testRequestUserCredential(c, &testRequestUserCredentialParams{
		passphrase:  "1234",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase | UserAuthTypePIN,
		expectedMsg: "Enter passphrase or PIN for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphraseOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testRequestUserCredentialParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
		expectedMsg: "Enter passphrase or recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPINOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testRequestUserCredentialParams{
		passphrase:  "00000-11111-22222-33333-44444-55555-00000-11111",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedMsg: "Enter PIN or recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphraseOrPINOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testRequestUserCredentialParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase | UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedMsg: "Enter passphrase, PIN or recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialInvalidResponse(c *C) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte("foo"), 0600), IsNil)

	requestor := NewSystemdAuthRequestor(map[UserAuthType]string{
		UserAuthTypePassphrase: "",
	})

	_, err := requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "systemd-ask-password output is missing terminating newline")
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialFailure(c *C) {
	requestor := NewSystemdAuthRequestor(map[UserAuthType]string{
		UserAuthTypePassphrase: "",
	})

	_, err := requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "cannot execute systemd-ask-password: exit status 1")
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialCanceledContext(c *C) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte("foo"), 0600), IsNil)

	requestor := NewSystemdAuthRequestor(map[UserAuthType]string{
		UserAuthTypePassphrase: "",
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := requestor.RequestUserCredential(ctx, "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "cannot execute systemd-ask-password: context canceled")
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
}
