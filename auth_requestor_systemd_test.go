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
	"bytes"
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

type authRequestorSystemdTestMixin struct {
	passwordFile      string
	mockSdAskPassword *snapd_testutil.MockCmd
}

func (m *authRequestorSystemdTestMixin) setUpTest(c *C) (restore func()) {
	dir := c.MkDir()
	m.passwordFile = filepath.Join(dir, "password") // password to be returned by the mock sd-ask-password

	sdAskPasswordBottom := `cat %[1]s`
	m.mockSdAskPassword = snapd_testutil.MockCommand(c, "systemd-ask-password", fmt.Sprintf(sdAskPasswordBottom, m.passwordFile))
	return m.mockSdAskPassword.Restore
}

func (m *authRequestorSystemdTestMixin) setPassphrase(c *C, passphrase string) {
	c.Assert(ioutil.WriteFile(m.passwordFile, []byte(passphrase+"\n"), 0600), IsNil)
}

type authRequestorSystemdSuite struct {
	snapd_testutil.BaseTest
	authRequestorSystemdTestMixin
}

func (s *authRequestorSystemdSuite) SetUpTest(c *C) {
	s.AddCleanup(s.authRequestorSystemdTestMixin.setUpTest(c))
}

var _ = Suite(&authRequestorSystemdSuite{})

type testSystemdRequestUserCredentialsParams struct {
	passphrase string

	ctx       context.Context
	name      string
	path      string
	authTypes UserAuthType

	expectedMsg string
}

func (s *authRequestorSystemdSuite) testRequestUserCredential(c *C, params *testSystemdRequestUserCredentialsParams) {
	s.setPassphrase(c, params.passphrase)

	requestor, err := NewSystemdAuthRequestor(nil, func(name, path string, authType UserAuthType) (string, error) {
		var fmtString string
		switch authType {
		case UserAuthTypePassphrase:
			fmtString = "Enter passphrase for %s (%s):"
		case UserAuthTypePIN:
			fmtString = "Enter PIN for %s (%s):"
		case UserAuthTypeRecoveryKey:
			fmtString = "Enter recovery key for %s (%s):"
		case UserAuthTypePassphrase | UserAuthTypePIN:
			fmtString = "Enter passphrase or PIN for %s (%s):"
		case UserAuthTypePassphrase | UserAuthTypeRecoveryKey:
			fmtString = "Enter passphrase or recovery key for %s (%s):"
		case UserAuthTypePIN | UserAuthTypeRecoveryKey:
			fmtString = "Enter PIN or recovery key for %s (%s):"
		case UserAuthTypePassphrase | UserAuthTypePIN | UserAuthTypeRecoveryKey:
			fmtString = "Enter passphrase, PIN or recovery key for %s (%s):"
		default:
			return "", errors.New("unexpected UserAuthType")
		}
		return fmt.Sprintf(fmtString, name, path), nil
	})
	c.Assert(err, IsNil)

	passphrase, passphraseType, err := requestor.RequestUserCredential(params.ctx, params.name, params.path, params.authTypes)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, params.passphrase)
	c.Check(passphraseType, Equals, params.authTypes)

	c.Check(s.mockSdAskPassword.Calls(), HasLen, 1)
	c.Check(s.mockSdAskPassword.Calls()[0], DeepEquals, []string{"systemd-ask-password", "--icon", "drive-harddisk",
		"--id", filepath.Base(os.Args[0]) + ":" + params.path, params.expectedMsg})

	c.Assert(requestor, testutil.ConvertibleTo, &SystemdAuthRequestor{})
	c.Check(requestor.(*SystemdAuthRequestor).LastRequestUserCredentialPath(), Equals, params.path)
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphrase(c *C) {
	s.testRequestUserCredential(c, &testSystemdRequestUserCredentialsParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphraseDifferentPassphrase(c *C) {
	s.testRequestUserCredential(c, &testSystemdRequestUserCredentialsParams{
		passphrase:  "1234",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialDifferentPath(c *C) {
	s.testRequestUserCredential(c, &testSystemdRequestUserCredentialsParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/nvme0n1p1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for data (/dev/nvme0n1p1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphraseDifferentName(c *C) {
	s.testRequestUserCredential(c, &testSystemdRequestUserCredentialsParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "foo",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for foo (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPIN(c *C) {
	s.testRequestUserCredential(c, &testSystemdRequestUserCredentialsParams{
		passphrase:  "1234",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePIN,
		expectedMsg: "Enter PIN for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSystemdRequestUserCredentialsParams{
		passphrase:  "00000-11111-22222-33333-44444-55555-00000-11111",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypeRecoveryKey,
		expectedMsg: "Enter recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphraseOrPIN(c *C) {
	s.testRequestUserCredential(c, &testSystemdRequestUserCredentialsParams{
		passphrase:  "1234",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase | UserAuthTypePIN,
		expectedMsg: "Enter passphrase or PIN for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphraseOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSystemdRequestUserCredentialsParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
		expectedMsg: "Enter passphrase or recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPINOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSystemdRequestUserCredentialsParams{
		passphrase:  "00000-11111-22222-33333-44444-55555-00000-11111",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedMsg: "Enter PIN or recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialPassphraseOrPINOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSystemdRequestUserCredentialsParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase | UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedMsg: "Enter passphrase, PIN or recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorSystemdSuite) TestNewRequestorNotAvailable(c *C) {
	old := os.Getenv("PATH")
	dir := c.MkDir()
	os.Setenv("PATH", dir)
	defer func() { os.Setenv("PATH", old) }()

	_, err := NewSystemdAuthRequestor(nil, nil)
	c.Check(err, ErrorMatches, `the auth requestor is not available`)
	c.Check(errors.Is(err, ErrAuthRequestorNotAvailable), testutil.IsTrue)
}

func (s *authRequestorSystemdSuite) TestNewRequestorNoFormatStringCallback(c *C) {
	_, err := NewSystemdAuthRequestor(nil, nil)
	c.Check(err, ErrorMatches, `must supply a SystemdAuthRequestorStringFn`)
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialObtainMessageError(c *C) {
	requestor, err := NewSystemdAuthRequestor(nil, func(string, string, UserAuthType) (string, error) {
		return "", errors.New("some error")
	})
	c.Assert(err, IsNil)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, `cannot request message string: some error`)
	c.Assert(requestor, testutil.ConvertibleTo, &SystemdAuthRequestor{})
	c.Check(requestor.(*SystemdAuthRequestor).LastRequestUserCredentialPath(), Equals, "")
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialInvalidResponse(c *C) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte("foo"), 0600), IsNil)

	requestor, err := NewSystemdAuthRequestor(nil, func(string, string, UserAuthType) (string, error) {
		return "", nil
	})
	c.Assert(err, IsNil)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "systemd-ask-password output is missing terminating newline")
	c.Assert(requestor, testutil.ConvertibleTo, &SystemdAuthRequestor{})
	c.Check(requestor.(*SystemdAuthRequestor).LastRequestUserCredentialPath(), Equals, "")
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialFailure(c *C) {
	requestor, err := NewSystemdAuthRequestor(nil, func(string, string, UserAuthType) (string, error) {
		return "", nil
	})
	c.Assert(err, IsNil)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "cannot execute systemd-ask-password: exit status 1")
	c.Assert(requestor, testutil.ConvertibleTo, &SystemdAuthRequestor{})
	c.Check(requestor.(*SystemdAuthRequestor).LastRequestUserCredentialPath(), Equals, "")
}

func (s *authRequestorSystemdSuite) TestRequestUserCredentialCanceledContext(c *C) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte("foo"), 0600), IsNil)

	requestor, err := NewSystemdAuthRequestor(nil, func(string, string, UserAuthType) (string, error) {
		return "", nil
	})
	c.Assert(err, IsNil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = requestor.RequestUserCredential(ctx, "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "cannot execute systemd-ask-password: context canceled")
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
	c.Assert(requestor, testutil.ConvertibleTo, &SystemdAuthRequestor{})
	c.Check(requestor.(*SystemdAuthRequestor).LastRequestUserCredentialPath(), Equals, "")
}

type testSystemdNotifyUserAuthResultParams struct {
	path                 string
	result               UserAuthResult
	authTypes            UserAuthType
	unavailableAuthTypes UserAuthType

	expectedMsg string
}

func (s *authRequestorSystemdSuite) testNotifyUserAuthResult(c *C, params *testSystemdNotifyUserAuthResultParams) {
	console := new(bytes.Buffer)
	requestor := NewSystemdAuthRequestorForTesting(console, nil, params.path)

	c.Check(requestor.NotifyUserAuthResult(nil, params.result, params.authTypes, params.unavailableAuthTypes), IsNil)
	c.Check(console.String(), Equals, params.expectedMsg)
}

func (s *authRequestorSystemdSuite) TestNotifyUserAuthResultSuccess(c *C) {
	s.testNotifyUserAuthResult(c, &testSystemdNotifyUserAuthResultParams{
		result: UserAuthResultSuccess,
	})
}

func (s *authRequestorSystemdSuite) TestNotifyUserAuthResultFailurePassphrase(c *C) {
	s.testNotifyUserAuthResult(c, &testSystemdNotifyUserAuthResultParams{
		path:      "/dev/sda1",
		result:    UserAuthResultFailed,
		authTypes: UserAuthTypePassphrase,
		expectedMsg: `Incorrect passphrase for /dev/sda1
`,
	})
}

func (s *authRequestorSystemdSuite) TestNotifyUserAuthResultFailurePIN(c *C) {
	s.testNotifyUserAuthResult(c, &testSystemdNotifyUserAuthResultParams{
		path:      "/dev/sda1",
		result:    UserAuthResultFailed,
		authTypes: UserAuthTypePIN,
		expectedMsg: `Incorrect PIN for /dev/sda1
`,
	})
}

func (s *authRequestorSystemdSuite) TestNotifyUserAuthResultFailurePassphraseOrRecoveryKey(c *C) {
	s.testNotifyUserAuthResult(c, &testSystemdNotifyUserAuthResultParams{
		path:      "/dev/sda1",
		result:    UserAuthResultFailed,
		authTypes: UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
		expectedMsg: `Incorrect passphrase or recovery key for /dev/sda1
`,
	})
}

func (s *authRequestorSystemdSuite) TestNotifyUserAuthResultFailureDifferentPath(c *C) {
	s.testNotifyUserAuthResult(c, &testSystemdNotifyUserAuthResultParams{
		path:      "/dev/nvme0n1p3",
		result:    UserAuthResultFailed,
		authTypes: UserAuthTypePassphrase,
		expectedMsg: `Incorrect passphrase for /dev/nvme0n1p3
`,
	})
}

func (s *authRequestorSystemdSuite) TestNotifyUserAuthResultFailurePassphraseNoMoreTriesLeft(c *C) {
	s.testNotifyUserAuthResult(c, &testSystemdNotifyUserAuthResultParams{
		path:                 "/dev/sda1",
		result:               UserAuthResultFailed,
		authTypes:            UserAuthTypePassphrase,
		unavailableAuthTypes: UserAuthTypePassphrase,
		expectedMsg: `Incorrect passphrase for /dev/sda1
No more passphrase tries remaining
`,
	})
}

func (s *authRequestorSystemdSuite) TestNotifyUserAuthResultFailureRecoveryKeyNoMoreTriesLeft(c *C) {
	s.testNotifyUserAuthResult(c, &testSystemdNotifyUserAuthResultParams{
		path:                 "/dev/sda1",
		result:               UserAuthResultFailed,
		authTypes:            UserAuthTypeRecoveryKey,
		unavailableAuthTypes: UserAuthTypeRecoveryKey,
		expectedMsg: `Incorrect recovery key for /dev/sda1
No more recovery key tries remaining
`,
	})
}

func (s *authRequestorSystemdSuite) TestNotifyUserAuthResultInvalidPIN(c *C) {
	s.testNotifyUserAuthResult(c, &testSystemdNotifyUserAuthResultParams{
		result:    UserAuthResultInvalidFormat,
		authTypes: UserAuthTypePIN,
		expectedMsg: `Incorrectly formatted PIN
`,
	})
}

func (s *authRequestorSystemdSuite) TestNotifyUserAuthResultInvalidPINOrRecoveryKey(c *C) {
	s.testNotifyUserAuthResult(c, &testSystemdNotifyUserAuthResultParams{
		result:    UserAuthResultInvalidFormat,
		authTypes: UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedMsg: `Incorrectly formatted PIN or recovery key
`,
	})
}
