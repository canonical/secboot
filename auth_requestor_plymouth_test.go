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

package secboot_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
)

type authRequestorPlymouthTestMixin struct {
	passwordFile           string
	stopPlymouthdFile      string
	displayMessageFailFile string
	mockPlymouth           *snapd_testutil.MockCmd
}

func (m *authRequestorPlymouthTestMixin) setUpTest(c *C) (restore func()) {
	dir := c.MkDir()
	m.passwordFile = filepath.Join(dir, "password") // password to be returned by the mock plymouth
	m.stopPlymouthdFile = filepath.Join(dir, "plymouthd-stopped")
	m.displayMessageFailFile = filepath.Join(dir, "display-message-fail")

	plymouthBottom := `if [ "$1" == "--ping" ] && [ -e %[1]s ]; then
	exit 1
elif [ "$1" == "ask-for-password" ]; then
	cat %[2]s
elif [ "$1" == "display-message" ] && [ -e %[3]s ]; then
	exit 1
fi`
	m.mockPlymouth = snapd_testutil.MockCommand(c, "plymouth", fmt.Sprintf(plymouthBottom, m.stopPlymouthdFile, m.passwordFile, m.displayMessageFailFile))
	return m.mockPlymouth.Restore
}

func (m *authRequestorPlymouthTestMixin) setPassphrase(c *C, passphrase string) {
	c.Assert(ioutil.WriteFile(m.passwordFile, []byte(passphrase), 0600), IsNil)
}

func (m *authRequestorPlymouthTestMixin) stopPlymouthd(c *C) {
	f, err := os.Create(m.stopPlymouthdFile)
	c.Assert(err, IsNil)
	f.Close()
}

func (m *authRequestorPlymouthTestMixin) makePlymouthDisplayMessageFail(c *C) {
	f, err := os.Create(m.displayMessageFailFile)
	c.Assert(err, IsNil)
	f.Close()
}

type authRequestorPlymouthSuite struct {
	snapd_testutil.BaseTest
	authRequestorPlymouthTestMixin
}

func (s *authRequestorPlymouthSuite) SetUpTest(c *C) {
	s.AddCleanup(s.authRequestorPlymouthTestMixin.setUpTest(c))
}

var _ = Suite(&authRequestorPlymouthSuite{})

type mockPlymouthAuthRequestorStringer struct {
	err error
}

func (s *mockPlymouthAuthRequestorStringer) RequestUserCredentialString(name, path string, authType UserAuthType) (string, error) {
	if s.err != nil {
		return "", s.err
	}

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
}

func (s *mockPlymouthAuthRequestorStringer) NotifyUserAuthResultString(name, path string, result UserAuthResult, authTypes, unavailableAuthTypes UserAuthType) (string, error) {
	if s.err != nil {
		return "", s.err
	}

	switch result {
	case UserAuthResultSuccess:
		var fmtString string
		switch authTypes {
		case UserAuthTypePassphrase:
			fmtString = "Unlocked %s (%s) successfully with passphrase"
		case UserAuthTypePIN:
			fmtString = "Unlocked %s (%s) successfully with PIN"
		case UserAuthTypeRecoveryKey:
			fmtString = "Unlocked %s (%s) successfully with recovery key"
		default:
			return "", errors.New("unexpected UserAuthType")
		}
		return fmt.Sprintf(fmtString, name, path), nil
	case UserAuthResultFailed:
		var b strings.Builder

		switch authTypes {
		case UserAuthTypePassphrase:
			io.WriteString(&b, "Incorrect passphrase")
		case UserAuthTypePIN:
			io.WriteString(&b, "Incorrect PIN")
		case UserAuthTypeRecoveryKey:
			io.WriteString(&b, "Incorrect recovery key")
		case UserAuthTypePassphrase | UserAuthTypePIN:
			io.WriteString(&b, "Incorrect passphrase or PIN")
		case UserAuthTypePassphrase | UserAuthTypeRecoveryKey:
			io.WriteString(&b, "Incorrect passphrase or recovery key")
		case UserAuthTypePIN | UserAuthTypeRecoveryKey:
			io.WriteString(&b, "Incorrect PIN or recovery key")
		case UserAuthTypePassphrase | UserAuthTypePIN | UserAuthTypeRecoveryKey:
			io.WriteString(&b, "Incorrect passphrase, PIN or recovery key")
		default:
			return "", errors.New("unexpected UserAuthType")
		}

		switch unavailableAuthTypes {
		case UserAuthType(0):
		case UserAuthTypePassphrase:
			io.WriteString(&b, ". No more passphrase tries remaining")
		case UserAuthTypePIN:
			io.WriteString(&b, ". No more PIN tries remaining")
		case UserAuthTypeRecoveryKey:
			io.WriteString(&b, ". No more recovery key tries remaining")
		case UserAuthTypePassphrase | UserAuthTypePIN:
			io.WriteString(&b, ". No more passphrase or PIN tries remaining")
		case UserAuthTypePassphrase | UserAuthTypeRecoveryKey:
			io.WriteString(&b, ". No more passphrase or recovery key tries remaining")
		case UserAuthTypePIN | UserAuthTypeRecoveryKey:
			io.WriteString(&b, ". No more PIN or recovery key tries remaining")
		case UserAuthTypePassphrase | UserAuthTypePIN | UserAuthTypeRecoveryKey:
			io.WriteString(&b, ". No more passphrase, PIN or recovery key tries remaining")
		default:
			return "", errors.New("unexpected UserAuthType")
		}

		return b.String(), nil
	case UserAuthResultInvalidFormat:
		switch authTypes {
		case UserAuthTypePIN:
			return "Invalid PIN", nil
		case UserAuthTypeRecoveryKey:
			return "Invalid recovery key", nil
		case UserAuthTypePIN | UserAuthTypeRecoveryKey:
			return "Invalid PIN or recovery key", nil
		default:
			return "", errors.New("unexpected UserAuthType")
		}
	default:
		return "", errors.New("unexpected UserAuthResult")
	}
}

type testPlymouthRequestUserCredentialsParams struct {
	passphrase string

	ctx       context.Context
	name      string
	path      string
	authTypes UserAuthType

	expectedMsg string
}

func (s *authRequestorPlymouthSuite) testRequestUserCredential(c *C, params *testPlymouthRequestUserCredentialsParams) {
	s.setPassphrase(c, params.passphrase)

	requestor, err := NewPlymouthAuthRequestor(new(mockPlymouthAuthRequestorStringer))
	c.Assert(err, IsNil)

	passphrase, passphraseType, err := requestor.RequestUserCredential(params.ctx, params.name, params.path, params.authTypes)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, params.passphrase)
	c.Check(passphraseType, Equals, params.authTypes)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "ask-for-password", "--prompt", params.expectedMsg},
	})

	c.Assert(requestor, testutil.ConvertibleTo, &PlymouthAuthRequestor{})
	c.Check(requestor.(*PlymouthAuthRequestor).LastRequestUserCredentialCtx(), DeepEquals, PlymouthRequestUserCredentialContext{
		Name: params.name,
		Path: params.path,
	})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialPassphrase(c *C) {
	s.testRequestUserCredential(c, &testPlymouthRequestUserCredentialsParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for data (/dev/sda1):",
	})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialPassphraseDifferentPassphrase(c *C) {
	s.testRequestUserCredential(c, &testPlymouthRequestUserCredentialsParams{
		passphrase:  "1234",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for data (/dev/sda1):",
	})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialDifferentPath(c *C) {
	s.testRequestUserCredential(c, &testPlymouthRequestUserCredentialsParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/nvme0n1p1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for data (/dev/nvme0n1p1):",
	})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialPassphraseDifferentName(c *C) {
	s.testRequestUserCredential(c, &testPlymouthRequestUserCredentialsParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "foo",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Enter passphrase for foo (/dev/sda1):",
	})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialPIN(c *C) {
	s.testRequestUserCredential(c, &testPlymouthRequestUserCredentialsParams{
		passphrase:  "1234",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePIN,
		expectedMsg: "Enter PIN for data (/dev/sda1):",
	})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testPlymouthRequestUserCredentialsParams{
		passphrase:  "00000-11111-22222-33333-44444-55555-00000-11111",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypeRecoveryKey,
		expectedMsg: "Enter recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialPassphraseOrPIN(c *C) {
	s.testRequestUserCredential(c, &testPlymouthRequestUserCredentialsParams{
		passphrase:  "1234",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase | UserAuthTypePIN,
		expectedMsg: "Enter passphrase or PIN for data (/dev/sda1):",
	})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialPassphraseOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testPlymouthRequestUserCredentialsParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
		expectedMsg: "Enter passphrase or recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialPINOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testPlymouthRequestUserCredentialsParams{
		passphrase:  "00000-11111-22222-33333-44444-55555-00000-11111",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedMsg: "Enter PIN or recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialPassphraseOrPINOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testPlymouthRequestUserCredentialsParams{
		passphrase:  "password",
		ctx:         context.Background(),
		name:        "data",
		path:        "/dev/sda1",
		authTypes:   UserAuthTypePassphrase | UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedMsg: "Enter passphrase, PIN or recovery key for data (/dev/sda1):",
	})
}

func (s *authRequestorPlymouthSuite) TestNewRequestorNotAvailable(c *C) {
	old := os.Getenv("PATH")
	dir := c.MkDir()
	os.Setenv("PATH", dir)
	defer func() { os.Setenv("PATH", old) }()

	_, err := NewPlymouthAuthRequestor(nil)
	c.Check(err, ErrorMatches, `the auth requestor is not available`)
	c.Check(errors.Is(err, ErrAuthRequestorNotAvailable), testutil.IsTrue)
}

func (s *authRequestorPlymouthSuite) TestNewRequestorNoStringer(c *C) {
	_, err := NewPlymouthAuthRequestor(nil)
	c.Check(err, ErrorMatches, `must supply an implementation of PlymouthAuthRequestorStringer`)
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialObtainMessageError(c *C) {
	requestor, err := NewPlymouthAuthRequestor(&mockPlymouthAuthRequestorStringer{
		err: errors.New("some error"),
	})
	c.Assert(err, IsNil)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, `cannot request message string: some error`)
	c.Assert(requestor, testutil.ConvertibleTo, &PlymouthAuthRequestor{})
	c.Check(requestor.(*PlymouthAuthRequestor).LastRequestUserCredentialCtx(), DeepEquals, PlymouthRequestUserCredentialContext{})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialFailure(c *C) {
	requestor, err := NewPlymouthAuthRequestor(new(mockPlymouthAuthRequestorStringer))
	c.Assert(err, IsNil)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "cannot execute plymouth ask-for-password: exit status 1")
	c.Assert(requestor, testutil.ConvertibleTo, &PlymouthAuthRequestor{})
	c.Check(requestor.(*PlymouthAuthRequestor).LastRequestUserCredentialCtx(), DeepEquals, PlymouthRequestUserCredentialContext{})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialCanceledContext(c *C) {
	s.setPassphrase(c, "foo")

	requestor, err := NewPlymouthAuthRequestor(new(mockPlymouthAuthRequestorStringer))
	c.Assert(err, IsNil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = requestor.RequestUserCredential(ctx, "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "cannot execute plymouth --ping: context canceled")
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
	c.Assert(requestor, testutil.ConvertibleTo, &PlymouthAuthRequestor{})
	c.Check(requestor.(*PlymouthAuthRequestor).LastRequestUserCredentialCtx(), DeepEquals, PlymouthRequestUserCredentialContext{})
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialNotAvailable(c *C) {
	requestor, err := NewPlymouthAuthRequestor(new(mockPlymouthAuthRequestorStringer))
	c.Assert(err, IsNil)

	s.stopPlymouthd(c)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "the auth requestor is not available")
	c.Check(errors.Is(err, ErrAuthRequestorNotAvailable), testutil.IsTrue)
	c.Assert(requestor, testutil.ConvertibleTo, &PlymouthAuthRequestor{})
	c.Check(requestor.(*PlymouthAuthRequestor).LastRequestUserCredentialCtx(), DeepEquals, PlymouthRequestUserCredentialContext{})
}

type testPlymouthNotifyUserAuthResultParams struct {
	name                 string
	path                 string
	result               UserAuthResult
	authTypes            UserAuthType
	unavailableAuthTypes UserAuthType

	expectedMsg string
}

func (s *authRequestorPlymouthSuite) testNotifyUserAuthResult(c *C, params *testPlymouthNotifyUserAuthResultParams) {
	requestor := NewPlymouthAuthRequestorForTesting(new(mockPlymouthAuthRequestorStringer), &PlymouthRequestUserCredentialContext{Name: params.name, Path: params.path})

	c.Check(requestor.NotifyUserAuthResult(context.Background(), params.result, params.authTypes, params.unavailableAuthTypes), IsNil)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "display-message", "--text", params.expectedMsg},
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultSuccessPassphrase(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "data",
		path:        "/dev/sda1",
		result:      UserAuthResultSuccess,
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Unlocked data (/dev/sda1) successfully with passphrase",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultSuccessDifferentName(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "foo",
		path:        "/dev/sda1",
		result:      UserAuthResultSuccess,
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Unlocked foo (/dev/sda1) successfully with passphrase",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultSuccessDifferentPath(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "data",
		path:        "/dev/nvme0n1p3",
		result:      UserAuthResultSuccess,
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Unlocked data (/dev/nvme0n1p3) successfully with passphrase",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultSuccessPIN(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "data",
		path:        "/dev/sda1",
		result:      UserAuthResultSuccess,
		authTypes:   UserAuthTypePIN,
		expectedMsg: "Unlocked data (/dev/sda1) successfully with PIN",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultSuccessRecoveryKey(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "data",
		path:        "/dev/sda1",
		result:      UserAuthResultSuccess,
		authTypes:   UserAuthTypeRecoveryKey,
		expectedMsg: "Unlocked data (/dev/sda1) successfully with recovery key",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultFailurePassphrase(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "data",
		path:        "/dev/sda1",
		result:      UserAuthResultFailed,
		authTypes:   UserAuthTypePassphrase,
		expectedMsg: "Incorrect passphrase",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultFailurePIN(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "data",
		path:        "/dev/sda1",
		result:      UserAuthResultFailed,
		authTypes:   UserAuthTypePIN,
		expectedMsg: "Incorrect PIN",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultFailurePassphraseOrRecoveryKey(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "data",
		path:        "/dev/sda1",
		result:      UserAuthResultFailed,
		authTypes:   UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
		expectedMsg: "Incorrect passphrase or recovery key",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultFailurePassphraseNoMoreTriesLeft(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:                 "data",
		path:                 "/dev/sda1",
		result:               UserAuthResultFailed,
		authTypes:            UserAuthTypePassphrase,
		unavailableAuthTypes: UserAuthTypePassphrase,
		expectedMsg:          "Incorrect passphrase. No more passphrase tries remaining",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultFailureRecoveryKeyNoMoreTriesLeft(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:                 "data",
		path:                 "/dev/sda1",
		result:               UserAuthResultFailed,
		authTypes:            UserAuthTypeRecoveryKey,
		unavailableAuthTypes: UserAuthTypeRecoveryKey,
		expectedMsg:          "Incorrect recovery key. No more recovery key tries remaining",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultInvalidPIN(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "data",
		path:        "/dev/sda1",
		result:      UserAuthResultInvalidFormat,
		authTypes:   UserAuthTypePIN,
		expectedMsg: "Invalid PIN",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultInvalidRecoveryKey(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "data",
		path:        "/dev/sda1",
		result:      UserAuthResultInvalidFormat,
		authTypes:   UserAuthTypeRecoveryKey,
		expectedMsg: "Invalid recovery key",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultInvalidPINOrRecoveryKey(c *C) {
	s.testNotifyUserAuthResult(c, &testPlymouthNotifyUserAuthResultParams{
		name:        "data",
		path:        "/dev/sda1",
		result:      UserAuthResultInvalidFormat,
		authTypes:   UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedMsg: "Invalid PIN or recovery key",
	})
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultNotAvailable(c *C) {
	requestor, err := NewPlymouthAuthRequestor(new(mockPlymouthAuthRequestorStringer))
	c.Assert(err, IsNil)

	s.stopPlymouthd(c)

	err = requestor.NotifyUserAuthResult(context.Background(), UserAuthResultSuccess, UserAuthTypePassphrase, 0)
	c.Check(err, ErrorMatches, "the auth requestor is not available")
	c.Check(errors.Is(err, ErrAuthRequestorNotAvailable), testutil.IsTrue)
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultObtainMessageError(c *C) {
	requestor, err := NewPlymouthAuthRequestor(&mockPlymouthAuthRequestorStringer{
		err: errors.New("some error"),
	})
	c.Assert(err, IsNil)

	err = requestor.NotifyUserAuthResult(context.Background(), UserAuthResultSuccess, UserAuthTypePassphrase, 0)
	c.Check(err, ErrorMatches, `cannot request message string: some error`)
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultCanceledContext(c *C) {
	requestor := NewPlymouthAuthRequestorForTesting(new(mockPlymouthAuthRequestorStringer), &PlymouthRequestUserCredentialContext{Name: "data", Path: "/dev/sda1"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := requestor.NotifyUserAuthResult(ctx, UserAuthResultSuccess, UserAuthTypePassphrase, 0)
	c.Check(err, ErrorMatches, "cannot execute plymouth --ping: context canceled")
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
}

func (s *authRequestorPlymouthSuite) TestNotifyUserAuthResultFailure(c *C) {
	requestor := NewPlymouthAuthRequestorForTesting(new(mockPlymouthAuthRequestorStringer), &PlymouthRequestUserCredentialContext{Name: "data", Path: "/dev/sda1"})

	s.makePlymouthDisplayMessageFail(c)

	err := requestor.NotifyUserAuthResult(context.Background(), UserAuthResultSuccess, UserAuthTypePassphrase, 0)
	c.Check(err, ErrorMatches, "cannot execute plymouth display-message: exit status 1")
}
