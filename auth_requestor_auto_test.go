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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"
)

type authRequestorAutoSuite struct {
	snapd_testutil.BaseTest
	authRequestorPlymouthTestMixin
	authRequestorSystemdTestMixin
}

func (s *authRequestorAutoSuite) SetUpTest(c *C) {
	s.AddCleanup(s.authRequestorPlymouthTestMixin.setUpTest(c))
	s.AddCleanup(s.authRequestorSystemdTestMixin.setUpTest(c))
}

func (s *authRequestorAutoSuite) setPassphrase(c *C, passphrase string) {
	s.authRequestorPlymouthTestMixin.setPassphrase(c, passphrase)
	s.authRequestorSystemdTestMixin.setPassphrase(c, passphrase)
}

var _ = Suite(&authRequestorAutoSuite{})

type mockAutoAuthRequestorStringer struct {
	err error
}

func (s *mockAutoAuthRequestorStringer) RequestUserCredentialString(name, path string, authType UserAuthType) (string, error) {
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

func (s *mockAutoAuthRequestorStringer) NotifyUserAuthResultString(name, path string, result UserAuthResult, authTypes, unavailableAuthTypes UserAuthType) (string, error) {
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

func (s *authRequestorAutoSuite) TestNewAuthRequestor(c *C) {
	sdConsole := new(bytes.Buffer)

	restore := MockNewSystemdAuthRequestor(func(console io.Writer, stringFn SystemdAuthRequestorStringFn) (AuthRequestor, error) {
		c.Check(console, Equals, sdConsole)
		return NewSystemdAuthRequestor(console, stringFn)
	})
	defer restore()

	requestor, err := NewAutoAuthRequestor(sdConsole, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)
	c.Assert(requestor, NotNil)
	c.Assert(requestor, testutil.ConvertibleTo, &AutoAuthRequestor{})
	c.Assert(requestor.(*AutoAuthRequestor).Requestors(), HasLen, 2)
	c.Check(requestor.(*AutoAuthRequestor).Requestors()[0], testutil.ConvertibleTo, &PlymouthAuthRequestor{})
	c.Check(requestor.(*AutoAuthRequestor).Requestors()[1], testutil.ConvertibleTo, &SystemdAuthRequestor{})
}

func (s *authRequestorAutoSuite) TestNewAuthRequestorPlymouthNotAvailable(c *C) {
	restore := MockNewPlymouthAuthRequestor(func(_ PlymouthAuthRequestorStringer) (AuthRequestor, error) {
		return nil, ErrAuthRequestorNotAvailable
	})
	defer restore()

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)
	c.Assert(requestor, NotNil)
	c.Assert(requestor, testutil.ConvertibleTo, &AutoAuthRequestor{})
	c.Assert(requestor.(*AutoAuthRequestor).Requestors(), HasLen, 1)
	c.Check(requestor.(*AutoAuthRequestor).Requestors()[0], testutil.ConvertibleTo, &SystemdAuthRequestor{})
}

func (s *authRequestorAutoSuite) TestNewAuthRequestorSystemdNotAvailable(c *C) {
	restore := MockNewSystemdAuthRequestor(func(_ io.Writer, _ SystemdAuthRequestorStringFn) (AuthRequestor, error) {
		return nil, ErrAuthRequestorNotAvailable
	})
	defer restore()

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)
	c.Assert(requestor, NotNil)
	c.Assert(requestor, testutil.ConvertibleTo, &AutoAuthRequestor{})
	c.Assert(requestor.(*AutoAuthRequestor).Requestors(), HasLen, 1)
	c.Check(requestor.(*AutoAuthRequestor).Requestors()[0], testutil.ConvertibleTo, &PlymouthAuthRequestor{})
}

func (s *authRequestorAutoSuite) TestNewAuthRequestorNotAvailable(c *C) {
	restore := MockNewPlymouthAuthRequestor(func(_ PlymouthAuthRequestorStringer) (AuthRequestor, error) {
		return nil, ErrAuthRequestorNotAvailable
	})
	defer restore()

	restore = MockNewSystemdAuthRequestor(func(_ io.Writer, _ SystemdAuthRequestorStringFn) (AuthRequestor, error) {
		return nil, ErrAuthRequestorNotAvailable
	})
	defer restore()

	_, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Check(err, ErrorMatches, "the auth requestor is not available")
	c.Check(errors.Is(err, ErrAuthRequestorNotAvailable), testutil.IsTrue)
}

func (s *authRequestorAutoSuite) TestNewAuthRequestorPlymouthError(c *C) {
	_, err := NewAutoAuthRequestor(nil, nil)
	c.Check(err, ErrorMatches, "cannot create Plymouth AuthRequestor: must supply an implementation of PlymouthAuthRequestorStringer")
}

func (s *authRequestorAutoSuite) TestNewAuthRequestorSystemdError(c *C) {
	restore := MockNewSystemdAuthRequestor(func(_ io.Writer, _ SystemdAuthRequestorStringFn) (AuthRequestor, error) {
		return nil, errors.New("some error")
	})
	defer restore()

	_, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Check(err, ErrorMatches, "cannot create systemd AuthRequestor: some error")
}

func (s *authRequestorAutoSuite) TestRequestUserCredentialPlymouth(c *C) {
	// Ensure that plymouth is used first if available.
	s.setPassphrase(c, "password")

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)

	passphrase, passphraseType, err := requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, "password")
	c.Check(passphraseType, Equals, UserAuthTypePassphrase)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "ask-for-password", "--prompt", "Enter passphrase for data (/dev/sda1):"},
	})
	c.Check(s.mockSdAskPassword.Calls(), HasLen, 0)

	c.Assert(requestor, testutil.ConvertibleTo, &AutoAuthRequestor{})
	c.Check(requestor.(*AutoAuthRequestor).LastUsed(), testutil.ConvertibleTo, &PlymouthAuthRequestor{})
}

func (s *authRequestorAutoSuite) TestRequestUserCredentialSystemd(c *C) {
	// Ensure that systemd-ask-password is used if plymouth isn't running.
	s.setPassphrase(c, "password")
	s.stopPlymouthd(c)

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)

	passphrase, passphraseType, err := requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, "password")
	c.Check(passphraseType, Equals, UserAuthTypePassphrase)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{{"plymouth", "--ping"}})
	c.Check(s.mockSdAskPassword.Calls(), DeepEquals, [][]string{{"systemd-ask-password", "--icon", "drive-harddisk", "--id", "secboot.test:/dev/sda1", "Enter passphrase for data (/dev/sda1):"}})

	c.Assert(requestor, testutil.ConvertibleTo, &AutoAuthRequestor{})
	c.Check(requestor.(*AutoAuthRequestor).LastUsed(), testutil.ConvertibleTo, &SystemdAuthRequestor{})
}

func (s *authRequestorAutoSuite) TestRequestUserCredentialDifferentName(c *C) {
	s.setPassphrase(c, "password")

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)

	passphrase, passphraseType, err := requestor.RequestUserCredential(context.Background(), "foo", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, "password")
	c.Check(passphraseType, Equals, UserAuthTypePassphrase)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "ask-for-password", "--prompt", "Enter passphrase for foo (/dev/sda1):"},
	})
	c.Check(s.mockSdAskPassword.Calls(), HasLen, 0)

	c.Assert(requestor, testutil.ConvertibleTo, &AutoAuthRequestor{})
	c.Check(requestor.(*AutoAuthRequestor).LastUsed(), testutil.ConvertibleTo, &PlymouthAuthRequestor{})
}

func (s *authRequestorAutoSuite) TestRequestUserCredentialDifferentPath(c *C) {
	s.setPassphrase(c, "password")

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)

	passphrase, passphraseType, err := requestor.RequestUserCredential(context.Background(), "data", "/dev/nvme0n1p3", UserAuthTypePassphrase)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, "password")
	c.Check(passphraseType, Equals, UserAuthTypePassphrase)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "ask-for-password", "--prompt", "Enter passphrase for data (/dev/nvme0n1p3):"},
	})
	c.Check(s.mockSdAskPassword.Calls(), HasLen, 0)

	c.Assert(requestor, testutil.ConvertibleTo, &AutoAuthRequestor{})
	c.Check(requestor.(*AutoAuthRequestor).LastUsed(), testutil.ConvertibleTo, &PlymouthAuthRequestor{})
}

func (s *authRequestorAutoSuite) TestRequestUserCredentialDifferentCredentialType(c *C) {
	s.setPassphrase(c, "password")

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)

	passphrase, passphraseType, err := requestor.RequestUserCredential(context.Background(), "foo", "/dev/sda1", UserAuthTypePassphrase|UserAuthTypeRecoveryKey)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, "password")
	c.Check(passphraseType, Equals, UserAuthTypePassphrase|UserAuthTypeRecoveryKey)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "ask-for-password", "--prompt", "Enter passphrase or recovery key for foo (/dev/sda1):"},
	})
	c.Check(s.mockSdAskPassword.Calls(), HasLen, 0)

	c.Assert(requestor, testutil.ConvertibleTo, &AutoAuthRequestor{})
	c.Check(requestor.(*AutoAuthRequestor).LastUsed(), testutil.ConvertibleTo, &PlymouthAuthRequestor{})
}

func (s *authRequestorAutoSuite) TestRequestUserCredentialDifferentPassphrase(c *C) {
	s.setPassphrase(c, "1234")

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)

	passphrase, passphraseType, err := requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, "1234")
	c.Check(passphraseType, Equals, UserAuthTypePassphrase)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "ask-for-password", "--prompt", "Enter passphrase for data (/dev/sda1):"},
	})
	c.Check(s.mockSdAskPassword.Calls(), HasLen, 0)

	c.Assert(requestor, testutil.ConvertibleTo, &AutoAuthRequestor{})
	c.Check(requestor.(*AutoAuthRequestor).LastUsed(), testutil.ConvertibleTo, &PlymouthAuthRequestor{})
}

func (s *authRequestorAutoSuite) TestRequestUserCredentialCanceledContext(c *C) {
	s.setPassphrase(c, "password")

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = requestor.RequestUserCredential(ctx, "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, `cannot execute plymouth --ping: context canceled`)
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
}

func (s *authRequestorAutoSuite) TestRequestUserCredentialPlymouthFails(c *C) {
	// Ensure we get an error if any implementation fails with an unexpected error.
	s.authRequestorSystemdTestMixin.setPassphrase(c, "password")

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "cannot execute plymouth ask-for-password: exit status 1")
}

func (s *authRequestorAutoSuite) TestRequestUserCredentialNotAvailable(c *C) {
	// Ensure we get an appropriate error if no auth requestor is available.
	s.stopPlymouthd(c)

	restore := MockNewSystemdAuthRequestor(func(_ io.Writer, _ SystemdAuthRequestorStringFn) (AuthRequestor, error) {
		return nil, ErrAuthRequestorNotAvailable
	})
	defer restore()

	requestor, err := NewAutoAuthRequestor(nil, new(mockAutoAuthRequestorStringer))
	c.Assert(err, IsNil)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "the auth requestor is not available")
	c.Check(errors.Is(err, ErrAuthRequestorNotAvailable), testutil.IsTrue)
}

func (s *authRequestorAutoSuite) TestNotifyUserAuthResult(c *C) {
	requestor := NewAutoAuthRequestorForTesting(nil, NewPlymouthAuthRequestorForTesting(new(mockPlymouthAuthRequestorStringer), &PlymouthRequestUserCredentialContext{Name: "data", Path: "/dev/sda1"}))

	c.Check(requestor.NotifyUserAuthResult(context.Background(), UserAuthResultSuccess, UserAuthTypePassphrase, 0), IsNil)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "display-message", "--text", "Unlocked data (/dev/sda1) successfully with passphrase"},
	})
}

func (s *authRequestorAutoSuite) TestNotifyUserAuthResultDifferentResult(c *C) {
	requestor := NewAutoAuthRequestorForTesting(nil, NewPlymouthAuthRequestorForTesting(new(mockPlymouthAuthRequestorStringer), &PlymouthRequestUserCredentialContext{Name: "data", Path: "/dev/sda1"}))

	c.Check(requestor.NotifyUserAuthResult(context.Background(), UserAuthResultFailed, UserAuthTypePassphrase, 0), IsNil)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "display-message", "--text", "Incorrect passphrase"},
	})
}

func (s *authRequestorAutoSuite) TestNotifyUserAuthResultDifferentAuthType(c *C) {
	requestor := NewAutoAuthRequestorForTesting(nil, NewPlymouthAuthRequestorForTesting(new(mockPlymouthAuthRequestorStringer), &PlymouthRequestUserCredentialContext{Name: "data", Path: "/dev/sda1"}))

	c.Check(requestor.NotifyUserAuthResult(context.Background(), UserAuthResultSuccess, UserAuthTypePIN, 0), IsNil)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "display-message", "--text", "Unlocked data (/dev/sda1) successfully with PIN"},
	})
}

func (s *authRequestorAutoSuite) TestNotifyUserAuthResultWithExhaustedAuthTypes(c *C) {
	requestor := NewAutoAuthRequestorForTesting(nil, NewPlymouthAuthRequestorForTesting(new(mockPlymouthAuthRequestorStringer), &PlymouthRequestUserCredentialContext{Name: "data", Path: "/dev/sda1"}))

	c.Check(requestor.NotifyUserAuthResult(context.Background(), UserAuthResultFailed, UserAuthTypePassphrase, UserAuthTypePassphrase), IsNil)

	c.Check(s.mockPlymouth.Calls(), DeepEquals, [][]string{
		{"plymouth", "--ping"},
		{"plymouth", "display-message", "--text", "Incorrect passphrase. No more passphrase tries remaining"},
	})
}

func (s *authRequestorAutoSuite) TestNotifyUserAuthResultNoLastUsed(c *C) {
	requestor := NewAutoAuthRequestorForTesting(nil, nil)

	err := requestor.NotifyUserAuthResult(context.Background(), UserAuthResultSuccess, UserAuthTypePassphrase, 0)
	c.Check(err, ErrorMatches, `no user credential requested yet`)
}

func (s *authRequestorAutoSuite) TestNotifyUserAuthResultCanceledContext(c *C) {
	requestor := NewAutoAuthRequestorForTesting(nil, NewPlymouthAuthRequestorForTesting(new(mockPlymouthAuthRequestorStringer), &PlymouthRequestUserCredentialContext{Name: "data", Path: "/dev/sda1"}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := requestor.NotifyUserAuthResult(ctx, UserAuthResultSuccess, UserAuthTypePassphrase, 0)
	c.Check(err, ErrorMatches, `cannot execute plymouth --ping: context canceled`)
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
}

func (s *authRequestorAutoSuite) TestNotifyUserAuthResultFail(c *C) {
	requestor := NewAutoAuthRequestorForTesting(nil, NewPlymouthAuthRequestorForTesting(&mockPlymouthAuthRequestorStringer{err: errors.New("some error")}, &PlymouthRequestUserCredentialContext{Name: "data", Path: "/dev/sda1"}))

	err := requestor.NotifyUserAuthResult(context.Background(), UserAuthResultSuccess, UserAuthTypePassphrase, 0)
	c.Check(err, ErrorMatches, `cannot request message string: some error`)
}
