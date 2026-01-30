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
	"io/ioutil"
	"path/filepath"

	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
)

type authRequestorPlymouthSuite struct {
	snapd_testutil.BaseTest

	passwordFile string
	mockPlymouth *snapd_testutil.MockCmd
}

func (s *authRequestorPlymouthSuite) SetUpTest(c *C) {
	dir := c.MkDir()
	s.passwordFile = filepath.Join(dir, "password") // password to be returned by the mock plymouth

	plymouthBottom := `cat %[1]s`
	s.mockPlymouth = snapd_testutil.MockCommand(c, "plymouth", fmt.Sprintf(plymouthBottom, s.passwordFile))
	s.AddCleanup(s.mockPlymouth.Restore)
}

func (s *authRequestorPlymouthSuite) setPassphrase(c *C, passphrase string) {
	c.Assert(ioutil.WriteFile(s.passwordFile, []byte(passphrase), 0600), IsNil)
}

var _ = Suite(&authRequestorPlymouthSuite{})

type mockPlymouthAuthRequestorStringer struct {
	rucErr error
}

func (s *mockPlymouthAuthRequestorStringer) RequestUserCredentialString(name, path string, authType UserAuthType) (string, error) {
	if s.rucErr != nil {
		return "", s.rucErr
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

	c.Check(s.mockPlymouth.Calls(), HasLen, 1)
	c.Check(s.mockPlymouth.Calls()[0], DeepEquals, []string{"plymouth", "ask-for-password", "--prompt", params.expectedMsg})
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

func (s *authRequestorPlymouthSuite) TestNewRequestorNoStringer(c *C) {
	_, err := NewPlymouthAuthRequestor(nil)
	c.Check(err, ErrorMatches, `must supply an implementation of PlymouthAuthRequestorStringer`)
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialObtainMessageError(c *C) {
	requestor, err := NewPlymouthAuthRequestor(&mockPlymouthAuthRequestorStringer{
		rucErr: errors.New("some error"),
	})
	c.Assert(err, IsNil)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, `cannot request message string: some error`)
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialFailure(c *C) {
	requestor, err := NewPlymouthAuthRequestor(new(mockPlymouthAuthRequestorStringer))
	c.Assert(err, IsNil)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "cannot execute plymouth ask-for-password: exit status 1")
}

func (s *authRequestorPlymouthSuite) TestRequestUserCredentialCanceledContext(c *C) {
	s.setPassphrase(c, "foo")

	requestor, err := NewPlymouthAuthRequestor(new(mockPlymouthAuthRequestorStringer))
	c.Assert(err, IsNil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = requestor.RequestUserCredential(ctx, "data", "/dev/sda1", UserAuthTypePassphrase)
	c.Check(err, ErrorMatches, "cannot execute plymouth ask-for-password: context canceled")
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
}
