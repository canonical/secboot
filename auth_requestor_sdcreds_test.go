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
	"os"
	"path/filepath"
	"strings"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"
)

type authRequestorSdCredsTestMixin struct {
	credsDir string
}

func (m *authRequestorSdCredsTestMixin) setUpTest(c *C) (restore func()) {
	m.credsDir = c.MkDir()

	name := "CREDENTIALS_DIRECTORY"
	orig, set := os.LookupEnv(name)
	c.Assert(os.Setenv(name, m.credsDir), IsNil)
	return func() {
		if !set {
			return
		}
		c.Assert(os.Setenv(name, orig), IsNil)
	}
}

func (m *authRequestorSdCredsTestMixin) writeCred(c *C, prefix, path, cred, credType string) string {
	name := filepath.Join(m.credsDir, fmt.Sprintf("%s.%s.%s", prefix, strings.ReplaceAll(path[1:], "/", "-"), credType))
	c.Assert(os.WriteFile(name, []byte(cred), 0644), IsNil)
	return name
}

type authRequestorSdCredsSuite struct {
	snapd_testutil.BaseTest
	authRequestorSdCredsTestMixin
}

func (s *authRequestorSdCredsSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.AddCleanup(s.authRequestorSdCredsTestMixin.setUpTest(c))
}

var _ = Suite(&authRequestorSdCredsSuite{})

type testSdCredsRequestUserCredentialParams struct {
	passphrase     string
	passphraseType string

	prefix string

	path      string
	authTypes UserAuthType

	expectedAuthType UserAuthType
}

func (s *authRequestorSdCredsSuite) testRequestUserCredential(c *C, params *testSdCredsRequestUserCredentialParams) {
	prefix := params.prefix
	if prefix == "" {
		prefix = "ubuntu-fde"
	}
	credPath := s.writeCred(c, prefix, params.path, params.passphrase, params.passphraseType)

	requestor, err := NewSystemdCredsAuthRequestor(nil, params.prefix)
	c.Assert(err, IsNil)

	passphrase, passphraseType, err := requestor.RequestUserCredential(context.Background(), "data", params.path, params.authTypes)
	c.Check(err, IsNil)
	c.Check(passphrase, Equals, params.passphrase)
	c.Check(passphraseType, Equals, params.expectedAuthType)

	c.Assert(requestor, testutil.ConvertibleTo, &SystemdCredsAuthRequestor{})
	c.Check(requestor.(*SystemdCredsAuthRequestor).LastRequestUserCredentialCtx(), DeepEquals, SystemdCredsRequestUserCredentialContext{
		Path:     params.path,
		CredPath: credPath,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredential(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "password",
		passphraseType:   "passphrase",
		path:             "/dev/sda1",
		authTypes:        UserAuthTypePassphrase,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialDifferentPassphrase(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "1234",
		passphraseType:   "passphrase",
		path:             "/dev/sda1",
		authTypes:        UserAuthTypePassphrase,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialDifferentPath(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "password",
		passphraseType:   "passphrase",
		path:             "/dev/nvme0n1p3",
		authTypes:        UserAuthTypePassphrase,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialPIN(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "1234",
		passphraseType:   "pin",
		path:             "/dev/sda1",
		authTypes:        UserAuthTypePIN,
		expectedAuthType: UserAuthTypePIN,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "00000-11111-22222-33333-44444-55555-00000-11111",
		passphraseType:   "recoverykey",
		path:             "/dev/sda1",
		authTypes:        UserAuthTypeRecoveryKey,
		expectedAuthType: UserAuthTypeRecoveryKey,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialPassphraseOrPIN(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "1234",
		passphraseType:   "pin",
		path:             "/dev/sda1",
		authTypes:        UserAuthTypePassphrase | UserAuthTypePIN,
		expectedAuthType: UserAuthTypePIN,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialPassphraseOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "password",
		passphraseType:   "passphrase",
		path:             "/dev/sda1",
		authTypes:        UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialPINOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "1234",
		passphraseType:   "pin",
		path:             "/dev/sda1",
		authTypes:        UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedAuthType: UserAuthTypePIN,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialPassphraseOrPINOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "password",
		passphraseType:   "passphrase",
		path:             "/dev/sda1",
		authTypes:        UserAuthTypePassphrase | UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialDifferentPrefix(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "password",
		passphraseType:   "passphrase",
		prefix:           "foo",
		path:             "/dev/sda1",
		authTypes:        UserAuthTypePassphrase,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestNewRequestorNotAvailable(c *C) {
	c.Assert(os.Unsetenv("CREDENTIALS_DIRECTORY"), IsNil)

	_, err := NewSystemdCredsAuthRequestor(nil, "")
	c.Check(err, ErrorMatches, `the auth requestor is not available`)
	c.Check(errors.Is(err, ErrAuthRequestorNotAvailable), testutil.IsTrue)
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialNotAvailable(c *C) {
	s.writeCred(c, "ubuntu-fde", "/dev/sda1", "passphrase", "passphrase")

	requestor, err := NewSystemdCredsAuthRequestor(nil, "")
	c.Assert(err, IsNil)

	_, _, err = requestor.RequestUserCredential(context.Background(), "data", "/dev/sda1", UserAuthTypePIN|UserAuthTypeRecoveryKey)
	c.Check(err, ErrorMatches, `the auth requestor is not available`)
	c.Check(errors.Is(err, ErrAuthRequestorNotAvailable), testutil.IsTrue)

	c.Assert(requestor, testutil.ConvertibleTo, &SystemdCredsAuthRequestor{})
	c.Check(requestor.(*SystemdCredsAuthRequestor).LastRequestUserCredentialCtx(), DeepEquals, SystemdCredsRequestUserCredentialContext{})
}

type testSdCredsNotifyUserAuthResultParams struct {
	path                 string
	credPath             string
	result               UserAuthResult
	authTypes            UserAuthType
	unavailableAuthTypes UserAuthType

	expectedMsg string
}

func (s *authRequestorSdCredsSuite) testNotifyUserAuthResult(c *C, params *testSdCredsNotifyUserAuthResultParams) {
	console := new(bytes.Buffer)
	requestor := NewSystemdCredsAuthRequestorForTesting(console, "", "", &SystemdCredsRequestUserCredentialContext{
		CredPath: params.credPath,
		Path:     params.path,
	})

	c.Check(requestor.NotifyUserAuthResult(nil, params.result, params.authTypes, params.unavailableAuthTypes), IsNil)
	c.Check(console.String(), Equals, params.expectedMsg)
}

func (s *authRequestorSdCredsSuite) TestNotifyUserAuthResultSuccess(c *C) {
	s.testNotifyUserAuthResult(c, &testSdCredsNotifyUserAuthResultParams{
		result: UserAuthResultSuccess,
	})
}

func (s *authRequestorSdCredsSuite) TestNotifyUserAuthResultFailurePassphrase(c *C) {
	s.testNotifyUserAuthResult(c, &testSdCredsNotifyUserAuthResultParams{
		path:      "/dev/sda1",
		credPath:  "/foo/ubuntu-fde.dev-sda1.passphrase",
		result:    UserAuthResultFailed,
		authTypes: UserAuthTypePassphrase,
		expectedMsg: `Incorrect passphrase from credential /foo/ubuntu-fde.dev-sda1.passphrase for /dev/sda1
`,
	})
}

func (s *authRequestorSdCredsSuite) TestNotifyUserAuthResultFailurePIN(c *C) {
	s.testNotifyUserAuthResult(c, &testSdCredsNotifyUserAuthResultParams{
		path:      "/dev/sda1",
		credPath:  "/foo/ubuntu-fde.dev-sda1.pin",
		result:    UserAuthResultFailed,
		authTypes: UserAuthTypePIN,
		expectedMsg: `Incorrect PIN from credential /foo/ubuntu-fde.dev-sda1.pin for /dev/sda1
`,
	})
}

func (s *authRequestorSdCredsSuite) TestNotifyUserAuthResultFailureDifferentPath(c *C) {
	s.testNotifyUserAuthResult(c, &testSdCredsNotifyUserAuthResultParams{
		path:      "/dev/nvme0n1p3",
		credPath:  "/foo/ubuntu-fde.dev-nvme0n1p3.passphrase",
		result:    UserAuthResultFailed,
		authTypes: UserAuthTypePassphrase,
		expectedMsg: `Incorrect passphrase from credential /foo/ubuntu-fde.dev-nvme0n1p3.passphrase for /dev/nvme0n1p3
`,
	})
}

func (s *authRequestorSdCredsSuite) TestNotifyUserAuthResultInvalidPIN(c *C) {
	s.testNotifyUserAuthResult(c, &testSdCredsNotifyUserAuthResultParams{
		path:      "/dev/sda1",
		credPath:  "/foo/ubuntu-fde.dev-sda1.pin",
		result:    UserAuthResultInvalidFormat,
		authTypes: UserAuthTypePIN,
		expectedMsg: `Incorrectly formatted PIN from credential /foo/ubuntu-fde.dev-sda1.pin
`,
	})
}

func (s *authRequestorSdCredsSuite) TestNotifyUserAuthResultInvalidRecoveryKey(c *C) {
	s.testNotifyUserAuthResult(c, &testSdCredsNotifyUserAuthResultParams{
		path:      "/dev/sda1",
		credPath:  "/foo/ubuntu-fde.dev-sda1.recoverykey",
		result:    UserAuthResultInvalidFormat,
		authTypes: UserAuthTypeRecoveryKey,
		expectedMsg: `Incorrectly formatted recovery key from credential /foo/ubuntu-fde.dev-sda1.recoverykey
`,
	})
}
