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
			c.Assert(os.Unsetenv(name), IsNil)
		} else {
			c.Assert(os.Setenv(name, orig), IsNil)
		}
	}
}

func (m *authRequestorSdCredsTestMixin) writeCred(c *C, prefix, uuid, cred, credType string) string {
	var name string
	if len(uuid) > 0 {
		name = filepath.Join(m.credsDir, fmt.Sprintf("%s.%s.%s", prefix, credType, uuid))
	} else {
		name = filepath.Join(m.credsDir, fmt.Sprintf("%s.%s", prefix, credType))
	}
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

	s.AddCleanup(MockLuks2LuksUUID(func(devicePath string) (string, error) {
		c.Errorf("unexpected call")
		return "", fmt.Errorf("unexpected call")
	}))
}

var _ = Suite(&authRequestorSdCredsSuite{})

type testSdCredsRequestUserCredentialParams struct {
	passphrase     string
	passphraseType string

	prefix string

	path      string
	uuid      string
	authTypes UserAuthType
	matchAny  bool

	expectedAuthType UserAuthType
}

func (s *authRequestorSdCredsSuite) testRequestUserCredential(c *C, params *testSdCredsRequestUserCredentialParams) {
	defer MockLuks2LuksUUID(func(devicePath string) (string, error) {
		c.Check(devicePath, Equals, params.path)
		if params.uuid == "" {
			return "", fmt.Errorf("NO UUID")
		}
		return params.uuid, nil
	})()

	prefix := params.prefix
	if prefix == "" {
		prefix = "ubuntu-fde"
	}
	var credPath string
	if params.matchAny {
		credPath = s.writeCred(c, prefix, "", params.passphrase, params.passphraseType)
	} else {
		credPath = s.writeCred(c, prefix, params.uuid, params.passphrase, params.passphraseType)
	}

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
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
		authTypes:        UserAuthTypePassphrase,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialMatchAny(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "password",
		passphraseType:   "passphrase",
		path:             "/dev/sda1",
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
		matchAny:         true,
		authTypes:        UserAuthTypePassphrase,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialMatchAnyNoUUID(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "password",
		passphraseType:   "passphrase",
		path:             "/dev/sda1",
		matchAny:         true,
		authTypes:        UserAuthTypePassphrase,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialDifferentPassphrase(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "1234",
		passphraseType:   "passphrase",
		path:             "/dev/sda1",
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
		authTypes:        UserAuthTypePassphrase,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialDifferentPath(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "password",
		passphraseType:   "passphrase",
		path:             "/dev/nvme0n1p3",
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
		authTypes:        UserAuthTypePassphrase,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialPIN(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "1234",
		passphraseType:   "pin",
		path:             "/dev/sda1",
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
		authTypes:        UserAuthTypePIN,
		expectedAuthType: UserAuthTypePIN,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "00000-11111-22222-33333-44444-55555-00000-11111",
		passphraseType:   "recoverykey",
		path:             "/dev/sda1",
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
		authTypes:        UserAuthTypeRecoveryKey,
		expectedAuthType: UserAuthTypeRecoveryKey,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialPassphraseOrPIN(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "1234",
		passphraseType:   "pin",
		path:             "/dev/sda1",
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
		authTypes:        UserAuthTypePassphrase | UserAuthTypePIN,
		expectedAuthType: UserAuthTypePIN,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialPassphraseOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "password",
		passphraseType:   "passphrase",
		path:             "/dev/sda1",
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
		authTypes:        UserAuthTypePassphrase | UserAuthTypeRecoveryKey,
		expectedAuthType: UserAuthTypePassphrase,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialPINOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "1234",
		passphraseType:   "pin",
		path:             "/dev/sda1",
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
		authTypes:        UserAuthTypePIN | UserAuthTypeRecoveryKey,
		expectedAuthType: UserAuthTypePIN,
	})
}

func (s *authRequestorSdCredsSuite) TestRequestUserCredentialPassphraseOrPINOrRecoveryKey(c *C) {
	s.testRequestUserCredential(c, &testSdCredsRequestUserCredentialParams{
		passphrase:       "password",
		passphraseType:   "passphrase",
		path:             "/dev/sda1",
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
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
		uuid:             "c629f6fc-081d-40b9-b7f9-dcc574f1fa79",
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
	defer MockLuks2LuksUUID(func(devicePath string) (string, error) {
		c.Check(devicePath, Equals, "/dev/sda1")
		return "c629f6fc-081d-40b9-b7f9-dcc574f1fa79", nil
	})()

	s.writeCred(c, "ubuntu-fde", "c629f6fc-081d-40b9-b7f9-dcc574f1fa79", "passphrase", "passphrase")

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
