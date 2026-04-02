// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package tpm2_test

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type primaryKeyMixin struct {
	tpmTest *tpm2_testutil.TPMTest
}

func (m *primaryKeyMixin) validatePrimaryKeyAgainstTemplate(c *C, hierarchy, handle tpm2.Handle, template *tpm2.Public) {
	c.Assert(m.tpmTest, NotNil) // primaryKeyMixin.tpmTest must be set!

	// The easiest way to validate that the primary key was created with the supplied
	// template is to just create it again and compare the names
	expected := m.tpmTest.CreatePrimary(c, hierarchy, template)
	defer m.tpmTest.TPM.FlushContext(expected)

	key, err := m.tpmTest.TPM.NewResourceContext(handle)
	c.Assert(err, IsNil)
	c.Check(key.Name(), DeepEquals, expected.Name())
}

func (m *primaryKeyMixin) validateSRK(c *C) {
	m.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, tcg.SRKTemplate)
}

func (m *primaryKeyMixin) validateEK(c *C) {
	m.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleEndorsement, tcg.EKHandle, tcg.EKTemplate)
}

type provisioningSuite struct {
	tpm2test.TPMTest
	primaryKeyMixin
	lockoutauthSuiteMixin
}

func (s *provisioningSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureLockoutHierarchy |
		tpm2test.TPMFeaturePlatformHierarchy | // Allow the test fixture to reenable owner clear
		tpm2test.TPMFeatureClear |
		tpm2test.TPMFeatureNV
}

func (s *provisioningSuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)
	s.primaryKeyMixin.tpmTest = &s.TPMTest.TPMTest
}

type provisioningSimulatorSuite struct {
	tpm2test.TPMSimulatorTest
	primaryKeyMixin
}

func (s *provisioningSimulatorSuite) SetUpTest(c *C) {
	s.TPMSimulatorTest.SetUpTest(c)
	s.primaryKeyMixin.tpmTest = &s.TPMTest
}

// Split the tests into 2 suites - one which requires a simulator because we want to
// control the initial conditions of the test.
var _ = Suite(&provisioningSuite{})
var _ = Suite(&provisioningSimulatorSuite{})

func lockoutAuthValue(c *C, tpm *Connection, data []byte) []byte {
	val, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyContextHash)
	c.Assert(err, IsNil)
	contextHash := tpm2.HashAlgorithmId(val)
	c.Assert(contextHash.IsValid(), testutil.IsTrue)
	return data[:contextHash.Size()]
}

type testProvisionNewTPMData struct {
	clear                   bool
	lockoutAuthBytes        []byte
	expectedLockoutAuthData [][]byte
}

func (s *provisioningSimulatorSuite) testProvisionNewTPM(c *C, data *testProvisionNewTPMData) {
	origHmacSession := s.TPM().HmacSession()

	expectedLockoutAuthData := data.expectedLockoutAuthData
	syncLockoutAuthData := func(data []byte) error {
		c.Logf("%s", string(data))
		c.Assert(expectedLockoutAuthData, Not(HasLen), 0)
		expected := expectedLockoutAuthData[0]
		expectedLockoutAuthData = expectedLockoutAuthData[1:]
		c.Check(data, DeepEquals, expected)
		return nil
	}

	opts := []EnsureProvisionedOption{WithLockoutAuthValue(nil), WithProvisionNewLockoutAuthValue(bytes.NewReader(data.lockoutAuthBytes), syncLockoutAuthData)}
	if data.clear {
		opts = append(opts, WithClearBeforeProvision())
	}
	c.Check(s.TPM().EnsureProvisioned(opts...), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), data.lockoutAuthBytes))
		c.Check(s.TPM().HierarchyChangeAuth(s.TPM().LockoutHandleContext(), nil, nil), IsNil)
	})

	c.Check(expectedLockoutAuthData, HasLen, 0)

	s.validateEK(c)
	s.validateSRK(c)

	// Validate the DA parameters
	value, err := s.TPM().GetCapabilityTPMProperty(tpm2.PropertyMaxAuthFail)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(32))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutInterval)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(7200))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutRecovery)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(86400))

	// Verify that owner control is disabled, that the lockout hierarchy auth is set, no
	// other hierarchy auth is set, and there is no lockout.
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Check(err, IsNil)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrLockoutAuthSet, Equals, tpm2.AttrLockoutAuthSet)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrDisableClear, Equals, tpm2.AttrDisableClear)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrOwnerAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrEndorsementAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrInLockout, Equals, tpm2.PermanentAttributes(0))

	// Test the lockout hierarchy auth
	s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), data.lockoutAuthBytes))
	c.Check(s.TPM().DictionaryAttackLockReset(s.TPM().LockoutHandleContext(), nil), IsNil)

	c.Check(s.TPM().HmacSession(), NotNil)
	c.Check(s.TPM().HmacSession().Handle().Type(), Equals, tpm2.HandleTypeHMACSession)
	c.Check(s.TPM().HmacSession(), Not(Equals), origHmacSession)

	// Make sure ProvisionTPM didn't leak transient objects
	handles, err := s.TPM().GetCapabilityHandles(tpm2.HandleTypeTransient.BaseHandle(), tpm2.CapabilityMaxProperties)
	c.Check(err, IsNil)
	c.Check(handles, HasLen, 0)

	handles, err = s.TPM().GetCapabilityHandles(tpm2.HandleTypeLoadedSession.BaseHandle(), tpm2.CapabilityMaxProperties)
	c.Check(err, IsNil)
	c.Check(handles, HasLen, 1)
}

func (s *provisioningSimulatorSuite) TestProvisionNewTPMClear(c *C) {
	s.testProvisionNewTPM(c, &testProvisionNewTPMData{
		clear:            true,
		lockoutAuthBytes: testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c"),
		expectedLockoutAuthData: [][]byte{
			[]byte(`{"auth-value":null,"new-auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","new-auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA="}`),
			[]byte(`{"auth-value":null,"auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF"}`),
			[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-policy":"AAAAAAAAAAEADHqZCU8TuxgO7/elTguGw5So3SieBY2dRYOphhKVmu/mfi0NZyjHZFs+bMdtqZ284AAAAAAAAAACIAEBcQAAAAUAAAAAAAEADDuidKgJLPOC+/XOxwcOj4kEPzOZ/Z1YUWk9Coew5Aw15qxGHJWewJDjXAceJJnPkAAAAAEAAAFsAAABOQAAAAAAAQAML2Gkl0eOgfHT9Y1kGXkkE3jVI90qXY6wBtT2Ygksi3HgeTdQwD5WkH4QRDBsnYACAAAAAQAAAWwAAAE6AAAAAAABAAwutwj6joYO8lx+lgwraBTEMW6r5tQ2E+4QIxx/oEZ9ypxOerrTVEjGvnpGCmH/ym8AAAABAAABbAAAAScAAAAAAAEADFWgOLNA+yd26JBC+OGmP0ddbtEpzhpdo1wtbJIlwSui4lkkKncZB7rSyqFuZuALsAAAAAEAAAFsAAABJgAAAAAAAQAMladi5DAnH2ss5iXXhVU2rjlbDNmYkSGb4C7ZBqD+eDxKyQEruFSI6WY5/Lb4ppZNAAAAAQAAAWwAAAEuAAABaw=="}`),
			[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEADHqZCU8TuxgO7/elTguGw5So3SieBY2dRYOphhKVmu/mfi0NZyjHZFs+bMdtqZ284AAAAAAAAAACIAEBcQAAAAUAAAAAAAEADDuidKgJLPOC+/XOxwcOj4kEPzOZ/Z1YUWk9Coew5Aw15qxGHJWewJDjXAceJJnPkAAAAAEAAAFsAAABOQAAAAAAAQAML2Gkl0eOgfHT9Y1kGXkkE3jVI90qXY6wBtT2Ygksi3HgeTdQwD5WkH4QRDBsnYACAAAAAQAAAWwAAAE6AAAAAAABAAwutwj6joYO8lx+lgwraBTEMW6r5tQ2E+4QIxx/oEZ9ypxOerrTVEjGvnpGCmH/ym8AAAABAAABbAAAAScAAAAAAAEADFWgOLNA+yd26JBC+OGmP0ddbtEpzhpdo1wtbJIlwSui4lkkKncZB7rSyqFuZuALsAAAAAEAAAFsAAABJgAAAAAAAQAMladi5DAnH2ss5iXXhVU2rjlbDNmYkSGb4C7ZBqD+eDxKyQEruFSI6WY5/Lb4ppZNAAAAAQAAAWwAAAEuAAABaw=="}`),
		},
	})
}

func (s *provisioningSimulatorSuite) TestProvisionNewTPMFull(c *C) {
	s.testProvisionNewTPM(c, &testProvisionNewTPMData{
		clear:            false,
		lockoutAuthBytes: testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c"),
		expectedLockoutAuthData: [][]byte{
			[]byte(`{"auth-value":null,"new-auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","new-auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA="}`),
			[]byte(`{"auth-value":null,"auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF"}`),
			[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-policy":"AAAAAAAAAAEADHqZCU8TuxgO7/elTguGw5So3SieBY2dRYOphhKVmu/mfi0NZyjHZFs+bMdtqZ284AAAAAAAAAACIAEBcQAAAAUAAAAAAAEADDuidKgJLPOC+/XOxwcOj4kEPzOZ/Z1YUWk9Coew5Aw15qxGHJWewJDjXAceJJnPkAAAAAEAAAFsAAABOQAAAAAAAQAML2Gkl0eOgfHT9Y1kGXkkE3jVI90qXY6wBtT2Ygksi3HgeTdQwD5WkH4QRDBsnYACAAAAAQAAAWwAAAE6AAAAAAABAAwutwj6joYO8lx+lgwraBTEMW6r5tQ2E+4QIxx/oEZ9ypxOerrTVEjGvnpGCmH/ym8AAAABAAABbAAAAScAAAAAAAEADFWgOLNA+yd26JBC+OGmP0ddbtEpzhpdo1wtbJIlwSui4lkkKncZB7rSyqFuZuALsAAAAAEAAAFsAAABJgAAAAAAAQAMladi5DAnH2ss5iXXhVU2rjlbDNmYkSGb4C7ZBqD+eDxKyQEruFSI6WY5/Lb4ppZNAAAAAQAAAWwAAAEuAAABaw=="}`),
			[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEADHqZCU8TuxgO7/elTguGw5So3SieBY2dRYOphhKVmu/mfi0NZyjHZFs+bMdtqZ284AAAAAAAAAACIAEBcQAAAAUAAAAAAAEADDuidKgJLPOC+/XOxwcOj4kEPzOZ/Z1YUWk9Coew5Aw15qxGHJWewJDjXAceJJnPkAAAAAEAAAFsAAABOQAAAAAAAQAML2Gkl0eOgfHT9Y1kGXkkE3jVI90qXY6wBtT2Ygksi3HgeTdQwD5WkH4QRDBsnYACAAAAAQAAAWwAAAE6AAAAAAABAAwutwj6joYO8lx+lgwraBTEMW6r5tQ2E+4QIxx/oEZ9ypxOerrTVEjGvnpGCmH/ym8AAAABAAABbAAAAScAAAAAAAEADFWgOLNA+yd26JBC+OGmP0ddbtEpzhpdo1wtbJIlwSui4lkkKncZB7rSyqFuZuALsAAAAAEAAAFsAAABJgAAAAAAAQAMladi5DAnH2ss5iXXhVU2rjlbDNmYkSGb4C7ZBqD+eDxKyQEruFSI6WY5/Lb4ppZNAAAAAQAAAWwAAAEuAAABaw=="}`),
		},
	})
}

func (s *provisioningSimulatorSuite) TestProvisionNewTPMDifferentLockoutAuth(c *C) {
	s.testProvisionNewTPM(c, &testProvisionNewTPMData{
		clear:            true,
		lockoutAuthBytes: testutil.DecodeHexString(c, "f10fa81ad01d6912916951039ed6a06c33f6995a5b6cd307f246d2dd6551edce865b7d2793cf6f2577730e4c6318b8189c5659b86bfa15703825b09359dc9cf9"),
		expectedLockoutAuthData: [][]byte{
			[]byte(`{"auth-value":null,"new-auth-value":"8Q+oGtAdaRKRaVEDntagbDP2mVpbbNMH8kbS3WVR7c6GW30nk89vJXdzDkxjGLgY","new-auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA="}`),
			[]byte(`{"auth-value":null,"auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-value":"8Q+oGtAdaRKRaVEDntagbDP2mVpbbNMH8kbS3WVR7c6GW30nk89vJXdzDkxjGLgY"}`),
			[]byte(`{"auth-value":"8Q+oGtAdaRKRaVEDntagbDP2mVpbbNMH8kbS3WVR7c6GW30nk89vJXdzDkxjGLgY","auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-policy":"AAAAAAAAAAEADHqZCU8TuxgO7/elTguGw5So3SieBY2dRYOphhKVmu/mfi0NZyjHZFs+bMdtqZ284AAAAAAAAAACIAEBcQAAAAUAAAAAAAEADDuidKgJLPOC+/XOxwcOj4kEPzOZ/Z1YUWk9Coew5Aw15qxGHJWewJDjXAceJJnPkAAAAAEAAAFsAAABOQAAAAAAAQAML2Gkl0eOgfHT9Y1kGXkkE3jVI90qXY6wBtT2Ygksi3HgeTdQwD5WkH4QRDBsnYACAAAAAQAAAWwAAAE6AAAAAAABAAwutwj6joYO8lx+lgwraBTEMW6r5tQ2E+4QIxx/oEZ9ypxOerrTVEjGvnpGCmH/ym8AAAABAAABbAAAAScAAAAAAAEADFWgOLNA+yd26JBC+OGmP0ddbtEpzhpdo1wtbJIlwSui4lkkKncZB7rSyqFuZuALsAAAAAEAAAFsAAABJgAAAAAAAQAMladi5DAnH2ss5iXXhVU2rjlbDNmYkSGb4C7ZBqD+eDxKyQEruFSI6WY5/Lb4ppZNAAAAAQAAAWwAAAEuAAABaw=="}`),
			[]byte(`{"auth-value":"8Q+oGtAdaRKRaVEDntagbDP2mVpbbNMH8kbS3WVR7c6GW30nk89vJXdzDkxjGLgY","auth-policy":"AAAAAAAAAAEADHqZCU8TuxgO7/elTguGw5So3SieBY2dRYOphhKVmu/mfi0NZyjHZFs+bMdtqZ284AAAAAAAAAACIAEBcQAAAAUAAAAAAAEADDuidKgJLPOC+/XOxwcOj4kEPzOZ/Z1YUWk9Coew5Aw15qxGHJWewJDjXAceJJnPkAAAAAEAAAFsAAABOQAAAAAAAQAML2Gkl0eOgfHT9Y1kGXkkE3jVI90qXY6wBtT2Ygksi3HgeTdQwD5WkH4QRDBsnYACAAAAAQAAAWwAAAE6AAAAAAABAAwutwj6joYO8lx+lgwraBTEMW6r5tQ2E+4QIxx/oEZ9ypxOerrTVEjGvnpGCmH/ym8AAAABAAABbAAAAScAAAAAAAEADFWgOLNA+yd26JBC+OGmP0ddbtEpzhpdo1wtbJIlwSui4lkkKncZB7rSyqFuZuALsAAAAAEAAAFsAAABJgAAAAAAAQAMladi5DAnH2ss5iXXhVU2rjlbDNmYkSGb4C7ZBqD+eDxKyQEruFSI6WY5/Lb4ppZNAAAAAQAAAWwAAAEuAAABaw=="}`),
		},
	})
}

func (s *provisioningSimulatorSuite) TestProvisionNewTPMNoLockoutAuthPolicies(c *C) {
	// Test with a TPM that doesn't support TPM_CAP_AUTH_POLICIES
	s.TPMTest.Transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandle tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
		if cmdCode != tpm2.CommandGetCapability {
			return
		}

		// Unpack the command parameters
		var capability tpm2.Capability
		var property uint32
		var propertyCount uint32
		_, err := mu.UnmarshalFromBytes(cpBytes, &capability, &property, &propertyCount)
		c.Assert(err, IsNil)
		if capability != tpm2.CapabilityAuthPolicies {
			return
		}

		// Return a TPM_RC_VALUE + TPM_RC_P + TPM_RC_1 error
		rsp.Reset()
		c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseValue+tpm2.ResponseP+tpm2.ResponseIndex1, nil, nil, nil), IsNil)
	}

	s.testProvisionNewTPM(c, &testProvisionNewTPMData{
		clear:            false,
		lockoutAuthBytes: testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c"),
		expectedLockoutAuthData: [][]byte{
			[]byte(`{"auth-value":null,"new-auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","new-auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA="}`),
			[]byte(`{"auth-value":null,"new-auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","new-auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA="}`),
			[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF"}`),
		},
	})
}

func (s *provisioningSuite) TestProvisionWithLockoutAuthValue(c *C) {
	authValue := []byte("1234")
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, authValue)

	c.Check(s.TPM().EnsureProvisioned(WithLockoutAuthValue(authValue)), IsNil)

	// Validate the DA parameters
	value, err := s.TPM().GetCapabilityTPMProperty(tpm2.PropertyMaxAuthFail)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(32))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutInterval)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(7200))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutRecovery)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(86400))

	// Verify that owner control is disabled, that the lockout hierarchy auth is set, no
	// other hierarchy auth is set, and there is no lockout.
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Check(err, IsNil)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrLockoutAuthSet, Equals, tpm2.AttrLockoutAuthSet)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrDisableClear, Equals, tpm2.AttrDisableClear)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrOwnerAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrEndorsementAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrInLockout, Equals, tpm2.PermanentAttributes(0))

	// Test the lockout hierarchy auth
	s.TPM().LockoutHandleContext().SetAuthValue(authValue)
	c.Check(s.TPM().DictionaryAttackLockReset(s.TPM().LockoutHandleContext(), nil), IsNil)
}

func (s *provisioningSuite) TestProvisionWithLockoutAuthData(c *C) {
	authValue := []byte("1234")
	policyDigest, data := s.makeDefaultLockoutAuthData(c, tpm2.HashAlgorithmSHA256, authValue)
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, authValue)
	c.Assert(s.TPM().SetPrimaryPolicy(s.TPM().LockoutHandleContext(), policyDigest, tpm2.HashAlgorithmSHA256, nil), IsNil)

	c.Check(s.TPM().EnsureProvisioned(WithLockoutAuthData(data)), IsNil)

	// Validate the DA parameters
	value, err := s.TPM().GetCapabilityTPMProperty(tpm2.PropertyMaxAuthFail)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(32))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutInterval)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(7200))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutRecovery)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(86400))

	// Verify that owner control is disabled, that the lockout hierarchy auth is set, no
	// other hierarchy auth is set, and there is no lockout.
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Check(err, IsNil)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrLockoutAuthSet, Equals, tpm2.AttrLockoutAuthSet)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrDisableClear, Equals, tpm2.AttrDisableClear)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrOwnerAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrEndorsementAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrInLockout, Equals, tpm2.PermanentAttributes(0))

	// Test the lockout hierarchy auth
	s.TPM().LockoutHandleContext().SetAuthValue(authValue)
	c.Check(s.TPM().DictionaryAttackLockReset(s.TPM().LockoutHandleContext(), nil), IsNil)
}

func (s *provisioningSuite) TestProvisionWithLockoutAuthDataNoAuthPolicies(c *C) {
	authValue := []byte("1234")
	data := s.makeLockoutAuthData(c, &LockoutAuthParams{
		AuthValue: authValue,
	})
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, authValue)

	c.Check(s.TPM().EnsureProvisioned(WithLockoutAuthData(data)), IsNil)

	// Validate the DA parameters
	value, err := s.TPM().GetCapabilityTPMProperty(tpm2.PropertyMaxAuthFail)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(32))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutInterval)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(7200))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutRecovery)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(86400))

	// Verify that owner control is disabled, that the lockout hierarchy auth is set, no
	// other hierarchy auth is set, and there is no lockout.
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Check(err, IsNil)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrLockoutAuthSet, Equals, tpm2.AttrLockoutAuthSet)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrDisableClear, Equals, tpm2.AttrDisableClear)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrOwnerAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrEndorsementAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrInLockout, Equals, tpm2.PermanentAttributes(0))

	// Test the lockout hierarchy auth
	s.TPM().LockoutHandleContext().SetAuthValue(authValue)
	c.Check(s.TPM().DictionaryAttackLockReset(s.TPM().LockoutHandleContext(), nil), IsNil)
}

func (s *provisioningSuite) TestProvisionResumeNewLockoutAuthValue1(c *C) {
	// Test resuming with WithProvisionNewLockoutAuthValue after a previous attempt was interrupted
	// after prepare
	origValue := []byte("1234")
	policyDigest, policy1 := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)
	_, policy2 := s.newUpdateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, origValue)
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, origValue)
	c.Assert(s.TPM().SetPrimaryPolicy(s.TPM().LockoutHandleContext(), policyDigest, tpm2.HashAlgorithmSHA256, nil), IsNil)

	lockoutAuthBytes := testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c")

	data := s.makeLockoutAuthData(c, &LockoutAuthParams{
		AuthValue:     origValue,
		AuthPolicy:    policy1,
		NewAuthValue:  lockoutAuthValue(c, s.TPM(), lockoutAuthBytes),
		NewAuthPolicy: policy2,
	})

	expectedLockoutAuthData := [][]byte{
		[]byte(`{"auth-value":"MTIzNA==","auth-policy":"AAAAAAAAAAEAC3I61USvx7CvOmM61pIa40NXvY6AqinRzDx16Py3QDnvAAAAAAAAAAEgAQFxAAAAAgAAAAAAAQAL/g0OavvRqALD6F4sJD+kB1TWHYxCvdViNHPYjqSJqbIAAAACAAABbAAAAS4AAAFrAAAAAAABAAvbx93A0uFXIca/EFHCBbGmUYmB95xoVE6ZYxLqI5of2gAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIBwf0eeWXYZJ+PFN0xQ+9xaG+03+fD2SC1aOweJmzl9xACDWXojHU30aQKHFCkSWvhdsU1U0q+qTVp7hcjLvddqrLwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF"}`),
		[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEAC3I61USvx7CvOmM61pIa40NXvY6AqinRzDx16Py3QDnvAAAAAAAAAAEgAQFxAAAAAgAAAAAAAQAL/g0OavvRqALD6F4sJD+kB1TWHYxCvdViNHPYjqSJqbIAAAACAAABbAAAAS4AAAFrAAAAAAABAAvbx93A0uFXIca/EFHCBbGmUYmB95xoVE6ZYxLqI5of2gAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIBwf0eeWXYZJ+PFN0xQ+9xaG+03+fD2SC1aOweJmzl9xACDWXojHU30aQKHFCkSWvhdsU1U0q+qTVp7hcjLvddqrLwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-policy":"AAAAAAAAAAEAC8fpxFXFnW/i+VVUXTr6s3kopn5+LbHkhqxSYqdusGu/AAAAAAAAAAIgAQFxAAAABQAAAAAAAQALtsXAXlgZCc3qffel+RwPLu03/XbxVSLu5bVfiW8tVj8AAAABAAABbAAAATkAAAAAAAEACxxoJ3ydZWTdgbzPfla6PtyrOI/GDOlbOkQr0nJY9g38AAAAAQAAAWwAAAE6AAAAAAABAAuUDPtCF7se3Pf7QZN8qXSqaOaYq3i4EksHARPiEf1G/AAAAAEAAAFsAAABJwAAAAAAAQALxN+rztqN6DbJVmGVKJKx3vcgOvtG/v7EP/z8k75UBzAAAAABAAABbAAAASYAAAAAAAEAC3G+h1vfkVM3lejs6YjXVDuULEStbQE7L3xfQ4MLi6IXAAAAAQAAAWwAAAEuAAABaw=="}`),
		[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEAC8fpxFXFnW/i+VVUXTr6s3kopn5+LbHkhqxSYqdusGu/AAAAAAAAAAIgAQFxAAAABQAAAAAAAQALtsXAXlgZCc3qffel+RwPLu03/XbxVSLu5bVfiW8tVj8AAAABAAABbAAAATkAAAAAAAEACxxoJ3ydZWTdgbzPfla6PtyrOI/GDOlbOkQr0nJY9g38AAAAAQAAAWwAAAE6AAAAAAABAAuUDPtCF7se3Pf7QZN8qXSqaOaYq3i4EksHARPiEf1G/AAAAAEAAAFsAAABJwAAAAAAAQALxN+rztqN6DbJVmGVKJKx3vcgOvtG/v7EP/z8k75UBzAAAAABAAABbAAAASYAAAAAAAEAC3G+h1vfkVM3lejs6YjXVDuULEStbQE7L3xfQ4MLi6IXAAAAAQAAAWwAAAEuAAABaw=="}`),
	}
	syncLockoutAuthData := func(data []byte) error {
		c.Assert(expectedLockoutAuthData, Not(HasLen), 0)
		expected := expectedLockoutAuthData[0]
		expectedLockoutAuthData = expectedLockoutAuthData[1:]
		c.Check(data, DeepEquals, expected)
		return nil
	}

	c.Check(s.TPM().EnsureProvisioned(WithLockoutAuthData(data), WithProvisionNewLockoutAuthValue(bytes.NewReader(nil), syncLockoutAuthData)), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
		s.HierarchyChangeAuth(c, tpm2.HandleLockout, nil)
	})

	c.Check(expectedLockoutAuthData, HasLen, 0)

	// Validate the DA parameters
	value, err := s.TPM().GetCapabilityTPMProperty(tpm2.PropertyMaxAuthFail)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(32))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutInterval)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(7200))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutRecovery)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(86400))

	// Verify that owner control is disabled, that the lockout hierarchy auth is set, no
	// other hierarchy auth is set, and there is no lockout.
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Check(err, IsNil)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrLockoutAuthSet, Equals, tpm2.AttrLockoutAuthSet)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrDisableClear, Equals, tpm2.AttrDisableClear)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrOwnerAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrEndorsementAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrInLockout, Equals, tpm2.PermanentAttributes(0))

	// Test the lockout hierarchy auth
	s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
	c.Check(s.TPM().DictionaryAttackLockReset(s.TPM().LockoutHandleContext(), nil), IsNil)
}

func (s *provisioningSuite) TestProvisionResumeNewLockoutAuthValue2(c *C) {
	// Test resuming with WithProvisionNewLockoutAuthValue after a previous attempt was interrupted
	// after setNewAuthValuePolicy
	origValue := []byte("1234")
	policyDigest, policy := s.newUpdateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, origValue)
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, origValue)
	c.Assert(s.TPM().SetPrimaryPolicy(s.TPM().LockoutHandleContext(), policyDigest, tpm2.HashAlgorithmSHA256, nil), IsNil)

	lockoutAuthBytes := testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c")

	data := s.makeLockoutAuthData(c, &LockoutAuthParams{
		AuthValue:    origValue,
		AuthPolicy:   policy,
		NewAuthValue: lockoutAuthValue(c, s.TPM(), lockoutAuthBytes),
	})

	expectedLockoutAuthData := [][]byte{
		[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEAC3I61USvx7CvOmM61pIa40NXvY6AqinRzDx16Py3QDnvAAAAAAAAAAEgAQFxAAAAAgAAAAAAAQAL/g0OavvRqALD6F4sJD+kB1TWHYxCvdViNHPYjqSJqbIAAAACAAABbAAAAS4AAAFrAAAAAAABAAvbx93A0uFXIca/EFHCBbGmUYmB95xoVE6ZYxLqI5of2gAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIBwf0eeWXYZJ+PFN0xQ+9xaG+03+fD2SC1aOweJmzl9xACDWXojHU30aQKHFCkSWvhdsU1U0q+qTVp7hcjLvddqrLwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-policy":"AAAAAAAAAAEAC8fpxFXFnW/i+VVUXTr6s3kopn5+LbHkhqxSYqdusGu/AAAAAAAAAAIgAQFxAAAABQAAAAAAAQALtsXAXlgZCc3qffel+RwPLu03/XbxVSLu5bVfiW8tVj8AAAABAAABbAAAATkAAAAAAAEACxxoJ3ydZWTdgbzPfla6PtyrOI/GDOlbOkQr0nJY9g38AAAAAQAAAWwAAAE6AAAAAAABAAuUDPtCF7se3Pf7QZN8qXSqaOaYq3i4EksHARPiEf1G/AAAAAEAAAFsAAABJwAAAAAAAQALxN+rztqN6DbJVmGVKJKx3vcgOvtG/v7EP/z8k75UBzAAAAABAAABbAAAASYAAAAAAAEAC3G+h1vfkVM3lejs6YjXVDuULEStbQE7L3xfQ4MLi6IXAAAAAQAAAWwAAAEuAAABaw=="}`),
		[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEAC8fpxFXFnW/i+VVUXTr6s3kopn5+LbHkhqxSYqdusGu/AAAAAAAAAAIgAQFxAAAABQAAAAAAAQALtsXAXlgZCc3qffel+RwPLu03/XbxVSLu5bVfiW8tVj8AAAABAAABbAAAATkAAAAAAAEACxxoJ3ydZWTdgbzPfla6PtyrOI/GDOlbOkQr0nJY9g38AAAAAQAAAWwAAAE6AAAAAAABAAuUDPtCF7se3Pf7QZN8qXSqaOaYq3i4EksHARPiEf1G/AAAAAEAAAFsAAABJwAAAAAAAQALxN+rztqN6DbJVmGVKJKx3vcgOvtG/v7EP/z8k75UBzAAAAABAAABbAAAASYAAAAAAAEAC3G+h1vfkVM3lejs6YjXVDuULEStbQE7L3xfQ4MLi6IXAAAAAQAAAWwAAAEuAAABaw=="}`),
	}
	syncLockoutAuthData := func(data []byte) error {
		c.Assert(expectedLockoutAuthData, Not(HasLen), 0)
		expected := expectedLockoutAuthData[0]
		expectedLockoutAuthData = expectedLockoutAuthData[1:]
		c.Check(data, DeepEquals, expected)
		return nil
	}

	c.Check(s.TPM().EnsureProvisioned(WithLockoutAuthData(data), WithProvisionNewLockoutAuthValue(bytes.NewReader(nil), syncLockoutAuthData)), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
		s.HierarchyChangeAuth(c, tpm2.HandleLockout, nil)
	})

	c.Check(expectedLockoutAuthData, HasLen, 0)

	// Validate the DA parameters
	value, err := s.TPM().GetCapabilityTPMProperty(tpm2.PropertyMaxAuthFail)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(32))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutInterval)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(7200))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutRecovery)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(86400))

	// Verify that owner control is disabled, that the lockout hierarchy auth is set, no
	// other hierarchy auth is set, and there is no lockout.
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Check(err, IsNil)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrLockoutAuthSet, Equals, tpm2.AttrLockoutAuthSet)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrDisableClear, Equals, tpm2.AttrDisableClear)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrOwnerAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrEndorsementAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrInLockout, Equals, tpm2.PermanentAttributes(0))

	// Test the lockout hierarchy auth
	s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
	c.Check(s.TPM().DictionaryAttackLockReset(s.TPM().LockoutHandleContext(), nil), IsNil)
}

func (s *provisioningSuite) TestProvisionAfterInterruptedNewLockoutAuthValue2(c *C) {
	// Test that we get an appropriate error if a previous call with WithProvisionNewLockoutAuthValue
	// was interrupted after setNewAuthValuePolicy.
	origValue := []byte("1234")
	policyDigest, policy := s.newUpdateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, origValue)
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, origValue)
	c.Assert(s.TPM().SetPrimaryPolicy(s.TPM().LockoutHandleContext(), policyDigest, tpm2.HashAlgorithmSHA256, nil), IsNil)

	lockoutAuthBytes := testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c")

	data := s.makeLockoutAuthData(c, &LockoutAuthParams{
		AuthValue:    origValue,
		AuthPolicy:   policy,
		NewAuthValue: lockoutAuthValue(c, s.TPM(), lockoutAuthBytes),
	})

	err := s.TPM().EnsureProvisioned(WithLockoutAuthData(data))
	c.Check(err, Equals, ErrLockoutAuthUpdateInterrupted)
	c.Check(err, ErrorMatches, `a previous attempt to update the authorization parameters for the lockout hierarchy was interrupted`)
}

func (s *provisioningSuite) TestProvisionResumeNewLockoutAuthValue3(c *C) {
	// Test resuming with WithProvisionNewLockoutAuthValue after a previous attempt was interrupted
	// after setNewAuthValue
	lockoutAuthBytes := testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c")

	policyDigest, policy1 := s.newUpdateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, []byte("1234"))
	_, policy2 := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
	c.Assert(s.TPM().SetPrimaryPolicy(s.TPM().LockoutHandleContext(), policyDigest, tpm2.HashAlgorithmSHA256, nil), IsNil)

	data := s.makeLockoutAuthData(c, &LockoutAuthParams{
		AuthValue:     lockoutAuthValue(c, s.TPM(), lockoutAuthBytes),
		AuthPolicy:    policy1,
		NewAuthPolicy: policy2,
	})

	expectedLockoutAuthData := [][]byte{
		[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEAC8fpxFXFnW/i+VVUXTr6s3kopn5+LbHkhqxSYqdusGu/AAAAAAAAAAIgAQFxAAAABQAAAAAAAQALtsXAXlgZCc3qffel+RwPLu03/XbxVSLu5bVfiW8tVj8AAAABAAABbAAAATkAAAAAAAEACxxoJ3ydZWTdgbzPfla6PtyrOI/GDOlbOkQr0nJY9g38AAAAAQAAAWwAAAE6AAAAAAABAAuUDPtCF7se3Pf7QZN8qXSqaOaYq3i4EksHARPiEf1G/AAAAAEAAAFsAAABJwAAAAAAAQALxN+rztqN6DbJVmGVKJKx3vcgOvtG/v7EP/z8k75UBzAAAAABAAABbAAAASYAAAAAAAEAC3G+h1vfkVM3lejs6YjXVDuULEStbQE7L3xfQ4MLi6IXAAAAAQAAAWwAAAEuAAABaw=="}`),
	}
	syncLockoutAuthData := func(data []byte) error {
		c.Assert(expectedLockoutAuthData, Not(HasLen), 0)
		expected := expectedLockoutAuthData[0]
		expectedLockoutAuthData = expectedLockoutAuthData[1:]
		c.Check(data, DeepEquals, expected)
		return nil
	}

	c.Check(s.TPM().EnsureProvisioned(WithLockoutAuthData(data), WithProvisionNewLockoutAuthValue(bytes.NewReader(nil), syncLockoutAuthData)), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
		s.HierarchyChangeAuth(c, tpm2.HandleLockout, nil)
	})

	c.Check(expectedLockoutAuthData, HasLen, 0)

	// Validate the DA parameters
	value, err := s.TPM().GetCapabilityTPMProperty(tpm2.PropertyMaxAuthFail)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(32))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutInterval)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(7200))
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutRecovery)
	c.Check(err, IsNil)
	c.Check(value, Equals, uint32(86400))

	// Verify that owner control is disabled, that the lockout hierarchy auth is set, no
	// other hierarchy auth is set, and there is no lockout.
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Check(err, IsNil)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrLockoutAuthSet, Equals, tpm2.AttrLockoutAuthSet)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrDisableClear, Equals, tpm2.AttrDisableClear)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrOwnerAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrEndorsementAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrInLockout, Equals, tpm2.PermanentAttributes(0))

	// Test the lockout hierarchy auth
	s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
	c.Check(s.TPM().DictionaryAttackLockReset(s.TPM().LockoutHandleContext(), nil), IsNil)
}

func (s *provisioningSuite) TestProvisionAfterInterruptedNewLockoutAuthValue3(c *C) {
	// Test that we get an appropriate error if a previous call with WithProvisionNewLockoutAuthValue
	// was interrupted after setNewAuthValue.
	lockoutAuthBytes := testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c")

	policyDigest, policy1 := s.newUpdateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, []byte("1234"))
	_, policy2 := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
	c.Assert(s.TPM().SetPrimaryPolicy(s.TPM().LockoutHandleContext(), policyDigest, tpm2.HashAlgorithmSHA256, nil), IsNil)

	data := s.makeLockoutAuthData(c, &LockoutAuthParams{
		AuthValue:     lockoutAuthValue(c, s.TPM(), lockoutAuthBytes),
		AuthPolicy:    policy1,
		NewAuthPolicy: policy2,
	})

	err := s.TPM().EnsureProvisioned(WithLockoutAuthData(data))
	c.Check(err, Equals, ErrLockoutAuthUpdateInterrupted)
	c.Check(err, ErrorMatches, `a previous attempt to update the authorization parameters for the lockout hierarchy was interrupted`)
}

func (s *provisioningSimulatorSuite) TestProvisionTPMInLockout(c *C) {
	// Trip the DA logic by triggering an auth failure with a DA protected
	// resource.
	c.Assert(s.TPM().DictionaryAttackParameters(s.TPM().LockoutHandleContext(), 1, 10000, 10000, nil), IsNil)
	pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, []byte("foo"), []byte("5678"))
	c.Assert(err, IsNil)
	key, err := s.TPM().LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)
	key.SetAuthValue(nil)
	_, err = s.TPM().Unseal(key, nil)
	c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandUnseal, 1), testutil.IsTrue)
	// Need to explicitly flush because we check that EnsureProvisioned doesn't leave transient objects.
	c.Check(s.TPM().FlushContext(key), IsNil)

	s.testProvisionNewTPM(c, &testProvisionNewTPMData{
		clear:            false,
		lockoutAuthBytes: testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c"),
		expectedLockoutAuthData: [][]byte{
			[]byte(`{"auth-value":null,"new-auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","new-auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA="}`),
			[]byte(`{"auth-value":null,"auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF"}`),
			[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEADPSFreqYTJyYmYLZuV9t3FD6miDHK9Bk6csiDmxMYzssvhbvXp4XFg1FTZVRuPKb1AAAAAAAAAABIAEBcQAAAAIAAAAAAAEADPCh6SbxQFvoOsy16T+o1t9ppyxh3wCCATIk2ijXiQK7tY58W/2t8FysjP0RUEOq6AAAAAIAAAFsAAABLgAAAWsAAAAAAAEADPM/YpABRQGCbrCHesmtd7NQohItlVrJ+xFdG13xqo3ZFwpeCldZirZUOfTzZmQXPwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIOsLyU/JRbgdKwtENNG1brDVsXEXRbQfOGc6oFCNFRuNACAIxXx8JXqfNxSy3h59UX4Jmd9nFeX85yMUGtGxB54+SwARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA=","new-auth-policy":"AAAAAAAAAAEADHqZCU8TuxgO7/elTguGw5So3SieBY2dRYOphhKVmu/mfi0NZyjHZFs+bMdtqZ284AAAAAAAAAACIAEBcQAAAAUAAAAAAAEADDuidKgJLPOC+/XOxwcOj4kEPzOZ/Z1YUWk9Coew5Aw15qxGHJWewJDjXAceJJnPkAAAAAEAAAFsAAABOQAAAAAAAQAML2Gkl0eOgfHT9Y1kGXkkE3jVI90qXY6wBtT2Ygksi3HgeTdQwD5WkH4QRDBsnYACAAAAAQAAAWwAAAE6AAAAAAABAAwutwj6joYO8lx+lgwraBTEMW6r5tQ2E+4QIxx/oEZ9ypxOerrTVEjGvnpGCmH/ym8AAAABAAABbAAAAScAAAAAAAEADFWgOLNA+yd26JBC+OGmP0ddbtEpzhpdo1wtbJIlwSui4lkkKncZB7rSyqFuZuALsAAAAAEAAAFsAAABJgAAAAAAAQAMladi5DAnH2ss5iXXhVU2rjlbDNmYkSGb4C7ZBqD+eDxKyQEruFSI6WY5/Lb4ppZNAAAAAQAAAWwAAAEuAAABaw=="}`),
			[]byte(`{"auth-value":"wExnNggDTz9v3Rsrp1La+K5fqcpdf8IbX18dvdlCfOqm81wND5jCkmoLApKW8GzF","auth-policy":"AAAAAAAAAAEADHqZCU8TuxgO7/elTguGw5So3SieBY2dRYOphhKVmu/mfi0NZyjHZFs+bMdtqZ284AAAAAAAAAACIAEBcQAAAAUAAAAAAAEADDuidKgJLPOC+/XOxwcOj4kEPzOZ/Z1YUWk9Coew5Aw15qxGHJWewJDjXAceJJnPkAAAAAEAAAFsAAABOQAAAAAAAQAML2Gkl0eOgfHT9Y1kGXkkE3jVI90qXY6wBtT2Ygksi3HgeTdQwD5WkH4QRDBsnYACAAAAAQAAAWwAAAE6AAAAAAABAAwutwj6joYO8lx+lgwraBTEMW6r5tQ2E+4QIxx/oEZ9ypxOerrTVEjGvnpGCmH/ym8AAAABAAABbAAAAScAAAAAAAEADFWgOLNA+yd26JBC+OGmP0ddbtEpzhpdo1wtbJIlwSui4lkkKncZB7rSyqFuZuALsAAAAAEAAAFsAAABJgAAAAAAAQAMladi5DAnH2ss5iXXhVU2rjlbDNmYkSGb4C7ZBqD+eDxKyQEruFSI6WY5/Lb4ppZNAAAAAQAAAWwAAAEuAAABaw=="}`),
		},
	})
}

func (s *provisioningSimulatorSuite) testProvisionErrorHandling(c *C, mode ProvisionMode) error {
	defer func() {
		// Some of these tests trip the lockout for the lockout auth,
		// which can't be undone by the test fixture. Clear the TPM
		// else the test fixture fails the test.
		s.ClearTPMUsingPlatformHierarchy(c)
	}()
	var opts []EnsureProvisionedOption
	switch mode {
	case ProvisionModeFull:
		opts = append(opts, WithLockoutAuthValue(nil))
	case ProvisionModeClear:
		opts = append(opts, WithLockoutAuthValue(nil), WithClearBeforeProvision())
	}
	return s.TPM().EnsureProvisioned(opts...)
}

func (s *provisioningSuite) testProvisionErrorHandling(c *C, mode ProvisionMode) error {
	defer func() {
		// Some of these tests trip the lockout for the lockout auth,
		// which can't be undone by the test fixture. Clear the TPM
		// else the test fixture fails the test.
		s.ClearTPMUsingPlatformHierarchy(c)
	}()
	var opts []EnsureProvisionedOption
	switch mode {
	case ProvisionModeFull:
		opts = append(opts, WithLockoutAuthValue(nil))
	case ProvisionModeClear:
		opts = append(opts, WithLockoutAuthValue(nil), WithClearBeforeProvision())
	}
	return s.TPM().EnsureProvisioned(opts...)
}

func (s *provisioningSuite) TestProvisionErrorHandlingClearRequiresPPI(c *C) {
	c.Check(s.TPM().ClearControl(s.TPM().LockoutHandleContext(), true, nil), IsNil)

	err := s.testProvisionErrorHandling(c, ProvisionModeClear)
	c.Check(err, Equals, ErrTPMClearRequiresPPI)
}

func (s *provisioningSuite) TestProvisionErrorHandlingLockoutAuthFail1(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))

	err := s.testProvisionErrorHandling(c, ProvisionModeFull)
	c.Assert(err, testutil.ConvertibleTo, AuthFailError{})
	c.Check(err.(AuthFailError).Handle, Equals, tpm2.HandleLockout)
}

func (s *provisioningSuite) TestProvisionErrorHandlingLockoutAuthFail2(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))

	err := s.testProvisionErrorHandling(c, ProvisionModeClear)
	c.Assert(err, testutil.ConvertibleTo, AuthFailError{})
	c.Check(err.(AuthFailError).Handle, Equals, tpm2.HandleLockout)
}

func (s *provisioningSuite) TestProvisionErrorHandlingInLockout1(c *C) {
	authValue := []byte("1234")
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, authValue)

	// Trip the DA lockout for the lockout hierarchy.
	s.TPM().LockoutHandleContext().SetAuthValue(nil)
	c.Check(s.TPM().HierarchyChangeAuth(s.TPM().LockoutHandleContext(), nil, nil), testutil.ErrorIs,
		&tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandHierarchyChangeAuth, Code: tpm2.ErrorAuthFail}, Index: 1})
	s.TPM().LockoutHandleContext().SetAuthValue(authValue)

	err := s.testProvisionErrorHandling(c, ProvisionModeFull)
	c.Check(err, Equals, ErrTPMLockout)
}

func (s *provisioningSuite) TestProvisionErrorHandlingInLockout2(c *C) {
	authValue := []byte("1234")
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, authValue)

	// Trip the DA lockout for the lockout hierarchy.
	s.TPM().LockoutHandleContext().SetAuthValue(nil)
	c.Check(s.TPM().HierarchyChangeAuth(s.TPM().LockoutHandleContext(), nil, nil), testutil.ErrorIs,
		&tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandHierarchyChangeAuth, Code: tpm2.ErrorAuthFail}, Index: 1})
	s.TPM().LockoutHandleContext().SetAuthValue(authValue)

	err := s.testProvisionErrorHandling(c, ProvisionModeClear)
	c.Check(err, Equals, ErrTPMLockout)
}

func (s *provisioningSuite) TestProvisionErrorHandlingOwnerAuthFail(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
	s.TPM().OwnerHandleContext().SetAuthValue(nil)

	err := s.testProvisionErrorHandling(c, ProvisionModeWithoutLockout)
	c.Assert(err, testutil.ConvertibleTo, AuthFailError{})
	c.Check(err.(AuthFailError).Handle, Equals, tpm2.HandleOwner)
}

func (s *provisioningSuite) TestProvisionErrorHandlingEndorsementAuthFail(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, []byte("1234"))
	s.TPM().EndorsementHandleContext().SetAuthValue(nil)

	err := s.testProvisionErrorHandling(c, ProvisionModeWithoutLockout)
	c.Assert(err, testutil.ConvertibleTo, AuthFailError{})
	c.Check(err.(AuthFailError).Handle, Equals, tpm2.HandleEndorsement)
}

func (s *provisioningSimulatorSuite) TestProvisionErrorHandlingRequiresLockout1(c *C) {
	err := s.testProvisionErrorHandling(c, ProvisionModeWithoutLockout)
	c.Check(err, Equals, ErrTPMProvisioningRequiresLockout)
}

func (s *provisioningSimulatorSuite) TestProvisionErrorHandlingRequiresLockout2(c *C) {
	c.Check(s.TPM().ClearControl(s.TPM().LockoutHandleContext(), true, nil), IsNil)

	err := s.testProvisionErrorHandling(c, ProvisionModeWithoutLockout)
	c.Check(err, Equals, ErrTPMProvisioningRequiresLockout)
}

func (s *provisioningSimulatorSuite) TestProvisionErrorHandlingRequiresLockout3(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))

	err := s.testProvisionErrorHandling(c, ProvisionModeWithoutLockout)
	c.Check(err, Equals, ErrTPMProvisioningRequiresLockout)
}

func (s *provisioningSimulatorSuite) TestProvisionErrorHandlingRequiresLockout4(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
	c.Check(s.TPM().ClearControl(s.TPM().LockoutHandleContext(), true, nil), IsNil)
	// Trip the DA logic by triggering an auth failure with a DA protected
	// resource.
	c.Assert(s.TPM().DictionaryAttackParameters(s.TPM().LockoutHandleContext(), 1, 10000, 10000, nil), IsNil)
	pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, []byte("foo"), []byte("5678"))
	c.Assert(err, IsNil)
	key, err := s.TPM().LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)
	key.SetAuthValue(nil)
	_, err = s.TPM().Unseal(key, nil)
	c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandUnseal, 1), testutil.IsTrue)

	err = s.testProvisionErrorHandling(c, ProvisionModeWithoutLockout)
	c.Check(err, Equals, ErrTPMProvisioningRequiresLockout)
}

func (s *provisioningSimulatorSuite) TestProvisionErrorHandlingRequiresLockout5(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
	c.Check(s.TPM().ClearControl(s.TPM().LockoutHandleContext(), true, nil), IsNil)

	err := s.testProvisionErrorHandling(c, ProvisionModeWithoutLockout)
	c.Check(err, Equals, ErrTPMProvisioningRequiresLockout)
}

func (s *provisioningSuite) testProvisionRecreateEK(c *C, full bool) {
	lockoutAuthBytes := testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c")
	var lockoutAuthData []byte

	c.Check(s.TPM().EnsureProvisioned(
		WithLockoutAuthValue(nil),
		WithProvisionNewLockoutAuthValue(bytes.NewReader(lockoutAuthBytes), func(data []byte) error {
			lockoutAuthData = data
			return nil
		}),
	), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
		s.HierarchyChangeAuth(c, tpm2.HandleLockout, nil)
	})

	origHmacSession := s.TPM().HmacSession()

	ek, err := s.TPM().NewResourceContext(tcg.EKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, ek, ek.Handle())

	var opts []EnsureProvisionedOption
	if full {
		opts = append(opts, WithLockoutAuthData(lockoutAuthData))
	}
	c.Check(s.TPM().EnsureProvisioned(opts...), IsNil)

	s.validateEK(c)
	s.validateSRK(c)

	c.Check(s.TPM().HmacSession(), NotNil)
	c.Check(s.TPM().HmacSession().Handle().Type(), Equals, tpm2.HandleTypeHMACSession)
	c.Check(s.TPM().HmacSession(), Not(Equals), origHmacSession)
	c.Check(origHmacSession.Handle(), Equals, tpm2.HandleUnassigned)
}

func (s *provisioningSuite) TestRecreateEKFull(c *C) {
	s.testProvisionRecreateEK(c, true)
}

func (s *provisioningSuite) TestRecreateEKWithoutLockout(c *C) {
	s.testProvisionRecreateEK(c, false)
}

func (s *provisioningSuite) testProvisionRecreateSRK(c *C, full bool) {
	lockoutAuthBytes := testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c")
	var lockoutAuthData []byte

	c.Check(s.TPM().EnsureProvisioned(
		WithLockoutAuthValue(nil),
		WithProvisionNewLockoutAuthValue(bytes.NewReader(lockoutAuthBytes), func(data []byte) error {
			lockoutAuthData = data
			return nil
		}),
	), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
		s.HierarchyChangeAuth(c, tpm2.HandleLockout, nil)
	})

	srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
	c.Assert(err, IsNil)
	expectedName := srk.Name()
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	var opts []EnsureProvisionedOption
	if full {
		opts = append(opts, WithLockoutAuthData(lockoutAuthData))
	}
	c.Check(s.TPM().EnsureProvisioned(opts...), IsNil)

	s.validateEK(c)
	s.validateSRK(c)

	srk, err = s.TPM().NewResourceContext(tcg.SRKHandle)
	c.Assert(err, IsNil)
	c.Check(srk.Name(), DeepEquals, expectedName)
}

func (s *provisioningSuite) TestProvisionRecreateSRKFull(c *C) {
	s.testProvisionRecreateSRK(c, true)
}

func (s *provisioningSuite) TestProvisionRecreateSRKWithoutLockout(c *C) {
	s.testProvisionRecreateSRK(c, false)
}

func (s *provisioningSuite) TestProvisionWithEndorsementAuth(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, []byte("1234"))

	c.Check(s.TPM().EnsureProvisioned(), Equals, ErrTPMProvisioningRequiresLockout)

	s.validateEK(c)
	s.validateSRK(c)
}

func (s *provisioningSuite) TestProvisionWithOwnerAuth(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))

	c.Check(s.TPM().EnsureProvisioned(), Equals, ErrTPMProvisioningRequiresLockout)

	s.validateEK(c)
	s.validateSRK(c)
}

func (s *provisioningSuite) testProvisionWithCustomSRKTemplate(c *C, clear bool) {
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
			tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}

	opts := []EnsureProvisionedOption{WithLockoutAuthValue(nil), WithCustomSRKTemplate(&template)}
	if clear {
		opts = append(opts, WithClearBeforeProvision())
	}
	c.Check(s.TPM().EnsureProvisioned(opts...), IsNil)

	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, &template)

	nv, err := s.TPM().NewResourceContext(0x01810001)
	c.Assert(err, IsNil)

	nvPub, _, err := s.TPM().NVReadPublic(nv)
	c.Assert(err, IsNil)
	c.Check(nvPub.Attrs, Equals, tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite|tpm2.AttrNVWriteDefine|tpm2.AttrNVOwnerRead|tpm2.AttrNVNoDA|tpm2.AttrNVWriteLocked|tpm2.AttrNVWritten))

	tmplBytes, err := s.TPM().NVRead(s.TPM().OwnerHandleContext(), nv, nvPub.Size, 0, nil)
	c.Check(err, IsNil)
	c.Check(tmplBytes, DeepEquals, mu.MustMarshalToBytes(&template))
}

func (s *provisioningSuite) TestProvisionWithCustomSRKTemplateClear(c *C) {
	s.testProvisionWithCustomSRKTemplate(c, true)
}

func (s *provisioningSuite) TestProvisionWithCustomSRKTemplateFull(c *C) {
	s.testProvisionWithCustomSRKTemplate(c, false)
}

func (s *provisioningSuite) TestProvisionWithInvalidCustomSRKTemplate(c *C) {
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
			tpm2.AttrRestricted | tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	err := s.TPM().EnsureProvisioned(WithCustomSRKTemplate(&template))
	c.Check(err, ErrorMatches, "supplied SRK template is not valid for a parent key")
}

func (s *provisioningSuite) testProvisionDefaultPreservesCustomSRKTemplate(c *C, full bool) {
	lockoutAuthBytes := testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5a5a368364e3d07c6d6169c9443a70c3c")
	var lockoutAuthData []byte

	template := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
			tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}

	c.Check(s.TPM().EnsureProvisioned(
		WithLockoutAuthValue(nil),
		WithProvisionNewLockoutAuthValue(bytes.NewReader(lockoutAuthBytes), func(data []byte) error {
			lockoutAuthData = data
			return nil
		}),
		WithCustomSRKTemplate(&template),
	), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		s.TPM().LockoutHandleContext().SetAuthValue(lockoutAuthValue(c, s.TPM(), lockoutAuthBytes))
		s.HierarchyChangeAuth(c, tpm2.HandleLockout, nil)
	})

	srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	var opts []EnsureProvisionedOption
	if full {
		opts = append(opts, WithLockoutAuthData(lockoutAuthData))
	}
	c.Check(s.TPM().EnsureProvisioned(opts...), IsNil)

	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, &template)
}

func (s *provisioningSuite) TestProvisionDefaultPreservesCustomSRKTemplateFull(c *C) {
	s.testProvisionDefaultPreservesCustomSRKTemplate(c, true)
}

func (s *provisioningSuite) TestProvisionDefaultPreservesCustomSRKTemplateWithoutLockout(c *C) {
	s.testProvisionDefaultPreservesCustomSRKTemplate(c, false)
}

func (s *provisioningSuite) TestProvisionDefaultClearRemovesCustomSRKTemplate(c *C) {
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
			tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	c.Check(s.TPM().EnsureProvisioned(WithCustomSRKTemplate(&template)), Equals, ErrTPMProvisioningRequiresLockout)
	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, &template)

	c.Check(s.TPM().EnsureProvisioned(WithLockoutAuthValue(nil), WithClearBeforeProvision()), IsNil)
	s.validateSRK(c)
}

func (s *provisioningSuite) TestProvisionWithCustomSRKTemplateOverwritesExisting(c *C) {
	template1 := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
			tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	c.Check(s.TPM().EnsureProvisioned(WithCustomSRKTemplate(&template1)), Equals, ErrTPMProvisioningRequiresLockout)
	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, &template1)

	template2 := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
			tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 256},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	c.Check(s.TPM().EnsureProvisioned(WithCustomSRKTemplate(&template2)), Equals, ErrTPMProvisioningRequiresLockout)
	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, &template2)

	nv, err := s.TPM().NewResourceContext(0x01810001)
	c.Assert(err, IsNil)

	nvPub, _, err := s.TPM().NVReadPublic(nv)
	c.Assert(err, IsNil)
	c.Check(nvPub.Attrs, Equals, tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite|tpm2.AttrNVWriteDefine|tpm2.AttrNVOwnerRead|tpm2.AttrNVNoDA|tpm2.AttrNVWriteLocked|tpm2.AttrNVWritten))

	tmplBytes, err := s.TPM().NVRead(s.TPM().OwnerHandleContext(), nv, nvPub.Size, 0, nil)
	c.Check(err, IsNil)
	c.Check(tmplBytes, DeepEquals, mu.MustMarshalToBytes(&template2))
}

func (s *provisioningSuite) TestProvisionNewLockoutAuthValueWithoutPolicySupport(c *C) {
	// Test with a TPM that doesn't support TPM_CAP_AUTH_POLICIES
	s.TPMTest.TPMTest.Transport.ResponseIntercept = func(cmdCode tpm2.CommandCode, cmdHandle tpm2.HandleList, cmdAuthArea []tpm2.AuthCommand, cpBytes []byte, rsp *bytes.Buffer) {
		if cmdCode != tpm2.CommandGetCapability {
			return
		}

		// Unpack the command parameters
		var capability tpm2.Capability
		var property uint32
		var propertyCount uint32
		_, err := mu.UnmarshalFromBytes(cpBytes, &capability, &property, &propertyCount)
		c.Assert(err, IsNil)
		if capability != tpm2.CapabilityAuthPolicies {
			return
		}

		// Return a TPM_RC_VALUE + TPM_RC_P + TPM_RC_1 error
		rsp.Reset()
		c.Check(tpm2.WriteResponsePacket(rsp, tpm2.ResponseValue+tpm2.ResponseP+tpm2.ResponseIndex1, nil, nil, nil), IsNil)
	}

	origValue := []byte("1234")
	data := s.makeLockoutAuthData(c, &LockoutAuthParams{
		AuthValue: origValue,
	})
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, origValue)

	err := s.TPM().EnsureProvisioned(WithLockoutAuthData(data), WithProvisionNewLockoutAuthValue(rand.Reader, func(_ []byte) error { return nil }))
	c.Check(err, ErrorMatches, `cannot set new lockout hierarchy authorization value: updating the authorization parameters for the lockout hierarchy is not supported`)
	c.Check(errors.Is(err, ErrLockoutAuthUpdateUnsupported), testutil.IsTrue)
}
