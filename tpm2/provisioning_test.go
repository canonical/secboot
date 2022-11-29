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
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
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

	key, err := m.tpmTest.TPM.CreateResourceContextFromTPM(handle)
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

type testProvisionNewTPMData struct {
	mode        ProvisionMode
	lockoutAuth []byte
}

func (s *provisioningSimulatorSuite) testProvisionNewTPM(c *C, data *testProvisionNewTPMData) {
	origEk, _ := s.TPM().EndorsementKey()
	origHmacSession := s.TPM().HmacSession()

	c.Check(s.TPM().EnsureProvisioned(data.mode, data.lockoutAuth), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		c.Check(s.TPM().HierarchyChangeAuth(s.TPM().LockoutHandleContext(), nil, nil), IsNil)
	})

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

	// Verify that owner control is disabled, that the lockout hierarchy auth is set, and no
	// other hierarchy auth is set
	value, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	c.Check(err, IsNil)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrLockoutAuthSet, Equals, tpm2.AttrLockoutAuthSet)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrDisableClear, Equals, tpm2.AttrDisableClear)
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrOwnerAuthSet, Equals, tpm2.PermanentAttributes(0))
	c.Check(tpm2.PermanentAttributes(value)&tpm2.AttrEndorsementAuthSet, Equals, tpm2.PermanentAttributes(0))

	// Test the lockout hierarchy auth
	s.TPM().LockoutHandleContext().SetAuthValue(data.lockoutAuth)
	c.Check(s.TPM().DictionaryAttackLockReset(s.TPM().LockoutHandleContext(), nil), IsNil)

	c.Check(s.TPM().HmacSession(), NotNil)
	c.Check(s.TPM().HmacSession().Handle().Type(), Equals, tpm2.HandleTypeHMACSession)
	c.Check(s.TPM().HmacSession(), Not(Equals), origHmacSession)

	ek, err := s.TPM().EndorsementKey()
	c.Check(err, IsNil)
	c.Check(ek.Handle(), Equals, tcg.EKHandle)
	c.Check(ek, Not(Equals), origEk)

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
		mode:        ProvisionModeClear,
		lockoutAuth: []byte("1234")})
}

func (s *provisioningSimulatorSuite) TestProvisionNewTPMFull(c *C) {
	s.testProvisionNewTPM(c, &testProvisionNewTPMData{
		mode:        ProvisionModeFull,
		lockoutAuth: []byte("1234")})
}

func (s *provisioningSimulatorSuite) TestProvisionNewTPMDifferentLockoutAuth(c *C) {
	s.testProvisionNewTPM(c, &testProvisionNewTPMData{
		mode:        ProvisionModeClear,
		lockoutAuth: []byte("foo")})
}

func (s *provisioningSimulatorSuite) testProvisionErrorHandling(c *C, mode ProvisionMode) error {
	defer func() {
		// Some of these tests trip the lockout for the lockout auth,
		// which can't be undone by the test fixture. Clear the TPM
		// else the test fixture fails the test.
		s.ClearTPMUsingPlatformHierarchy(c)
	}()
	return s.TPM().EnsureProvisioned(mode, nil)
}

func (s *provisioningSuite) testProvisionErrorHandling(c *C, mode ProvisionMode) error {
	defer func() {
		// Some of these tests trip the lockout for the lockout auth,
		// which can't be undone by the test fixture. Clear the TPM
		// else the test fixture fails the test.
		s.ClearTPMUsingPlatformHierarchy(c)
	}()
	return s.TPM().EnsureProvisioned(mode, nil)
}

func (s *provisioningSuite) TestProvisionErrorHandlingClearRequiresPPI(c *C) {
	c.Check(s.TPM().ClearControl(s.TPM().LockoutHandleContext(), true, nil), IsNil)

	err := s.testProvisionErrorHandling(c, ProvisionModeClear)
	c.Check(err, Equals, ErrTPMClearRequiresPPI)
}

func (s *provisioningSuite) TestProvisionErrorHandlingLockoutAuthFail1(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
	s.TPM().LockoutHandleContext().SetAuthValue(nil)

	err := s.testProvisionErrorHandling(c, ProvisionModeFull)
	c.Assert(err, testutil.ConvertibleTo, AuthFailError{})
	c.Check(err.(AuthFailError).Handle, Equals, tpm2.HandleLockout)
}

func (s *provisioningSuite) TestProvisionErrorHandlingLockoutAuthFail2(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, []byte("1234"))
	s.TPM().LockoutHandleContext().SetAuthValue(nil)

	err := s.testProvisionErrorHandling(c, ProvisionModeClear)
	c.Assert(err, testutil.ConvertibleTo, AuthFailError{})
	c.Check(err.(AuthFailError).Handle, Equals, tpm2.HandleLockout)
}

func (s *provisioningSuite) TestProvisionErrorHandlingInLockout1(c *C) {
	authValue := []byte("1234")
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, authValue)

	// Trip the DA lockout
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

	// Trip the DA lockout
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

	err := s.testProvisionErrorHandling(c, ProvisionModeWithoutLockout)
	c.Check(err, Equals, ErrTPMProvisioningRequiresLockout)
}

func (s *provisioningSuite) testProvisionRecreateEK(c *C, mode ProvisionMode) {
	lockoutAuth := []byte("1234")

	c.Check(s.TPM().EnsureProvisioned(ProvisionModeFull, lockoutAuth), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		s.HierarchyChangeAuth(c, tpm2.HandleLockout, nil)
	})

	origEk, _ := s.TPM().EndorsementKey()
	origHmacSession := s.TPM().HmacSession()

	ek, err := s.TPM().CreateResourceContextFromTPM(tcg.EKHandle)
	s.EvictControl(c, tpm2.HandleOwner, ek, ek.Handle())

	c.Check(s.TPM().EnsureProvisioned(mode, lockoutAuth), IsNil)

	s.validateEK(c)
	s.validateSRK(c)

	c.Check(s.TPM().HmacSession(), NotNil)
	c.Check(s.TPM().HmacSession().Handle().Type(), Equals, tpm2.HandleTypeHMACSession)
	c.Check(s.TPM().HmacSession(), Not(Equals), origHmacSession)
	c.Check(origHmacSession.Handle(), Equals, tpm2.HandleUnassigned)

	ek, err = s.TPM().EndorsementKey()
	c.Check(err, IsNil)
	c.Check(ek.Handle(), Equals, tcg.EKHandle)
	c.Check(ek, Not(Equals), origEk)
}

func (s *provisioningSuite) TestRecreateEKFull(c *C) {
	s.testProvisionRecreateEK(c, ProvisionModeFull)
}

func (s *provisioningSuite) TestRecreateEKWithoutLockout(c *C) {
	s.testProvisionRecreateEK(c, ProvisionModeWithoutLockout)
}

func (s *provisioningSuite) testProvisionRecreateSRK(c *C, mode ProvisionMode) {
	lockoutAuth := []byte("1234")

	c.Check(s.TPM().EnsureProvisioned(ProvisionModeFull, lockoutAuth), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		s.HierarchyChangeAuth(c, tpm2.HandleLockout, nil)
	})

	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	expectedName := srk.Name()
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	c.Check(s.TPM().EnsureProvisioned(mode, lockoutAuth), IsNil)

	s.validateEK(c)
	s.validateSRK(c)

	srk, err = s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	c.Check(srk.Name(), DeepEquals, expectedName)
}

func (s *provisioningSuite) TestProvisionRecreateSRKFull(c *C) {
	s.testProvisionRecreateSRK(c, ProvisionModeFull)
}

func (s *provisioningSuite) TestProvisionRecreateSRKWithoutLockout(c *C) {
	s.testProvisionRecreateSRK(c, ProvisionModeWithoutLockout)
}

func (s *provisioningSuite) TestProvisionWithEndorsementAuth(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, []byte("1234"))

	c.Check(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil),
		testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})

	s.validateEK(c)
	s.validateSRK(c)
}

func (s *provisioningSuite) TestProvisionWithOwnerAuth(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))

	c.Check(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil),
		testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})

	s.validateEK(c)
	s.validateSRK(c)
}

func (s *provisioningSimulatorSuite) TestProvisionWithInvalidEkCert(c *C) {
	ConnectToTPM = secureConnectToDefaultTPMHelper
	defer func() { ConnectToTPM = ConnectToDefaultTPM }()

	s.ReinitTPMConnectionFromExisting(c)

	// Temporarily modify the public template so that ProvisionTPM generates a primary key that doesn't match the EK cert
	ekTemplate := tcg.MakeDefaultEKTemplate()
	ekTemplate.Unique.RSA[0] = 0xff
	restore := tpm2test.MockEKTemplate(ekTemplate)
	s.AddCleanup(restore)

	err := s.TPM().EnsureProvisioned(ProvisionModeFull, nil)
	c.Assert(err, testutil.ConvertibleTo, TPMVerificationError{})
	c.Check(err, ErrorMatches, "cannot verify that the TPM is the device for which "+
		"the supplied EK certificate was issued: cannot reinitialize TPM connection "+
		"after provisioning endorsement key: cannot verify public area of endorsement "+
		"key read from the TPM: public area doesn't match certificate")
}

func (s *provisioningSuite) testProvisionWithCustomSRKTemplate(c *C, mode ProvisionMode) {
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
	c.Check(s.TPM().EnsureProvisionedWithCustomSRK(mode, nil, &template), IsNil)

	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, &template)

	nv, err := s.TPM().CreateResourceContextFromTPM(0x01810001)
	c.Assert(err, IsNil)

	nvPub, _, err := s.TPM().NVReadPublic(nv)
	c.Assert(err, IsNil)
	c.Check(nvPub.Attrs, Equals, tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite|tpm2.AttrNVWriteDefine|tpm2.AttrNVOwnerRead|tpm2.AttrNVNoDA|tpm2.AttrNVWriteLocked|tpm2.AttrNVWritten))

	tmplBytes, err := s.TPM().NVRead(s.TPM().OwnerHandleContext(), nv, nvPub.Size, 0, nil)
	c.Check(err, IsNil)
	c.Check(tmplBytes, DeepEquals, mu.MustMarshalToBytes(&template))
}

func (s *provisioningSuite) TestProvisionWithCustomSRKTemplateClear(c *C) {
	s.testProvisionWithCustomSRKTemplate(c, ProvisionModeClear)
}

func (s *provisioningSuite) TestProvisionWithCustomSRKTemplateFull(c *C) {
	s.testProvisionWithCustomSRKTemplate(c, ProvisionModeFull)
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
	err := s.TPM().EnsureProvisionedWithCustomSRK(ProvisionModeFull, nil, &template)
	c.Check(err, ErrorMatches, "supplied SRK template is not valid for a parent key")
}

func (s *provisioningSuite) testProvisionDefaultPreservesCustomSRKTemplate(c *C, mode ProvisionMode) {
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

	lockoutAuth := []byte("1234")
	c.Check(s.TPM().EnsureProvisionedWithCustomSRK(ProvisionModeFull, lockoutAuth, &template), IsNil)
	s.AddCleanup(func() {
		// github.com/canonical/go-tpm2/testutil cannot restore this because
		// EnsureProvisioned uses command parameter encryption. We have to do
		// this manually else the test fixture fails the test.
		s.HierarchyChangeAuth(c, tpm2.HandleLockout, nil)
	})

	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	c.Check(s.TPM().EnsureProvisioned(mode, lockoutAuth), IsNil)

	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, &template)
}

func (s *provisioningSuite) TestProvisionDefaultPreservesCustomSRKTemplateFull(c *C) {
	s.testProvisionDefaultPreservesCustomSRKTemplate(c, ProvisionModeFull)
}

func (s *provisioningSuite) TestProvisionDefaultPreservesCustomSRKTemplateWithoutLockout(c *C) {
	s.testProvisionDefaultPreservesCustomSRKTemplate(c, ProvisionModeWithoutLockout)
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
	c.Check(s.TPM().EnsureProvisionedWithCustomSRK(ProvisionModeWithoutLockout, nil, &template),
		testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})
	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, &template)

	c.Check(s.TPM().EnsureProvisioned(ProvisionModeClear, nil), IsNil)
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
	c.Check(s.TPM().EnsureProvisionedWithCustomSRK(ProvisionModeFull, nil, &template1), IsNil)
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
	c.Check(s.TPM().EnsureProvisionedWithCustomSRK(ProvisionModeFull, nil, &template2), IsNil)
	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, &template2)

	nv, err := s.TPM().CreateResourceContextFromTPM(0x01810001)
	c.Assert(err, IsNil)

	nvPub, _, err := s.TPM().NVReadPublic(nv)
	c.Assert(err, IsNil)
	c.Check(nvPub.Attrs, Equals, tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite|tpm2.AttrNVWriteDefine|tpm2.AttrNVOwnerRead|tpm2.AttrNVNoDA|tpm2.AttrNVWriteLocked|tpm2.AttrNVWritten))

	tmplBytes, err := s.TPM().NVRead(s.TPM().OwnerHandleContext(), nv, nvPub.Size, 0, nil)
	c.Check(err, IsNil)
	c.Check(tmplBytes, DeepEquals, mu.MustMarshalToBytes(&template2))
}
