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
	"crypto/x509"
	"io"
	"os"
	"syscall"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type tpmSuiteNoTPM struct {
	tpm2_testutil.BaseTest
}

type tpmSuiteCommon struct{}

type tpmSuite struct {
	tpm2test.TPMTest
	tpmSuiteCommon
}

func (s *tpmSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureNV
}

type tpmSuitePlatform struct {
	tpm2test.TPMTest
	tpmSuiteCommon
}

func (s *tpmSuitePlatform) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeaturePlatformHierarchy |
		tpm2test.TPMFeatureNV |
		tpm2test.TPMFeatureLockoutHierarchy
}

type tpmSuiteSimulator struct {
	tpm2test.TPMSimulatorTest
	tpmSuiteCommon
}

func (s *tpmSuiteSimulator) ekCert(c *C) *x509.Certificate {
	cert, err := x509.ParseCertificate(testEkCert)
	c.Assert(err, IsNil)
	return cert
}

func (s *tpmSuiteSimulator) caCert(c *C) *x509.Certificate {
	cert, err := x509.ParseCertificate(testCACert)
	c.Assert(err, IsNil)
	return cert
}

var _ = Suite(&tpmSuiteNoTPM{})
var _ = Suite(&tpmSuite{})
var _ = Suite(&tpmSuitePlatform{})
var _ = Suite(&tpmSuiteSimulator{})

func (s *tpmSuitePlatform) TestConnectionIsEnabled(c *C) {
	c.Check(s.TPM().IsEnabled(), testutil.IsTrue)

	c.Check(s.TPM().HierarchyControl(s.TPM().OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
	c.Check(s.TPM().IsEnabled(), testutil.IsFalse)

	c.Check(s.TPM().HierarchyControl(s.TPM().EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)
	c.Check(s.TPM().IsEnabled(), testutil.IsFalse)

	c.Check(s.TPM().HierarchyControl(s.TPM().PlatformHandleContext(), tpm2.HandleOwner, true, nil), IsNil)
	c.Check(s.TPM().IsEnabled(), testutil.IsFalse)
}

func (s *tpmSuitePlatform) TestConnectionLockoutAuthSet(c *C) {
	c.Check(s.TPM().LockoutAuthSet(), testutil.IsFalse)

	// Put the TPM in DA lockout mode
	c.Check(s.TPM().DictionaryAttackParameters(s.TPM().LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	c.Check(s.TPM().LockoutAuthSet(), testutil.IsTrue)
}

func (s *tpmSuiteCommon) testConnectToDefaultTPM(c *C, hasEk bool) {
	tpm, err := ConnectToDefaultTPM()
	c.Assert(err, IsNil)
	defer func() {
		c.Check(tpm.Close(), IsNil)
	}()

	c.Check(tpm.VerifiedEKCertChain(), HasLen, 0)
	c.Check(tpm.VerifiedDeviceAttributes(), IsNil)

	ek, err := tpm.EndorsementKey()
	if !hasEk {
		c.Check(ek, IsNil)
		c.Check(err, Equals, ErrTPMProvisioning)
	} else {
		c.Check(ek.Handle(), Equals, tcg.EKHandle)
		c.Check(err, IsNil)
	}

	session := tpm.HmacSession()
	c.Check(session, NotNil)
	c.Check(session.Handle().Type(), Equals, tpm2.HandleTypeHMACSession)
}

func (s *tpmSuiteSimulator) TestConnectToDefaultTPMUnprovisioned(c *C) {
	s.testConnectToDefaultTPM(c, false)
}

func (s *tpmSuite) TestConnectToDefaultTPMProvisioned(c *C) {
	c.Check(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil),
		testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})
	s.testConnectToDefaultTPM(c, true)
}

func (s *tpmSuite) TestConnectToDefaultTPMInvalidEK(c *C) {
	primary := s.CreatePrimary(c, tpm2.HandleEndorsement, tcg.SRKTemplate)
	s.EvictControl(c, tpm2.HandleOwner, primary, tcg.EKHandle)
	s.testConnectToDefaultTPM(c, false)
}

func (s *tpmSuiteNoTPM) TestConnectToDefaultTPMNoTPM(c *C) {
	restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return nil, &os.PathError{Op: "open", Path: "/dev/tpm0", Err: syscall.ENOENT}
	})
	s.AddCleanup(restore)

	tpm, err := ConnectToDefaultTPM()
	c.Check(err, Equals, ErrNoTPM2Device)
	c.Check(tpm, IsNil)
}

// We don't have a TPM1.2 simulator, so create a mock TCTI that just returns
// a TPM_BAD_ORDINAL error
type mockTPM12Tcti struct{}

func (t *mockTPM12Tcti) Read(data []byte) (int, error) {
	// tag = TPM_TAG_RSP_COMMAND (0xc4)
	// paramSize = 10
	// returnCode = TPM_BAD_ORDINAL (10)
	b := mu.MustMarshalToBytes(tpm2.TagRspCommand, uint32(10), tpm2.ResponseBadTag)
	return copy(data, b), io.EOF
}

func (t *mockTPM12Tcti) Write(data []byte) (int, error) {
	return len(data), nil
}

func (t *mockTPM12Tcti) Close() error {
	return nil
}

func (t *mockTPM12Tcti) SetLocality(locality uint8) error {
	return nil
}

func (t *mockTPM12Tcti) MakeSticky(handle tpm2.Handle, sticky bool) error {
	return nil
}

func (s *tpmSuiteNoTPM) TestConnectToDefaultTPM12(c *C) {
	restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return &mockTPM12Tcti{}, nil
	})
	s.AddCleanup(restore)

	tpm, err := ConnectToDefaultTPM()
	c.Check(err, Equals, ErrNoTPM2Device)
	c.Check(tpm, IsNil)
}

type testSecureConnectToDefaultTPMData struct {
	ekCertData io.Reader
	auth       []byte
	expectEk   bool
}

func (s *tpmSuiteSimulator) testSecureConnectToDefaultTPM(c *C, data *testSecureConnectToDefaultTPMData) {
	tpm, err := SecureConnectToDefaultTPM(data.ekCertData, data.auth)
	c.Assert(err, IsNil)
	s.AddCleanup(func() {
		c.Check(tpm.Close(), IsNil)
	})

	c.Check(tpm.VerifiedEKCertChain(), HasLen, 2)
	c.Check(tpm.VerifiedEKCertChain()[0].Raw, DeepEquals, testEkCert)

	c.Check(tpm.VerifiedDeviceAttributes(), NotNil)
	c.Check(tpm.VerifiedDeviceAttributes().Manufacturer, Equals, tpm2.TPMManufacturerIBM)
	c.Check(tpm.VerifiedDeviceAttributes().Model, Equals, "FakeTPM")
	c.Check(tpm.VerifiedDeviceAttributes().FirmwareVersion, Equals, uint32(0x00010002))

	ek, err := tpm.EndorsementKey()
	if !data.expectEk {
		c.Check(ek, IsNil)
		c.Check(err, Equals, ErrTPMProvisioning)
	} else {
		c.Check(ek.Handle(), Equals, tcg.EKHandle)
		c.Check(err, IsNil)
	}

	session := tpm.HmacSession()
	c.Check(session, NotNil)
	c.Check(session.Handle().Type(), Equals, tpm2.HandleTypeHMACSession)
}

func (s *tpmSuiteSimulator) TestSecureConnectToDefaultTPMUnprovisioned(c *C) {
	// Test that we verify successfully with a transient EK
	ekCertData := new(bytes.Buffer)
	c.Check(EncodeEKCertificateChain(nil, []*x509.Certificate{s.caCert(c)}, ekCertData), IsNil)
	s.testSecureConnectToDefaultTPM(c, &testSecureConnectToDefaultTPMData{
		ekCertData: ekCertData})
}

func (s *tpmSuiteSimulator) TestSecureConnectToDefaultTPMUnprovisionedWithEndorsementAuth(c *C) {
	// Test that we verify successfully with a transient EK when the endorsement hierarchy has an authorization value and we know it
	testAuth := []byte("56789")
	s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, testAuth)

	ekCertData := new(bytes.Buffer)
	c.Check(EncodeEKCertificateChain(nil, []*x509.Certificate{s.caCert(c)}, ekCertData), IsNil)
	s.testSecureConnectToDefaultTPM(c, &testSecureConnectToDefaultTPMData{
		ekCertData: ekCertData,
		auth:       testAuth})
}

func (s *tpmSuiteSimulator) TestSecureConnectToDefaultTPMProvisioned(c *C) {
	// Test that we verify successfully with the properly provisioned persistent EK
	c.Check(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil), Equals, ErrTPMProvisioningRequiresLockout)

	ekCertData := new(bytes.Buffer)
	c.Check(EncodeEKCertificateChain(nil, []*x509.Certificate{s.caCert(c)}, ekCertData), IsNil)
	s.testSecureConnectToDefaultTPM(c, &testSecureConnectToDefaultTPMData{
		ekCertData: ekCertData,
		expectEk:   true})
}

func (s *tpmSuiteSimulator) TestSecureConnectToDefaultTPMCallerProvidedEKCert(c *C) {
	// Test that we can verify without a TPM provisioned EK certificate
	ekCertData := new(bytes.Buffer)
	c.Check(EncodeEKCertificateChain(s.ekCert(c), []*x509.Certificate{s.caCert(c)}, ekCertData), IsNil)
	s.testSecureConnectToDefaultTPM(c, &testSecureConnectToDefaultTPMData{
		ekCertData: ekCertData})
}

func (s *tpmSuiteSimulator) TestSecureConnectToDefaultTPMIncorrectPersistentEK(c *C) {
	// Test that we verify successfully using a transient EK if the persistent EK doesn't match the certificate

	// This produces a primary key that doesn't match the certificate created in TestMain
	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	ek, _, _, _, _, err := s.TPM().CreatePrimary(s.TPM().EndorsementHandleContext(), &sensitive, tcg.EKTemplate, nil, nil, nil)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, ek, tcg.EKHandle)

	ekCertData := new(bytes.Buffer)
	c.Check(EncodeEKCertificateChain(nil, []*x509.Certificate{s.caCert(c)}, ekCertData), IsNil)
	s.testSecureConnectToDefaultTPM(c, &testSecureConnectToDefaultTPMData{
		ekCertData: ekCertData})
}

func (s *tpmSuiteSimulator) TestSecureConnectToDefaultTPMIncorrectPersistentEKWithEndorsementAuth(c *C) {
	// Test that we verify successfully using a transient EK if the persistent EK doesn't match the certificate and we have set the
	// endorsement hierarchy authorization value

	// This produces a primary key that doesn't match the certificate created in TestMain
	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	ek, _, _, _, _, err := s.TPM().CreatePrimary(s.TPM().EndorsementHandleContext(), &sensitive, tcg.EKTemplate, nil, nil, nil)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, ek, tcg.EKHandle)

	testAuth := []byte("12345")
	s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, testAuth)

	ekCertData := new(bytes.Buffer)
	c.Check(EncodeEKCertificateChain(nil, []*x509.Certificate{s.caCert(c)}, ekCertData), IsNil)
	s.testSecureConnectToDefaultTPM(c, &testSecureConnectToDefaultTPMData{
		ekCertData: ekCertData,
		auth:       testAuth})
}

func (s *tpmSuiteSimulator) TestSecureConnectToDefaultTPMUnprovisionedWithUnknownEndorsementAuth(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, []byte("1234"))

	ekCertData := new(bytes.Buffer)
	c.Check(EncodeEKCertificateChain(nil, []*x509.Certificate{s.caCert(c)}, ekCertData), IsNil)
	_, err := SecureConnectToDefaultTPM(ekCertData, nil)
	c.Check(err, Equals, ErrTPMProvisioning)
}

func (s *tpmSuiteSimulator) TestSecureConnectToDefaultTPMInvalidEKCert(c *C) {
	// Test that we get the right error if the provided EK cert data is invalid
	ekCertData := new(bytes.Buffer)
	ekCertData.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	_, err := SecureConnectToDefaultTPM(ekCertData, nil)
	c.Check(err, testutil.ConvertibleTo, EKCertVerificationError{})
	c.Check(err, ErrorMatches, "cannot verify the endorsement key certificate: certificate verification failed: x509: certificate signed by unknown authority")
}

func (s *tpmSuiteSimulator) TestSecureConnectToDefaultTPMEKCertUnknownIssuer(c *C) {
	// Test that we get the right error if the provided EK cert has an unknown issuer
	caCertRaw, caKey, err := tpm2test.CreateTestCA()
	c.Assert(err, IsNil)
	certRaw, err := tpm2test.CreateTestEKCert(s.TPM().TPMContext, caCertRaw, caKey)
	c.Assert(err, IsNil)
	cert, _ := x509.ParseCertificate(certRaw)
	caCert, _ := x509.ParseCertificate(caCertRaw)

	ekCertData := new(bytes.Buffer)
	c.Check(EncodeEKCertificateChain(cert, []*x509.Certificate{caCert}, ekCertData), IsNil)
	_, err = SecureConnectToDefaultTPM(ekCertData, nil)
	c.Check(err, testutil.ConvertibleTo, EKCertVerificationError{})
	c.Check(err, ErrorMatches, "cannot verify the endorsement key certificate: certificate verification failed: x509: certificate signed by unknown authority")
}

func (s *tpmSuiteSimulator) TestSecureConnectToDefaultTPMIncorrectPersistentEKWithUnknownEndorsementAuth(c *C) {
	// Verify that we get the expected error if the persistent EK doesn't match the certificate and we can't create a transient EK

	// This produces a primary key that doesn't match the certificate created in TestMain
	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	ek, _, _, _, _, err := s.TPM().CreatePrimary(s.TPM().EndorsementHandleContext(), &sensitive, tcg.EKTemplate, nil, nil, nil)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, ek, tcg.EKHandle)

	testAuth := []byte("12345")
	s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, testAuth)

	ekCertData := new(bytes.Buffer)
	c.Check(EncodeEKCertificateChain(nil, []*x509.Certificate{s.caCert(c)}, ekCertData), IsNil)
	_, err = SecureConnectToDefaultTPM(ekCertData, nil)
	c.Check(err, testutil.ConvertibleTo, EKCertVerificationError{})
	c.Check(err, ErrorMatches, "cannot verify that the TPM is the device for which the supplied EK certificate was issued: "+
		"cannot verify public area of endorsement key read from the TPM: public area doesn't match certificate")
}
