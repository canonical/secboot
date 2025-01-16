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
	"crypto/x509"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2_device"
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
		tpm2test.TPMFeatureLockoutHierarchy |
		tpm2test.TPMFeaturePlatformHierarchy |
		tpm2test.TPMFeatureNV
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

	// FullProvising of the TPM puts it in DA lockout mode
	c.Check(s.TPM().EnsureProvisioned(ProvisionModeFull, []byte("1234")), IsNil)
	s.AddCleanup(func() {
		c.Check(s.TPM().HierarchyChangeAuth(s.TPM().LockoutHandleContext(), nil, nil), IsNil)
	})
	c.Check(s.TPM().LockoutAuthSet(), testutil.IsTrue)
}

func (s *tpmSuiteCommon) testConnectToDefaultTPM(c *C, hasEncryption bool) {
	tpm, err := ConnectToDefaultTPM()
	c.Assert(err, IsNil)
	defer func() {
		c.Check(tpm.Close(), IsNil)
	}()

	session := tpm.HmacSession()
	c.Check(session, NotNil)
	c.Check(session.Handle().Type(), Equals, tpm2.HandleTypeHMACSession)

	if hasEncryption {
		session = session.IncludeAttrs(tpm2.AttrResponseEncrypt)
	}
	_, err = tpm.GetRandom(16, session)
	if hasEncryption {
		c.Check(err, IsNil)
	} else {
		c.Check(tpm2.IsTPMSessionError(err, tpm2.ErrorAttributes, tpm2.CommandGetRandom, 1), testutil.IsTrue)
	}
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
	primary := s.CreatePrimary(c, tpm2.HandleOwner, tpm2_testutil.NewRSAKeyTemplate(objectutil.UsageDecrypt, nil))
	s.EvictControl(c, tpm2.HandleOwner, primary, tcg.EKHandle)
	s.testConnectToDefaultTPM(c, false)
}

func (s *tpmSuiteNoTPM) TestConnectToDefaultTPMNoTPM(c *C) {
	restore := tpm2test.MockDefaultDeviceFn(func(tpm2_device.DeviceMode) (tpm2_device.TPMDevice, error) {
		return nil, tpm2_device.ErrNoTPM2Device
	})
	s.AddCleanup(restore)

	tpm, err := ConnectToDefaultTPM()
	c.Check(err, Equals, ErrNoTPM2Device)
	c.Check(tpm, IsNil)
}
