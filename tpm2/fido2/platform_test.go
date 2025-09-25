// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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

package tpm2_fido2_test

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/fido2"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
	. "github.com/snapcore/secboot/tpm2/fido2"
)

type platformSuite struct {
	tpm2test.TPMTest

	lastEncryptedPayload []byte
}

var _ = Suite(&platformSuite{})

func (s *platformSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureLockoutHierarchy |
		tpm2test.TPMFeaturePCR |
		tpm2test.TPMFeatureNV
}

func (s *platformSuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	c.Check(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil), Equals, ErrTPMProvisioningRequiresLockout)

	s.lastEncryptedPayload = nil
	s.AddCleanup(MockSecbootNewKeyData(func(params *secboot.KeyParams) (*secboot.KeyData, error) {
		s.lastEncryptedPayload = params.EncryptedPayload
		return secboot.NewKeyData(params)
	}))
	origKdf := secboot.SetArgon2KDF(&testutil.MockArgon2KDF{})
	s.AddCleanup(func() { secboot.SetArgon2KDF(origKdf) })
}

func (s *platformSuite) TestPlatformName(c *C) {
	c.Check(PlatformName, Equals, "tpm2-fido2")
}

func (s *platformSuite) TestRecoverKeys(c *C) {
	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "foo",
	}

	// This is needed because the combined TPM2+FIDO2 platform first creates the TPM protected key
	// and then the FIDO2 platform needs to recover the symmetric secret from the TPM in order to
	// pass it to the FIDO2 authenticator. Since the FIDO2 API is provider agnostic/isn't supplied with a
	// TPM connection, we need to temporarily close the mock connection prior to calling it, for the tests.
	restore := MockFido2NewFIDO2ProtectedKeyWithSaltProvider(func() {
		s.AddCleanup(s.CloseMockConnection(c))
	})
	defer restore()

	// Using a physical FIDO2 authenticator with 12345 set as the PIN
	authRequestor := &testutil.MockFidoAuthRequestor{Pin: "12345"}

	authenticator, err := fido2.ConnectToFIDO2Authenticator(authRequestor)
	c.Assert(err, IsNil)

	kd, expectedPrimaryKey, expectedUnlockKey, err := NewTPM2FIDO2ProtectedKey(s.TPM(), params, authenticator)
	c.Assert(err, IsNil)

	restore = MockSecbootNewSystemdAuthRequestor(authRequestor)
	defer restore()

	unlockKey, primaryKey, err := kd.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(unlockKey, DeepEquals, expectedUnlockKey)
	c.Check(primaryKey, DeepEquals, expectedPrimaryKey)
}

func (s *platformSuite) TestRecoverKeysBio(c *C) {
	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "foo",
	}

	// This is needed because the combined TPM2+FIDO2 platform first creates the TPM protected key
	// and then the FIDO2 platform needs to recover the symmetric secret from the TPM in order to
	// pass it to the FIDO2 authenticator. Since the FIDO2 API is provider agnostic/isn't supplied with a
	// TPM connection, we need to temporarily close the mock connection prior to calling it, for the tests.
	restore := MockFido2NewFIDO2ProtectedKeyWithSaltProvider(func() {
		s.AddCleanup(s.CloseMockConnection(c))
	})
	defer restore()

	// Using a physical FIDO2 authenticator with 12345 set as the PIN and a fingerprint enrolled
	// but not passing the PIN.
	// Fingerprint reading failure causes this test to fail.
	authRequestor := &testutil.MockFidoAuthRequestor{Pin: ""}

	authenticator, err := fido2.ConnectToFIDO2Authenticator(authRequestor)
	c.Assert(err, IsNil)

	kd, expectedPrimaryKey, expectedUnlockKey, err := NewTPM2FIDO2ProtectedKey(s.TPM(), params, authenticator)
	c.Assert(err, IsNil)

	restore = MockSecbootNewSystemdAuthRequestor(authRequestor)
	defer restore()

	unlockKey, primaryKey, err := kd.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(unlockKey, DeepEquals, expectedUnlockKey)
	c.Check(primaryKey, DeepEquals, expectedPrimaryKey)
}
