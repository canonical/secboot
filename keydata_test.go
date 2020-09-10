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

package secboot_test

import (
	"math/rand"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type keyDataSuite struct {
	testutil.TPMSimulatorTestBase
}

var _ = Suite(&keyDataSuite{})

func (s *keyDataSuite) TestValidateAfterLock(c *C) {
	c.Assert(ProvisionTPM(s.TPM, ProvisionModeFull, nil), IsNil)

	key := make([]byte, 64)
	rand.Read(key)

	dir := c.MkDir()
	keyFile := dir + "/keydata"

	pinHandle := tpm2.Handle(0x0181fff0)

	c.Assert(SealKeyToTPM(s.TPM, key, keyFile, "", &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.Handle(0x0181fff0)}), IsNil)
	pinIndex, err := s.TPM.CreateResourceContextFromTPM(pinHandle)
	c.Assert(err, IsNil)
	s.AddCleanupNVSpace(c, s.TPM.OwnerHandleContext(), pinIndex)

	c.Check(ValidateKeyDataFile(s.TPM.TPMContext, keyFile, "", s.TPM.HmacSession()), IsNil)

	c.Assert(LockAccessToSealedKeys(s.TPM), IsNil)
	defer s.ResetTPMSimulator(c)
	c.Check(ValidateKeyDataFile(s.TPM.TPMContext, keyFile, "", s.TPM.HmacSession()), IsNil)
}
