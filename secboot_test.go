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
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"
)

var (
	testAuth = []byte("1234")
)

func Test(t *testing.T) { TestingT(t) }

type tpmTestBase struct {
	testutil.BaseTest
	tpm *TPMConnection // Not anonymous because of tpm2.TPMContext.TestParms
}

func (b *tpmTestBase) setUpTestBase(c *C, tpm *TPMConnection) {
	b.BaseTest.SetUpTest(c)
	b.tpm = tpm

	getFlushableHandles := func() (out []tpm2.Handle) {
		for _, t := range []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession} {
			h, err := b.tpm.GetCapabilityHandles(t.BaseHandle(), tpm2.CapabilityMaxProperties, nil)
			c.Assert(err, IsNil)
			out = append(out, h...)
		}
		for i, h := range out {
			if h.Type() == tpm2.HandleTypePolicySession {
				out[i] = (h & 0xffffff) | (tpm2.Handle(tpm2.HandleTypeHMACSession) << 24)
			}
		}
		return
	}
	startFlushableHandles := getFlushableHandles()

	b.AddCleanup(func() {
		for _, h := range getFlushableHandles() {
			found := false
			for _, sh := range startFlushableHandles {
				if sh == h {
					found = true
					break
				}
			}
			if found {
				continue
			}
			var hc tpm2.HandleContext
			switch h.Type() {
			case tpm2.HandleTypeTransient:
				var err error
				hc, err = b.tpm.CreateResourceContextFromTPM(h)
				c.Check(err, IsNil)
			case tpm2.HandleTypeHMACSession:
				hc = tpm2.CreateIncompleteSessionContext(h)
			default:
				c.Fatalf("Unexpected handle type")
			}
			c.Check(b.tpm.FlushContext(hc), IsNil)
		}
	})
}

func (b *tpmTestBase) SetUpTest(c *C) {
	tpm, err := openTPMForTestingCommon()
	c.Assert(err, IsNil)
	if tpm == nil {
		c.Skip("-use-mssim and -use-tpm not supplied")
	}
	b.setUpTestBase(c, tpm)
}

func (b *tpmTestBase) TearDownTest(c *C) {
	// testutil.BaseTest doesn't execute cleanup handlers in reverse order, so we don't use AddCleanup for closing the TPM
	// connection, as this is opened first and should be cleanup up last.
	b.BaseTest.TearDownTest(c)
	c.Assert(b.tpm.Close(), IsNil)
}

func (b *tpmTestBase) addCleanupNVSpace(c *C, authHandle, index tpm2.ResourceContext) {
	b.AddCleanup(func() {
		c.Check(b.tpm.NVUndefineSpace(authHandle, index, nil), IsNil)
	})
}

func (b *tpmTestBase) setHierarchyAuth(c *C, hierarchy tpm2.Handle) {
	c.Assert(b.tpm.HierarchyChangeAuth(b.tpm.GetPermanentContext(hierarchy), tpm2.Auth(testAuth), nil), IsNil)
	b.AddCleanup(func() {
		c.Check(b.tpm.HierarchyChangeAuth(b.tpm.GetPermanentContext(hierarchy), nil, nil), IsNil)
	})
}

type tpmSimulatorTestBase struct {
	tpmTestBase
	tcti *tpm2.TctiMssim
}

func (b *tpmSimulatorTestBase) SetUpTest(c *C) {
	tpm, tcti, err := openTPMSimulatorForTestingCommon()
	c.Assert(err, IsNil)
	if tpm == nil {
		c.Skip("-use-mssim not supplied")
	}
	b.setUpTestBase(c, tpm)
	b.tcti = tcti
}

func (b *tpmSimulatorTestBase) resetTPMSimulator(c *C) {
	c.Assert(resetTPMSimulatorCommon(b.tpm, b.tcti), IsNil)
}

type testRng struct{}

func (r *testRng) Read(p []byte) (int, error) {
	return rand.Read(p)
}

var testRandReader = &testRng{}

func decodeHexString(c *C, s string) []byte {
	b, err := hex.DecodeString(s)
	c.Assert(err, IsNil)
	return b
}
