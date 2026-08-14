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

// This file contains drift-guard tests comparing the architecture-neutral
// Feature* constants declared in this package against their upstream cpuid
// equivalents.

package cpuid_test

import (
	"testing"

	upstream_cpuid "github.com/canonical/cpuid"
	internal_cpuid "github.com/snapcore/secboot/internal/cpuid"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type cpuidSuite struct{}

var _ = Suite(&cpuidSuite{})

func (s *cpuidSuite) TestFeatureSMXMatchesCpuidPackage(c *C) {
	// Drift guard: FeatureSMX must equal cpuid.SMX. If the upstream package
	// ever changes its bit positions this test will catch it.
	c.Check(internal_cpuid.FeatureSMX, Equals, upstream_cpuid.SMX)
}

func (s *cpuidSuite) TestFeatureSDBGMatchesCpuidPackage(c *C) {
	// Drift guard: FeatureSDBG must equal cpuid.SDBG. If the upstream package
	// ever changes its bit positions this test will catch it.
	c.Check(internal_cpuid.FeatureSDBG, Equals, upstream_cpuid.SDBG)
}
