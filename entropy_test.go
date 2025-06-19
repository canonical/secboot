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

package secboot_test

import (
	. "github.com/snapcore/secboot"
	. "gopkg.in/check.v1"
)

type entropySuite struct{}

var _ = Suite(&entropySuite{})

func (t *entropySuite) TestCheckPassphraseEntropy1234(c *C) {
	stats, err := CheckPassphraseEntropy("1234")
	c.Check(err, IsNil)
	c.Assert(stats.SymbolPoolSize, Equals, uint32(10)) // 10 digits
	c.Assert(stats.NumberOfSymbols, Equals, uint32(2)) // runs of more than 2 from the digits set get compressed
	c.Assert(stats.EntropyBits, Equals, uint32(6))     // log2(10^2)
}

func (t *entropySuite) TestCheckPassphraseEntropy194753(c *C) {
	stats, err := CheckPassphraseEntropy("194753")
	c.Check(err, IsNil)
	c.Assert(stats.SymbolPoolSize, Equals, uint32(10)) // 10 digits
	c.Assert(stats.NumberOfSymbols, Equals, uint32(6)) // 6 non-identical chars not in proximity set order
	c.Assert(stats.EntropyBits, Equals, uint32(19))    // log2(10^6)
}

func (t *entropySuite) TestCheckPassphraseEntropyPassword1(c *C) {
	stats, err := CheckPassphraseEntropy("password1")
	c.Check(err, IsNil)
	c.Assert(stats.SymbolPoolSize, Equals, uint32(36)) // 26 lowercase letters + 10 digits
	c.Assert(stats.NumberOfSymbols, Equals, uint32(9)) // only "as" in proximity set order but that's <= 2, so 9 chars
	c.Assert(stats.EntropyBits, Equals, uint32(46))    // log2(36^9)
}

func (t *entropySuite) TestCheckPassphraseEntropyLParenFoobarDollar(c *C) {
	stats, err := CheckPassphraseEntropy("(Foobar$")
	c.Check(err, IsNil)
	c.Assert(stats.SymbolPoolSize, Equals, uint32(79)) // 26 lowercase letters + 26 uppercase letters + $ in set of 5 chars + ( in set of 22 chars
	c.Assert(stats.NumberOfSymbols, Equals, uint32(8)) // nothing in proximity set order
	c.Assert(stats.EntropyBits, Equals, uint32(50))    // log2(79^8)
}
