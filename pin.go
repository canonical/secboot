// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package secboot

import (
	"errors"
	"fmt"
	"math"
	"math/big"
)

// PIN represents a numeric PIN.
type PIN struct {
	length uint8   // the length of the PIN in bytes, as a sequence of ASCII characters. Support PINs of 1-256 digits
	value  big.Int // the PIN value, encoded in big-endian form without leading zeroes.
}

// ParsePIN parses the supplied string and returns a PIN. If the supplied
// string has a length of zero, or more than 256, or contains anything other
// than ASCII base-10 digits, an error will be returned.
func ParsePIN(s string) (PIN, error) {
	l := len(s)
	switch {
	case l == 0:
		return PIN{}, errors.New("invalid PIN: zero length")
	case int64(l) > math.MaxUint8+1:
		return PIN{}, errors.New("invalid PIN: too long")
	}

	val := new(big.Int)

	b := big.NewInt(10) // base 10
	bn := big.NewInt(1) // bn = 10^n (our virtual n is 0 at this point)
	for len(s) > 0 {
		c := s[len(s)-1] // Obtain the next least significant digit.
		s = s[:len(s)-1]

		if c < '0' || c > '9' {
			return PIN{}, fmt.Errorf("invalid PIN: unexpected character '%c'", c)
		}

		val.Add(val, new(big.Int).Mul(bn, big.NewInt(int64(c)-int64('0')))) // res += int(c)*(10^n)

		bn.Mul(bn, b) // increment our virtual n and update bn = 10^n
	}

	return PIN{
		length: uint8(l - 1),
		value:  *val,
	}, nil
}

// String implements [fmt.Stringer].
func (p PIN) String() string {
	str := p.value.String()
	if len(str) > int(p.length)+1 {
		panic("PIN length and value inconsistent")
	}
	return fmt.Sprintf("%0*s", p.length+1, str)
}

// Bytes provides a binary representation of this PIN which can be used as
// low-entropy key material. The binary representation is a variable-length
// quantity of the original PIN encoded in a way that preserves any leading
// zeroes.
func (p PIN) Bytes() []byte {
	// Prepend "1" to the PIN so that we can accurately encode leading zeroes
	// in the VLQ encoding. Although we can prepend leading base128 numbers in
	// the resulting encoding, we can't guarantee that the most-significant
	// leading zero of the PIN sits on a base128 number boundary.
	// val += 10^n, where n == length+1.
	val := new(big.Int).Add(&p.value, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(p.length+1)), nil))

	src := val.Bytes()
	srcL := len(src) // The length of the source buffer.
	srcI := srcL - 1 // Track index into the source buffer.

	dst := make([]byte, ((srcL*8)+6)/7) // Allocate a destination buffer for the VLQ encoded PIN.
	dstI := len(dst) - 1                // Track index into the destination buffer.

	var b byte // The current destination byte.
	lsb := true

	// Loop over the source buffer from the least significant to the most significant byte.
	// On each loop, we encode the least significant bits of the source byte into the
	// current destination byte. At this point, we've always encoded 7 bits either all from
	// the current source byte (when i % 7 == 0), or from a combination of the current and
	// previous source byte, so we save the current destination byte and move onto the next
	// one. Into that, we encode the most significant bits of the source byte. If we're on
	// the last source byte or we've encoded 7 bits (when i % 7 == 6) then we save the
	// currrent destination byte, else the remaining bits are encoded from the next source
	// byte.
	for i := 0; srcI >= 0; i = (i + 1) % 7 {
		// Encode the least significant bits of this source byte into the current destination byte.
		mask := byte(0x7f) >> (i % 7)
		b |= (src[srcI] & mask) << (i % 7)
		if !lsb {
			// All bytes other than the least significant in the destination buffer have their MSB set.
			b |= 0x80
		}
		lsb = false

		if dstI < 0 {
			// This would panic anyway, but have an explicit check.
			panic("encoded PIN overflows destination buffer")
		}
		dst[dstI] = b // We've always encoded 7 bits by this point, so save this byte.
		dstI -= 1     // Move on to the next destination byte.

		// Encode the most significant bits of this source byte into the next destination byte.
		mask = ^mask
		b = (src[srcI] & mask) >> (7 - (i % 7))

		if mask == 0xfe || srcI == 0 {
			// We've encoded 7 bits or there are no more source bytes, so save the
			// current destination byte.
			b |= 0x80
			if dstI < 0 {
				// This would panic anyway, but have an explicit check.
				panic("encoded PIN overflows destination buffer")
			}
			dst[dstI] = b
			dstI -= 1 // Move on to the next destination byte.
			b = 0
		}

		srcI -= 1 // Move on to the next source byte.
	}

	if dst[0] == 0x80 {
		dst = dst[1:]
	}

	return dst
}
