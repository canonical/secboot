package secboot_test

import (
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type pinSuite struct{}

var _ = Suite(&pinSuite{})

func (s *pinSuite) TestPIN(c *C) {
	pin, err := ParsePIN("1234")
	c.Assert(err, IsNil)

	c.Check(pin.String(), Equals, "1234")
	c.Check(pin.Bytes(), DeepEquals, testutil.DecodeHexString(c, "0404d2"))
}

func (s *pinSuite) TestPINZeroPaddedIsDifferent(c *C) {
	pin, err := ParsePIN("00001234")
	c.Assert(err, IsNil)

	c.Check(pin.String(), Equals, "00001234")
	c.Check(pin.Bytes(), DeepEquals, testutil.DecodeHexString(c, "08000004d2"))
}

func (s *pinSuite) TestPIN2(c *C) {
	pin, err := ParsePIN("12345678")
	c.Assert(err, IsNil)

	c.Check(pin.String(), Equals, "12345678")
	c.Check(pin.Bytes(), DeepEquals, testutil.DecodeHexString(c, "0800bc614e"))
}

func (s *pinSuite) TestPIN3(c *C) {
	pin, err := ParsePIN("00000000")
	c.Assert(err, IsNil)

	c.Check(pin.String(), Equals, "00000000")
	c.Check(pin.Bytes(), DeepEquals, testutil.DecodeHexString(c, "0800000000"))
}

func (s *pinSuite) TestPIN4(c *C) {
	pin, err := ParsePIN("99999999")
	c.Assert(err, IsNil)

	c.Check(pin.String(), Equals, "99999999")
	c.Check(pin.Bytes(), DeepEquals, testutil.DecodeHexString(c, "0805f5e0ff"))
}

func (s *pinSuite) TestPIN5(c *C) {
	pin, err := ParsePIN("246813")
	c.Assert(err, IsNil)

	c.Check(pin.String(), Equals, "246813")
	c.Check(pin.Bytes(), DeepEquals, testutil.DecodeHexString(c, "0603c41d"))
}

func (s *pinSuite) TestPINLongest(c *C) {
	pin, err := ParsePIN("1234567812345678123456781234567812345678123456781234567812345678" +
		"12345678123456781234567812345678123456781234567812345678123456781234567812345678" +
		"12345678123456781234567812345678123456781234567812345678123456781234567812345678" +
		"1234567812345678123456781234567")
	c.Assert(err, IsNil)

	c.Check(pin.String(), Equals, "1234567812345678123456781234567812345678123456781234567812345678"+
		"12345678123456781234567812345678123456781234567812345678123456781234567812345678"+
		"12345678123456781234567812345678123456781234567812345678123456781234567812345678"+
		"1234567812345678123456781234567")
	c.Check(pin.Bytes(), DeepEquals, testutil.DecodeHexString(c, "ff10d6ce8940392078ffd0aa1ced339ebd632df03586ebc7a964a198aa06dfecf4417552290933dd874c2e00f55ea5ba5c1d4bea13735a8c5fc9edfbdb473a2df4dda455f0c098d6c0d592a7cb42a5383e7b9a34b3d5b8ccde89851ecf645becf69d528a2af48c8b923187"))
}

func (s *pinSuite) TestPINMax(c *C) {
	pin, err := ParsePIN("9999999999999999999999999999999999999999999999999999999999999999" +
		"99999999999999999999999999999999999999999999999999999999999999999999999999999999" +
		"99999999999999999999999999999999999999999999999999999999999999999999999999999999" +
		"9999999999999999999999999999999")
	c.Assert(err, IsNil)

	c.Check(pin.String(), Equals, "9999999999999999999999999999999999999999999999999999999999999999"+
		"99999999999999999999999999999999999999999999999999999999999999999999999999999999"+
		"99999999999999999999999999999999999999999999999999999999999999999999999999999999"+
		"9999999999999999999999999999999")
	c.Check(pin.Bytes(), DeepEquals, testutil.DecodeHexString(c, "ff8865899617fb18717e2fa67c7a658892d0e50a3297e8c7a2252cd6ccbb9b0606aebc361bb89d4493d7119d783e8b155bc8ce61877171a4630813ce9bb7f3fc15c32513152722c26b0c667fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
}

func (s *pinSuite) TestPINTooLong(c *C) {
	_, err := ParsePIN("1234567812345678123456781234567812345678123456781234567812345678" +
		"12345678123456781234567812345678123456781234567812345678123456781234567812345678" +
		"12345678123456781234567812345678123456781234567812345678123456781234567812345678" +
		"12345678123456781234567812345678")
	c.Check(err, ErrorMatches, `invalid PIN: too long`)
}

func (s *pinSuite) TestPINInvalidChars(c *C) {
	_, err := ParsePIN("1234abc")
	c.Check(err, ErrorMatches, `invalid PIN`)
}
