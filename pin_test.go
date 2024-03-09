package secboot_test

import (
	. "github.com/snapcore/secboot"

	. "gopkg.in/check.v1"
)

func makePIN(c *C, in string) PIN {
	out, err := ParsePIN(in)
	c.Assert(err, IsNil)
	return out
}

type pinSuite struct{}

var _ = Suite(&pinSuite{})

func (s *pinSuite) TestPIN(c *C) {
	pin, err := ParsePIN("1234")
	c.Assert(err, IsNil)
	c.Check(pin, DeepEquals, MakePIN(4, []byte{0x04, 0xd2}))

	c.Check(pin.String(), Equals, "1234")
	c.Check(pin.Bytes(), DeepEquals, []byte{0xd7, 0x62})
}

func (s *pinSuite) TestPINZeroPaddedIsDifferent(c *C) {
	pin, err := ParsePIN("00001234")
	c.Assert(err, IsNil)
	c.Check(pin, DeepEquals, MakePIN(8, []byte{0x04, 0xd2}))

	c.Check(pin.String(), Equals, "00001234")
	c.Check(pin.Bytes(), DeepEquals, []byte{0xaf, 0xd7, 0xcb, 0x52})
}

func (s *pinSuite) TestPIN2(c *C) {
	pin, err := ParsePIN("12345678")
	c.Assert(err, IsNil)
	c.Check(pin, DeepEquals, MakePIN(8, []byte{0xbc, 0x61, 0x4e}))

	c.Check(pin.String(), Equals, "12345678")
	c.Check(pin.Bytes(), DeepEquals, []byte{0xb5, 0xc9, 0x84, 0x4e})
}

func (s *pinSuite) TestPIN3(c *C) {
	pin, err := ParsePIN("00000000")
	c.Assert(err, IsNil)
	c.Check(pin, DeepEquals, MakePIN(8, []byte{}))

	c.Check(pin.String(), Equals, "00000000")
	c.Check(pin.Bytes(), DeepEquals, []byte{0xaf, 0xd7, 0xc2, 0x00})
}

func (s *pinSuite) TestPIN4(c *C) {
	pin, err := ParsePIN("99999999")
	c.Assert(err, IsNil)
	c.Check(pin, DeepEquals, MakePIN(8, []byte{0x05, 0xf5, 0xe0, 0xff}))

	c.Check(pin.String(), Equals, "99999999")
	c.Check(pin.Bytes(), DeepEquals, []byte{0xdf, 0xaf, 0x83, 0x7f})
}

func (s *pinSuite) TestPIN5(c *C) {
	pin, err := ParsePIN("246813")
	c.Assert(err, IsNil)
	c.Check(pin, DeepEquals, MakePIN(6, []byte{0x03, 0xc4, 0x1d}))

	c.Check(pin.String(), Equals, "246813")
	c.Check(pin.Bytes(), DeepEquals, []byte{0xcc, 0x8c, 0x5d})
}

func (s *pinSuite) TestPIN6(c *C) {
	pin, err := ParsePIN("100000000")
	c.Assert(err, IsNil)
	c.Check(pin, DeepEquals, MakePIN(9, []byte{0x05, 0xf5, 0xe1, 0x00}))

	c.Check(pin.String(), Equals, "100000000")
	c.Check(pin.Bytes(), DeepEquals, []byte{0x84, 0x8c, 0xc2, 0xd6, 0x00})
}

func (s *pinSuite) TestPINZeroLength(c *C) {
	_, err := ParsePIN("")
	c.Check(err, ErrorMatches, `invalid PIN: zero length`)
}

func (s *pinSuite) TestPINTooLong(c *C) {
	_, err := ParsePIN("12345678901234567890123456789012345678901234567890123456789012345678901234567890" +
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890" +
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890" +
		"12345678901234567")
	c.Check(err, ErrorMatches, `invalid PIN: too long`)
}

func (s *pinSuite) TestPINInvalidChars(c *C) {
	_, err := ParsePIN("1234abc")
	c.Check(err, ErrorMatches, `invalid PIN: unexpected character 'c'`)
}

func (s *pinSuite) TestPINStringError(c *C) {
	pin := MakePIN(8, []byte{0xff, 0xff, 0xff, 0xff})
	c.Check(func() { pin.String() }, PanicMatches, `PIN length and value inconsistent`)
}
