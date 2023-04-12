// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package efi_test

import (
	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
)

type envSuite struct{}

var _ = Suite(&envSuite{})

func (s *envSuite) TestRootVarReaderReadVar(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "SecureBoot", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess},
	}, nil)

	reader := NewRootVarReader(env)

	data, attrs, err := reader.ReadVar("SecureBoot", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{1})
	c.Check(attrs, Equals, efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
}

func (s *envSuite) TestRootVarReaderApplyOneUpdate(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(NewVarUpdate(nil, efi.VariableDescriptor{Name: "foo", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}))

	data, attrs, err := reader.ReadVar("foo", testGuid1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{2})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)
}

func (s *envSuite) TestRootVarReaderApplyMultipleUpdates(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(
		NewVarUpdate(
			NewVarUpdate(nil, efi.VariableDescriptor{Name: "bar", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}),
			efi.VariableDescriptor{Name: "foo", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}))

	data, attrs, err := reader.ReadVar("foo", testGuid1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{2})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)

	data, attrs, err = reader.ReadVar("bar", testGuid1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{5})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)
}

func (s *envSuite) TestRootVarReaderApplyUpdatesOrdering(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(
		NewVarUpdate(
			NewVarUpdate(nil, efi.VariableDescriptor{Name: "foo", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}),
			efi.VariableDescriptor{Name: "foo", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{3}))

	data, attrs, err := reader.ReadVar("foo", testGuid1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{3})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)
}

func (s *envSuite) TestRootVarReaderKey(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	c.Check(reader.Key(), DeepEquals, RootVarReaderKey{})
}

func (s *envSuite) TestRootVarReaderKeyWithOneUpdate(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(NewVarUpdate(nil, efi.VariableDescriptor{Name: "foo", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}))

	var expected RootVarReaderKey
	copy(expected[:], testutil.DecodeHexString(c, "af83642902c9f89dc8f761bb03a29bae54cc648e"))
	c.Check(reader.Key(), DeepEquals, expected)
}

func (s *envSuite) TestRootVarReaderKeyWithMultipleUpdates(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(
		NewVarUpdate(
			NewVarUpdate(nil, efi.VariableDescriptor{Name: "bar", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}),
			efi.VariableDescriptor{Name: "foo", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}))

	var expected RootVarReaderKey
	copy(expected[:], testutil.DecodeHexString(c, "d9d3425d3e48666ff1ffc66d211b4bbe2dc654ae"))
	c.Check(reader.Key(), DeepEquals, expected)
}

func (s *envSuite) TestRootVarReaderKeyOmitsUnchanged(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(NewVarUpdate(nil, efi.VariableDescriptor{Name: "foo", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{1}))

	c.Check(reader.Key(), DeepEquals, RootVarReaderKey{})
}

func (s *envSuite) TestRootVarReaderCopy(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(
		NewVarUpdate(
			NewVarUpdate(nil, efi.VariableDescriptor{Name: "bar", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}),
			efi.VariableDescriptor{Name: "foo", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}))

	reader2 := reader.Copy()
	c.Check(reader2, DeepEquals, reader)

	// Make sure modifying one doesn't affect the other
	reader.ApplyUpdates(NewVarUpdate(nil, efi.VariableDescriptor{Name: "foo", GUID: testGuid1}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{10}))

	data, attrs, err := reader2.ReadVar("foo", testGuid1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{2})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)

	data, attrs, err = reader2.ReadVar("bar", testGuid1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{5})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)
}

type testRootVarsCollectorData struct {
	env HostEnvironment

	// expected are the variable values to test for each starting state. These
	// are tested before the state is then mutated by mutatorFns.
	expected []map[efi.VariableDescriptor]*mockEFIVar

	// peekTotal is the expected number of starting states returned from
	// PeekAll.
	peekTotal []int

	// mutatorFns is called for each starting state to apply updates to it, which
	// may involve creating branches from it (by copying the supplied varBranch).
	// These updates may create new starting states which must be consumed by
	// setting states to an appropriate value.
	mutatorFns []func(root *VarBranch)
}

func (s *envSuite) testRootVarsCollector(c *C, data *testRootVarsCollectorData) {
	collector := NewRootVarsCollector(data.env)
	c.Assert(collector, NotNil)

	for i, expected := range data.expected {
		c.Assert(collector.More(), testutil.IsTrue)

		c.Check(collector.PeekAll(), HasLen, data.peekTotal[i])

		root := collector.Next()
		c.Assert(root, NotNil)

		for k, v := range expected {
			b, attrs, err := root.ReadVar(k.Name, k.GUID)
			if v == nil {
				c.Check(err, Equals, efi.ErrVarNotExist)
			} else {
				c.Check(b, DeepEquals, v.data)
				c.Check(attrs, Equals, v.attrs)
			}
		}

		if i >= len(data.mutatorFns) || data.mutatorFns[i] == nil {
			continue
		}
		data.mutatorFns[i](root)
	}

	c.Check(collector.More(), testutil.IsFalse)
}

func (s *envSuite) TestRootVarsCollectorWriteOne(c *C) {
	// Test that one write in the initial state works and creates one new starting state
	s.testRootVarsCollector(c, &testRootVarsCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		peekTotal: []int{1, 1},
		mutatorFns: []func(*VarBranch){
			func(vars *VarBranch) {
				c.Check(vars.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)
			},
		},
	})
}

func (s *envSuite) TestRootVarsCollectorWriteOneNew(c *C) {
	// Test that one write in the initial state works and creates one new starting state
	s.testRootVarsCollector(c, &testRootVarsCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: testGuid1}: nil,
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		peekTotal: []int{1, 1},
		mutatorFns: []func(*VarBranch){
			func(vars *VarBranch) {
				c.Check(vars.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)
			},
		},
	})
}

func (s *envSuite) TestRootVarsCollectorWriteOneNoChange(c *C) {
	// Test that one write in the initial state that makes no change is ignored
	s.testRootVarsCollector(c, &testRootVarsCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		peekTotal: []int{1},
		mutatorFns: []func(*VarBranch){
			func(vars *VarBranch) {
				c.Check(vars.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{1}), IsNil)
			},
		},
	})
}

func (s *envSuite) TestRootVarsCollectorWriteTwo(c *C) {
	// Test that two writes in the initial state works and creates two new starting states
	s.testRootVarsCollector(c, &testRootVarsCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		peekTotal: []int{1, 2, 1},
		mutatorFns: []func(*VarBranch){
			func(vars *VarBranch) {
				c.Check(vars.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)
				c.Check(vars.WriteVar("bar", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}), IsNil)
			},
		},
	})
}

func (s *envSuite) TestRootVarsCollectorShouldDedup1(c *C) {
	// Test that duplicate branches in the initial state are de-duplicated
	s.testRootVarsCollector(c, &testRootVarsCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		peekTotal: []int{1, 2, 1},
		mutatorFns: []func(*VarBranch){
			func(vars *VarBranch) {
				vars1 := *vars
				c.Check(vars1.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)
				c.Check(vars1.WriteVar("bar", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}), IsNil)
				vars2 := *vars
				c.Check(vars2.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)
				c.Check(vars2.WriteVar("bar", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}), IsNil)
			},
		},
	})
}

func (s *envSuite) TestRootVarsCollectorShouldDedup2(c *C) {
	// Test that duplicate branches in the initial state are de-duplicated
	s.testRootVarsCollector(c, &testRootVarsCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		peekTotal: []int{1, 2, 1},
		mutatorFns: []func(*VarBranch){
			func(vars *VarBranch) {
				c.Check(vars.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)

				vars1 := *vars
				c.Check(vars1.WriteVar("bar", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}), IsNil)

				vars2 := *vars
				c.Check(vars2.WriteVar("bar", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}), IsNil)
			},
		},
	})
}

func (s *envSuite) TestRootVarsCollectorShouldntDedup1(c *C) {
	// Test that non-duplicate branches in the initial state are not de-duplicated
	s.testRootVarsCollector(c, &testRootVarsCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		peekTotal: []int{1, 3, 2, 1},
		mutatorFns: []func(*VarBranch){
			func(vars *VarBranch) {
				vars1 := *vars
				c.Check(vars1.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)
				c.Check(vars1.WriteVar("bar", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}), IsNil)

				vars2 := *vars
				c.Check(vars2.WriteVar("bar", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}), IsNil)
				c.Check(vars2.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)
			},
		},
	})
}

func (s *envSuite) TestRootVarsCollectorShouldntDedup2(c *C) {
	// Test that non-duplicate branches in the initial state are not de-duplicated
	s.testRootVarsCollector(c, &testRootVarsCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: testGuid1}: {data: []byte{4}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		peekTotal: []int{1, 3, 2, 1},
		mutatorFns: []func(*VarBranch){
			func(vars *VarBranch) {
				c.Check(vars.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)

				vars1 := *vars
				c.Check(vars1.WriteVar("bar", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}), IsNil)

				vars2 := *vars
				c.Check(vars2.WriteVar("bar", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{4}), IsNil)
			},
		},
	})
}

func (s *envSuite) TestRootVarsCollectorWriteToSecondState(c *C) {
	// Test that one write in the second state works and creates one new starting state
	s.testRootVarsCollector(c, &testRootVarsCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{3}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		peekTotal: []int{1, 1, 1},
		mutatorFns: []func(*VarBranch){
			func(vars *VarBranch) {
				c.Check(vars.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)
			},
			func(vars *VarBranch) {
				c.Check(vars.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{3}), IsNil)
			},
		},
	})
}

func (s *envSuite) TestRootVarsCollectorWriteToSecondStateDedup(c *C) {
	// Test that one write in the second state that reverts to the initial state works and is de-duplicated
	s.testRootVarsCollector(c, &testRootVarsCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: testGuid1}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		peekTotal: []int{1, 1},
		mutatorFns: []func(*VarBranch){
			func(vars *VarBranch) {
				c.Check(vars.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}), IsNil)
			},
			func(vars *VarBranch) {
				c.Check(vars.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{1}), IsNil)
			},
		},
	})
}

func (s *envSuite) TestRootVarsCollectorPeekAll(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "SecureBoot", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess},
	}, nil)

	collector := NewRootVarsCollector(env)
	c.Assert(collector, NotNil)

	roots := collector.PeekAll()
	c.Check(roots, HasLen, 1)

	c.Check(roots[0].WriteVar("SecureBoot", efi.GlobalVariable, efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess, []byte{0}), IsNil)

	roots = collector.PeekAll()
	c.Check(roots, HasLen, 2)

	data, attrs, err := roots[0].ReadVar("SecureBoot", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{1})
	c.Check(attrs, Equals, efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)

	data, attrs, err = roots[1].ReadVar("SecureBoot", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{0})
	c.Check(attrs, Equals, efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)

	collector.Next()
	c.Check(collector.PeekAll(), HasLen, 1)
}

func (s *envSuite) TestVarBranchReadsUpdate(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{}, nil)

	collector := NewRootVarsCollector(env)
	root := collector.Next()

	c.Check(root.WriteVar("foo", testGuid1, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{1}), IsNil)

	data, attrs, err := root.ReadVar("foo", testGuid1)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{1})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)
}
