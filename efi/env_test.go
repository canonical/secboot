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
		{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(NewVarUpdate(nil, efi.VariableDescriptor{Name: "foo", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}))

	data, attrs, err := reader.ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{2})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)
}

func (s *envSuite) TestRootVarReaderApplyMultipleUpdates(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(
		NewVarUpdate(
			NewVarUpdate(nil, efi.VariableDescriptor{Name: "bar", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}),
			efi.VariableDescriptor{Name: "foo", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}))

	data, attrs, err := reader.ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{2})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)

	data, attrs, err = reader.ReadVar("bar", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{5})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)
}

func (s *envSuite) TestRootVarReaderApplyUpdatesOrdering(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(
		NewVarUpdate(
			NewVarUpdate(nil, efi.VariableDescriptor{Name: "foo", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}),
			efi.VariableDescriptor{Name: "foo", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{3}))

	data, attrs, err := reader.ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{3})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)
}

func (s *envSuite) TestRootVarReaderKey(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	c.Check(reader.Key(), DeepEquals, RootVarReaderKey{})
}

func (s *envSuite) TestRootVarReaderKeyWithOneUpdate(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(NewVarUpdate(nil, efi.VariableDescriptor{Name: "foo", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}))

	var expected RootVarReaderKey
	copy(expected[:], testutil.DecodeHexString(c, "8077e484b66e7e94c7c1d55021ea8b5db62596e5"))
	c.Check(reader.Key(), DeepEquals, expected)
}

func (s *envSuite) TestRootVarReaderKeyWithMultipleUpdates(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(
		NewVarUpdate(
			NewVarUpdate(nil, efi.VariableDescriptor{Name: "bar", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}),
			efi.VariableDescriptor{Name: "foo", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}))

	var expected RootVarReaderKey
	copy(expected[:], testutil.DecodeHexString(c, "8ec0b80e0eef01a152af83a8addcc0a955ad6e03"))
	c.Check(reader.Key(), DeepEquals, expected)
}

func (s *envSuite) TestRootVarReaderKeyOmitsUnchanged(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(NewVarUpdate(nil, efi.VariableDescriptor{Name: "foo", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{1}))

	c.Check(reader.Key(), DeepEquals, RootVarReaderKey{})
}

func (s *envSuite) TestRootVarReaderCopy(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
	}, nil)

	reader := NewRootVarReader(env)
	reader.ApplyUpdates(
		NewVarUpdate(
			NewVarUpdate(nil, efi.VariableDescriptor{Name: "bar", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5}),
			efi.VariableDescriptor{Name: "foo", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2}))

	reader2 := reader.Copy()
	c.Check(reader2, DeepEquals, reader)

	// Make sure modifying one doesn't affect the other
	reader.ApplyUpdates(NewVarUpdate(nil, efi.VariableDescriptor{Name: "foo", GUID: efi.GlobalVariable}, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{10}))

	data, attrs, err := reader2.ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{2})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)

	data, attrs, err = reader2.ReadVar("bar", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{5})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)
}

func (s *envSuite) TestStartingVarStateCollectorRoot(c *C) {
	// Test that we can read an unmodified variable from the host environment
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
		{Name: "SecureBoot", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess},
	}, nil)

	collector := NewRootVarsCollector(env)
	c.Assert(collector, NotNil)

	root := collector.Root()
	c.Assert(root, NotNil)

	data, attrs, err := root.ReadVar("SecureBoot", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{1})
	c.Check(attrs, Equals, efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
}

type testStartingVarStateCollectorData struct {
	env HostEnvironment

	states     int
	expected   []map[efi.VariableDescriptor]*mockEFIVar
	handlerFns []func(root *VarBranchState)
}

func (s *envSuite) testStartingVarStateCollector(c *C, data *testStartingVarStateCollectorData) {
	collector := NewRootVarsCollector(data.env)
	c.Assert(collector, NotNil)

	for i, expected := range data.expected {
		c.Assert(collector.More(), testutil.IsTrue)

		root := collector.Next()
		c.Assert(root, NotNil)

		state := NewVarBranchState(root, collector)

		for k, v := range expected {
			b, attrs, err := state.ReadVar(k.Name, k.GUID)
			if v == nil {
				c.Check(err, Equals, efi.ErrVarNotExist)
			} else {
				c.Check(b, DeepEquals, v.data)
				c.Check(attrs, Equals, v.attrs)
			}
		}

		if i >= len(data.handlerFns) || data.handlerFns[i] == nil {
			continue
		}
		data.handlerFns[i](state)
	}

	c.Check(collector.More(), testutil.IsFalse)
	c.Check(collector.Err(), IsNil)
}

func (s *envSuite) TestStartingVarStateCollectorWriteOne(c *C) {
	// Test that one write in the initial state works and creates one new starting state
	s.testStartingVarStateCollector(c, &testStartingVarStateCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		handlerFns: []func(*VarBranchState){
			func(state *VarBranchState) {
				state.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})
			},
		},
	})
}

func (s *envSuite) TestStartingVarStateCollectorWriteOneNew(c *C) {
	// Test that one write in the initial state works and creates one new starting state
	s.testStartingVarStateCollector(c, &testStartingVarStateCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: efi.GlobalVariable}: nil,
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		handlerFns: []func(*VarBranchState){
			func(state *VarBranchState) {
				state.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})
			},
		},
	})
}

func (s *envSuite) TestStartingVarStateCollectorWriteOneNoChange(c *C) {
	// Test that one write in the initial state that makes no change is ignored
	s.testStartingVarStateCollector(c, &testStartingVarStateCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		handlerFns: []func(*VarBranchState){
			func(state *VarBranchState) {
				state.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{1})
			},
		},
	})
}

func (s *envSuite) TestStartingVarStateCollectorWriteTwo(c *C) {
	// Test that two writes in the initial state works and creates two new starting states
	s.testStartingVarStateCollector(c, &testStartingVarStateCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		handlerFns: []func(*VarBranchState){
			func(state *VarBranchState) {
				state.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})
				state.WriteVar("bar", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5})
			},
		},
	})
}

func (s *envSuite) TestStartingVarStateCollectorShouldDedup1(c *C) {
	// Test that duplicate branches in the initial state are de-duplicated
	s.testStartingVarStateCollector(c, &testStartingVarStateCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		handlerFns: []func(*VarBranchState){
			func(state *VarBranchState) {
				state1 := *state
				state1.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})
				state1.WriteVar("bar", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5})
				state2 := *state
				state2.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})
				state2.WriteVar("bar", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5})
			},
		},
	})
}

func (s *envSuite) TestStartingVarStateCollectorShouldDedup2(c *C) {
	// Test that duplicate branches in the initial state are de-duplicated
	s.testStartingVarStateCollector(c, &testStartingVarStateCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		handlerFns: []func(*VarBranchState){
			func(state *VarBranchState) {
				state.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})

				state1 := *state
				state1.WriteVar("bar", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5})

				state2 := *state
				state2.WriteVar("bar", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5})
			},
		},
	})
}

func (s *envSuite) TestStartingVarStateCollectorShouldntDedup1(c *C) {
	// Test that non-duplicate branches in the initial state are not de-duplicated
	s.testStartingVarStateCollector(c, &testStartingVarStateCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		handlerFns: []func(*VarBranchState){
			func(state *VarBranchState) {
				state1 := *state
				state1.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})
				state1.WriteVar("bar", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5})

				state2 := *state
				state2.WriteVar("bar", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5})
				state2.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})
			},
		},
	})
}

func (s *envSuite) TestStartingVarStateCollectorShouldntDedup2(c *C) {
	// Test that non-duplicate branches in the initial state are not de-duplicated
	s.testStartingVarStateCollector(c, &testStartingVarStateCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{5}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
				{Name: "bar", GUID: efi.GlobalVariable}: {data: []byte{4}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		handlerFns: []func(*VarBranchState){
			func(state *VarBranchState) {
				state.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})

				state1 := *state
				state1.WriteVar("bar", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{5})

				state2 := *state
				state2.WriteVar("bar", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{4})
			},
		},
	})
}

func (s *envSuite) TestStartingVarStateCollectorWriteToSecondState(c *C) {
	// Test that one write in the second state works and creates one new starting state
	s.testStartingVarStateCollector(c, &testStartingVarStateCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{3}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		handlerFns: []func(*VarBranchState){
			func(state *VarBranchState) {
				state.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})
			},
			func(state *VarBranchState) {
				state.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{3})
			},
		},
	})
}

func (s *envSuite) TestStartingVarStateCollectorWriteToSecondStateDedup(c *C) {
	// Test that one write in the second state that reverts to the initial state works and is de-duplicated
	s.testStartingVarStateCollector(c, &testStartingVarStateCollectorData{
		env: newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{
			{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
		}, nil),
		expected: []map[efi.VariableDescriptor]*mockEFIVar{
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{1}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
			{
				{Name: "foo", GUID: efi.GlobalVariable}: {data: []byte{2}, attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess},
			},
		},
		handlerFns: []func(*VarBranchState){
			func(state *VarBranchState) {
				state.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{2})
			},
			func(state *VarBranchState) {
				state.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{1})
			},
		},
	})
}

func (s *envSuite) TestVarBranchStateReadsUpdate(c *C) {
	env := newMockEFIEnvironment(map[efi.VariableDescriptor]*mockEFIVar{}, nil)

	collector := NewRootVarsCollector(env)
	branch := NewVarBranchState(collector.Root(), collector)

	c.Check(branch.WriteVar("foo", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess, []byte{1}), IsNil)

	data, attrs, err := branch.ReadVar("foo", efi.GlobalVariable)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{1})
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess)
}
