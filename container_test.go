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

package secboot_test

import (
	"context"
	"errors"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"
)

type containerSuite struct {
	snapd_testutil.BaseTest
	backend *mockStorageContainerBackend
}

func (s *containerSuite) SetUpTest(c *C) {
	s.backend = newMockStorageContainerBackend()
	RegisterStorageContainerBackend(mockStorageContainerType, s.backend)
	s.AddCleanup(func() { RegisterStorageContainerBackend(mockStorageContainerType, nil) })
}

var _ = Suite(&containerSuite{})

func (s *containerSuite) TestFindStorageContainer1(c *C) {
	expectedContainer := newMockStorageContainer("", "")
	s.backend.addContainer("/dev/sda1", expectedContainer)

	expectedCtx := context.Background()

	container, err := FindStorageContainer(expectedCtx, "/dev/sda1")
	c.Assert(err, IsNil)
	c.Assert(container, testutil.ConvertibleTo, &mockStorageContainerWithProbeContext{})
	c.Check(container.(interface{ probeContext() context.Context }).probeContext(), Equals, expectedCtx)
	c.Check(container.(*mockStorageContainerWithProbeContext).mockStorageContainer, Equals, expectedContainer)
}

func (s *containerSuite) TestFindStorageContainer2(c *C) {
	expectedContainer := newMockStorageContainer("", "")
	s.backend.addContainer("/dev/vdb2", expectedContainer)

	expectedCtx := context.Background()

	container, err := FindStorageContainer(expectedCtx, "/dev/vdb2")
	c.Assert(err, IsNil)
	c.Assert(container, testutil.ConvertibleTo, &mockStorageContainerWithProbeContext{})
	c.Check(container.(interface{ probeContext() context.Context }).probeContext(), Equals, expectedCtx)
	c.Check(container.(*mockStorageContainerWithProbeContext).mockStorageContainer, Equals, expectedContainer)
}

func (s *containerSuite) TestFindStorageContainerNotFound(c *C) {
	_, err := FindStorageContainer(context.Background(), "/dev/sda1")
	c.Check(err, Equals, ErrNoStorageContainer)
}

func (s *containerSuite) TestFindStorageContainerNotFoundWithMultipleBackends(c *C) {
	RegisterStorageContainerBackend("foo", new(mockStorageContainerBackend))
	defer RegisterStorageContainerBackend("foo", nil)

	_, err := FindStorageContainer(context.Background(), "/dev/sda1")
	c.Check(err, Equals, ErrNoStorageContainer)
}

func (s *containerSuite) TestFindStorageContainerProbeError1(c *C) {
	expectedErr := errors.New("some error")
	s.backend.setProbeErr(expectedErr)

	_, err := FindStorageContainer(context.Background(), "/dev/sda1")
	c.Check(err, ErrorMatches, `cannot probe "mock" backend for path "\/dev\/sda1": some error`)
	c.Check(errors.Is(err, expectedErr), testutil.IsTrue)
}

func (s *containerSuite) TestFindStorageContainerProbeError2(c *C) {
	otherBackend := newMockStorageContainerBackend()
	expectedErr := errors.New("some error")
	otherBackend.setProbeErr(expectedErr)
	RegisterStorageContainerBackend("foo", otherBackend)
	defer RegisterStorageContainerBackend("foo", nil)

	_, err := FindStorageContainer(context.Background(), "/dev/sdb2")
	c.Check(err, ErrorMatches, `cannot probe "foo" backend for path "\/dev\/sdb2": some error`)
	c.Check(errors.Is(err, expectedErr), testutil.IsTrue)
}

func (s *containerSuite) TestFindActivatedStorageContainer1(c *C) {
	expectedContainer := newMockStorageContainer("", "")
	s.backend.addActivatedContainer("/dev/dm-1", expectedContainer)

	expectedCtx := context.Background()

	container, err := FindActivatedStorageContainer(expectedCtx, "/dev/dm-1")
	c.Assert(err, IsNil)
	c.Assert(container, testutil.ConvertibleTo, &mockStorageContainerWithProbeContext{})
	c.Check(container.(interface{ probeContext() context.Context }).probeContext(), Equals, expectedCtx)
	c.Check(container.(*mockStorageContainerWithProbeContext).mockStorageContainer, Equals, expectedContainer)
}

func (s *containerSuite) TestFindActivatedStorageContainer2(c *C) {
	expectedContainer := newMockStorageContainer("", "")
	s.backend.addActivatedContainer("/dev/dm-3", expectedContainer)

	expectedCtx := context.Background()

	container, err := FindActivatedStorageContainer(expectedCtx, "/dev/dm-3")
	c.Assert(err, IsNil)
	c.Assert(container, testutil.ConvertibleTo, &mockStorageContainerWithProbeContext{})
	c.Check(container.(interface{ probeContext() context.Context }).probeContext(), Equals, expectedCtx)
	c.Check(container.(*mockStorageContainerWithProbeContext).mockStorageContainer, Equals, expectedContainer)
}

func (s *containerSuite) TestFindActivatedStorageContainerNotFound(c *C) {
	_, err := FindActivatedStorageContainer(context.Background(), "/dev/dm-1")
	c.Check(err, Equals, ErrNoStorageContainer)
}

func (s *containerSuite) TestFindActivatedStorageContainerNotFoundWithMultipleBackends(c *C) {
	RegisterStorageContainerBackend("foo", new(mockStorageContainerBackend))
	defer RegisterStorageContainerBackend("foo", nil)

	_, err := FindActivatedStorageContainer(context.Background(), "/dev/dm-1")
	c.Check(err, Equals, ErrNoStorageContainer)
}

func (s *containerSuite) TestFindActivatedStorageContainerProbeError1(c *C) {
	expectedErr := errors.New("some error")
	s.backend.setProbeActivatedErr(expectedErr)

	_, err := FindActivatedStorageContainer(context.Background(), "/dev/dm-1")
	c.Check(err, ErrorMatches, `cannot probe "mock" backend for path "\/dev\/dm-1": some error`)
	c.Check(errors.Is(err, expectedErr), testutil.IsTrue)
}

func (s *containerSuite) TestFindActivatedStorageContainerProbeError2(c *C) {
	otherBackend := newMockStorageContainerBackend()
	expectedErr := errors.New("some error")
	otherBackend.setProbeActivatedErr(expectedErr)
	RegisterStorageContainerBackend("foo", otherBackend)
	defer RegisterStorageContainerBackend("foo", nil)

	_, err := FindActivatedStorageContainer(context.Background(), "/dev/dm-1")
	c.Check(err, ErrorMatches, `cannot probe "foo" backend for path "\/dev\/dm-1": some error`)
	c.Check(errors.Is(err, expectedErr), testutil.IsTrue)
}
