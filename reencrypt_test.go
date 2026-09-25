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

package secboot_test

import (
	"context"
	"errors"
	"github.com/snapcore/secboot"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	. "gopkg.in/check.v1"
)

type reencryptSuite struct {
	snapd_testutil.BaseTest
	backend *mockStorageContainerBackend
}

// mockReencryption implements [secboot.Reencryption]
type mockReencryption struct {
	name string
}

func (r *mockReencryption) Status() (*secboot.ReencryptionStatus, error) {
	return nil, errors.New("not implemented")
}

func (r *mockReencryption) Initialize(ctx context.Context, unlockKeys map[string][]byte) error {
	return errors.New("not implemented")
}

func (r *mockReencryption) Resume(ctx context.Context, unlockKey []byte) (<-chan secboot.ReencryptionProgressEvent, error) {
	return nil, errors.New("not implemented")
}

func (s *reencryptSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.backend = newMockStorageContainerBackend()
	secboot.RegisterStorageContainerBackend("backend-mock-1", s.backend)
	s.AddCleanup(func() { secboot.RegisterStorageContainerBackend("backend-mock-1", nil) })
}

var _ = Suite(&reencryptSuite{})

func (s *reencryptSuite) TestReencryptionStatus(c *C) {
	status := secboot.ReencryptionStatusNone
	c.Check(status.String(), Equals, "none")

	status = secboot.ReencryptionStatusInitialized
	c.Check(status.String(), Equals, "initialized")
}

func (s *reencryptSuite) TestReencryptionProgressEventType(c *C) {
	eventType := secboot.ReencryptionProgressStarted
	c.Check(eventType.String(), Equals, "started")

	eventType = secboot.ReencryptionProgressRunning
	c.Check(eventType.String(), Equals, "running")

	eventType = secboot.ReencryptionProgressCompleted
	c.Check(eventType.String(), Equals, "completed")

	eventType = secboot.ReencryptionProgressError
	c.Check(eventType.String(), Equals, "error")
}

func (s *reencryptSuite) TestReencryptionForActiveVolume(c *C) {
	s.backend.addReencryption("active-name-1", &mockReencryption{name: "active-name-1"})
	defer s.backend.addReencryption("active-name-1", nil)

	reencryption, err := secboot.ReencryptionForActiveVolume("active-name-1")
	c.Assert(err, IsNil)
	c.Assert(reencryption, NotNil)
	c.Check(reencryption, DeepEquals, &mockReencryption{name: "active-name-1"})
}

func (s *reencryptSuite) TestReencryptionForActiveVolumeNotFound(c *C) {
	_, err := secboot.ReencryptionForActiveVolume("active-name-2")
	c.Check(err, Equals, secboot.ErrReencryptionNoBackend)
}

func (s *reencryptSuite) TestReencryptionForActiveVolumeWithMultipleBackends(c *C) {
	// Test that a backend that doesn't recognize the active name (ie,
	// returns (nil, nil)) doesn't prevent another backend that does
	// recognize it from returning an error.
	secboot.RegisterStorageContainerBackend("backend-mock-22", new(mockStorageContainerBackend))
	defer secboot.RegisterStorageContainerBackend("backend-mock-22", nil)

	s.backend.addReencryption("active-name-1", &mockReencryption{name: "active-name-1"})
	defer s.backend.addReencryption("active-name-1", nil)

	reencryption, err := secboot.ReencryptionForActiveVolume("active-name-1")
	c.Assert(err, IsNil)
	c.Assert(reencryption, NotNil)
	c.Check(reencryption, DeepEquals, &mockReencryption{name: "active-name-1"})
}

func (s *reencryptSuite) TestReencryptionForActiveVolumeError(c *C) {
	expectedErr := errors.New("some error")
	s.backend.setNewOnlineReencryptionErr(expectedErr)

	reencryption, err := secboot.ReencryptionForActiveVolume("active-name-x")
	c.Check(err, ErrorMatches, `cannot probe "backend-mock-1" backend for active name "active-name-x": some error`)
	c.Assert(reencryption, IsNil)
}
