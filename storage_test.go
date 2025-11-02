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

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
)

const mockStorageContainerType = "mock"

type mockStorageContainerWithProbeContext struct {
	backendProbeCtx context.Context
	*mockStorageContainer
}

func (c *mockStorageContainerWithProbeContext) probeContext() context.Context {
	return c.backendProbeCtx
}

type mockStorageContainerBackend struct {
	containers          map[string]*mockStorageContainer
	activatedContainers map[string]*mockStorageContainer
	probeErr            error
	probeActivatedErr   error
}

func newMockStorageContainerBackend() *mockStorageContainerBackend {
	return &mockStorageContainerBackend{
		containers:          make(map[string]*mockStorageContainer),
		activatedContainers: make(map[string]*mockStorageContainer),
	}
}

func (b *mockStorageContainerBackend) addContainer(path string, container *mockStorageContainer) {
	if container == nil {
		delete(b.containers, path)
		return
	}
	b.containers[path] = container
}

func (b *mockStorageContainerBackend) deleteContainer(path string) {
	delete(b.containers, path)
}

func (b *mockStorageContainerBackend) setProbeErr(err error) {
	b.probeErr = err
}

func (b *mockStorageContainerBackend) activatedContainer(c *C, path string) *mockStorageContainer {
	container, exists := b.activatedContainers[path]
	c.Assert(exists, testutil.IsTrue)
	return container
}

func (b *mockStorageContainerBackend) addActivatedContainer(path string, container *mockStorageContainer) {
	if container == nil {
		delete(b.activatedContainers, path)
		return
	}
	b.activatedContainers[path] = container
}

func (b *mockStorageContainerBackend) deleteActivatedContainer(path string) {
	delete(b.activatedContainers, path)
}

func (b *mockStorageContainerBackend) setProbeActivatedErr(err error) {
	b.probeActivatedErr = err
}

func (b *mockStorageContainerBackend) Probe(ctx context.Context, path string) (StorageContainer, error) {
	if b.probeErr != nil {
		return nil, b.probeErr
	}

	container, exists := b.containers[path]
	if !exists {
		return nil, nil
	}
	return &mockStorageContainerWithProbeContext{
		backendProbeCtx:      ctx,
		mockStorageContainer: container,
	}, nil
}

func (b *mockStorageContainerBackend) ProbeActivated(ctx context.Context, path string) (StorageContainer, error) {
	if b.probeActivatedErr != nil {
		return nil, b.probeActivatedErr
	}

	container, exists := b.activatedContainers[path]
	if !exists {
		return nil, nil
	}
	return &mockStorageContainerWithProbeContext{
		backendProbeCtx:      ctx,
		mockStorageContainer: container,
	}, nil
}

type storageSuite struct{}

var _ = Suite(&storageSuite{})

func (*storageSuite) TestRegisterStorageContainerBackend(c *C) {
	_, exists := StorageContainerHandlers["foo"]
	c.Check(exists, testutil.IsFalse)

	expectedBackend := new(mockStorageContainerBackend)
	RegisterStorageContainerBackend("foo", expectedBackend)
	defer RegisterStorageContainerBackend("foo", nil)

	backend, exists := StorageContainerHandlers["foo"]
	c.Assert(exists, testutil.IsTrue)
	c.Check(backend, Equals, expectedBackend)

	RegisterStorageContainerBackend("foo", nil)

	_, exists = StorageContainerHandlers["foo"]
	c.Check(exists, testutil.IsFalse)
}
