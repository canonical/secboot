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
	"bytes"
	"context"
	"errors"
	"sort"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"
)

type mockKeyslotData struct {
	key []byte

	slotType KeyslotType
	priority int
	data     []byte
}

func newMockKeyslotData(key []byte, slotType KeyslotType, priority int, data []byte) *mockKeyslotData {
	return &mockKeyslotData{
		key:      key,
		slotType: slotType,
		priority: priority,
		data:     data,
	}
}

type mockStorageContainerReaderOption = func(*mockStorageContainerReader)

func withStorageContainerReaderExpectedContext(ctx context.Context) mockStorageContainerReaderOption {
	return func(r *mockStorageContainerReader) {
		r.expectedCtx = ctx
	}
}

func withStorageContainerReaderCloseErr(err error) mockStorageContainerReaderOption {
	return func(r *mockStorageContainerReader) {
		r.closeErr = err
	}
}

func withStorageContainerReaderListKeyslotNamesErr(err error) mockStorageContainerReaderOption {
	return func(r *mockStorageContainerReader) {
		r.listKeyslotNamesErr = err
	}
}

func withStorageContainerReaderReadKeyslotErr(name string, err error) mockStorageContainerReaderOption {
	return func(r *mockStorageContainerReader) {
		r.readKeyslotErrs[name] = err
	}
}

type mockKeyslot struct {
	slotType KeyslotType
	name     string
	priority int
	data     KeyDataReader
}

func (s *mockKeyslot) Type() KeyslotType {
	return s.slotType
}

func (s *mockKeyslot) Name() string {
	return s.name
}

func (s *mockKeyslot) Priority() int {
	return s.priority
}

func (s *mockKeyslot) Data() KeyDataReader {
	return s.data
}

type mockStorageContainerReader struct {
	container *mockStorageContainer
	closed    bool

	expectedCtx context.Context

	closeErr            error
	listKeyslotNamesErr error
	readKeyslotErrs     map[string]error
}

func newMockStorageContainerReader(container *mockStorageContainer, opts ...mockStorageContainerReaderOption) *mockStorageContainerReader {
	r := &mockStorageContainerReader{
		container:       container,
		readKeyslotErrs: make(map[string]error),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *mockStorageContainerReader) checkContext(ctx context.Context) error {
	if r.expectedCtx != nil && ctx != r.expectedCtx {
		return errors.New("unexpected context")
	}
	return ctx.Err()
}

func (r *mockStorageContainerReader) Container() StorageContainer {
	return r.container
}

func (r *mockStorageContainerReader) Close() error {
	if r.closeErr != nil {
		return r.closeErr
	}
	if r.closed {
		return ErrStorageContainerClosed
	}
	r.closed = true
	r.container.nReaders -= 1
	return nil
}

func (r *mockStorageContainerReader) ListKeyslotNames(ctx context.Context) ([]string, error) {
	if err := r.checkContext(ctx); err != nil {
		return nil, err
	}
	if r.listKeyslotNamesErr != nil {
		return nil, r.listKeyslotNamesErr
	}
	if r.closed {
		return nil, ErrStorageContainerClosed
	}

	var keys []string
	for key := range r.container.slots {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys, nil
}

func (r *mockStorageContainerReader) ReadKeyslot(ctx context.Context, name string) (Keyslot, error) {
	if err := r.checkContext(ctx); err != nil {
		return nil, err
	}
	if err := r.readKeyslotErrs[name]; err != nil {
		return nil, err
	}
	if r.closed {
		return nil, ErrStorageContainerClosed
	}
	slot, exists := r.container.slots[name]
	if !exists {
		return nil, ErrKeyslotNotFound
	}

	return &mockKeyslot{
		slotType: slot.slotType,
		name:     name,
		priority: slot.priority,
		data:     &mockKeyDataReader{Reader: bytes.NewReader(slot.data)},
	}, nil
}

type mockStorageContainerOption = func(*mockStorageContainer)

func withStorageContainerPath(path string) mockStorageContainerOption {
	return func(c *mockStorageContainer) {
		c.path = path
	}
}

func withStorageContainerCredentialName(name string) mockStorageContainerOption {
	return func(c *mockStorageContainer) {
		c.credentialName = name
	}
}

func withStorageContainerActivated() mockStorageContainerOption {
	return func(c *mockStorageContainer) {
		c.activated = true
	}
}

func withStorageContainerKeyslot(name string, key []byte, slotType KeyslotType, priority int, data []byte) mockStorageContainerOption {
	return func(c *mockStorageContainer) {
		c.slots[name] = newMockKeyslotData(key, slotType, priority, data)
	}
}

func withStorageContainerExpectedContext(ctx context.Context) mockStorageContainerOption {
	return func(c *mockStorageContainer) {
		c.expectedCtx = ctx
	}
}

func withStorageContainerActivateErr(name string, err error) mockStorageContainerOption {
	return func(c *mockStorageContainer) {
		c.activateErrs[name] = err
	}
}

func withStorageContainerDeactivateErr(err error) mockStorageContainerOption {
	return func(c *mockStorageContainer) {
		c.deactivateErr = err
	}
}

func withStorageContainerOpenReadErr(err error) mockStorageContainerOption {
	return func(c *mockStorageContainer) {
		c.openReadErr = err
	}
}

func withStorageContainerReaderOptions(opts ...mockStorageContainerReaderOption) mockStorageContainerOption {
	return func(c *mockStorageContainer) {
		c.readerOpts = opts
	}
}

type mockStorageContainer struct {
	backend *mockStorageContainerBackend

	path           string
	credentialName string

	slots map[string]*mockKeyslotData

	expectedCtx context.Context

	activateErrs  map[string]error
	deactivateErr error

	openReadErr error
	readerOpts  []mockStorageContainerReaderOption

	activated        bool
	activationKey    DiskUnlockKey
	activationConfig ActivateConfigGetter
	tryKeys          [][]byte

	nReaders int
}

func newMockStorageContainer(opts ...mockStorageContainerOption) *mockStorageContainer {
	c := &mockStorageContainer{
		slots:        make(map[string]*mockKeyslotData),
		activateErrs: make(map[string]error),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *mockStorageContainer) activateTryKeys() [][]byte {
	return c.tryKeys
}

func (c *mockStorageContainer) isActivated() bool {
	return c.activated
}

func (ct *mockStorageContainer) activationParams(c *C) (key DiskUnlockKey, cfg ActivateConfigGetter) {
	c.Assert(ct.activated, testutil.IsTrue)
	return ct.activationKey, ct.activationConfig
}

func (c *mockStorageContainer) checkContext(ctx context.Context) error {
	if c.expectedCtx != nil && ctx != c.expectedCtx {
		return errors.New("unexpected context")
	}
	return ctx.Err()
}

func (c *mockStorageContainer) Path() string {
	return c.path
}

func (c *mockStorageContainer) CredentialName() string {
	return c.credentialName
}

func (c *mockStorageContainer) BackendName() string {
	return mockStorageContainerType
}

func (c *mockStorageContainer) Activate(ctx context.Context, keyslot Keyslot, key []byte, cfg ActivateConfigGetter) error {
	if err := c.checkContext(ctx); err != nil {
		return err
	}
	if err := c.activateErrs[keyslot.Name()]; err != nil {
		return err
	}
	if c.activated {
		return errors.New("already activated")
	}

	c.activationConfig = cfg
	c.tryKeys = append(c.tryKeys, key)

	switch slot := keyslot.(type) {
	case *mockKeyslot:
		data, exists := c.slots[slot.Name()]
		if !exists {
			return errors.New("invalid keyslot")
		}
		if bytes.Equal(key, data.key) {
			c.activated = true
		}
	default:
		for _, data := range c.slots {
			if bytes.Equal(key, data.key) {
				c.activated = true
				break
			}
		}
	}

	if !c.activated {
		return errors.New("invalid key")
	}

	c.activationKey = key

	return nil
}

func (c *mockStorageContainer) Deactivate(ctx context.Context) error {
	if err := c.checkContext(ctx); err != nil {
		return err
	}
	if c.deactivateErr != nil {
		return c.deactivateErr
	}
	if !c.activated {
		return ErrStorageContainerNotActive
	}
	c.activated = false
	return nil
}

func (c *mockStorageContainer) OpenRead(ctx context.Context) (StorageContainerReader, error) {
	if err := c.checkContext(ctx); err != nil {
		return nil, err
	}
	if c.openReadErr != nil {
		return nil, c.openReadErr
	}
	return newMockStorageContainerReader(c, c.readerOpts...), nil
}

type containerSuite struct {
	snapd_testutil.BaseTest
	backend *mockStorageContainerBackend
}

func (s *containerSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.backend = newMockStorageContainerBackend()
	RegisterStorageContainerBackend(mockStorageContainerType, s.backend)
	s.AddCleanup(func() { RegisterStorageContainerBackend(mockStorageContainerType, nil) })
}

var _ = Suite(&containerSuite{})

func (s *containerSuite) TestFindStorageContainer1(c *C) {
	expectedContainer := newMockStorageContainer()
	s.backend.addContainer("/dev/sda1", expectedContainer)

	expectedCtx := context.Background()

	container, err := FindStorageContainer(expectedCtx, "/dev/sda1")
	c.Assert(err, IsNil)
	c.Assert(container, testutil.ConvertibleTo, &mockStorageContainerWithProbeContext{})
	c.Check(container.(interface{ probeContext() context.Context }).probeContext(), Equals, expectedCtx)
	c.Check(container.(*mockStorageContainerWithProbeContext).mockStorageContainer, Equals, expectedContainer)
}

func (s *containerSuite) TestFindStorageContainer2(c *C) {
	expectedContainer := newMockStorageContainer()
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
	expectedContainer := newMockStorageContainer()
	s.backend.addActivatedContainer("/dev/dm-1", expectedContainer)

	expectedCtx := context.Background()

	container, err := FindActivatedStorageContainer(expectedCtx, "/dev/dm-1")
	c.Assert(err, IsNil)
	c.Assert(container, testutil.ConvertibleTo, &mockStorageContainerWithProbeContext{})
	c.Check(container.(interface{ probeContext() context.Context }).probeContext(), Equals, expectedCtx)
	c.Check(container.(*mockStorageContainerWithProbeContext).mockStorageContainer, Equals, expectedContainer)
}

func (s *containerSuite) TestFindActivatedStorageContainer2(c *C) {
	expectedContainer := newMockStorageContainer()
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
