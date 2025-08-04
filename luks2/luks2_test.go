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

package luks2_test

import (
	"bytes"
	"testing"

	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luksview"
	. "github.com/snapcore/secboot/luks2"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type mockLuks2KeyDataReader struct {
	name     string
	slot     int
	priority int
	*bytes.Reader
}

func newMockLuks2KeyDataReader(name string, slot, priority int, data []byte) *mockLuks2KeyDataReader {
	return &mockLuks2KeyDataReader{
		name:     name,
		slot:     slot,
		priority: priority,
		Reader:   bytes.NewReader(data),
	}
}

func (r *mockLuks2KeyDataReader) ReadableName() string {
	return r.name
}

func (r *mockLuks2KeyDataReader) KeyslotID() int {
	return r.slot
}

func (r *mockLuks2KeyDataReader) Priority() int {
	return r.priority
}

type mockContainerData struct {
	recoveryKeyslots map[string]int
	platformKeyslots map[string]Luks2KeyDataReader

	listUnlockKeyNamesErr   error
	listRecoveryKeyNamesErr error
	newKeyDataReaderErr     error
}

func newMockContainerData() *mockContainerData {
	return &mockContainerData{
		recoveryKeyslots: make(map[string]int),
		platformKeyslots: make(map[string]Luks2KeyDataReader),
	}
}

type mockToken struct {
	tokenType luks2.TokenType
	keyslot   int
	name      string
}

func (t *mockToken) Type() luks2.TokenType {
	return t.tokenType
}

func (t *mockToken) Keyslots() []int {
	return []int{t.keyslot}
}

func (t *mockToken) Name() string {
	return t.name
}

type mockLuksView struct {
	data *mockContainerData
}

func (v *mockLuksView) TokenByName(name string) (token luksview.NamedToken, id int, inUse bool) {
	id, exists := v.data.recoveryKeyslots[name]
	if exists {
		return &mockToken{
			tokenType: luksview.RecoveryTokenType,
			keyslot:   id,
			name:      name,
		}, 0, true // We return 0 for all token IDs because the test doesn't use it.
	}

	r, exists := v.data.platformKeyslots[name]
	if exists {
		return &mockToken{
			tokenType: luksview.KeyDataTokenType,
			keyslot:   r.KeyslotID(),
			name:      name,
		}, 0, true // We return 0 for all token IDs because the test doesn't use it.
	}

	return nil, 0, false
}

func newMockLuksView(data *mockContainerData) LuksView {
	return &mockLuksView{data: data}
}
