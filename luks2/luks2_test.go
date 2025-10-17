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

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luksview"
	. "github.com/snapcore/secboot/luks2"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type mockExternalKeyslot struct {
}

func (*mockExternalKeyslot) Type() secboot.KeyslotType {
	return secboot.KeyslotTypePlatform
}

func (*mockExternalKeyslot) Name() string {
	return "mock external keyslot"
}

func (*mockExternalKeyslot) Priority() int {
	return 0
}

func (*mockExternalKeyslot) Data() secboot.KeyDataReader {
	return nil
}

type mockKeyslot struct {
	keyslotType     secboot.KeyslotType
	keyslotName     string
	keyslotPriority int
	keyslotData     secboot.KeyDataReader
	keyslotId       int
}

func (i *mockKeyslot) Type() secboot.KeyslotType {
	return i.keyslotType
}

func (i *mockKeyslot) Name() string {
	return i.keyslotName
}

func (i *mockKeyslot) Priority() int {
	return i.keyslotPriority
}

func (i *mockKeyslot) Data() secboot.KeyDataReader {
	return i.keyslotData
}

func (i *mockKeyslot) KeyslotID() int {
	return i.keyslotId
}

type mockLuks2KeyDataReader struct {
	*bytes.Reader
}

func newMockLuks2KeyDataReader(token *luksview.KeyDataToken) *mockLuks2KeyDataReader {
	return &mockLuks2KeyDataReader{
		Reader: bytes.NewReader(token.Data),
	}
}

func (r *mockLuks2KeyDataReader) ReadableName() string {
	return ""
}

type mockContainerData struct {
	recoveryKeyslots map[string]int
	platformKeyslots map[string]*luksview.KeyDataToken

	listUnlockKeyNamesErr   error
	listRecoveryKeyNamesErr error
	newKeyDataReaderErr     error
}

func newMockContainerData() *mockContainerData {
	return &mockContainerData{
		recoveryKeyslots: make(map[string]int),
		platformKeyslots: make(map[string]*luksview.KeyDataToken),
	}
}

func newKeyDataToken(name string, slot, priority int, data []byte) *luksview.KeyDataToken {
	return &luksview.KeyDataToken{
		TokenBase: luksview.TokenBase{
			TokenKeyslot: slot,
			TokenName:    name,
		},
		Priority: priority,
		Data:     data,
	}
}

type mockLuksView struct {
	data *mockContainerData
}

func (v *mockLuksView) TokenByName(name string) (token luksview.NamedToken, id int, inUse bool) {
	if id, exists := v.data.recoveryKeyslots[name]; exists {
		return &luksview.RecoveryToken{
			TokenBase: luksview.TokenBase{
				TokenKeyslot: id,
				TokenName:    name,
			},
		}, 0, true // We return 0 for all token IDs because the test doesn't use it.
	}

	if token, exists := v.data.platformKeyslots[name]; exists {
		return token, 0, true // We return 0 for all token IDs because the test doesn't use it.
	}

	return nil, 0, false
}

func newMockLuksView(data *mockContainerData) LuksView {
	return &mockLuksView{data: data}
}
