// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package secboot

import (
	"bytes"
	"errors"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luksview"
)

// LUKS2KeyDataReader provides a mechanism to read a KeyData from a LUKS2 token.
type LUKS2KeyDataReader struct {
	name     string
	slot     int
	priority int
	*bytes.Reader
}

func (r *LUKS2KeyDataReader) ReadableName() string {
	return r.name
}

// KeyslotID indicates the keyslot ID associated with the token from which this
// KeyData is read.
func (r *LUKS2KeyDataReader) KeyslotID() int {
	return r.slot
}

// Priority indicates the priority of the keyslot associated with the token from
// which this KeyData is read. The default priority is 0 with higher numbers
// indicating a higher priority.
func (r *LUKS2KeyDataReader) Priority() int {
	return r.priority
}

// NewLUKS2KeyDataReader is used to read a LUKS2 token containing key data with
// the specified name on the specified LUKS2 container.
func NewLUKS2KeyDataReader(devicePath, name string) (*LUKS2KeyDataReader, error) {
	view, err := newLUKSView(devicePath, luks2.LockModeBlocking)
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain LUKS2 header view: %w", err)
	}

	token, _, exists := view.TokenByName(name)
	if !exists {
		return nil, errors.New("a keyslot with the specified name does not exist")
	}

	kdToken, ok := token.(*luksview.KeyDataToken)
	if !ok {
		return nil, errors.New("named keyslot is the wrong type")
	}

	if kdToken.Data == nil {
		return nil, errors.New("named keyslot does not contain key data yet")
	}

	return &LUKS2KeyDataReader{
		name:     devicePath + ":" + name,
		slot:     token.Keyslots()[0],
		priority: kdToken.Priority,
		Reader:   bytes.NewReader(kdToken.Data)}, nil
}

// LUKS2KeyDataWriter provides a mechanism to write a KeyData to a LUKS2 token.
type LUKS2KeyDataWriter struct {
	devicePath string
	id         int
	slot       int
	name       string
	priority   int
	*bytes.Buffer
}

func (w *LUKS2KeyDataWriter) Commit() error {
	token := &luksview.KeyDataToken{
		TokenBase: luksview.TokenBase{
			TokenKeyslot: w.slot,
			TokenName:    w.name},
		Priority: w.priority,
		Data:     w.Bytes()}

	return luks2ImportToken(w.devicePath, token, &luks2.ImportTokenOptions{Id: w.id, Replace: true})
}

// NewLUKS2KeyDataWriter creates a new LUKS2KeyDataWriter for atomically writing a
// KeyData to a LUKS2 token with the specicied name and priority on the specified
// LUKS2 container.
//
// The container must already contain a token of the correct type with the supplied
// name. The initial token is bootstrapped by InitializeLUKS2Container or
// SetLUKS2ContainerUnlockKey.
func NewLUKS2KeyDataWriter(devicePath, name string, priority int) (*LUKS2KeyDataWriter, error) {
	view, err := newLUKSView(devicePath, luks2.LockModeBlocking)
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain LUKS2 header view: %w", err)
	}

	token, id, exists := view.TokenByName(name)
	if !exists {
		return nil, errors.New("a keyslot with the specified name does not exist")
	}

	if token.Type() != luksview.KeyDataTokenType {
		return nil, errors.New("named keyslot has the wrong type")
	}

	return &LUKS2KeyDataWriter{
		devicePath: devicePath,
		id:         id,
		slot:       token.Keyslots()[0],
		name:       name,
		priority:   priority,
		Buffer:     new(bytes.Buffer)}, nil
}
