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

package luksview

import (
	"encoding/json"
	"errors"
	"strconv"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot/internal/luks2"
)

const (
	KeyDataTokenType  luks2.TokenType = "ubuntu-fde"
	RecoveryTokenType luks2.TokenType = "ubuntu-fde-recovery"
)

var (
	errInvalidNamedToken  = errors.New("invalid named token")
	errOrphanedNamedToken = errors.New("orphaned named token")
)

func fallbackDecodeTokenHelper(data []byte, origErr error) (luks2.Token, error) {
	switch {
	case origErr == nil:
		panic("asked to decode fallback token without an error")
	case xerrors.Is(origErr, errOrphanedNamedToken):
		var token *orphanedToken
		if err := json.Unmarshal(data, &token); err != nil {
			return nil, err
		}
		return token, nil
	case xerrors.Is(origErr, errInvalidNamedToken):
		var token *luks2.GenericToken
		if err := json.Unmarshal(data, &token); err != nil {
			return nil, err
		}
		return token, nil
	default:
		return nil, origErr
	}
}

func init() {
	luks2.RegisterTokenDecoder(KeyDataTokenType, func(data []byte) (luks2.Token, error) {
		var token *KeyDataToken
		if err := json.Unmarshal(data, &token); err != nil {
			return fallbackDecodeTokenHelper(data, err)
		}
		return token, nil
	})

	luks2.RegisterTokenDecoder(RecoveryTokenType, func(data []byte) (luks2.Token, error) {
		var token *RecoveryToken
		if err := json.Unmarshal(data, &token); err != nil {
			return fallbackDecodeTokenHelper(data, err)
		}
		return token, nil
	})
}

// NamedToken corresponds to a token created by secboot, which identifies
// the associated keyslot with a name and may contain data required to
// activate a volume using the associated keyslot.
type NamedToken interface {
	luks2.Token

	// Name returns the name of this token. A name is an arbitrary
	// string used to identify the associated keyslot, and the name is
	// intended to be unique between keyslots.
	Name() string
}

type tokenKeyslots []int

func (k tokenKeyslots) MarshalJSON() ([]byte, error) {
	var keyslots []luks2.JsonNumber
	for _, slot := range k {
		keyslots = append(keyslots, luks2.JsonNumber(strconv.Itoa(slot)))
	}
	return json.Marshal(keyslots)
}

func (k *tokenKeyslots) UnmarshalJSON(data []byte) error {
	var rawslots []luks2.JsonNumber
	if err := json.Unmarshal(data, &rawslots); err != nil {
		return err
	}

	var keyslots tokenKeyslots
	for _, v := range rawslots {
		slot, err := v.Int()
		if err != nil {
			return xerrors.Errorf("invalid keyslot ID: %w", err)
		}
		keyslots = append(keyslots, slot)
	}
	*k = keyslots
	return nil
}

type tokenBaseRaw struct {
	Type     luks2.TokenType `json:"type"`
	Keyslots tokenKeyslots   `json:"keyslots"`
	Name     string          `json:"ubuntu_fde_name"`
}

type recoveryTokenRaw struct {
	tokenBaseRaw
}

type keyDataTokenRaw struct {
	tokenBaseRaw
	Priority int             `json:"ubuntu_fde_priority"`
	Data     json.RawMessage `json:"ubuntu_fde_data,omitempty"`
}

// TokenBase provides the fields that are common to all tokens created by secboot.
type TokenBase struct {
	TokenKeyslot int    // The ID of the keyslot associated with this token
	TokenName    string // The name of the keyslot that this token is associated with
}

func (t *TokenBase) Keyslots() []int {
	return []int{t.TokenKeyslot}
}

func (t *TokenBase) Name() string {
	return t.TokenName
}

// RecoveryToken represents a token with the type "ubuntu-fde-recovery",
// associated with a recovery keyslot
type RecoveryToken struct {
	TokenBase
}

func (t *RecoveryToken) Type() luks2.TokenType {
	return RecoveryTokenType
}

func (t *RecoveryToken) MarshalJSON() ([]byte, error) {
	raw := &recoveryTokenRaw{
		tokenBaseRaw: tokenBaseRaw{
			Type:     RecoveryTokenType,
			Keyslots: tokenKeyslots{t.TokenKeyslot},
			Name:     t.TokenName}}
	return json.Marshal(raw)
}

func (t *RecoveryToken) UnmarshalJSON(data []byte) error {
	var raw *recoveryTokenRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch {
	case raw.Name == "" || len(raw.Keyslots) > 1:
		return errInvalidNamedToken
	case len(raw.Keyslots) == 0:
		// Cryptsetup removes the keyslot ID from associated tokens
		// when the slot is deleted, so a token with no associated
		// keyslots is orphaned.
		return errOrphanedNamedToken
	}

	*t = RecoveryToken{
		TokenBase: TokenBase{
			TokenKeyslot: int(raw.Keyslots[0]),
			TokenName:    raw.Name}}
	return nil
}

// KeyDataToken represents a token with the "ubuntu-fde" type, associated
// with a platform protected keyslot. It is created as a placeholder when
// a keyslot is created, and then is subsequently updated to contain an
// encoded KeyData.
type KeyDataToken struct {
	TokenBase

	// Priority is the priority of the keyslot associated with
	// this token. 0 is the default, with higher numbers indicating a
	// higher priority. A negative priority means that the associated
	// keyslot shouldn't be used unless requested explicitly by name.
	Priority int

	Data json.RawMessage // The raw KeyData JSON payload
}

func (t *KeyDataToken) Type() luks2.TokenType {
	return KeyDataTokenType
}

func (t *KeyDataToken) MarshalJSON() ([]byte, error) {
	raw := &keyDataTokenRaw{
		tokenBaseRaw: tokenBaseRaw{
			Type:     KeyDataTokenType,
			Keyslots: tokenKeyslots{t.TokenKeyslot},
			Name:     t.TokenName},
		Priority: t.Priority,
		Data:     t.Data}
	return json.Marshal(raw)
}

func (t *KeyDataToken) UnmarshalJSON(data []byte) error {
	var raw *keyDataTokenRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch {
	case raw.Name == "" || len(raw.Keyslots) > 1:
		return errInvalidNamedToken
	case len(raw.Keyslots) == 0:
		// Cryptsetup removes the keyslot ID from associated tokens
		// when the slot is deleted, so a token with no associated
		// keyslots is orphaned.
		return errOrphanedNamedToken
	}

	*t = KeyDataToken{
		TokenBase: TokenBase{
			TokenKeyslot: int(raw.Keyslots[0]),
			TokenName:    raw.Name},
		Priority: raw.Priority,
		Data:     raw.Data}
	return nil
}

type orphanedToken struct {
	raw tokenBaseRaw
}

func (t *orphanedToken) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &t.raw)
}

func (t *orphanedToken) Type() luks2.TokenType {
	return t.raw.Type
}

func (t *orphanedToken) Keyslots() []int {
	return nil
}

func (t *orphanedToken) Name() string {
	return t.raw.Name
}

// MockOrphanedToken returns a new orphaned named token with the
// supplied type and name, which is useful for testing.
func MockOrphanedToken(t luks2.TokenType, name string) NamedToken {
	return &orphanedToken{
		raw: tokenBaseRaw{
			Type: t,
			Name: name}}
}
