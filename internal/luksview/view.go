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
	"context"
	"fmt"
	"sort"

	"github.com/snapcore/secboot/internal/luks2"
)

type namedTokenData struct {
	id    int
	token NamedToken
}

// HeaderSource provides a mechanism to read a LUKS2 header repeatedly.
type HeaderSource interface {
	ReadHeader() (*luks2.HeaderInfo, error)
}

type defaultHeaderSource struct {
	ctx        context.Context
	devicePath string
}

func (s *defaultHeaderSource) ReadHeader() (*luks2.HeaderInfo, error) {
	return luks2.ReadHeader(s.ctx, s.devicePath)
}

// View provides a read-only view of a LUKS2 header in a way that is useful
// to secboot.
type View struct {
	source HeaderSource

	hdr *luks2.HeaderInfo

	// namedTokens contains a map of keyslot name to valid named tokens.
	namedTokens map[string]namedTokenData
}

// NewView creates a new View from the LUKS2 container at the specified
// path, using the specified locking mode.
func NewView(ctx context.Context, devicePath string) (*View, error) {
	view := &View{source: &defaultHeaderSource{
		ctx:        ctx,
		devicePath: devicePath}}

	if err := view.Reread(); err != nil {
		return nil, err
	}

	return view, nil
}

// NewViewFromCustomHeaderSource creates a new View from the LUKS2 header
// obtained from the supplied source. This is useful for mocking the header
// in unit tests.
func NewViewFromCustomHeaderSource(source HeaderSource) (*View, error) {
	view := &View{source: source}

	if err := view.Reread(); err != nil {
		return nil, err
	}

	return view, nil
}

// Reread updates this view from the source container.
func (v *View) Reread() error {
	hdr, err := v.source.ReadHeader()
	if err != nil {
		return err
	}

	v.hdr = hdr
	v.namedTokens = make(map[string]namedTokenData)

	// Rebuild map of named tokens
	for id, token := range hdr.Metadata.Tokens {
		named, ok := token.(NamedToken)
		if !ok {
			continue
		}

		if _, isOrphaned := named.(*orphanedToken); isOrphaned {
			// Ignore orphaned tokens so that its name can be reused.
			continue
		}

		if _, exists := v.namedTokens[named.Name()]; exists {
			return fmt.Errorf("multiple tokens with the same name (%s)", named.Name())
		}

		v.namedTokens[named.Name()] = namedTokenData{id: id, token: named}
	}

	return nil
}

// TokenNames returns a sorted list of all of the keyslot names from this view.
// This doesn't return names associated with tokens that have been orphaned
// because their associated keyslot has been deleted.
func (v *View) TokenNames() (names []string) {
	for name := range v.namedTokens {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// TokenByName returns the token and its ID for the keyslot with the supplied name.
// This doesn't return tokens that have been orphaned because their associated
// keyslot has been deleted.
func (v *View) TokenByName(name string) (token NamedToken, id int, inUse bool) {
	data, exists := v.namedTokens[name]
	if !exists {
		return nil, 0, false
	}
	return data.token, data.id, true
}

// KeyDataTokensByPriority returns all of the key data tokens in order of priority,
// from highest to lowest. Tokens with the same priority are returned in the order in
// which their names are sorted. This omits any with a priority of less than 0, and
// any tokens that have been orphaned because their associated keyslot has been
// deleted.
func (v *View) KeyDataTokensByPriority() (tokens []*KeyDataToken) {
	// Build a map of tokens by priority
	tokensByPriority := make(map[int][]*KeyDataToken)
	for _, name := range v.TokenNames() {
		t := v.namedTokens[name].token

		if t.Type() != KeyDataTokenType {
			continue
		}

		token := t.(*KeyDataToken)

		if token.Priority < 0 {
			// Priority -1 tokens are ignored unless called explicitly
			// by name.
			continue
		}
		tokensByPriority[token.Priority] = append(tokensByPriority[token.Priority], token)
	}

	// Create a list of priorites, sorted in reverse order (highest to lowest)
	priorities := make([]int, 0, len(tokensByPriority))
	for priority := range tokensByPriority {
		priorities = append(priorities, priority)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(priorities)))

	// Build the list of tokens in priority order (highest to lowest)
	for _, priority := range priorities {
		tokens = append(tokens, tokensByPriority[priority]...)
	}

	return tokens
}

// OrphanedTokenIds returns a list of ids for tokens that have been orphaned
// and can be removed. Orphaned tokens are those where the associated keyslot
// doesn't has been deleted and can occur if the process of removing a keyslot
// and its tokens is interrupted.
func (v *View) OrphanedTokenIds() (ids []int) {
	for id, token := range v.hdr.Metadata.Tokens {
		if _, isOrphaned := token.(*orphanedToken); !isOrphaned {
			continue
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// UsedKeyslots returns a list of ids for currently active keyslots.
func (v *View) UsedKeyslots() (slots []int) {
	for slot := range v.hdr.Metadata.Keyslots {
		slots = append(slots, slot)
	}
	sort.Ints(slots)
	return slots
}
