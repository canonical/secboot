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

package luks2

import (
	"context"
	"io"

	"github.com/snapcore/secboot"
	internal_luks2 "github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luksview"
)

type luksView interface {
	TokenByName(name string) (token luksview.NamedToken, id int, inUse bool)
}

var newLuksView = func(ctx context.Context, path string) (luksView, error) {
	return luksview.NewView(ctx, path)
}

type luks2KeyDataReader interface {
	ReadableName() string
	KeyslotID() int
	Priority() int
	io.Reader
}

func newLUKS2KeyDataReader(devicePath, name string) (luks2KeyDataReader, error) {
	return secboot.NewLUKS2KeyDataReader(devicePath, name)
}

// luks2Api allows the legacy secboot calls to be mocked in unit tests.
type luks2Api struct {
	Activate             func(string, string, []byte, int) error
	Deactivate           func(string) error
	ListUnlockKeyNames   func(string) ([]string, error)
	ListRecoveryKeyNames func(string) ([]string, error)
	NewKeyDataReader     func(string, string) (luks2KeyDataReader, error)
}

// luks2Ops is a structure of LUKS2 operations that just delegate to the existing
// LUKS2 specific secboot APIs - eventually this functionality (and that in
// internal/luksview) will be implemented natively in this package and the
// existing LUKS2 specific APIs in the core secboot package will be deleted.
var luks2Ops = &luks2Api{
	Activate:             internal_luks2.Activate,
	Deactivate:           internal_luks2.Deactivate,
	ListUnlockKeyNames:   secboot.ListLUKS2ContainerUnlockKeyNames,
	ListRecoveryKeyNames: secboot.ListLUKS2ContainerRecoveryKeyNames,
	NewKeyDataReader:     newLUKS2KeyDataReader,
}
