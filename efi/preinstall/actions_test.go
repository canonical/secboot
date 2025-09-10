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

package preinstall_test

import (
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type actionsSuite struct{}

var _ = Suite(&actionsSuite{})

func (*actionsSuite) TestIsExternalActionTrue(c *C) {
	for _, action := range []Action{
		ActionReboot,
		ActionShutdown,
		ActionRebootToFWSettings,
		ActionContactOEM,
		ActionContactOSVendor,
	} {
		c.Check(action.IsExternalAction(), testutil.IsTrue, Commentf("action: %v", action))
	}
}

func (*actionsSuite) TestIsExternalActionFalse(c *C) {
	for _, action := range []Action{
		ActionEnableTPMViaFirmware,
		ActionEnableAndClearTPMViaFirmware,
		ActionClearTPMViaFirmware,
	} {
		c.Check(action.IsExternalAction(), testutil.IsFalse, Commentf("action: %v", action))
	}
}
