// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package testutil

import (
	"fmt"
	"os/exec"

	"github.com/snapcore/secboot/internal/luks2"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"
)

func MockRunDir(path string) (restore func()) {
	origRunDir := luks2.RunDir
	luks2.RunDir = path
	return func() {
		luks2.RunDir = origRunDir
	}
}

func MockSystemdCryptsetupPath(path string) (restore func()) {
	origSystemdCryptsetupPath := luks2.SystemdCryptsetupPath
	luks2.SystemdCryptsetupPath = path
	return func() {
		luks2.SystemdCryptsetupPath = origSystemdCryptsetupPath
	}
}

func WrapCryptsetup(c *C) *snapd_testutil.MockCmd {
	cryptsetupWrapperBottom := `
# Set max locked memory to 0. Without this and without CAP_IPC_LOCK, mlockall will
# succeed but subsequent calls to mmap will fail because the limit is too low. Setting
# this to 0 here will cause mlockall to fail, which cryptsetup ignores.
ulimit -l 0
exec %[1]s "$@" </dev/stdin
`

	cryptsetup, err := exec.LookPath("cryptsetup")
	c.Assert(err, IsNil)

	return snapd_testutil.MockCommand(c, "cryptsetup", fmt.Sprintf(cryptsetupWrapperBottom, cryptsetup))
}
