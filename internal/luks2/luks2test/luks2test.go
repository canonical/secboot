// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020-2021 Canonical Ltd
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

package luks2test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/luks2/internal"
)

func WrapCryptsetup(c *C) (restore func()) {
	cryptsetupWrapperBottom := `
# Set max locked memory to 0. Without this and without CAP_IPC_LOCK, mlockall will
# succeed but subsequent calls to mmap will fail because the limit is too low. Setting
# this to 0 here will cause mlockall to fail, which cryptsetup ignores.
ulimit -l 0
exec %[1]s "$@" </dev/stdin
`

	cryptsetup, err := exec.LookPath("cryptsetup")
	c.Assert(err, IsNil)

	cmd := testutil.MockCommand(c, "cryptsetup", fmt.Sprintf(cryptsetupWrapperBottom, cryptsetup))
	return cmd.Restore
}

func CreateEmptyDiskImage(c *C, sz int) string {
	f, err := os.OpenFile(filepath.Join(c.MkDir(), "disk.img"), os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	c.Assert(f.Truncate(int64(sz)*1024*1024), IsNil)
	return f.Name()
}

func CheckLUKS2Passphrase(c *C, devicePath string, key []byte) {
	cmd := exec.Command("cryptsetup", "open", "--test-passphrase", "--key-file", "-", devicePath)
	cmd.Stdin = bytes.NewReader(key)
	c.Check(cmd.Run(), IsNil)
}

func ResetCryptsetupFeatures() {
	internal.FeaturesOnce = sync.Once{}
}
