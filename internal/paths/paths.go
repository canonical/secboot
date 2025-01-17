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

package paths

import "path/filepath"

var (
	RunDir = "/run"

	// Argon2OutOfProcessHandlerSystemLockPath is the lock file path used to
	// serialize KDF requests system-wide. All process's that use the system-wide
	// lock participate in the lock/unlock contract described above.
	Argon2OutOfProcessHandlerSystemLockPath = filepath.Join(RunDir, "secboot_argon2.lock")
)
