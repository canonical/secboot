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

// Package processinit should be imported by applications that want a
// process keyring created before the go runtime starts.
package processinit

/*
#cgo LDFLAGS: -lkeyutils
#include <errno.h>
#include <keyutils.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
__attribute__((constructor))
void init_process_keyring() {
	key_serial_t res;
	if ((res = keyctl_get_keyring_ID(KEY_SPEC_PROCESS_KEYRING, 1)) < 0) {
		fprintf(stderr, "FATAL: Cannot create process keyring (%s)\n", strerror(errno));
		_exit(1);
	}
}
*/
import "C"
