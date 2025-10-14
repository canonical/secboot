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

// Package forcesessioninit should be imported by applications that want to
// unconditionally join a new anonymous session keyring before the go runtime starts.
package forcesessioninit

/*
#cgo LDFLAGS: -lkeyutils
#include <errno.h>
#include <keyutils.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
__attribute__((constructor))
void force_init_session_keyring() {
	key_serial_t res;
	if ((res = keyctl_join_session_keyring(NULL)) < 0) {
		fprintf(stderr, "FATAL: Cannot join anonymous session keyring (%s)\n", strerror(errno));
		_exit(1);
	}
}
*/
import "C"
