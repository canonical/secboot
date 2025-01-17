// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2024 Canonical Ltd
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

package testenv

var testBinary string = ""

// IsTestBinary returns whether the current binary is a test binary. To
// define something as a test binary and make this return true, pass
// "-ldflags '-X github.com/snapcore/secboot/internal/testenv.testBinary=enabled'"
// to "go build" or "go test".
func IsTestBinary() bool {
	return testBinary == "enabled"
}
