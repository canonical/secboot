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

package secboot

// AuthRequestor is an interface for requesting credentials.
type AuthRequestor interface {
	// RequestPassphrase is used to request the passphrase for a platform
	// protected key that is being used to unlock the container at the
	// specified sourceDevicePath.
	RequestPassphrase(volumeName, sourceDevicePath string) (string, error)

	// RequestRecoveryKey is used to request the recovery key to unlock the
	// container at the specified sourceDevicePath.
	RequestRecoveryKey(volumeName, sourceDevicePath string) (RecoveryKey, error)
}
