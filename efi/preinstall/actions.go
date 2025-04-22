// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package preinstall

// Action describes an Action to resolve a detected error. Some [ErrorKind]s may
// be associated with one or more Actions that can be taken in order to resolve
// the error. The code that calls [RunChecksContext.Run] can respond with one of
// these actions.
//
// An installer UI may offer some of these actions in response to detected errors,
// although note that it doesn't have to offer all actions associated with an error,
// and the documentation for some actions provide hints as to whether they are
// inappropriate for an installer UI. In some cases, it may be appropriate for snapd
// to choose an action as opposed to exposing it to the installer UI.
//
// TODO: Add some meaningful actions here later on.
type Action string

const (
	// ActionNone corresponds to no action.
	ActionNone Action = ""

	// ActionReboot corresponds to rebooting the device. Note that this is a
	// pseudo-action. It cannot be performed by this package - the caller
	// should trigger the reboot.
	ActionReboot Action = "reboot"

	// ActionShutdown corresponds to shutting down the device. Note that this
	// is a pseudo-action. It cannot be performed by this package - the caller
	// should trigger the shutdown.
	ActionShutdown Action = "shutdown"

	// ActionRebootToFWSettings corresponds to rebooting the device to the firmware
	// settings in order to resolve a problem manually. Note that this is a
	// pseudo-action. It cannot be performed by this package - the caller should
	// trigger the reboot to FW settings.
	//
	// TODO: How do we improve this by offering a hint of what needs to change
	// from entering the firmware settings UI?
	ActionRebootToFWSettings Action = "reboot-to-fw-settings"

	// ActionContactOEM is a hint that the user should contact the OEM for the
	// device because of a bug in the platform. It is a pseudo-action and cannnot
	// be performed by this package.
	ActionContactOEM Action = "contact-oem"

	// ActionContactOSVendor is a hint that the user should contact the OS vendor
	// because of a bug in the OS. It is a pseudo-action and cannnot be performed
	// by this package.
	ActionContactOSVendor Action = "contact-os-vendor"
)

// IsPseudoAction will return true if the action cannot actually be executed by
// [RunChecksContext.Run], but the action is expected to be performed by the caller
// (eg, snapd or the installer) instead.
//
// TODO: Add extra actions that can be performed by this package by passing the
// action to [RunChecksContext.Run].
func (a Action) IsPseudoAction() bool {
	switch a {
	case ActionReboot, ActionShutdown, ActionRebootToFWSettings, ActionContactOEM, ActionContactOSVendor:
		return true
	default:
		return false
	}
}
