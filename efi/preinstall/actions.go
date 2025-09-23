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

import "encoding/json"

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
type Action string

const (
	// XXX: When adding actions here, remember to add them to the tests in
	// actionsSuite.TestIsExternalAction{False, True}

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

	// ActionEnableTPMViaFirmware tells RunChecksContext.Run to enable the TPM
	// via the physical presence interface. If successful, this action will
	// respond with ErrorKindShutdown or ErrorKindReboot.
	ActionEnableTPMViaFirmware Action = "enable-tpm-via-firmware"

	// ActionEnableAndClearTPMViaFirmware tells RunChecksContext.Run to enable
	// and clear the TPM via the physical presence interface. If successful, this
	// action will respond with ErrorKindShutdown or ErrorKindReboot.
	ActionEnableAndClearTPMViaFirmware Action = "enable-and-clear-tpm-via-firmware"

	// ActionClearTPMViaFirmware tells RunChecksContext.Run to clear the TPM
	// via the physical presence interface. If successful, this action will
	// respond with ErrorKindShutdown or ErrorKindReboot.
	ActionClearTPMViaFirmware Action = "clear-tpm-via-firmware"

	// ActionProceed tells RunChecksContext.Run to turn on the appropriate
	// CheckFlags so that the corresponding errors are ignored. If multiple errors
	// are returned with this action in a single call, then calling
	// RunChecksContext.Run with it will result in all of those errors being
	// ignored if no argument is supplied. If the optional ActionProceedArgs
	// argument is supplied, then only the CheckFlags associated with those errors
	// will be turned on. This provides the user with an opportunity to evaluate
	// and accept any risk associated with ignoring the returned errors, before
	// proceeding.
	//
	// Some errors that support this action may also still support other actions
	// that offer a way to rectify the error.
	ActionProceed Action = "proceed"
)

// IsExternalAction will return true if the action cannot actually be executed by
// [RunChecksContext.Run], but the action is expected to be performed by the caller
// (eg, snapd or the installer) instead.
func (a Action) IsExternalAction() bool {
	switch a {
	case ActionReboot, ActionShutdown, ActionRebootToFWSettings, ActionContactOEM, ActionContactOSVendor:
		return true
	default:
		return false
	}
}

// ActionProceedArgs represents the optional argument for ActionProceed.
type ActionProceedArgs []ErrorKind

// MarshalJSON implements [json.Marshaler].
func (a ActionProceedArgs) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string][]ErrorKind{"error-kinds": []ErrorKind(a)})
}

// UnmarshalJSON implements [json.Unmarshaler].
func (a *ActionProceedArgs) UnmarshalJSON(data []byte) error {
	var arg map[string][]ErrorKind
	if err := json.Unmarshal(data, &arg); err != nil {
		return err
	}

	*a = ActionProceedArgs(arg["error-kinds"])
	return nil
}
