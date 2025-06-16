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

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snapcore/secboot/internal/keyring"
)

// KeyringKeyPurpose describes the purpose of a key stored in the kyring.
type KeyringKeyPurpose string

const (
	keyringKeyPurposeAuxiliary KeyringKeyPurpose = "aux"

	// KeyringKeyPurposePrimary references the primary key recovered from
	// the metadata for a normal keyslot. Any container unlocked with a
	// normal keyslot will have one of these.
	KeyringKeyPurposePrimary KeyringKeyPurpose = "primary"

	// KeyringKeyPurposeUnique references the unique key recovered from the
	// metadata for a normal keyslot. This and the primary key are used to
	// derive the unlock key, and can be used to derive keys for other
	// purposes.
	//
	// XXX: This key will not initially be present in the keyring because
	// it isn't exposed from [KeyData.RecoverKeys]. It may be added later.
	// In any case, the presence of both the primary and unlock keys will be
	// sufficient for now in order for us to add new keyslots or update
	// existing ones.
	KeyringKeyPurposeUnique KeyringKeyPurpose = "unique"

	// KeyringKeyPurposeUnlock references the unlock key used to unlock a
	// keyslot. It can be recovered from the metadata for a normal keyslot,
	// or be supplied as a recovery key. All unlocked containers will have
	// one of these.
	KeyringKeyPurposeUnlock KeyringKeyPurpose = "unlock"
)

// ErrKernelKeyNotFound indicates that a key with the supplied parameters
// could not be found in the expected location in the keyring.
var ErrKernelKeyNotFound = errors.New("cannot find key in kernel keyring")

func keyringPrefixOrDefault(prefix string) string {
	if prefix == "" {
		return "ubuntu-fde"
	}
	return prefix
}

func formatDesc(path string, purpose KeyringKeyPurpose, prefix string) string {
	return prefix + ":" + path + ":" + string(purpose)
}

// GetDiskUnlockKeyFromKernel retrieves the key that was used to unlock the
// encrypted container at the specified path. The value of prefix must match
// the prefix that was supplied via ActivateVolumeOptions during unlocking.
//
// If remove is true, the key will be removed from the kernel keyring prior
// to returning.
//
// If no key is found, a ErrKernelKeyNotFound error will be returned.
func GetDiskUnlockKeyFromKernel(prefix, devicePath string, remove bool) (DiskUnlockKey, error) {
	id, err := keyring.SearchKey(keyring.UserKeyring, keyring.UserKeyType, formatDesc(devicePath, KeyringKeyPurposeUnlock, keyringPrefixOrDefault(prefix)), 0)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotExist) {
			return nil, ErrKernelKeyNotFound
		}
		return nil, err
	}

	key, err := keyring.ReadKey(context.TODO(), id)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotExist) {
			return nil, ErrKernelKeyNotFound
		}
		return nil, err
	}

	if remove {
		if err := keyring.UnlinkKey(id, keyring.UserKeyring); err != nil {
			fmt.Fprintf(os.Stderr, "secboot: cannot remove key from user keyring: %v\n", err)
		}
	}

	return key, nil
}

// GetPrimaryKeyFromKernel retrieves the auxiliary key associated with the
// KeyData that was used to unlock the encrypted container at the specified path.
// The value of prefix must match the prefix that was supplied via
// ActivateVolumeOptions during unlocking.
//
// If remove is true, the key will be removed from the kernel keyring prior
// to returning.
//
// If no key is found, a ErrKernelKeyNotFound error will be returned.
func GetPrimaryKeyFromKernel(prefix, devicePath string, remove bool) (PrimaryKey, error) {
	id, err := keyring.SearchKey(keyring.UserKeyring, keyring.UserKeyType, formatDesc(devicePath, keyringKeyPurposeAuxiliary, keyringPrefixOrDefault(prefix)), 0)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotExist) {
			return nil, ErrKernelKeyNotFound
		}
		return nil, err
	}

	key, err := keyring.ReadKey(context.TODO(), id)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotExist) {
			return nil, ErrKernelKeyNotFound
		}
		return nil, err
	}

	if remove {
		if err := keyring.UnlinkKey(id, keyring.UserKeyring); err != nil {
			fmt.Fprintf(os.Stderr, "secboot: cannot remove key from user keyring: %v\n", err)
		}
	}

	return key, nil
}

func addKeyToUserKeyringLegacy(key []byte, path string, purpose KeyringKeyPurpose, prefix string) error {
	_, err := keyring.AddKey(key, keyring.UserKeyType, formatDesc(path, purpose, prefix), keyring.UserKeyring)
	return err
}

var filepathEvalSymlinks = filepath.EvalSymlinks

// GetKeyFromKernel retrieves the key with the supplied purpose and associated with
// the storage container with the specified path from the user keyring. The value of
// prefix must match the prefix that was used whe the key was added.
//
// If unlink is true, the key will be unlinked from the user keyring prior to
// returning.
//
// If no key is found, a ErrKernelKeyNotFound error will be returned.
func GetKeyFromKernel(ctx context.Context, path string, purpose KeyringKeyPurpose, prefix string, unlink bool) ([]byte, error) {
	resolvedPath, err := filepathEvalSymlinks(path)
	if err != nil {
		return nil, err
	}

	id, err := keyring.SearchKey(keyring.UserKeyring, keyring.UserKeyType, formatDesc(resolvedPath, purpose, keyringPrefixOrDefault(prefix)), 0)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotExist) {
			return nil, ErrKernelKeyNotFound
		}
		return nil, err
	}

	key, err := keyring.ReadKey(ctx, id)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotExist) {
			return nil, ErrKernelKeyNotFound
		}
		return nil, err
	}

	if unlink {
		if err := keyring.UnlinkKey(id, keyring.UserKeyring); err != nil {
			fmt.Fprintf(os.Stderr, "secboot: cannot remove key from user keyring: %v\n", err)
		}
	}

	return key, nil
}

func addKeyToUserKeyring(key []byte, path string, purpose KeyringKeyPurpose, prefix string) (keyring.KeyID, error) {
	resolvedPath, err := filepathEvalSymlinks(path)
	if err != nil {
		return 0, err
	}
	return keyring.AddKey(key, keyring.UserKeyType, formatDesc(resolvedPath, purpose, keyringPrefixOrDefault(prefix)), keyring.UserKeyring)
}
