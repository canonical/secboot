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
	"strings"

	"github.com/snapcore/secboot/internal/keyring"
	"golang.org/x/sys/unix"
)

var (
	keyringAddKey = keyring.AddKey
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

func formatKeyringKeyDesc(path string, purpose KeyringKeyPurpose, prefix string) string {
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
	id, err := keyring.SearchKey(keyring.UserKeyring, keyring.UserKeyType, formatKeyringKeyDesc(devicePath, KeyringKeyPurposeUnlock, keyringPrefixOrDefault(prefix)), 0)
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
	id, err := keyring.SearchKey(keyring.UserKeyring, keyring.UserKeyType, formatKeyringKeyDesc(devicePath, keyringKeyPurposeAuxiliary, keyringPrefixOrDefault(prefix)), 0)
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
	if strings.IndexAny(prefix, ":") >= 0 {
		return errors.New("invalid prefix")
	}
	if strings.IndexAny(string(purpose), ":") >= 0 {
		return errors.New("invalid purpose")
	}
	_, err := keyringAddKey(key, keyring.UserKeyType, formatKeyringKeyDesc(path, purpose, prefix), keyring.UserKeyring)
	return err
}

func parseKeyringKeyDesc(desc string) (prefix, name string, purpose KeyringKeyPurpose, ok bool) {
	comps := strings.Split(desc, ":")
	if len(comps) < 3 {
		return "", "", "", false
	}

	return comps[0], strings.Join(comps[1:len(comps)-1], ":"), KeyringKeyPurpose(comps[len(comps)-1]), true
}

// GetKeyFromKernel retrieves the key with the supplied purpose and associated with
// the storage container with the specified path from the user keyring. The value of
// prefix must match the prefix that was used whe the key was added.
//
// If no key is found, a ErrKernelKeyNotFound error will be returned.
func GetKeyFromKernel(ctx context.Context, container StorageContainer, purpose KeyringKeyPurpose, prefix string) ([]byte, error) {
	prefix = keyringPrefixOrDefault(prefix)

	// Handle the case that should succeed with a snap-bootstrap that uses the
	// new addKeyToUserKeyring function first.
	foundId, err := keyring.SearchKey(keyring.UserKeyring, keyring.UserKeyType, formatKeyringKeyDesc(container.CredentialName(), purpose, prefix), 0)
	switch {
	case errors.Is(err, keyring.ErrKeyNotExist):
		// Support for older snap-bootstraps that use the older keyring.AddKeyToUserKeyring
		// function (now replaced by addKeyToUserKeyringLegacy).
		// addKeyToUserKeyringLegacy uses a path (and specifically, a path to a block
		// device) to identify a key, but that path may be a symbolic link so we need to
		// ensure that the paths point to the same block device.
		path := container.Path()
		var st unix.Stat_t
		err = unixStat(path, &st)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil, ErrKernelKeyNotFound
		case err != nil:
			return nil, &os.PathError{Op: "stat", Path: path, Err: err}
		case st.Mode&unix.S_IFMT != unix.S_IFBLK:
			// Don't handle the legacy case if the container is not a block device.
			return nil, ErrKernelKeyNotFound
		}

		if purpose == KeyringKeyPurposePrimary {
			// keyring.AddKeyToUserKeyring (now addKeyToUserKeyringLegacy) was/is
			// called with "aux" rather than "primary".
			purpose = keyringKeyPurposeAuxiliary
		}

		ids, err := keyring.ListKeyringKeys(ctx, keyring.UserKeyring)
		if err != nil {
			return nil, fmt.Errorf("cannot list user keys: %w", err)
		}

		for _, id := range ids {
			desc, err := keyring.DescribeKey(id)
			if err != nil {
				if errors.Is(err, keyring.ErrKeyNotExist) {
					continue
				}
				return nil, fmt.Errorf("cannot obtain description for key %d: %w", id, err)
			}

			if desc.Type != keyring.UserKeyType {
				// Ignore anything that isn't a user key.
				continue
			}

			keyPrefix, keyName, keyPurpose, ok := parseKeyringKeyDesc(desc.Desc)
			if !ok {
				// Not a key added by us.
				continue
			}

			if keyPrefix != prefix {
				continue
			}

			if keyPurpose != purpose {
				continue
			}

			var keySt unix.Stat_t
			if err := unixStat(keyName, &keySt); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					// The credential name may not be a path.
					continue
				}
				return nil, &os.PathError{Op: "stat", Path: keyName, Err: err}
			}

			if keySt.Mode&unix.S_IFMT != unix.S_IFBLK {
				// The credential name is not a path to a block device.
				continue
			}

			if keySt.Rdev != st.Rdev {
				// The credential name is not a path to the block device
				// associated with the supplied storage container.
				continue
			}

			// We have a match.
			foundId = id
			break
		}
	case err != nil:
		return nil, fmt.Errorf("cannot search user keys: %w", err)
	}

	if foundId == keyring.KeyID(0) {
		return nil, ErrKernelKeyNotFound
	}

	key, err := keyring.ReadKey(ctx, foundId)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotExist) {
			return nil, ErrKernelKeyNotFound
		}
		return nil, err
	}

	return key, nil
}

func addKeyToUserKeyring(key []byte, container StorageContainer, purpose KeyringKeyPurpose, prefix string) error {
	if strings.IndexAny(prefix, ":") >= 0 {
		return errors.New("invalid prefix")
	}
	if strings.IndexAny(string(purpose), ":") >= 0 {
		return errors.New("invalid purpose")
	}
	_, err := keyringAddKey(key, keyring.UserKeyType, formatKeyringKeyDesc(container.CredentialName(), purpose, prefix), keyring.UserKeyring)
	return err
}
