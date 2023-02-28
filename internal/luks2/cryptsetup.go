// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package luks2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/snapcore/snapd/osutil"

	"golang.org/x/xerrors"
)

const (
	// AnySlot tells AddKey to automatically choose an appropriate slot
	// as opposed to hard coding one.
	AnySlot = -1

	// AnyId tells ImportToken to automatically choose an appropriate token
	// ID as opposed to hard coding one.
	AnyId = -1
)

var (
	// ErrMissingCryptsetupFeature is returned from some functions that make
	// use of the system's cryptsetup binary, if that binary is missing some
	// required features.
	ErrMissingCryptsetupFeature = errors.New("cannot perform the requested operation because a required feature is missing from cryptsetup")

	features     Features
	featuresOnce sync.Once

	keySize = 64
)

// Features indicates the set of features supported by this package,
// determined by the features of the system's cryptsetup binary.
type Features int

const (
	// FeatureHeaderSizeSetting indicates that the header size settings can be
	// specified when using the Format API. This was introduced to cryptsetup by:
	// https://gitlab.com/cryptsetup/cryptsetup/-/commit/ec07927b55fa83f8a3980ea7b0cc0dd8032927f0
	FeatureHeaderSizeSetting Features = 1 << iota

	// FeatureTokenImport indicates that ImportToken can be used. Token imports were
	// introduced to cryptsetup by
	// https://gitlab.com/cryptsetup/cryptsetup/-/commit/cc27088df92b669df7649217c4a64dc72f21987a
	FeatureTokenImport

	// FeatureTokenReplace indicates that tokens can be atomically replaced with
	// ImportToken (yet to be implemented). This was introduced to cryptsetup by:
	// https://gitlab.com/cryptsetup/cryptsetup/-/commit/98cd52c8d7bddf5b4c1ff775158a48bbb522acb2
	FeatureTokenReplace
)

// cryptsetupCmd is a helper for running the cryptsetup command. If stdin is supplied, data read
// from it is supplied to cryptsetup via its stdin. If callback is supplied, it will be invoked
// after cryptsetup has started.
func cryptsetupCmd(stdin io.Reader, callback func(cmd *exec.Cmd) error, args ...string) error {
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = stdin

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b

	if err := cmd.Start(); err != nil {
		return xerrors.Errorf("cannot start cryptsetup: %w", err)
	}

	var cbErr error
	if callback != nil {
		cbErr = callback(cmd)
	}

	err := cmd.Wait()

	switch {
	case cbErr != nil:
		return cbErr
	case err != nil:
		return fmt.Errorf("cryptsetup failed with: %v", osutil.OutputErr(b.Bytes(), err))
	}

	return nil
}

// DetectCryptsetupFeatures returns the features supported by the cryptsetup binary
// on this system.
func DetectCryptsetupFeatures() Features {
	featuresOnce.Do(func() {
		features = 0

		cmd := exec.Command("cryptsetup", "--version")
		out, err := cmd.CombinedOutput()
		if err == nil {
			var major, minor, patch int
			n, _ := fmt.Sscanf(string(out), "cryptsetup %d.%d.%d", &major, &minor, &patch)
			if n == 3 {
				if major >= 3 || (major == 2 && minor >= 1) {
					features |= FeatureHeaderSizeSetting
				}
				if major >= 3 || (major == 2 && minor >= 1) || (major == 2 && minor == 0 && patch >= 3) {
					features |= FeatureTokenImport
				}
			}
		}
		if err := cryptsetupCmd(nil, nil, "--test-args", "token", "import", "--token-id", "0",
			"--token-replace", "/dev/null"); err == nil {
			features |= FeatureTokenReplace
		}
	})
	return features
}

// KDFOptions specifies parameters for the Argon2 KDF.
type KDFOptions struct {
	// TargetDuration specifies the target time for benchmarking of the
	// time and memory cost parameters. If it is zero then the cryptsetup
	// default is used. If ForceIterations is not zero then this is ignored.
	TargetDuration time.Duration

	// MemoryKiB specifies the maximum memory cost in KiB when ForceIterations
	// is zero, or the actual memory cost in KiB when ForceIterations is not zero.
	// If this is set to zero, then the cryptsetup default is used.
	MemoryKiB int

	// ForceIterations specifies the time cost. If set to zero, the time
	// and memory cost are determined by benchmarking the algorithm based on
	// the specified TargetDuration. Set to a non-zero number to force the
	// time cost to the value of this field, and the memory cost to the value
	// of MemoryKiB, disabling benchmarking.
	ForceIterations int

	// Parallel sets the maximum number of parallel threads. Cryptsetup may
	// choose a lower value based on its own maximum and the number of available
	// CPU cores.
	Parallel int
}

func (options *KDFOptions) appendArguments(args []string) []string {
	// use argon2i as the KDF
	args = append(args, "--pbkdf", "argon2i")

	switch {
	case options.ForceIterations != 0:
		// Disable benchmarking by forcing the time cost
		args = append(args,
			"--pbkdf-force-iterations", strconv.Itoa(options.ForceIterations))
	case options.TargetDuration != 0:
		args = append(args,
			"--iter-time", strconv.FormatInt(int64(options.TargetDuration/time.Millisecond), 10))
	}

	if options.MemoryKiB != 0 {
		args = append(args, "--pbkdf-memory", strconv.Itoa(options.MemoryKiB))
	}

	if options.Parallel != 0 {
		args = append(args, "--pbkdf-parallel", strconv.Itoa(options.Parallel))
	}

	return args
}

// FormatOptions provide the options for formatting a new LUKS2 volume.
type FormatOptions struct {
	// MetadataKiBSize sets the size of the metadata area in KiB.
	// This size includes the 4KiB fixed-size binary header, with
	// the remaining space for the JSON area. Set to zero to use
	// the cryptsetup default. Must be any power of 2 between
	// 16KiB and 4MiB.
	MetadataKiBSize int

	// KeyslotsAreaKiBSize sets the size of the binary keyslots
	// area in KiB. Set to zero to use the cryptsetup default.
	// Must be a multiple of 4KiB.
	KeyslotsAreaKiBSize int

	// KDFOptions describes the KDF options for the initial
	// key slot.
	KDFOptions KDFOptions

	// InlineCryptoEngine set flag if to use Inline Crypto Engine
	InlineCryptoEngine bool
}

func (options *FormatOptions) validate() error {
	if (options.MetadataKiBSize != 0 || options.KeyslotsAreaKiBSize != 0) &&
		DetectCryptsetupFeatures()&FeatureHeaderSizeSetting == 0 {
		return ErrMissingCryptsetupFeature
	}

	if options.MetadataKiBSize != 0 {
		// Verify that the size is a power of 2 between 16KiB and 4MiB.
		found := false
		for sz := uint(16); sz <= uint(4*1024); sz <<= 1 {
			if uint(options.MetadataKiBSize) == sz {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("cannot set metadata size to %v KiB", options.MetadataKiBSize)
		}
	}

	if options.KeyslotsAreaKiBSize != 0 {
		// Verify that the size is sufficient for a single keyslot, not more than 128MiB
		// and a multiple of 4KiB.
		if options.KeyslotsAreaKiBSize < (keySize*4000)/1024 ||
			options.KeyslotsAreaKiBSize > 128*1024 || options.KeyslotsAreaKiBSize%4 != 0 {
			return fmt.Errorf("cannot set keyslots area size to %v KiB", options.KeyslotsAreaKiBSize)
		}
	}

	return nil
}

func (options *FormatOptions) appendArguments(args []string) []string {
	args = options.KDFOptions.appendArguments(args)

	if options.InlineCryptoEngine {
		// use inline crypto engine
		args = append(args, "--inline-crypto-engine")
	}

	if options.MetadataKiBSize != 0 {
		// override the default metadata area size if specified
		args = append(args, "--luks2-metadata-size", fmt.Sprintf("%dk", options.MetadataKiBSize))
	}
	if options.KeyslotsAreaKiBSize != 0 {
		// override the default keyslots area size if specified
		args = append(args, "--luks2-keyslots-size", fmt.Sprintf("%dk", options.KeyslotsAreaKiBSize))
	}

	return args
}

// Format will initialize a LUKS2 container with the specified options and set the primary key to the
// supplied key. The label for the new container will be set to the supplied label. This can only be
// called on a device that is not mapped.
//
// The container will be configured to encrypt data with AES-256 and XTS block cipher mode. The
// KDF for the primary keyslot will be configured to use argon2i with the supplied benchmark time.
//
// WARNING: This function is destructive. Calling this on an existing LUKS2 container will make the
// data contained inside of it irretrievable.
func Format(devicePath, label string, key []byte, opts *FormatOptions) error {
	if opts == nil {
		var defaultOpts FormatOptions
		opts = &defaultOpts
	}

	if err := opts.validate(); err != nil {
		return err
	}

	args := []string{
		// batch processing, no password verification for formatting an existing LUKS container
		"-q",
		// formatting a new volume
		"luksFormat",
		// use LUKS2
		"--type", "luks2",
		// read the key from stdin
		"--key-file", "-",
		// use AES-256 with XTS block cipher mode (XTS requires 2 keys)
		"--cipher", "aes-xts-plain64", "--key-size", strconv.Itoa(keySize * 8),
		// set LUKS2 label
		"--label", label}

	// apply options
	args = opts.appendArguments(args)

	args = append(args,
		// device to format
		devicePath)

	return cryptsetupCmd(bytes.NewReader(key), nil, args...)
}

// AddKeyOptions provides the options for adding a key to a LUKS2 volume
type AddKeyOptions struct {
	// KDFOptions describes the KDF options for the new key slot.
	KDFOptions KDFOptions

	// Slot is the keyslot to use. Note that the default value is slot 0. In
	// order to automatically choose a slot, use AnySlot.
	Slot int
}

// AddKey adds the supplied key in to a new keyslot for specified LUKS2 container. In order to do this,
// an existing key must be provided. The KDF for the new keyslot will be configured to use argon2i with
// the supplied benchmark time. The key will be added to the supplied slot.
//
// If options is not supplied, the default KDF benchmark time is used and the command will
// automatically choose an appropriate slot.
func AddKey(devicePath string, existingKey, key []byte, options *AddKeyOptions) error {
	if options == nil {
		options = &AddKeyOptions{Slot: AnySlot}
	}

	fifoPath, cleanupFifo, err := mkFifo()
	if err != nil {
		return xerrors.Errorf("cannot create FIFO for passing existing key to cryptsetup: %w", err)
	}
	defer cleanupFifo()

	args := []string{
		// add a new key
		"luksAddKey",
		// LUKS2 only
		"--type", "luks2",
		// read existing key from named pipe
		"--key-file", fifoPath}

	// apply KDF options
	args = options.KDFOptions.appendArguments(args)

	if options.Slot != AnySlot {
		args = append(args, "--key-slot", strconv.Itoa(options.Slot))
	}

	args = append(args,
		// container to add key to
		devicePath,
		// read new key from stdin.
		// Note that we can't supply the new key and existing key via the same channel
		// because pipes and FIFOs aren't seekable - we would need to use an actual file
		// in order to be able to do this.
		"-")

	writeExistingKeyToFifo := func(cmd *exec.Cmd) error {
		f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		if err != nil {
			// If we fail to open the write end, the read end will be blocked in open(), so
			// kill the process.
			cmd.Process.Kill()
			return xerrors.Errorf("cannot open FIFO for passing existing key to cryptsetup: %w", err)
		}

		if _, err := f.Write(existingKey); err != nil {
			// The read end is open and blocked inside read(). Closing our write end will result in the
			// read end returning 0 bytes (EOF) and continuing cleanly.
			if err := f.Close(); err != nil {
				// If we can't close the write end, the read end will remain blocked inside read(),
				// so kill the process.
				cmd.Process.Kill()
			}
			return xerrors.Errorf("cannot pass existing key to cryptsetup: %w", err)
		}

		if err := f.Close(); err != nil {
			// If we can't close the write end, the read end will remain blocked inside read(),
			// so kill the process.
			cmd.Process.Kill()
			return xerrors.Errorf("cannot close write end of FIFO: %w", err)
		}

		return nil
	}

	return cryptsetupCmd(bytes.NewReader(key), writeExistingKeyToFifo, args...)
}

// ImportTokenOptions provides the options for importing a JSON token into a LUKS2 header.
type ImportTokenOptions struct {
	// Id is the token ID to use. Note that the default value is slot 0. In
	// order to automatically choose an ID, use AnyId.
	Id int

	// Replace will overwrite an existing token at the specified slot.
	Replace bool
}

// ImportToken imports the supplied token in to the JSON metadata area of the specified LUKS2 container.
// This requires FeatureTokenImport. If the Replace field of options is set, then FeatureTokenReplace
// is required.
func ImportToken(devicePath string, token Token, options *ImportTokenOptions) error {
	if DetectCryptsetupFeatures()&FeatureTokenImport == 0 {
		return ErrMissingCryptsetupFeature
	}

	if options == nil {
		options = &ImportTokenOptions{Id: AnyId}
	}

	if options.Replace {
		if DetectCryptsetupFeatures()&FeatureTokenReplace == 0 {
			return ErrMissingCryptsetupFeature
		}
		if options.Id == AnyId {
			// Require replace to specify a slot
			return errors.New("replace requires a token ID")
		}
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return xerrors.Errorf("cannot serialize token: %w", err)
	}

	args := []string{"token", "import"}
	if options.Id != AnyId {
		args = append(args, "--token-id", strconv.Itoa(options.Id))
	}
	if options.Replace {
		args = append(args, "--token-replace")
	}
	args = append(args, devicePath)

	return cryptsetupCmd(bytes.NewReader(tokenJSON), nil, args...)
}

// RemoveToken removes the token with the supplied ID from the JSON metadata area of the specified
// LUKS2 container.
func RemoveToken(devicePath string, id int) error {
	return cryptsetupCmd(nil, nil, "token", "remove", "--token-id", strconv.Itoa(id), devicePath)
}

// KillSlot erases the keyslot with the supplied slot number from the specified LUKS2 container.
// Note that a valid key for a remaining keyslot must be supplied.
//
// WARNING: This function will remove the last keyslot if the key associated with it
// is supplied, which will make the encrypted data permanently inaccessible.
func KillSlot(devicePath string, slot int, key []byte) error {
	return cryptsetupCmd(bytes.NewReader(key), nil, "luksKillSlot", "--type", "luks2", "--key-file", "-", devicePath, strconv.Itoa(slot))
}

// SetSlotPriority sets the priority of the keyslot with the supplied slot number on
// the specified LUKS2 container.
func SetSlotPriority(devicePath string, slot int, priority SlotPriority) error {
	return cryptsetupCmd(nil, nil, "config", "--priority", priority.String(), "--key-slot", strconv.Itoa(slot), devicePath)
}
