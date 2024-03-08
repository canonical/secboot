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
	"os/exec"
	"runtime"
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
func cryptsetupCmd(stdin io.Reader, args ...string) error {
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = stdin

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cryptsetup failed with: %v", osutil.OutputErr(output, err))
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
		if err := cryptsetupCmd(nil, "--test-args", "token", "import", "--token-id", "0",
			"--token-replace", "/dev/null"); err == nil {
			features |= FeatureTokenReplace
		}
	})
	return features
}

// KDFOptions specifies parameters for the Argon2 KDF.
type KDFOptions struct {
	// Type is the KDF type.
	Type KDFType

	// TargetDuration specifies the target time for benchmarking of the
	// time and memory cost parameters. If it is zero then the cryptsetup
	// default is used. If ForceIterations is not zero then this is ignored.
	TargetDuration time.Duration

	// MemoryKiB specifies the maximum memory cost in KiB when ForceIterations
	// is zero, or the actual memory cost in KiB when ForceIterations is not zero.
	// If this is set to zero, then the cryptsetup default is used. This is only
	// relevant when Type is argon2i or argon2id.
	MemoryKiB uint32

	// ForceIterations specifies the time cost. If set to zero, the time
	// and memory cost are determined by benchmarking the algorithm based on
	// the specified TargetDuration. Set to a non-zero number to force the
	// time cost to the value of this field, and the memory cost to the value
	// of MemoryKiB, disabling benchmarking.
	ForceIterations uint32

	// Parallel sets the maximum number of parallel threads. Cryptsetup may
	// choose a lower value based on its own maximum and the number of available
	// CPU cores. This is only relevant when Type is argon2i or argon2id.
	Parallel uint8

	// Hash is the digest algorithm for the KDF. If set to zero then the cryptsetup
	// default is used. This is only relevant when Type is pbkdf2.
	Hash Hash
}

func (options *KDFOptions) validate() error {
	switch {
	case options.ForceIterations != 0 && options.TargetDuration != 0:
		return errors.New("cannot use both ForceIterations and TargetDuration")
	}

	switch options.Type {
	case KDFTypePBKDF2:
		switch {
		case options.MemoryKiB != 0 || options.Parallel != 0:
			return errors.New("cannot use argon2 options with pbkdf2")
		case options.ForceIterations != 0 && options.ForceIterations < 1000:
			return fmt.Errorf("cannot set pbkdf2 ForceIterations to %d", options.ForceIterations)
		}
		switch options.Hash {
		case HashSHA1, HashSHA224, HashSHA256, HashSHA384, HashSHA512, "":
			// ok
		default:
			return fmt.Errorf("cannot set pbkdf2 hash to %v", options.Hash)
		}
	case KDFTypeArgon2i, KDFTypeArgon2id:
		switch {
		case options.MemoryKiB != 0 && (options.MemoryKiB < 32 || options.MemoryKiB > 4*1024*1024):
			return fmt.Errorf("cannot set argon2 MemoryKiB to %d", options.MemoryKiB)
		case options.ForceIterations != 0 && options.ForceIterations < 4:
			return fmt.Errorf("cannot set argon2 ForceIterations to %d", options.ForceIterations)
		case options.Parallel > 4:
			return fmt.Errorf("cannot set argon2 Parallel to %d", options.Parallel)
		case options.Hash != "":
			return errors.New("cannot use pbkdf2 options with argon2")
		}
	case "":
		if options.MemoryKiB != 0 || options.ForceIterations != 0 || options.Parallel != 0 || options.Hash != "" {
			return errors.New("cannot set options without selecting a type")
		}
	default:
		return fmt.Errorf("cannot set type to %v", options.Type)
	}

	return nil
}

func (options *KDFOptions) appendArguments(args []string) []string {
	if options.Type != "" {
		args = append(args, "--pbkdf", string(options.Type))
	}
	if options.TargetDuration != 0 {
		args = append(args,
			"--iter-time", strconv.FormatInt(int64(options.TargetDuration/time.Millisecond), 10))
	}
	if options.MemoryKiB != 0 {
		args = append(args, "--pbkdf-memory", strconv.FormatUint(uint64(options.MemoryKiB), 10))
	}
	if options.ForceIterations != 0 {
		args = append(args,
			"--pbkdf-force-iterations", strconv.FormatUint(uint64(options.ForceIterations), 10))
	}
	if options.Parallel != 0 {
		args = append(args, "--pbkdf-parallel", strconv.FormatUint(uint64(options.Parallel), 10))
	}
	if options.Hash != "" {
		args = append(args, "--hash", string(options.Hash))
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
	MetadataKiBSize uint32

	// KeyslotsAreaKiBSize sets the size of the binary keyslots
	// area in KiB. Set to zero to use the cryptsetup default.
	// Must be a multiple of 4KiB.
	KeyslotsAreaKiBSize uint32

	// KDFOptions describes the KDF options for the initial
	// key slot.
	KDFOptions KDFOptions

	// InlineCryptoEngine set flag if to use Inline Crypto Engine
	InlineCryptoEngine bool
}

func (options *FormatOptions) validate(cipher string) error {
	if (options.MetadataKiBSize != 0 || options.KeyslotsAreaKiBSize != 0) &&
		DetectCryptsetupFeatures()&FeatureHeaderSizeSetting == 0 {
		return ErrMissingCryptsetupFeature
	}

	if options.MetadataKiBSize != 0 {
		// Verify that the size is a power of 2 between 16KiB and 4MiB.
		found := false
		for sz := uint32(16); sz <= uint32(4*1024); sz <<= 1 {
			if options.MetadataKiBSize == sz {
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
		if options.KeyslotsAreaKiBSize < uint32((keySize(cipher)*4000)/1024) ||
			options.KeyslotsAreaKiBSize > 128*1024 || options.KeyslotsAreaKiBSize%4 != 0 {
			return fmt.Errorf("cannot set keyslots area size to %v KiB", options.KeyslotsAreaKiBSize)
		}
	}

	return options.KDFOptions.validate()
}

func (options *FormatOptions) appendArguments(args []string) []string {
	args = options.KDFOptions.appendArguments(args)

	if options.MetadataKiBSize != 0 {
		// override the default metadata area size if specified
		args = append(args, "--luks2-metadata-size", fmt.Sprintf("%dk", options.MetadataKiBSize))
	}
	if options.KeyslotsAreaKiBSize != 0 {
		// override the default keyslots area size if specified
		args = append(args, "--luks2-keyslots-size", fmt.Sprintf("%dk", options.KeyslotsAreaKiBSize))
	}
	if options.InlineCryptoEngine {
		// use inline crypto engine
		args = append(args, "--inline-crypto-engine")
	}

	return args
}

var runtimeGOARCH = runtime.GOARCH

// selectCipher will return the cipher to use. This is aes-xts-plain64
// everywhere except on armhf (32bit arm) hardware where the XTS mode
// cannot be accelerated by the hardware.
//
// Note that this is a simple approach, we could run "cryptsetup
// benchmark" but that seems over engineered (and easy enough to
// switch if we need in the future).
func selectCipher() string {
	switch runtimeGOARCH {
	case "arm":
		// On many 32bit ARM SoCs there is a CAAM module that
		// can accelerate cryptographic operations which
		// ~doubles the speed. It does not support XTS though
		// so we use CBC mode here.
		return "aes-cbc-essiv:sha256"
	default:
		// use AES-256 with XTS block cipher mode (XTS requires 2 keys)
		return "aes-xts-plain64"
	}
}

// keySize returns the size of the key in bytes for the given encryption
// algorithm. It will panic if an unsupported cipher is passed in.
func keySize(cipher string) int {
	switch cipher {
	case "aes-xts-plain64":
		return 64
	case "aes-cbc-essiv:sha256":
		return 32
	default:
		panic(fmt.Sprintf("internal error: unknown keysize for cipher %v", cipher))
	}
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

	cipher := selectCipher()
	if err := opts.validate(cipher); err != nil {
		return err
	}

	ksize := keySize(cipher)
	args := []string{
		// batch processing, no password verification for formatting an existing LUKS container
		"--batch-mode",
		// formatting a new volume
		"luksFormat",
		// use LUKS2
		"--type", "luks2",
		// read the key from stdin
		"--key-file", "-",

		"--cipher", cipher, "--key-size", strconv.Itoa(ksize * 8),
		// set LUKS2 label
		"--label", label}

	// apply options
	args = opts.appendArguments(args)

	args = append(args,
		// device to format
		devicePath)

	return cryptsetupCmd(bytes.NewReader(key), args...)
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
	if err := options.KDFOptions.validate(); err != nil {
		return err
	}

	args := []string{
		// add a new key
		"luksAddKey",
		// LUKS2 only
		"--type", "luks2",
		// read existing key from stdin, specifying key size so
		// cryptsetup knows where the existing key ends and the new key
		// starts (we are passing both keys via stdin). Otherwise it
		// would interpret new lines as separator for the keys, while
		// we actually allow '\n' to be part of the keys.
		"--key-file", "-",
		"--keyfile-size", strconv.Itoa(len(existingKey)),
		// remove warnings and confirmation questions
		"--batch-mode"}

	// apply KDF options
	args = options.KDFOptions.appendArguments(args)

	if options.Slot != AnySlot {
		// TODO use --new-key-slot for newer crypsetup versions
		args = append(args, "--key-slot", strconv.Itoa(options.Slot))
	}

	args = append(args,
		// container to add key to
		devicePath,
		// we read raw bytes up to EOF (so new key can contain '\n':
		// without the option it would be interpreted as end of key)
		"-",
	)

	// existing and new key are both read from stdin
	cmdInput := bytes.NewReader(append(existingKey, key...))
	return cryptsetupCmd(cmdInput, args...)
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

	return cryptsetupCmd(bytes.NewReader(tokenJSON), args...)
}

// RemoveToken removes the token with the supplied ID from the JSON metadata area of the specified
// LUKS2 container.
func RemoveToken(devicePath string, id int) error {
	return cryptsetupCmd(nil, "token", "remove", "--token-id", strconv.Itoa(id), devicePath)
}

// KillSlot erases the keyslot with the supplied slot number from the specified LUKS2 container.
//
// WARNING: This function will remove the last keyslot if there is only one left,
// which will make the encrypted data permanently inaccessible.
func KillSlot(devicePath string, slot int) error {
	return cryptsetupCmd(nil, "luksKillSlot", "--batch-mode", "--type", "luks2", devicePath, strconv.Itoa(slot))
}

// SetSlotPriority sets the priority of the keyslot with the supplied slot number on
// the specified LUKS2 container.
func SetSlotPriority(devicePath string, slot int, priority SlotPriority) error {
	return cryptsetupCmd(nil, "config", "--priority", priority.String(), "--key-slot", strconv.Itoa(slot), devicePath)
}
