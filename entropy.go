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

package secboot

import (
	gpv "github.com/canonical/go-password-validator"
)

type PassphraseEntropyStats struct {
	SymbolPoolSize  uint32
	NumberOfSymbols uint32
	EntropyBits     uint32
}

// CheckPassphraseEntropy calculates entropy for PINs and passphrases (PINs will be supplied as a numeric passphrase).
func CheckPassphraseEntropy(passphrase string) (*PassphraseEntropyStats, error) {
	stats := &PassphraseEntropyStats{}
	stats.SymbolPoolSize = uint32(gpv.GetBase(passphrase))
	stats.NumberOfSymbols = uint32(gpv.GetLength(passphrase))
	stats.EntropyBits = uint32(gpv.GetEntropy(passphrase))
	return stats, nil
}
