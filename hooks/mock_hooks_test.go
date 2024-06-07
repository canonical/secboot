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

package hooks_test

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	_ "crypto/sha256"
	"encoding/json"
	"errors"
	"io"

	. "github.com/snapcore/secboot/hooks"
	"github.com/snapcore/secboot/internal/testutil"
	"golang.org/x/crypto/hkdf"
)

var rootKey = testutil.MustDecodeHexString("2e686fd54166ff8f7282900800e6cae5e9c5b122dd31ff1e3cdefe9b26a9f6c6")

type protectorFn func(io.Reader, []byte, []byte) ([]byte, []byte, error)
type mockKeyProtector protectorFn

func (p mockKeyProtector) ProtectKey(rand io.Reader, cleartext, aad []byte) (ciphertext []byte, handle []byte, err error) {
	return (protectorFn)(p)(rand, cleartext, aad)
}

func makeMockKeyProtector(fn protectorFn) KeyProtector {
	return mockKeyProtector(fn)
}

type revealerFn func([]byte, []byte, []byte) ([]byte, error)
type mockKeyRevealer revealerFn

func (r mockKeyRevealer) RevealKey(handle, ciphertext, aad []byte) (cleartext []byte, err error) {
	return (revealerFn)(r)(handle, ciphertext, aad)
}

func makeMockKeyRevealer(fn revealerFn) KeyRevealer {
	return mockKeyRevealer(fn)
}

type mockHooksKeyData struct {
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
}

func mockHooksProtector(rand io.Reader, cleartext, aad []byte) (ciphertext []byte, handle []byte, err error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, nil, err
	}

	r := hkdf.New(crypto.SHA256.New, rootKey, salt, []byte("KEY"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, nil, err
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aead, err := cipher.NewGCM(b)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, cleartext, aad)

	handle, err = json.Marshal(&mockHooksKeyData{
		Salt:  salt,
		Nonce: nonce,
	})
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, handle, nil
}

func mockHooksRevealer(handle, ciphertext, aad []byte) (cleartext []byte, err error) {
	var kd *mockHooksKeyData
	if err := json.Unmarshal(handle, &kd); err != nil {
		return nil, err
	}

	r := hkdf.New(crypto.SHA256.New, rootKey, kd.Salt, []byte("KEY"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCMWithNonceSize(b, len(kd.Nonce))
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, kd.Nonce, ciphertext, aad)
}

type mockHooksNoAEADKeyData struct {
	Salt []byte `json:"salt"`
	IV   []byte `json:"iv"`
}

func mockHooksProtectorNoAEAD(rand io.Reader, cleartext, _ []byte) (ciphertext []byte, handle []byte, err error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, nil, err
	}

	r := hkdf.New(crypto.SHA256.New, rootKey, salt, []byte("KEY"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, nil, err
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, nil, err
	}

	stream := cipher.NewCFBEncrypter(b, iv)

	ciphertext = make([]byte, len(cleartext))
	stream.XORKeyStream(ciphertext, cleartext)

	handle, err = json.Marshal(&mockHooksNoAEADKeyData{
		Salt: salt,
		IV:   iv,
	})
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, handle, nil
}

func mockHooksRevealerNoAEAD(handle, ciphertext, _ []byte) (cleartext []byte, err error) {
	var kd *mockHooksNoAEADKeyData
	if err := json.Unmarshal(handle, &kd); err != nil {
		return nil, err
	}

	r := hkdf.New(crypto.SHA256.New, rootKey, kd.Salt, []byte("KEY"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(kd.IV) != aes.BlockSize {
		return nil, errors.New("invalid IV size")
	}

	stream := cipher.NewCFBDecrypter(b, kd.IV)

	cleartext = make([]byte, len(ciphertext))
	stream.XORKeyStream(cleartext, ciphertext)

	return cleartext, nil
}

func makeFaultyMockHooksProtector(err error) KeyProtector {
	return makeMockKeyProtector(func(_ io.Reader, _, _ []byte) ([]byte, []byte, error) {
		return nil, nil, err
	})
}
