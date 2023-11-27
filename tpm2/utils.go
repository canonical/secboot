// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package tpm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"
)

func isPathError(err error) bool {
	var e *os.PathError
	return xerrors.As(err, &e)
}

// isAuthFailError indicates whether the specified error is a TPM authorization check failure, with or without DA implications.
func isAuthFailError(err error, command tpm2.CommandCode, index int) bool {
	return tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, command, index) ||
		tpm2.IsTPMSessionError(err, tpm2.ErrorBadAuth, command, index)
}

// isLoadInvalidParamError indicates whether the specified error is a TPM error associated with an invalid param
// supplied to a TPM2_Load command.
func isLoadInvalidParamError(err error) bool {
	return tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandLoad, tpm2.AnyParameterIndex)
}

func isImportInvalidParamError(err error) bool {
	// Ignore TPM_RC_SCHEME for inSymSeed, which is really an invalid parent.
	return tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandImport, tpm2.AnyParameterIndex) &&
		!tpm2.IsTPMParameterError(err, tpm2.ErrorScheme, tpm2.CommandImport, 4)
}

// isLoadInvalidParentError indicates whether the specified error is a TPM error associated with an invalid parent
// handle supplied to a TPM2_Load command.
func isLoadInvalidParentError(err error) bool {
	// TPM_RC_TYPE associated with the parent handle is an invalid parent
	return tpm2.IsTPMHandleError(err, tpm2.ErrorType, tpm2.CommandLoad, 1)
}

func isImportInvalidParentError(err error) bool {
	// TPM_RC_TYPE associated with the parent handle is an invalid parent, as is
	// TPM_RC_SCHEME associated with inSymSeed.
	return tpm2.IsTPMHandleError(err, tpm2.ErrorType, tpm2.CommandImport, 1) ||
		tpm2.IsTPMParameterError(err, tpm2.ErrorScheme, tpm2.CommandImport, 4)
}

type tpmErrorWithHandle struct {
	handle tpm2.Handle
	err    *tpm2.TPMError
}

func (e *tpmErrorWithHandle) Error() string {
	return fmt.Sprintf("%v (handle %v)", e.err, e.handle)
}

func (e *tpmErrorWithHandle) Unwrap() error {
	return e.err
}

// isTpmErrorWithHandle indicates whether the specified error is a *tpmErrorWithHandle.
func isTpmErrorWithHandle(err error) bool {
	var e *tpmErrorWithHandle
	return xerrors.As(err, &e)
}

func bigIntToBytesZeroExtended(x *big.Int, bytes int) (out []byte) {
	b := x.Bytes()
	if len(b) > bytes {
		return b
	}
	out = make([]byte, bytes)
	copy(out[bytes-len(b):], b)
	return
}

// createPublicAreaForECDSAKey creates a *tpm2.Public from a go *ecdsa.PublicKey, which is suitable for loading
// in to a TPM with TPMContext.LoadExternal.
func createTPMPublicAreaForECDSAKey(key *ecdsa.PublicKey) *tpm2.Public {
	var curve tpm2.ECCCurve
	switch key.Curve {
	case elliptic.P224():
		curve = tpm2.ECCCurveNIST_P224
	case elliptic.P256():
		curve = tpm2.ECCCurveNIST_P256
	case elliptic.P384():
		curve = tpm2.ECCCurveNIST_P384
	case elliptic.P521():
		curve = tpm2.ECCCurveNIST_P521
	default:
		panic("unsupported curve")
	}

	return &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.ECCScheme{
					Scheme:  tpm2.ECCSchemeECDSA,
					Details: &tpm2.AsymSchemeU{ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
				CurveID: curve,
				KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}},
		Unique: &tpm2.PublicIDU{
			ECC: &tpm2.ECCPoint{
				X: bigIntToBytesZeroExtended(key.X, key.Params().BitSize/8),
				Y: bigIntToBytesZeroExtended(key.Y, key.Params().BitSize/8)}}}
}

func createECDSAPrivateKeyFromTPM(public *tpm2.Public, private tpm2.ECCParameter) (*ecdsa.PrivateKey, error) {
	if public.Type != tpm2.ObjectTypeECC {
		return nil, errors.New("unsupported type")
	}

	var curve elliptic.Curve
	switch public.Params.ECCDetail.CurveID {
	case tpm2.ECCCurveNIST_P224:
		curve = elliptic.P224()
	case tpm2.ECCCurveNIST_P256:
		curve = elliptic.P256()
	case tpm2.ECCCurveNIST_P384:
		curve = elliptic.P384()
	case tpm2.ECCCurveNIST_P521:
		curve = elliptic.P521()
	default:
		return nil, errors.New("unsupported curve")
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(public.Unique.ECC.X),
			Y:     new(big.Int).SetBytes(public.Unique.ECC.Y)},
		D: new(big.Int).SetBytes(private)}, nil
}

// digestListContains indicates whether the specified digest is present in the list of digests.
func digestListContains(list tpm2.DigestList, digest tpm2.Digest) bool {
	for _, d := range list {
		if bytes.Equal(d, digest) {
			return true
		}
	}
	return false
}
