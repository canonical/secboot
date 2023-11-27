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
	_ "crypto/sha256"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/tcti"
)

// Connection corresponds to a connection to a TPM device, and is a wrapper around *tpm2.TPMContext.
type Connection struct {
	*tpm2.TPMContext
	provisionedSrk tpm2.ResourceContext
	hmacSession    tpm2.SessionContext
}

// IsEnabled indicates whether the TPM is enabled or whether it has been disabled by the platform firmware. A TPM device can be
// disabled by the platform firmware by disabling the storage and endorsement hierarchies, but still remain visible to the operating
// system.
func (t *Connection) IsEnabled() bool {
	props, err := t.GetCapabilityTPMProperties(tpm2.PropertyStartupClear, 1)
	if err != nil || len(props) == 0 {
		return false
	}
	const enabledMask = tpm2.AttrShEnable | tpm2.AttrEhEnable
	return tpm2.StartupClearAttributes(props[0].Value)&enabledMask == enabledMask
}

func (t *Connection) LockoutAuthSet() bool {
	value, err := t.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	if err != nil {
		return false
	}
	return tpm2.PermanentAttributes(value)&tpm2.AttrLockoutAuthSet > 0
}

// HmacSession returns a HMAC session instance which was created in order to conduct a proof-of-ownership check of the private part
// of the endorsement key on the TPM. It is retained in order to reduce the number of sessions that need to be created during unseal
// operations, and is created with a symmetric algorithm so that it is suitable for parameter encryption.
// If the connection was created with SecureConnectToDefaultTPM, the session is salted with a value protected by the public part
// of the key associated with the verified endorsement key certificate. The session key can only be retrieved by and used on the TPM
// for which the endorsement certificate was issued. If the connection was created with ConnectToDefaultTPM, the session may be
// salted with a value protected by the public part of the endorsement key if one exists or one is able to be created, but as the key
// is not associated with a verified credential, there is no guarantee that only the TPM is able to retrieve the session key.
func (t *Connection) HmacSession() tpm2.SessionContext {
	if t.hmacSession == nil {
		return nil
	}
	return t.hmacSession.WithAttrs(tpm2.AttrContinueSession)
}

func (t *Connection) Close() error {
	t.FlushContext(t.hmacSession)
	return t.TPMContext.Close()
}

func (t *Connection) init() (err error) {
	// Allow init to be called more than once by flushing the previous session
	if t.hmacSession != nil && t.hmacSession.Handle() != tpm2.HandleUnassigned {
		t.FlushContext(t.hmacSession)
		t.hmacSession = nil
	}
	t.provisionedSrk = nil

	ek, err := t.CreateResourceContextFromTPM(tcg.EKHandle)
	switch {
	case tpm2.IsResourceUnavailableError(err, tcg.EKHandle):
		// ok
	case err != nil:
		return xerrors.Errorf("cannot obtain EK context: %w", err)
	default:
		// Do a sanity check that the obtained context corresponds to a suitable key.
		// A suitable key is a non-duplicable aysymmetric storage parent. If it's not,
		// then don't use it.
		pub, _, _, err := t.ReadPublic(ek)
		if err != nil {
			return xerrors.Errorf("cannot obtain EK public area: %w", err)
		}

		if !pub.IsAsymmetric() || !pub.IsStorageParent() || pub.Attrs&(tpm2.AttrFixedParent|tpm2.AttrFixedTPM) != tpm2.AttrFixedParent|tpm2.AttrFixedTPM {
			ek = nil
		}
	}

	// Only enable parameter encryption if we have a suitable TPM key for key exchange.
	// If we don't, this means that any APIs that request parameter encryption with this
	// session will fail hard if the the TPM isn't provisioned.
	var symmetric *tpm2.SymDef
	if ek != nil {
		symmetric = &tpm2.SymDef{
			Algorithm: tpm2.SymAlgorithmAES,
			KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
			Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB},
		}
	}

	session, err := t.StartAuthSession(ek, nil, tpm2.SessionTypeHMAC, symmetric, defaultSessionHashAlgorithm, nil)
	if err != nil {
		return xerrors.Errorf("cannot create HMAC session: %w", err)
	}

	t.hmacSession = session
	return nil
}

// connectToDefaultTPM opens a connection to the default TPM device.
func connectToDefaultTPM() (*tpm2.TPMContext, error) {
	tcti, err := tcti.OpenDefault()
	if err != nil {
		if isPathError(err) {
			return nil, ErrNoTPM2Device
		}
		return nil, xerrors.Errorf("cannot open TPM device: %w", err)
	}

	tpm := tpm2.NewTPMContext(tcti)
	if !tpm.IsTPM2() {
		tpm.Close()
		return nil, ErrNoTPM2Device
	}

	return tpm, nil
}

// ConnectToDefaultTPM will attempt to connect to the default TPM. It makes no attempt to verify the authenticity of the TPM. This
// function is useful for connecting to a device that isn't correctly provisioned and for which the endorsement hierarchy
// authorization value is unknown (so that it can be cleared), or for connecting to a device in order to execute
// FetchAndSaveEKCertificateChain. It should not be used in any other scenario.
//
// If no TPM2 device is available, then a ErrNoTPM2Device error will be returned.
func ConnectToDefaultTPM() (*Connection, error) {
	tpm, err := connectToDefaultTPM()
	if err != nil {
		return nil, err
	}

	t := &Connection{TPMContext: tpm}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		t.Close()
	}()

	if err := t.init(); err != nil {
		return nil, xerrors.Errorf("cannot initialize TPM connection: %w", err)
	}

	succeeded = true
	return t, nil
}

// ConnectToTPM will attempt to connect to a TPM using the currently
// defined connection function. This is used internally by the tpm2
// package when a connection is required, and defaults to
// ConnectToDefaultTPM. This can be overridden with a custom connection
// function.
var ConnectToTPM func() (*Connection, error) = ConnectToDefaultTPM
