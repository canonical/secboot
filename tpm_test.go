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

package secboot_test

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
)

func TestTPMConnectionIsEnabled(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer func() {
		clearTPMWithPlatformAuth(t, tpm)
		closeTPM(t, tpm)
	}()

	if !tpm.IsEnabled() {
		t.Errorf("IsEnabled returned the wrong value")
	}

	hierarchyControl := func(auth tpm2.ResourceContext, hierarchy tpm2.Handle, enable bool) {
		if err := tpm.HierarchyControl(auth, hierarchy, enable, nil); err != nil {
			t.Errorf("HierarchyControl failed: %v", err)
		}
	}
	defer func() {
		hierarchyControl(tpm.PlatformHandleContext(), tpm2.HandleOwner, true)
		hierarchyControl(tpm.PlatformHandleContext(), tpm2.HandleEndorsement, true)
	}()

	hierarchyControl(tpm.OwnerHandleContext(), tpm2.HandleOwner, false)
	if tpm.IsEnabled() {
		t.Errorf("IsEnabled returned the wrong value")
	}

	hierarchyControl(tpm.EndorsementHandleContext(), tpm2.HandleEndorsement, false)
	if tpm.IsEnabled() {
		t.Errorf("IsEnabled returned the wrong value")
	}
}

func TestConnectToDefaultTPM(t *testing.T) {
	restore := testutil.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return tpm2.OpenMssim("", testutil.MssimPort, testutil.MssimPort+1)
	})
	defer restore()

	connectAndClear := func(t *testing.T) *TPMConnection {
		tpm, _ := openTPMSimulatorForTesting(t)
		clearTPMWithPlatformAuth(t, tpm)
		return tpm
	}

	run := func(t *testing.T, hasEk bool, cleanup func(*TPMConnection)) {
		tpm, err := ConnectToDefaultTPM()
		if err != nil {
			t.Fatalf("ConnectToDefaultTPM failed: %v", err)
		}
		defer func() {
			if cleanup != nil {
				cleanup(tpm)
			}
			closeTPM(t, tpm)
		}()

		if len(tpm.VerifiedEKCertChain()) > 0 {
			t.Errorf("Should be no verified EK cert chain")
		}
		if tpm.VerifiedDeviceAttributes() != nil {
			t.Errorf("Should be no verified device attributes")
		}
		rc, err := tpm.EndorsementKey()
		if !hasEk {
			if err == nil {
				t.Fatalf("TPMConnection.EndorsementKey should have returned an error")
			}
			if rc != nil {
				t.Errorf("TPMConnection.EndorsementKey should have returned a nil context")
			}
			if err != ErrTPMProvisioning {
				t.Errorf("TPMConnection.EndorsementKey returned an unexpected error: %v", err)
			}
		} else {
			if err != nil {
				t.Fatalf("TPMConnection.EndorsementKey failed: %v", err)
			}
			if rc == nil {
				t.Fatalf("TPMConnection.EndorsementKey returned a nil context")
			}
			if rc.Handle() != tcg.EKHandle {
				t.Errorf("TPMConnection.EndorsementKey returned an unexpected context")
			}
		}
		session := tpm.HmacSession()
		if session == nil || session.Handle().Type() != tpm2.HandleTypeHMACSession {
			t.Fatalf("TPMConnection.HmacSession returned invalid session context")
		}
	}

	t.Run("Unprovisioned", func(t *testing.T) {
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
		}()

		run(t, false, nil)
	})

	t.Run("Provisioned", func(t *testing.T) {
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
				t.Fatalf("EnsureProvisioned failed: %v", err)
			}
		}()

		run(t, true, nil)
	})

	t.Run("InvalidEK", func(t *testing.T) {
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			primary, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), nil, tcg.EKTemplate, nil, nil, nil)
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer flushContext(t, tpm, primary)

			sessionContext, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)
			sessionContext.SetAttrs(tpm2.AttrContinueSession)

			if _, _, err := tpm.PolicySecret(tpm.EndorsementHandleContext(), sessionContext, nil, nil, 0, nil); err != nil {
				t.Fatalf("PolicySecret failed: %v", err)
			}

			priv, pub, _, _, _, err := tpm.Create(primary, nil, tcg.EKTemplate, nil, nil, sessionContext)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			if _, _, err := tpm.PolicySecret(tpm.EndorsementHandleContext(), sessionContext, nil, nil, 0, nil); err != nil {
				t.Fatalf("PolicySecret failed: %v", err)
			}

			context, err := tpm.Load(primary, priv, pub, sessionContext)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			defer flushContext(t, tpm, context)

			if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), context, tcg.EKHandle, nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}
		}()

		run(t, false, nil)
	})
}

func TestConnectToDefaultTPMNoTPM(t *testing.T) {
	restore := testutil.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return nil, &os.PathError{Op: "open", Path: "/dev/tpm0", Err: syscall.ENOENT}
	})
	defer restore()

	tpm, err := ConnectToDefaultTPM()
	if tpm != nil {
		t.Errorf("ConnectToDefaultTPM should have failed")
	}
	if err != ErrNoTPM2Device {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestSecureConnectToDefaultTPM(t *testing.T) {
	if !testutil.UseMssim {
		t.SkipNow()
	}

	restore := testutil.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return tpm2.OpenMssim("", testutil.MssimPort, testutil.MssimPort+1)
	})
	defer restore()

	connectAndClear := func(t *testing.T) *TPMConnection {
		tpm, _ := openTPMSimulatorForTesting(t)
		clearTPMWithPlatformAuth(t, tpm)
		return tpm
	}

	run := func(t *testing.T, ekCert io.Reader, hasEk bool, auth []byte, cleanup func(*TPMConnection)) {
		tpm, err := SecureConnectToDefaultTPM(ekCert, auth)
		if err != nil {
			t.Fatalf("SecureConnectToDefaultTPM failed: %v", err)
		}
		defer func() {
			if cleanup != nil {
				cleanup(tpm)
			}
			closeTPM(t, tpm)
		}()

		if len(tpm.VerifiedEKCertChain()) != 2 {
			t.Fatalf("Unexpected number of certificates in chain")
		}
		if !bytes.Equal(tpm.VerifiedEKCertChain()[0].Raw, testEkCert) {
			t.Errorf("Unexpected leaf certificate")
		}

		if tpm.VerifiedDeviceAttributes() == nil {
			t.Fatalf("Should have verified device attributes")
		}
		if tpm.VerifiedDeviceAttributes().Manufacturer != tpm2.TPMManufacturerIBM {
			t.Errorf("Unexpected verified manufacturer")
		}
		if tpm.VerifiedDeviceAttributes().Model != "FakeTPM" {
			t.Errorf("Unexpected verified model")
		}
		if tpm.VerifiedDeviceAttributes().FirmwareVersion != binary.BigEndian.Uint32([]byte{0x00, 0x01, 0x00, 0x02}) {
			t.Errorf("Unexpected verified firmware version")
		}

		rc, err := tpm.EndorsementKey()
		if !hasEk {
			if err == nil {
				t.Fatalf("TPMConnection.EndorsementKey should have returned an error")
			}
			if rc != nil {
				t.Errorf("TPMConnection.EndorsementKey should have returned a nil context")
			}
			if err != ErrTPMProvisioning {
				t.Errorf("TPMConnection.EndorsementKey returned an unexpected error: %v", err)
			}
		} else {
			if err != nil {
				t.Fatalf("TPMConnection.EndorsementKey failed: %v", err)
			}
			if rc == nil {
				t.Fatalf("TPMConnection.EndorsementKey returned a nil context")
			}
			if rc.Handle() != tcg.EKHandle {
				t.Errorf("TPMConnection.EndorsementKey returned an unexpected context")
			}
		}
		session := tpm.HmacSession()
		if session == nil || session.Handle().Type() != tpm2.HandleTypeHMACSession {
			t.Fatalf("TPMConnection.HmacSession returned invalid session context")
		}
	}

	t.Run("Unprovisioned", func(t *testing.T) {
		// Test that we verify successfully with a transient EK
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
		}()

		run(t, bytes.NewReader(testutil.EncodedTPMSimulatorEKCertChain), false, nil, nil)
	})

	t.Run("UnprovisionedWithEndorsementAuth", func(t *testing.T) {
		// Test that we verify successfully with a transient EK when the endorsement hierarchy has an authorization value and we know it
		testAuth := []byte("56789")
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), testAuth, nil); err != nil {
				t.Fatalf("HierarchyChangeAuth failed: %v", err)
			}
		}()

		run(t, bytes.NewReader(testutil.EncodedTPMSimulatorEKCertChain), false, testAuth, func(tpm *TPMConnection) {
			clearTPMWithPlatformAuth(t, tpm)
		})
	})

	t.Run("UnprovisionedWithUnknownEndorsementAuth", func(t *testing.T) {
		// Test that we get the correct error if there is no persistent EK and we can't create a transient one
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), []byte("1234"), nil); err != nil {
				t.Fatalf("HierarchyChangeAuth failed: %v", err)
			}
		}()

		defer func() {
			tpm, err := ConnectToDefaultTPM()
			if err != nil {
				t.Fatalf("ConnectToTPM failed: %v", err)
			}
			defer closeTPM(t, tpm)
			clearTPMWithPlatformAuth(t, tpm)
		}()

		_, err := SecureConnectToDefaultTPM(bytes.NewReader(testutil.EncodedTPMSimulatorEKCertChain), nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if err != ErrTPMProvisioning {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Provisioned", func(t *testing.T) {
		// Test that we verify successfully with the properly provisioned persistent EK
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			if err := tpm.EnsureProvisioned(ProvisionModeFull, nil); err != nil {
				t.Fatalf("EnsureProvisioned failed: %v", err)
			}
		}()

		run(t, bytes.NewReader(testutil.EncodedTPMSimulatorEKCertChain), true, nil, nil)
	})

	t.Run("CallerProvidedEkCert", func(t *testing.T) {
		// Test that we can verify without a TPM provisioned EK certificate
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
		}()

		cert, _ := x509.ParseCertificate(testEkCert)
		caCert, _ := x509.ParseCertificate(testCACert)

		certData := new(bytes.Buffer)
		if err := EncodeEKCertificateChain(cert, []*x509.Certificate{caCert}, certData); err != nil {
			t.Fatalf("EncodeEKCertificateChain failed: %v", err)
		}

		run(t, certData, false, nil, nil)
	})

	t.Run("InvalidEkCert", func(t *testing.T) {
		// Test that we get the right error if the provided EK cert data is invalid
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
		}()

		certData := new(bytes.Buffer)
		certData.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		_, err := SecureConnectToDefaultTPM(certData, nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if _, ok := err.(EKCertVerificationError); !ok {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("EkCertUnknownIssuer", func(t *testing.T) {
		// Test that we get the right error if the provided EK cert has an unknown issuer
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)
		}()

		certData := func() io.Reader {
			caCertRaw, caKey, err := testutil.CreateTestCA()
			if err != nil {
				t.Fatalf("createTestCA failed: %v", err)
			}

			tpm, err := ConnectToDefaultTPM()
			if err != nil {
				t.Fatalf("ConnectToDefaultTPM failed: %v", err)
			}
			defer closeTPM(t, tpm)

			certRaw, err := testutil.CreateTestEKCert(tpm.TPMContext, caCertRaw, caKey)
			if err != nil {
				t.Fatalf("createTestEkCert failed: %v", err)
			}

			cert, _ := x509.ParseCertificate(certRaw)
			caCert, _ := x509.ParseCertificate(caCertRaw)

			b := new(bytes.Buffer)
			if err := EncodeEKCertificateChain(cert, []*x509.Certificate{caCert}, b); err != nil {
				t.Fatalf("EncodeEKCertificateChain failed: %v", err)
			}
			return b
		}()

		_, err := SecureConnectToDefaultTPM(certData, nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if _, ok := err.(EKCertVerificationError); !ok {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("IncorrectPersistentEK", func(t *testing.T) {
		// Test that we verify successfully using a transient EK if the persistent EK doesn't match the certificate
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			// This produces a primary key that doesn't match the certificate created in TestMain
			sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
			ekContext, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), &sensitive, tcg.EKTemplate, nil, nil, nil)
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer tpm.FlushContext(ekContext)
			if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), ekContext, tcg.EKHandle, nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}
		}()

		run(t, bytes.NewReader(testutil.EncodedTPMSimulatorEKCertChain), false, nil, nil)
	})

	t.Run("IncorrectPersistentEKWithEndorsementAuth", func(t *testing.T) {
		// Test that we verify successfully using a transient EK if the persistent EK doesn't match the certificate and we have set the
		// endorsement hierarchy authorization value
		testAuth := []byte("12345")
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			// This produces a primary key that doesn't match the certificate created in TestMain
			sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
			ekContext, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), &sensitive, tcg.EKTemplate, nil, nil, nil)
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer tpm.FlushContext(ekContext)
			if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), ekContext, tcg.EKHandle, nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}

			if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), testAuth, nil); err != nil {
				t.Fatalf("HierarchyChangeAuth failed: %v", err)
			}
		}()

		run(t, bytes.NewReader(testutil.EncodedTPMSimulatorEKCertChain), false, testAuth, func(tpm *TPMConnection) {
			clearTPMWithPlatformAuth(t, tpm)
		})
	})

	t.Run("IncorrectPersistentEKWithUnknownEndorsementAuth", func(t *testing.T) {
		// Verify that we get the expected error if the persistent EK doesn't match the certificate and we can't create a transient EK
		testAuth := []byte("12345")
		func() {
			tpm := connectAndClear(t)
			defer closeTPM(t, tpm)

			// This produces a primary key that doesn't match the certificate created in TestMain
			sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
			ekContext, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), &sensitive, tcg.EKTemplate, nil, nil, nil)
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer tpm.FlushContext(ekContext)
			if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), ekContext, tcg.EKHandle, nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}

			if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), testAuth, nil); err != nil {
				t.Fatalf("HierarchyChangeAuth failed: %v", err)
			}
		}()

		defer func() {
			tpm, err := ConnectToDefaultTPM()
			if err != nil {
				t.Fatalf("ConnectToTPM failed: %v", err)
			}
			defer closeTPM(t, tpm)
			clearTPMWithPlatformAuth(t, tpm)
		}()

		_, err := SecureConnectToDefaultTPM(bytes.NewReader(testutil.EncodedTPMSimulatorEKCertChain), nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if _, ok := err.(TPMVerificationError); !ok {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}
