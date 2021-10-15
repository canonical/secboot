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

package tpm2_test

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

func TestConnectionIsEnabled(t *testing.T) {
	tpm, _, closeTPM := tpm2test.OpenTPMConnectionT(t,
		tpm2test.TPMFeatureOwnerHierarchy|
			tpm2test.TPMFeatureEndorsementHierarchy|
			tpm2test.TPMFeaturePlatformHierarchy|
			tpm2test.TPMFeatureNV)
	defer closeTPM()

	if !tpm.IsEnabled() {
		t.Errorf("IsEnabled returned the wrong value")
	}

	hierarchyControl := func(auth tpm2.ResourceContext, hierarchy tpm2.Handle, enable bool) {
		if err := tpm.HierarchyControl(auth, hierarchy, enable, nil); err != nil {
			t.Errorf("HierarchyControl failed: %v", err)
		}
	}

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
	run := func(t *testing.T, tcti tpm2.TCTI, hasEk bool) {
		restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
			return tcti, nil
		})
		defer restore()

		tpm, err := ConnectToDefaultTPM()
		if err != nil {
			t.Fatalf("ConnectToDefaultTPM failed: %v", err)
		}
		defer func() {
			if err := tpm.Close(); err != nil {
				t.Errorf("close failed: %v", err)
			}
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
				t.Fatalf("Connection.EndorsementKey should have returned an error")
			}
			if rc != nil {
				t.Errorf("Connection.EndorsementKey should have returned a nil context")
			}
			if err != ErrTPMProvisioning {
				t.Errorf("Connection.EndorsementKey returned an unexpected error: %v", err)
			}
		} else {
			if err != nil {
				t.Fatalf("Connection.EndorsementKey failed: %v", err)
			}
			if rc == nil {
				t.Fatalf("Connection.EndorsementKey returned a nil context")
			}
			if rc.Handle() != tcg.EKHandle {
				t.Errorf("Connection.EndorsementKey returned an unexpected context")
			}
		}
		session := tpm.HmacSession()
		if session == nil || session.Handle().Type() != tpm2.HandleTypeHMACSession {
			t.Fatalf("Connection.HmacSession returned invalid session context")
		}
	}

	t.Run("Unprovisioned", func(t *testing.T) {
		tcti := tpm2_testutil.NewTCTIT(t, 0)
		run(t, tcti, false)
	})

	t.Run("Provisioned", func(t *testing.T) {
		tpm, tcti, closeTPM := tpm2test.OpenTPMConnectionT(t,
			tpm2test.TPMFeatureOwnerHierarchy|
				tpm2test.TPMFeatureEndorsementHierarchy|
				tpm2test.TPMFeatureNV)
		if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
			t.Errorf("EnsureProvisioned failed: %v", err)
		}

		// Close the *Connection to delete the session associated with it but keep the underlying TCTI open
		tcti.SetKeepOpen(true)
		closeTPM()

		run(t, tcti.Unwrap(), true)
	})

	t.Run("InvalidEK", func(t *testing.T) {
		tpm, tcti, _ := tpm2_testutil.NewTPMContextT(t, tpm2test.TPMFeatureOwnerHierarchy|tpm2test.TPMFeatureEndorsementHierarchy|tpm2test.TPMFeatureNV)
		defer tpm.Close()

		primary, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), nil, tcg.SRKTemplate, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), primary, tcg.EKHandle, nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		run(t, tcti, false)
	})
}

func TestConnectToDefaultTPMNoTPM(t *testing.T) {
	restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
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
	if tpm2_testutil.TPMBackend != tpm2_testutil.TPMBackendMssim {
		t.SkipNow()
	}

	ekCert, err := x509.ParseCertificate(testEkCert)
	if err != nil {
		t.Fatalf("cannot parse EK cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(testCACert)
	if err != nil {
		t.Fatalf("cannot parse CA cert: %v", err)
	}

	run := func(t *testing.T, tcti tpm2.TCTI, ekCertData io.Reader, hasEk bool, auth []byte) {
		restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
			return tcti, nil
		})
		defer restore()

		tpm, err := SecureConnectToDefaultTPM(ekCertData, auth)
		if err != nil {
			if err := tcti.Close(); err != nil {
				t.Errorf("close on error failed: %v", err)
			}
			t.Fatalf("SecureConnectToDefaultTPM failed: %v", err)
		}
		defer func() {
			if err := tpm.Close(); err != nil {
				t.Errorf("close failed: %v", err)
			}
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
				t.Fatalf("Connection.EndorsementKey should have returned an error")
			}
			if rc != nil {
				t.Errorf("Connection.EndorsementKey should have returned a nil context")
			}
			if err != ErrTPMProvisioning {
				t.Errorf("Connection.EndorsementKey returned an unexpected error: %v", err)
			}
		} else {
			if err != nil {
				t.Fatalf("Connection.EndorsementKey failed: %v", err)
			}
			if rc == nil {
				t.Fatalf("Connection.EndorsementKey returned a nil context")
			}
			if rc.Handle() != tcg.EKHandle {
				t.Errorf("Connection.EndorsementKey returned an unexpected context")
			}
		}
		session := tpm.HmacSession()
		if session == nil || session.Handle().Type() != tpm2.HandleTypeHMACSession {
			t.Fatalf("Connection.HmacSession returned invalid session context")
		}
	}

	t.Run("Unprovisioned", func(t *testing.T) {
		// Test that we verify successfully with a transient EK
		tcti := tpm2_testutil.NewSimulatorTCTIT(t)

		ekCertData := new(bytes.Buffer)
		if err := EncodeEKCertificateChain(nil, []*x509.Certificate{caCert}, ekCertData); err != nil {
			t.Errorf("cannot encode EK cert chain: %v", err)
		}

		run(t, tcti, ekCertData, false, nil)
	})

	t.Run("UnprovisionedWithEndorsementAuth", func(t *testing.T) {
		// Test that we verify successfully with a transient EK when the endorsement hierarchy has an authorization value and we know it
		tpm, tcti, _ := tpm2_testutil.NewTPMSimulatorContextT(t)

		ekCertData := new(bytes.Buffer)
		if err := EncodeEKCertificateChain(nil, []*x509.Certificate{caCert}, ekCertData); err != nil {
			t.Errorf("cannot encode EK cert chain: %v", err)
		}

		testAuth := []byte("56789")
		if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), testAuth, nil); err != nil {
			t.Errorf("HierarchyChangeAuth failed: %v", err)
		}

		run(t, tcti, ekCertData, false, testAuth)
	})

	t.Run("UnprovisionedWithUnknownEndorsementAuth", func(t *testing.T) {
		// Test that we get the correct error if there is no persistent EK and we can't create a transient one
		tpm, tcti, closeTPM := tpm2_testutil.NewTPMSimulatorContextT(t)
		defer func() {
			if closeTPM == nil {
				return
			}
			closeTPM()
		}()

		ekCertData := new(bytes.Buffer)
		if err := EncodeEKCertificateChain(nil, []*x509.Certificate{caCert}, ekCertData); err != nil {
			t.Errorf("cannot encode EK cert chain: %v", err)
		}

		if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), []byte("1234"), nil); err != nil {
			t.Errorf("HierarchyChangeAuth failed: %v", err)
		}

		restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
			closeTPM = nil
			return tcti, nil
		})
		defer restore()

		_, err := SecureConnectToDefaultTPM(ekCertData, nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if err != ErrTPMProvisioning {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Provisioned", func(t *testing.T) {
		// Test that we verify successfully with the properly provisioned persistent EK
		tpm, tcti, closeTPM := tpm2test.OpenTPMSimulatorConnectionT(t)

		ekCertData := new(bytes.Buffer)
		if err := EncodeEKCertificateChain(nil, []*x509.Certificate{caCert}, ekCertData); err != nil {
			t.Errorf("cannot encode EK cert chain: %v", err)
		}

		if err := tpm.EnsureProvisioned(ProvisionModeWithoutLockout, nil); err != ErrTPMProvisioningRequiresLockout {
			t.Errorf("EnsureProvisioned failed: %v", err)
		}

		// Close the *Connection to delete the session associated with it but keep the underlying TCTI open
		tcti.SetKeepOpen(true)
		closeTPM()

		run(t, tcti.Unwrap(), ekCertData, true, nil)
	})

	t.Run("CallerProvidedEkCert", func(t *testing.T) {
		// Test that we can verify without a TPM provisioned EK certificate
		tcti := tpm2_testutil.NewSimulatorTCTIT(t)

		ekCertData := new(bytes.Buffer)
		if err := EncodeEKCertificateChain(ekCert, []*x509.Certificate{caCert}, ekCertData); err != nil {
			t.Errorf("cannot encode EK cert chain: %v", err)
		}

		run(t, tcti, ekCertData, false, nil)
	})

	t.Run("InvalidEkCert", func(t *testing.T) {
		// Test that we get the right error if the provided EK cert data is invalid
		_, tcti, closeTPM := tpm2_testutil.NewTPMSimulatorContextT(t)
		defer func() {
			if closeTPM == nil {
				return
			}
			closeTPM()
		}()

		restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
			closeTPM = nil
			return tcti, nil
		})
		defer restore()

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
		tpm, tcti, closeTPM := tpm2_testutil.NewTPMSimulatorContextT(t)
		defer func() {
			if closeTPM == nil {
				return
			}
			closeTPM()
		}()

		caCertRaw, caKey, err := tpm2test.CreateTestCA()
		if err != nil {
			t.Fatalf("createTestCA failed: %v", err)
		}
		certRaw, err := tpm2test.CreateTestEKCert(tpm, caCertRaw, caKey)
		if err != nil {
			t.Fatalf("createTestEkCert failed: %v", err)
		}
		cert, _ := x509.ParseCertificate(certRaw)
		caCert, _ := x509.ParseCertificate(caCertRaw)

		ekCertData := new(bytes.Buffer)
		if err := EncodeEKCertificateChain(cert, []*x509.Certificate{caCert}, ekCertData); err != nil {
			t.Errorf("EncodeEKCertificateChain failed: %v", err)
		}

		restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
			closeTPM = nil
			return tcti, nil
		})
		defer restore()

		_, err = SecureConnectToDefaultTPM(ekCertData, nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if _, ok := err.(EKCertVerificationError); !ok {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("IncorrectPersistentEK", func(t *testing.T) {
		// Test that we verify successfully using a transient EK if the persistent EK doesn't match the certificate
		tpm, tcti, _ := tpm2_testutil.NewTPMSimulatorContextT(t)
		defer tpm.Close()

		ekCertData := new(bytes.Buffer)
		if err := EncodeEKCertificateChain(nil, []*x509.Certificate{caCert}, ekCertData); err != nil {
			t.Errorf("cannot encode EK cert chain: %v", err)
		}

		// This produces a primary key that doesn't match the certificate created in TestMain
		sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
		ek, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), &sensitive, tcg.EKTemplate, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), ek, tcg.EKHandle, nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		run(t, tcti, ekCertData, false, nil)
	})

	t.Run("IncorrectPersistentEKWithEndorsementAuth", func(t *testing.T) {
		// Test that we verify successfully using a transient EK if the persistent EK doesn't match the certificate and we have set the
		// endorsement hierarchy authorization value
		tpm, tcti, _ := tpm2_testutil.NewTPMSimulatorContextT(t)
		defer tpm.Close()

		ekCertData := new(bytes.Buffer)
		if err := EncodeEKCertificateChain(nil, []*x509.Certificate{caCert}, ekCertData); err != nil {
			t.Errorf("cannot encode EK cert chain: %v", err)
		}

		// This produces a primary key that doesn't match the certificate created in TestMain
		sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
		ek, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), &sensitive, tcg.EKTemplate, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), ek, tcg.EKHandle, nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		testAuth := []byte("12345")
		if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), testAuth, nil); err != nil {
			t.Errorf("HierarchyChangeAuth failed: %v", err)
		}

		run(t, tcti, ekCertData, false, testAuth)
	})

	t.Run("IncorrectPersistentEKWithUnknownEndorsementAuth", func(t *testing.T) {
		// Verify that we get the expected error if the persistent EK doesn't match the certificate and we can't create a transient EK
		tpm, tcti, closeTPM := tpm2_testutil.NewTPMSimulatorContextT(t)
		defer func() {
			if closeTPM == nil {
				return
			}
			closeTPM()
		}()

		ekCertData := new(bytes.Buffer)
		if err := EncodeEKCertificateChain(nil, []*x509.Certificate{caCert}, ekCertData); err != nil {
			t.Errorf("cannot encode EK cert chain: %v", err)
		}

		// This produces a primary key that doesn't match the certificate created in TestMain
		sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
		ek, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), &sensitive, tcg.EKTemplate, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), ek, tcg.EKHandle, nil); err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}

		if err := tpm.HierarchyChangeAuth(tpm.EndorsementHandleContext(), []byte("12345"), nil); err != nil {
			t.Errorf("HierarchyChangeAuth failed: %v", err)
		}

		restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
			closeTPM = nil
			return tcti, nil
		})
		defer restore()

		_, err = SecureConnectToDefaultTPM(ekCertData, nil)
		if err == nil {
			t.Fatalf("SecureConnectToDefaultTPM should have failed")
		}
		if _, ok := err.(TPMVerificationError); !ok {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}
