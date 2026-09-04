// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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
 */

package preinstall_test

import (
	"crypto"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	secboot_efi "github.com/snapcore/secboot/efi"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

const hpPreBootDMAConfigEventData = `"SVM CPU Virtualization":"Enable";"DMA protection":"Enable";"Pre-boot DMA protection":"All PCIe devices";`

func newLogWithHPPreBootDMAConfigEvent(c *C) *tcglog.Log {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	event := &tcglog.Event{
		PCRIndex:  internal_efi.SecureBootPolicyPCR,
		EventType: tcglog.EventTypeEFIAction,
		Digests: tcglog.DigestMap{
			tpm2.HashAlgorithmSHA256: tcglog.ComputeStringEventDigest(crypto.SHA256, hpPreBootDMAConfigEventData),
		},
		Data: tcglog.StringEventData(hpPreBootDMAConfigEventData),
	}

	var events []*tcglog.Event
	added := false
	for _, ev := range log.Events {
		if ev.PCRIndex == internal_efi.SecureBootPolicyPCR &&
			ev.EventType == tcglog.EventTypeEFIVariableDriverConfig &&
			!added {
			events = append(events, event)
			added = true
		}
		events = append(events, ev)
	}
	c.Assert(added, testutil.IsTrue)
	log.Events = events
	return log
}

func hpPreBootDMAConfigTestVars(c *C) efitest.MockVars {
	return efitest.MockVars{
		{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
		{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
		{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
		{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))
}

func hpPreBootDMAConfigTestIBL(c *C) secboot_efi.Image {
	return &mockImage{
		signatures: []*efi.WinCertificateAuthenticode{
			efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
		},
		digest: testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
	}
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesGoodWithHPPreBootDMAConfig(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(hpPreBootDMAConfigTestVars(c)),
			efitest.WithLog(newLogWithHPPreBootDMAConfigEvent(c)),
		),
		pcrAlg:        tpm2.HashAlgorithmSHA256,
		iblImage:      hpPreBootDMAConfigTestIBL(c),
		expectedFlags: SecureBootPolicyResultFlags(0),
		expectedUsedAuthorities: []*X509CertificateID{
			NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert)),
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr7Suite) checkHPPreBootDMAConfigLog(c *C, log *tcglog.Log) error {
	return s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(hpPreBootDMAConfigTestVars(c)),
			efitest.WithLog(log),
		),
		pcrAlg:   tpm2.HashAlgorithmSHA256,
		iblImage: hpPreBootDMAConfigTestIBL(c),
		expectedUsedAuthorities: []*X509CertificateID{
			NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert)),
		},
	})
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesRejectsHPPreBootDMAConfigWithWrongDigest(c *C) {
	log := newLogWithHPPreBootDMAConfigEvent(c)
	for _, ev := range log.Events {
		if internal_efi.IsHPPreBootDMAConfigEvent(ev) {
			ev.Digests[tpm2.HashAlgorithmSHA256] = make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size())
		}
	}

	err := s.checkHPPreBootDMAConfigLog(c, log)
	c.Check(err, ErrorMatches, `invalid digest for HP pre-boot DMA configuration event`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesRejectsDuplicateHPPreBootDMAConfig(c *C) {
	log := newLogWithHPPreBootDMAConfigEvent(c)
	var events []*tcglog.Event
	for _, ev := range log.Events {
		events = append(events, ev)
		if internal_efi.IsHPPreBootDMAConfigEvent(ev) {
			events = append(events, ev)
		}
	}
	log.Events = events

	err := s.checkHPPreBootDMAConfigLog(c, log)
	c.Check(err, ErrorMatches, `unexpected EV_EFI_ACTION event .* before config`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesRejectsMisplacedHPPreBootDMAConfig(c *C) {
	log := newLogWithHPPreBootDMAConfigEvent(c)
	var (
		events  []*tcglog.Event
		hpEvent *tcglog.Event
		added   bool
	)
	for _, ev := range log.Events {
		if internal_efi.IsHPPreBootDMAConfigEvent(ev) {
			hpEvent = ev
			continue
		}
		events = append(events, ev)
		if ev.PCRIndex == internal_efi.SecureBootPolicyPCR &&
			ev.EventType == tcglog.EventTypeEFIVariableDriverConfig &&
			!added {
			events = append(events, hpEvent)
			added = true
		}
	}
	c.Assert(hpEvent, NotNil)
	c.Assert(added, testutil.IsTrue)
	log.Events = events

	err := s.checkHPPreBootDMAConfigLog(c, log)
	c.Check(err, ErrorMatches, `unexpected EV_EFI_ACTION event .* whilst measuring config`)
}
