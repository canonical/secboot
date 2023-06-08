// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2023 Canonical Ltd
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

package efi_test

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	"time"

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type securebootSuite struct {
	SecureBootPolicyMixin
}

var _ = Suite(&securebootSuite{})

type testSecureBootPolicyMixinDetermineAuthorityData struct {
	dbs      []*SecureBootDB
	image    *mockImage
	expected *SecureBootAuthority
}

func (s *securebootSuite) testSecureBootPolicyMixinDetermineAuthority(c *C, data *testSecureBootPolicyMixinDetermineAuthorityData) error {
	authority, err := s.DetermineAuthority(data.dbs, data.image.newPeImageHandle())
	if err != nil {
		return err
	}
	c.Check(authority, DeepEquals, data.expected)
	return nil
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityShim(c *C) {
	db := &SecureBootDB{
		Name: Db,
		Contents: efi.SignatureDatabase{
			efitest.NewSignatureListX509(c, msPCACert, msOwnerGuid),
			efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
		},
	}

	err := s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs:   []*SecureBootDB{db},
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)),
		expected: &SecureBootAuthority{
			Source:    Db,
			Signature: db.Contents[1].Signatures[0]}})
	c.Check(err, IsNil)
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityGrub(c *C) {
	db := &SecureBootDB{
		Name: Db,
		Contents: efi.SignatureDatabase{
			efitest.NewSignatureListX509(c, msPCACert, msOwnerGuid),
			efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
		},
	}
	vendorDb := &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})}}

	err := s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs:   []*SecureBootDB{db, vendorDb},
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)),
		expected: &SecureBootAuthority{
			Source:    vendorDb.Name,
			Signature: vendorDb.Contents[0].Signatures[0]}})
	c.Check(err, IsNil)
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityGrubFromDb(c *C) {
	db := &SecureBootDB{
		Name: Db,
		Contents: efi.SignatureDatabase{
			efitest.NewSignatureListX509(c, msPCACert, msOwnerGuid),
			efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
			efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{}),
		},
	}
	vendorDb := &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})}}

	err := s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs:   []*SecureBootDB{db, vendorDb},
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, grubUbuntuSig3)),
		expected: &SecureBootAuthority{
			Source:    Db,
			Signature: db.Contents[2].Signatures[0]}})
	c.Check(err, IsNil)
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityDualSignature(c *C) {
	db := &SecureBootDB{
		Name: Db,
		Contents: efi.SignatureDatabase{
			efitest.NewSignatureListX509(c, msPCACert, msOwnerGuid),
			efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
			efitest.NewSignatureListX509(c, testUefiCACert1, testOwnerGuid),
		},
	}

	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)

	err := s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs: []*SecureBootDB{db},
		image: newMockImage().
			withDigest(sig.DigestAlgorithm(), sig.Digest()).
			sign(c, testutil.ParsePKCS1PrivateKey(c, testUefiSigningKey1_1), testutil.ParseCertificate(c, testUefiSigningCert1_1)).
			appendSignatures(sig),
		expected: &SecureBootAuthority{
			Source:    Db,
			Signature: db.Contents[2].Signatures[0]}})
	c.Check(err, IsNil)
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityDualSignatureSkipFirst(c *C) {
	db := &SecureBootDB{
		Name: Db,
		Contents: efi.SignatureDatabase{
			efitest.NewSignatureListX509(c, msPCACert, msOwnerGuid),
			efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
		},
	}

	sig := efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4)

	err := s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs: []*SecureBootDB{db},
		image: newMockImage().
			withDigest(sig.DigestAlgorithm(), sig.Digest()).
			sign(c, testutil.ParsePKCS1PrivateKey(c, testUefiSigningKey1_1), testutil.ParseCertificate(c, testUefiSigningCert1_1)).
			appendSignatures(sig),
		expected: &SecureBootAuthority{
			Source:    Db,
			Signature: db.Contents[1].Signatures[0]}})
	c.Check(err, IsNil)
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityNoAuthority(c *C) {
	db := &SecureBootDB{
		Name: Db,
		Contents: efi.SignatureDatabase{
			efitest.NewSignatureListX509(c, testUefiCACert1, testOwnerGuid),
		},
	}
	err := s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs:   []*SecureBootDB{db},
		image: newMockImage().appendSignatures(efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4))})
	c.Check(err, ErrorMatches, "cannot determine authority")
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityNoSignatures(c *C) {
	db := &SecureBootDB{Name: Db}
	err := s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs:   []*SecureBootDB{db},
		image: newMockImage()})
	c.Check(err, ErrorMatches, "no secure boot signatures")
}

type testApplySignatureDBUpdateData struct {
	vars          efitest.MockVars
	update        *SignatureDBUpdate
	mode          SignatureDBUpdateFirmwareQuirk
	newESLs       int
	newSignatures []int
	sha1hash      []byte
}

func (s *securebootSuite) testApplySignatureDBUpdate(c *C, data *testApplySignatureDBUpdateData) {
	collector := NewRootVarsCollector(efitest.NewMockHostEnvironment(data.vars, nil))
	vars := collector.Next()

	orig, origAttrs, err := vars.ReadVar(data.update.Name.Name, data.update.Name.GUID)
	c.Check(err, IsNil)

	c.Assert(ApplySignatureDBUpdate(vars, data.update, data.mode), IsNil)

	if data.newESLs == 0 {
		c.Check(collector.More(), testutil.IsFalse)
	} else {
		c.Assert(collector.More(), testutil.IsTrue)
		vars = collector.Next()

		updated, attrs, err := vars.ReadVar(data.update.Name.Name, data.update.Name.GUID)
		c.Check(err, IsNil)
		c.Check(attrs, Equals, origAttrs)

		// verify that an append was performed.
		c.Check(orig, DeepEquals, updated[:len(orig)])

		origDb, err := efi.ReadSignatureDatabase(bytes.NewReader(orig))
		c.Check(err, IsNil)

		// verify that the updated db is well formed
		updatedDb, err := efi.ReadSignatureDatabase(bytes.NewReader(updated))
		c.Check(err, IsNil)

		// verify that we get the correct number of extra signatures
		c.Check(len(updatedDb)-len(origDb), Equals, data.newESLs)
		for i := 0; i < data.newESLs; i++ {
			c.Check(updatedDb[len(origDb)+i].Signatures, HasLen, data.newSignatures[i])
		}

		// verify the digest of the contents
		h := crypto.SHA1.New()
		h.Write(updated)
		c.Check(h.Sum(nil), DeepEquals, data.sha1hash)
	}
}

func (s *securebootSuite) TestApplySignatureDBUpdateAppendOneCert(c *C) {
	// Test applying a single cert to db.
	update := efitest.GenerateSignedVariableUpdate(c,
		testutil.ParsePKCS1PrivateKey(c, testKEKKey),
		testutil.ParseCertificate(c, testKEKCert),
		Db.Name, Db.GUID,
		efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess|efi.AttributeAppendWrite,
		time.Date(2023, 6, 2, 14, 0, 0, 0, time.UTC),
		efitest.MakeVarPayload(c, testDb2(c)))
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          makeMockVars(c, withTestSecureBootConfig()),
		update:        &SignatureDBUpdate{Name: Db, Data: update},
		mode:          SignatureDBUpdateNoFirmwareQuirk,
		newESLs:       1,
		newSignatures: []int{1},
		sha1hash:      testutil.DecodeHexString(c, "6f940f3c622885caa5a334fc9da3e74ea4f55400")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateAppendExistingCert(c *C) {
	// Test applying a single duplicate cert to db works as expected.
	update := efitest.GenerateSignedVariableUpdate(c,
		testutil.ParsePKCS1PrivateKey(c, testKEKKey),
		testutil.ParseCertificate(c, testKEKCert),
		Db.Name, Db.GUID,
		efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess|efi.AttributeAppendWrite,
		time.Date(2023, 6, 2, 14, 0, 0, 0, time.UTC),
		efitest.MakeVarPayload(c, testDb2(c)))
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:     makeMockVars(c, withTestSecureBootConfig()).AppendDb(c, testDb2(c)),
		update:   &SignatureDBUpdate{Name: Db, Data: update},
		mode:     SignatureDBUpdateNoFirmwareQuirk,
		newESLs:  0,
		sha1hash: testutil.DecodeHexString(c, "6f940f3c622885caa5a334fc9da3e74ea4f55400")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateAppendMS2016DbxUpdate1(c *C) {
	// Test applying the 2016 dbx update from uefi.org.
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          makeMockVars(c, withMsSecureBootConfig()),
		update:        &SignatureDBUpdate{Name: Dbx, Data: msDbxUpdate1},
		mode:          SignatureDBUpdateNoFirmwareQuirk,
		newESLs:       1,
		newSignatures: []int{77},
		sha1hash:      testutil.DecodeHexString(c, "45cd62f8fc2a45e835ce76db192c6db382c83286")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateAppendMS2016DbxUpdate2(c *C) {
	// Test applying the 2016 dbx update from uefi.org with a different
	// quirk mode has no effect - the update doesn't duplicate any existing
	// signatures.
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          makeMockVars(c, withMsSecureBootConfig()),
		update:        &SignatureDBUpdate{Name: Dbx, Data: msDbxUpdate1},
		mode:          SignatureDBUpdateFirmwareDedupIgnoresOwner,
		newESLs:       1,
		newSignatures: []int{77},
		sha1hash:      testutil.DecodeHexString(c, "45cd62f8fc2a45e835ce76db192c6db382c83286")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateAppendMS2020DbxUpdate(c *C) {
	// Test applying the 2020 dbx update from uefi.org.
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          makeMockVars(c, withMsSecureBootConfig()),
		update:        &SignatureDBUpdate{Name: Dbx, Data: msDbxUpdate2},
		mode:          SignatureDBUpdateNoFirmwareQuirk,
		newESLs:       4,
		newSignatures: []int{1, 1, 1, 183},
		sha1hash:      testutil.DecodeHexString(c, "ba6baeecaa4cad2c2820fdc7fda08269c48afd98")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateAppendMS2020DbxUpdateOver2016Update(c *C) {
	// Test applying the 2020 dbx update from uefi.org over the 2016 update.
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          makeMockVars(c, withMsSecureBootConfig()).SetDbx(c, msDbx1(c)),
		update:        &SignatureDBUpdate{Name: Dbx, Data: msDbxUpdate2},
		mode:          SignatureDBUpdateNoFirmwareQuirk,
		newESLs:       4,
		newSignatures: []int{1, 1, 1, 156},
		sha1hash:      testutil.DecodeHexString(c, "0d4f7b720de269d82d6506199f26ad836b04ddb1")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateDedupNoQuirks(c *C) {
	// Verify that signatures are considered to be different if any of their fields is different
	// when the quirk mode is signatureDBUpdateNoFirmwareQuirk.
	testDbx := efi.SignatureDatabase{
		{
			Type: efi.CertSHA256Guid,
			Signatures: []*efi.SignatureData{
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "317650b68e9328b5c4232f1d6ca5ec9ae4fe6e5be99db36520e0ad67a4f17037")},
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "2f3e071421e7e76197943ddc7b9eca77f9fcf138a798c7e83224cfaad1544587")},
			},
		},
	}

	update := efi.SignatureDatabase{
		{
			Type: efi.CertSHA256Guid,
			Signatures: []*efi.SignatureData{
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "317650b68e9328b5c4232f1d6ca5ec9ae4fe6e5be99db36520e0ad67a4f17037")},
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "2f3e071421e7e76197943ddc7b9eca77f9fcf138a798c7e83224cfaad1544587")},
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "fa54080efe3072fb9ed5885f805d82e1e01628f104d328fea64ba6e19a444737")},
				// this is the last signature in the 20126 MS dbx update
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "45c7c8ae750acfbb48fc37527d6412dd644daed8913ccd8a24c94d856967df8e")},
			},
		},
	}
	updateAuth := efitest.GenerateSignedVariableUpdate(c,
		testutil.ParsePKCS1PrivateKey(c, testKEKKey),
		testutil.ParseCertificate(c, testKEKCert),
		Dbx.Name, Dbx.GUID,
		efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess|efi.AttributeAppendWrite,
		time.Date(2023, 6, 2, 14, 0, 0, 0, time.UTC),
		efitest.MakeVarPayload(c, update))

	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          makeMockVars(c, withSecureBootConfig(true, testPK, msSecureBootConfig, testSecureBootConfig)).SetDbx(c, msDbx1(c)).AppendDbx(c, testDbx),
		update:        &SignatureDBUpdate{Name: Dbx, Data: updateAuth},
		mode:          SignatureDBUpdateNoFirmwareQuirk,
		newESLs:       1,
		newSignatures: []int{2},
		sha1hash:      testutil.DecodeHexString(c, "57af2194a4d8c78b95ac0624a101f531db49de0e")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateDedupIgnoresOwner(c *C) {
	// Verify that signatures are considered to be duplicates if the signature data is the same even if the
	// owner GUID is different when the quirk mode is signatureDBUpdateFirmwareDedupIgnoresOwner.
	testDbx := efi.SignatureDatabase{
		{
			Type: efi.CertSHA256Guid,
			Signatures: []*efi.SignatureData{
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "317650b68e9328b5c4232f1d6ca5ec9ae4fe6e5be99db36520e0ad67a4f17037")},
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "2f3e071421e7e76197943ddc7b9eca77f9fcf138a798c7e83224cfaad1544587")},
			},
		},
	}

	update := efi.SignatureDatabase{
		{
			Type: efi.CertSHA256Guid,
			Signatures: []*efi.SignatureData{
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "317650b68e9328b5c4232f1d6ca5ec9ae4fe6e5be99db36520e0ad67a4f17037")},
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "2f3e071421e7e76197943ddc7b9eca77f9fcf138a798c7e83224cfaad1544587")},
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "fa54080efe3072fb9ed5885f805d82e1e01628f104d328fea64ba6e19a444737")},
				// this is the last signature in the 20126 MS dbx update
				{Owner: testOwnerGuid, Data: testutil.DecodeHexString(c, "45c7c8ae750acfbb48fc37527d6412dd644daed8913ccd8a24c94d856967df8e")},
			},
		},
	}
	updateAuth := efitest.GenerateSignedVariableUpdate(c,
		testutil.ParsePKCS1PrivateKey(c, testKEKKey),
		testutil.ParseCertificate(c, testKEKCert),
		Dbx.Name, Dbx.GUID,
		efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess|efi.AttributeAppendWrite,
		time.Date(2023, 6, 2, 14, 0, 0, 0, time.UTC),
		efitest.MakeVarPayload(c, update))

	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          makeMockVars(c, withSecureBootConfig(true, testPK, msSecureBootConfig, testSecureBootConfig)).SetDbx(c, msDbx1(c)).AppendDbx(c, testDbx),
		update:        &SignatureDBUpdate{Name: Dbx, Data: updateAuth},
		mode:          SignatureDBUpdateFirmwareDedupIgnoresOwner,
		newESLs:       1,
		newSignatures: []int{1},
		sha1hash:      testutil.DecodeHexString(c, "0f856566ff2cdd279da510259047cb21dc311ca4")})
}

func (s *securebootSuite) TestApplySignatureDBUpdatePK(c *C) {
	// Test that applying an update to PK does not append
	pk := efitest.NewSignatureListX509(c, testPKCert2, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde}))
	pkAuth := efitest.GenerateSignedVariableUpdate(c,
		testutil.ParsePKCS1PrivateKey(c, testPKKey1),
		testutil.ParseCertificate(c, testPKCert1),
		PK.Name, PK.GUID,
		efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess,
		time.Date(2023, 6, 2, 14, 0, 0, 0, time.UTC),
		efitest.MakeVarPayload(c, pk))

	update := &SignatureDBUpdate{Name: PK, Data: pkAuth}

	collector := NewRootVarsCollector(efitest.NewMockHostEnvironment(makeMockVars(c, withMsSecureBootConfig()), nil))
	vars := collector.Next()

	c.Assert(ApplySignatureDBUpdate(vars, update, SignatureDBUpdateNoFirmwareQuirk), IsNil)

	c.Assert(collector.More(), testutil.IsTrue)
	vars = collector.Next()

	data, attrs, err := vars.ReadVar(PK.Name, PK.GUID)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess)

	c.Check(data, DeepEquals, efitest.MakeVarPayload(c, pk))
}
