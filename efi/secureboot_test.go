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
	"io/ioutil"

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
)

type securebootSuite struct {
	SecureBootPolicyMixin
}

var _ = Suite(&securebootSuite{})

type testSecureBootPolicyMixinDetermineAuthorityData struct {
	dbs      []*SecureBootDB
	image    string
	expected *SecureBootAuthority
}

func (s *securebootSuite) testSecureBootPolicyMixinDetermineAuthority(c *C, data *testSecureBootPolicyMixinDetermineAuthorityData) error {
	image, err := OpenPeImage(NewFileImage(data.image))
	c.Assert(err, IsNil)
	defer image.Close()

	authority, err := s.DetermineAuthority(data.dbs, image)
	if err != nil {
		return err
	}
	c.Check(authority, DeepEquals, data.expected)
	return nil
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityShim(c *C) {
	data, _, err := testutil.EFIReadVar("testdata/efivars_mock1", Db.Name, Db.GUID)
	c.Check(err, IsNil)

	db, err := efi.ReadSignatureDatabase(bytes.NewReader(data))
	c.Check(err, IsNil)

	err = s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs:   []*SecureBootDB{{Name: Db, Contents: db}},
		image: "testdata/amd64/mockshim.efi.signed.1.1.1",
		expected: &SecureBootAuthority{
			Source:    Db,
			Signature: db[0].Signatures[0]}})
	c.Check(err, IsNil)
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityGrub(c *C) {
	data, _, err := testutil.EFIReadVar("testdata/efivars_mock1", Db.Name, Db.GUID)
	c.Check(err, IsNil)

	db, err := efi.ReadSignatureDatabase(bytes.NewReader(data))
	c.Check(err, IsNil)

	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockshim.efi.signed.1.1.1"))
	c.Assert(err, IsNil)
	defer image.Close()

	shimImage := NewShimImageHandle(image)
	shimDb, _, err := shimImage.ReadVendorDB()
	c.Check(err, IsNil)

	err = s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs: []*SecureBootDB{
			{Name: efi.VariableDescriptor{Name: ShimName, GUID: ShimGuid}, Contents: shimDb},
			{Name: Db, Contents: db}},
		image: "testdata/amd64/mockgrub1.efi.signed.shim.1",
		expected: &SecureBootAuthority{
			Source:    efi.VariableDescriptor{Name: ShimName, GUID: ShimGuid},
			Signature: shimDb[0].Signatures[0]}})
	c.Check(err, IsNil)
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityGrubFromDb(c *C) {
	data, _, err := testutil.EFIReadVar("testdata/efivars_mock1", Db.Name, Db.GUID)
	c.Check(err, IsNil)

	db, err := efi.ReadSignatureDatabase(bytes.NewReader(data))
	c.Check(err, IsNil)

	image, err := OpenPeImage(NewFileImage("testdata/amd64/mockshim.efi.signed.1.1.1"))
	c.Assert(err, IsNil)
	defer image.Close()

	shimImage := NewShimImageHandle(image)

	shimDb, _, err := shimImage.ReadVendorDB()
	c.Check(err, IsNil)

	err = s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs: []*SecureBootDB{
			{Name: efi.VariableDescriptor{Name: ShimName, GUID: ShimGuid}, Contents: shimDb},
			{Name: Db, Contents: db}},
		image: "testdata/amd64/mockgrub1.efi.signed.1.1.1",
		expected: &SecureBootAuthority{
			Source:    Db,
			Signature: db[0].Signatures[0]}})
	c.Check(err, IsNil)
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityDualSignature(c *C) {
	data, _, err := testutil.EFIReadVar("testdata/efivars_mock1_plus_mock2", Db.Name, Db.GUID)
	c.Check(err, IsNil)

	db, err := efi.ReadSignatureDatabase(bytes.NewReader(data))
	c.Check(err, IsNil)

	err = s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs:   []*SecureBootDB{{Name: Db, Contents: db}},
		image: "testdata/amd64/mockshim.efi.signed.2.1.1+1.1.1",
		expected: &SecureBootAuthority{
			Source:    Db,
			Signature: db[1].Signatures[0]}})
	c.Check(err, IsNil)
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityDualSignatureSkipFirst(c *C) {
	data, _, err := testutil.EFIReadVar("testdata/efivars_mock2", Db.Name, Db.GUID)
	c.Check(err, IsNil)

	db, err := efi.ReadSignatureDatabase(bytes.NewReader(data))
	c.Check(err, IsNil)

	err = s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs:   []*SecureBootDB{{Name: Db, Contents: db}},
		image: "testdata/amd64/mockshim.efi.signed.2.1.1+1.1.1",
		expected: &SecureBootAuthority{
			Source:    Db,
			Signature: db[0].Signatures[0]}})
	c.Check(err, IsNil)
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityNoAuthority(c *C) {
	data, _, err := testutil.EFIReadVar("testdata/efivars_ms", Db.Name, Db.GUID)
	c.Check(err, IsNil)

	db, err := efi.ReadSignatureDatabase(bytes.NewReader(data))
	c.Check(err, IsNil)

	err = s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs:   []*SecureBootDB{{Name: Db, Contents: db}},
		image: "testdata/amd64/mockshim.efi.signed.1.1.1"})
	c.Check(err, ErrorMatches, "cannot determine authority")
}

func (s *securebootSuite) TestSecureBootPolicyMixinDetermineAuthorityNoSignatures(c *C) {
	data, _, err := testutil.EFIReadVar("testdata/efivars_ms", Db.Name, Db.GUID)
	c.Check(err, IsNil)

	db, err := efi.ReadSignatureDatabase(bytes.NewReader(data))
	c.Check(err, IsNil)

	err = s.testSecureBootPolicyMixinDetermineAuthority(c, &testSecureBootPolicyMixinDetermineAuthorityData{
		dbs:   []*SecureBootDB{{Name: Db, Contents: db}},
		image: "testdata/amd64/mockkernel1.efi"})
	c.Check(err, ErrorMatches, "no secure boot signatures")
}

type testApplySignatureDBUpdateData struct {
	vars          string
	update        string
	db            efi.VariableDescriptor
	mode          SignatureDBUpdateFirmwareQuirk
	newESLs       int
	newSignatures []int
	sha1hash      []byte
}

func (s *securebootSuite) testApplySignatureDBUpdate(c *C, data *testApplySignatureDBUpdateData) {
	contents, err := ioutil.ReadFile(data.update)
	c.Check(err, IsNil)

	update := &SignatureDBUpdate{Name: data.db, Data: contents}

	collector := NewRootVarsCollector(newMockEFIEnvironmentFromFiles(c, data.vars, ""))
	vars := collector.Next()

	orig, origAttrs, err := vars.ReadVar(data.db.Name, data.db.GUID)
	c.Check(err, IsNil)

	c.Assert(ApplySignatureDBUpdate(vars, update, data.mode), IsNil)

	if data.newESLs == 0 {
		c.Check(collector.More(), testutil.IsFalse)
	} else {
		c.Assert(collector.More(), testutil.IsTrue)
		vars = collector.Next()

		updated, attrs, err := vars.ReadVar(data.db.Name, data.db.GUID)
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
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          "testdata/efivars_mock1",
		update:        "testdata/update_mock1/db/dbupdate.bin",
		db:            Db,
		mode:          SignatureDBUpdateNoFirmwareQuirk,
		newESLs:       1,
		newSignatures: []int{1},
		sha1hash:      testutil.DecodeHexString(c, "6f940f3c622885caa5a334fc9da3e74ea4f55400")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateAppendExistingCert(c *C) {
	// Test applying a single duplicate cert to db works as expected.
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:     "testdata/efivars_mock1_plus_extra_db_ca",
		update:   "testdata/update_mock1/db/dbupdate.bin",
		db:       Db,
		mode:     SignatureDBUpdateNoFirmwareQuirk,
		newESLs:  0,
		sha1hash: testutil.DecodeHexString(c, "6f940f3c622885caa5a334fc9da3e74ea4f55400")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateAppendMS2016DbxUpdate1(c *C) {
	// Test applying the 2016 dbx update from uefi.org.
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          "testdata/efivars_ms",
		update:        "testdata/update_uefi.org_2016-08-08/dbx/dbxupdate.bin",
		db:            Dbx,
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
		vars:          "testdata/efivars_ms",
		update:        "testdata/update_uefi.org_2016-08-08/dbx/dbxupdate.bin",
		db:            Dbx,
		mode:          SignatureDBUpdateFirmwareDedupIgnoresOwner,
		newESLs:       1,
		newSignatures: []int{77},
		sha1hash:      testutil.DecodeHexString(c, "45cd62f8fc2a45e835ce76db192c6db382c83286")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateAppendMS2020DbxUpdate(c *C) {
	// Test applying the 2020 dbx update from uefi.org.
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          "testdata/efivars_ms",
		update:        "testdata/update_uefi.org_2020-10-12/dbx/dbxupdate_x64_1.bin",
		db:            Dbx,
		mode:          SignatureDBUpdateNoFirmwareQuirk,
		newESLs:       4,
		newSignatures: []int{1, 1, 1, 183},
		sha1hash:      testutil.DecodeHexString(c, "ba6baeecaa4cad2c2820fdc7fda08269c48afd98")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateAppendMS2020DbxUpdateOver2016Update(c *C) {
	// Test applying the 2020 dbx update from uefi.org over the 2016 update.
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          "testdata/efivars_ms_plus_2016_dbx_update",
		update:        "testdata/update_uefi.org_2020-10-12/dbx/dbxupdate_x64_1.bin",
		db:            Dbx,
		mode:          SignatureDBUpdateNoFirmwareQuirk,
		newESLs:       4,
		newSignatures: []int{1, 1, 1, 156},
		sha1hash:      testutil.DecodeHexString(c, "7be4a669cf84c785457bede35b859e4b39f6889e")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateWithDuplicateSomeDuplicateSignatures1(c *C) {
	// Test applying the 2020 dbx update from uefi.org over the 2016 update.
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          "testdata/efivars_ms_plus_2016_dbx_update",
		update:        "testdata/update_modified_uefi.org_2016-08-08/dbx/dbxupdate.bin",
		db:            Dbx,
		mode:          SignatureDBUpdateNoFirmwareQuirk,
		newESLs:       1,
		newSignatures: []int{2},
		sha1hash:      testutil.DecodeHexString(c, "2fcb5e8c7e36a8fe3f61fac791f8bfa883170840")})
}

func (s *securebootSuite) TestApplySignatureDBUpdateWithDuplicateSomeDuplicateSignatures2(c *C) {
	// Test applying the 2020 dbx update from uefi.org over the 2016 update.
	s.testApplySignatureDBUpdate(c, &testApplySignatureDBUpdateData{
		vars:          "testdata/efivars_ms_plus_2016_dbx_update",
		update:        "testdata/update_modified_uefi.org_2016-08-08/dbx/dbxupdate.bin",
		db:            Dbx,
		mode:          SignatureDBUpdateFirmwareDedupIgnoresOwner,
		newESLs:       1,
		newSignatures: []int{1},
		sha1hash:      testutil.DecodeHexString(c, "7ccb56bc3e88fed4a18b91fb37836a73ce893bb3")})
}

func (s *securebootSuite) TestApplySignatureDBUpdatePK(c *C) {
	// Test that applying an update to PK does not append
	contents, err := ioutil.ReadFile("testdata/update_mock1/db/dbupdate.bin")
	c.Check(err, IsNil)

	update := &SignatureDBUpdate{Name: PK, Data: contents}

	collector := NewRootVarsCollector(newMockEFIEnvironmentFromFiles(c, "testdata/efivars_mock1", ""))
	vars := collector.Next()

	c.Assert(ApplySignatureDBUpdate(vars, update, SignatureDBUpdateNoFirmwareQuirk), IsNil)

	c.Assert(collector.More(), testutil.IsTrue)
	vars = collector.Next()

	data, attrs, err := vars.ReadVar(PK.Name, PK.GUID)
	c.Check(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess)

	buf := bytes.NewBuffer(contents)
	_, err = efi.ReadTimeBasedVariableAuthentication(buf)
	c.Check(err, IsNil)

	c.Check(data, DeepEquals, buf.Bytes())
}
