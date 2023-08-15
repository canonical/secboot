// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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
	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
)

var (
	msOwnerGuid   = efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})
	testOwnerGuid = efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})
)

func testPK(c *C) *efi.SignatureList {
	return efitest.NewSignatureListX509(c, testPKCert1, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde}))
}

func msKEK(c *C) efi.SignatureDatabase {
	return efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msKEKCert, msOwnerGuid),
	}
}

func testKEK(c *C) efi.SignatureDatabase {
	return efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, testKEKCert, testOwnerGuid),
	}
}

func msDb(c *C) efi.SignatureDatabase {
	return efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, msPCACert, msOwnerGuid),
		efitest.NewSignatureListX509(c, msUefiCACert, msOwnerGuid),
	}
}

func testDb1(c *C) efi.SignatureDatabase {
	return efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, testUefiCACert1, testOwnerGuid),
	}
}

func testDb2(c *C) efi.SignatureDatabase {
	return efi.SignatureDatabase{
		efitest.NewSignatureListX509(c, testUefiCACert2, testOwnerGuid),
	}
}

func msDbx1(c *C) efi.SignatureDatabase {
	_, db := efitest.ReadSignatureDatabaseUpdate(c, msDbxUpdate1)
	return db
}

func emptyDbx() efi.SignatureDatabase {
	return efi.SignatureDatabase{
		efitest.NewSignatureListNullSHA256(efi.MakeGUID(0xa0baa8a3, 0x041d, 0x48a8, 0xbc87, [...]uint8{0xc3, 0x6d, 0x12, 0x1b, 0x5e, 0x3d})),
	}
}

type secureBootConfig struct {
	kek func(*C) efi.SignatureDatabase
	db  func(*C) efi.SignatureDatabase
	dbx func(*C) efi.SignatureDatabase
}

var (
	msSecureBootConfig   = &secureBootConfig{kek: msKEK, db: msDb}
	testSecureBootConfig = &secureBootConfig{kek: testKEK, db: testDb1}
)

func withSecureBootConfig(enabled bool, pk func(*C) *efi.SignatureList, confs ...*secureBootConfig) mockVarsConfig {
	return func(c *C, vars efitest.MockVars) {
		vars.SetSecureBoot(enabled)
		vars.SetPK(c, pk(c))

		var (
			kek efi.SignatureDatabase
			db  efi.SignatureDatabase
			dbx efi.SignatureDatabase
		)
		for _, conf := range confs {
			kek = append(kek, conf.kek(c)...)
			db = append(db, conf.db(c)...)
			if conf.dbx != nil {
				dbx = append(dbx, conf.dbx(c)...)
			}
		}
		if len(dbx) == 0 {
			dbx = emptyDbx()
		}
		vars.SetKEK(c, kek)
		vars.SetDb(c, db)
		vars.SetDbx(c, dbx)
	}
}

func withMsSecureBootConfig() mockVarsConfig {
	return withSecureBootConfig(true, testPK, msSecureBootConfig)
}

func withTestSecureBootConfig() mockVarsConfig {
	return withSecureBootConfig(true, testPK, testSecureBootConfig)
}

func withSbatLevel(level []byte) mockVarsConfig {
	return func(c *C, vars efitest.MockVars) {
		vars.Set("SbatLevelRT", ShimGuid, efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess, level)
	}
}

func withSbatPolicy(policy ShimSbatPolicy) mockVarsConfig {
	return func(c *C, vars efitest.MockVars) {
		vars.Set("SbatPolicy", ShimGuid, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess, []byte{uint8(policy)})
	}
}

func withSecureBootDisabled() mockVarsConfig {
	return func(c *C, vars efitest.MockVars) {
		vars.SetSecureBoot(false)
	}
}

type mockVarsConfig func(*C, efitest.MockVars)

func makeMockVars(c *C, confs ...mockVarsConfig) efitest.MockVars {
	vars := efitest.MakeMockVars()
	for _, conf := range confs {
		conf(c, vars)
	}
	return vars
}
