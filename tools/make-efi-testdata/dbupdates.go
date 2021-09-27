package main

import (
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/canonical/go-efilib"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot/internal/testutil"
)

type modifiedMS2016DbxUpdate struct {
	key  string
	tmp  string
	cert []byte
	src  string
}

func (u *modifiedMS2016DbxUpdate) db() string { return "dbx" }

func (u *modifiedMS2016DbxUpdate) create() (string, error) {
	cert, err := ioutil.TempFile(u.tmp, "cert.")
	if err != nil {
		return "", xerrors.Errorf("cannot create cert: %w", err)
	}
	defer cert.Close()

	b := pem.Block{Type: "CERTIFICATE", Bytes: u.cert}
	if _, err := cert.Write(pem.EncodeToMemory(&b)); err != nil {
		return "", xerrors.Errorf("cannot write cert: %w", err)
	}
	cert.Close()

	f, err := os.Open(filepath.Join(u.src, "uefi.org/revocationlistfile/2016-08-08/dbxupdate.bin"))
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := efi.ReadTimeBasedVariableAuthentication(f); err != nil {
		return "", xerrors.Errorf("invalid authentication: %w", err)
	}

	db, err := efi.ReadSignatureDatabase(f)
	if err != nil {
		return "", xerrors.Errorf("invalid payload: %w", err)
	}

	if len(db) != 1 {
		return "", errors.New("unexpected number of ESLs")
	}
	if db[0].Type != efi.CertSHA256Guid {
		return "", errors.New("unexpected ESL type")
	}
	if len(db[0].Signatures) != 77 {
		return "", errors.New("unexpected number of signatures")
	}

	db[0].Signatures[10].Data[0] ^= 0xff
	db[0].Signatures[40].Owner = efi.MakeGUID(0xa0baa8a3, 0x041d, 0x48a8, 0xbc87, [...]uint8{0xc3, 0x6d, 0x12, 0x1b, 0x5e, 0x3d})

	update, err := ioutil.TempFile(u.tmp, "update.")
	if err != nil {
		return "", xerrors.Errorf("cannot create update: %w", err)
	}
	defer update.Close()

	if err := db.Write(update); err != nil {
		return "", xerrors.Errorf("cannot write update: %w", err)
	}
	update.Close()

	// This is not reproducible because the signed variable has a timestamp,
	// but this doesn't affect the tests.
	cmd := exec.Command("sbvarsign", "--key", u.key, "--cert", cert.Name(), "dbx", update.Name())
	if err := cmd.Run(); err != nil {
		return "", xerrors.Errorf("cannot sign update: %w", err)
	}

	return update.Name() + ".signed", nil
}

func (u *modifiedMS2016DbxUpdate) name() string { return "dbxupdate.bin" }

func newModifiedMS2016DbxUpdate(key, tmp string, cert []byte, srcDir string) *modifiedMS2016DbxUpdate {
	return &modifiedMS2016DbxUpdate{key, tmp, cert, srcDir}
}

type mockDbUpdate struct {
	d    string
	n    string
	key  string
	tmp  string
	cert []byte
	esls []esl
}

func newMockDbUpdate(db, name, key, tmp string, cert []byte, esls []esl) *mockDbUpdate {
	return &mockDbUpdate{db, name, key, tmp, cert, esls}
}

func (u *mockDbUpdate) db() string { return u.d }

func (u *mockDbUpdate) create() (string, error) {
	cert, err := ioutil.TempFile(u.tmp, "cert.")
	if err != nil {
		return "", xerrors.Errorf("cannot create cert: %w", err)
	}
	defer cert.Close()

	b := pem.Block{Type: "CERTIFICATE", Bytes: u.cert}
	if _, err := cert.Write(pem.EncodeToMemory(&b)); err != nil {
		return "", xerrors.Errorf("cannot write cert: %w", err)
	}
	cert.Close()

	update, err := ioutil.TempFile(u.tmp, "update.")
	if err != nil {
		return "", xerrors.Errorf("cannot create update: %w", err)
	}
	defer update.Close()

	var db efi.SignatureDatabase
	for _, esl := range u.esls {
		l, err := esl.get()
		if err != nil {
			return "", err
		}
		db = append(db, l)
	}

	if err := db.Write(update); err != nil {
		return "", xerrors.Errorf("cannot write update: %w", err)
	}
	update.Close()

	// This is not reproducible because the signed variable has a timestamp,
	// but this doesn't affect the tests.
	cmd := exec.Command("sbvarsign", "--key", u.key, "--cert", cert.Name(), u.d, update.Name())
	if err := cmd.Run(); err != nil {
		return "", xerrors.Errorf("cannot sign update: %w", err)
	}

	return update.Name() + ".signed", nil
}

func (u *mockDbUpdate) name() string { return u.n }

type dbUpdateFile struct {
	d string
	p string
	n string
}

func newDbUpdateFile(db, path, name string) *dbUpdateFile {
	return &dbUpdateFile{db, path, name}
}

func (f *dbUpdateFile) db() string              { return f.d }
func (f *dbUpdateFile) create() (string, error) { return f.p, nil }
func (f *dbUpdateFile) name() string            { return f.n }

type dbUpdate interface {
	db() string
	create() (string, error)
	name() string
}

type dbUpdateData struct {
	name    string
	updates []dbUpdate
}

func newDbUpdateData(srcDir, tmpDir string, certs map[string][]byte) []dbUpdateData {
	return []dbUpdateData{
		{
			name: "update_uefi.org_2016-08-08",
			updates: []dbUpdate{
				newDbUpdateFile("dbx", filepath.Join(srcDir, "uefi.org/revocationlistfile/2016-08-08/dbxupdate.bin"), "dbxupdate.bin"),
			},
		},
		{
			name: "update_uefi.org_2020-10-12",
			updates: []dbUpdate{
				newDbUpdateFile("dbx", filepath.Join(srcDir, "uefi.org/revocationlistfile/2020-10-12/dbxupdate_x64_1.bin"), "dbxupdate_x64_1.bin"),
			},
		},
		{
			name: "update_mock1",
			updates: []dbUpdate{
				newMockDbUpdate("db", "dbupdate.bin", filepath.Join(srcDir, "keys", "TestKek1.1.key"), tmpDir, certs["TestKek1.1"], []esl{
					&x509Esl{
						cert:  certs["TestUefiCA1.2"],
						owner: efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde}),
					},
				}),
			},
		},
		{
			name: "update_modified_uefi.org_2016-08-08",
			updates: []dbUpdate{
				newModifiedMS2016DbxUpdate(filepath.Join(srcDir, "keys", "TestKek1.1.key"), tmpDir, certs["TestKek1.1"], srcDir),
			},
		},
	}
}

func makeOneDbUpdate(dstDir string, data *dbUpdateData) error {
	for _, update := range data.updates {
		dir := filepath.Join(dstDir, data.name, update.db())
		if err := os.MkdirAll(dir, 0755); err != nil {
			return xerrors.Errorf("cannot mkdir for %s: %w", update.db(), err)
		}

		path, err := update.create()
		if err != nil {
			return xerrors.Errorf("cannot create update %s: %w", update.name(), err)
		}

		if err := testutil.CopyFile(filepath.Join(dir, update.name()), path, 0644); err != nil {
			return xerrors.Errorf("cannot copy update %s: %w", update.name(), err)
		}
	}

	return nil
}

func makeDbUpdates(srcDir, dstDir string) error {
	tmpDir, err := ioutil.TempDir("", "gen-efi-testdata.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	certs, err := makeCertificates(srcDir)
	if err != nil {
		return xerrors.Errorf("cannot make certificates: %w", err)
	}

	for _, data := range newDbUpdateData(srcDir, tmpDir, certs) {
		if err := makeOneDbUpdate(dstDir, &data); err != nil {
			return xerrors.Errorf("cannot create db update %s: %w", data.name, err)
		}
	}

	return nil
}

func extractESLsFromOneUpdate(srcDir, update string, esls map[string]*efi.SignatureList) error {
	f, err := os.Open(filepath.Join(srcDir, update))
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := efi.ReadTimeBasedVariableAuthentication(f); err != nil {
		return xerrors.Errorf("invalid authentication: %w", err)
	}

	db, err := efi.ReadSignatureDatabase(f)
	if err != nil {
		return xerrors.Errorf("invalid payload: %w", err)
	}

	for i, l := range db {
		esls[update+"."+strconv.Itoa(i)] = l
	}

	return nil
}

func extractESLsFromUpdates(srcDir string) (out map[string]*efi.SignatureList, err error) {
	out = make(map[string]*efi.SignatureList)

	for _, update := range []string{
		"uefi.org/revocationlistfile/2016-08-08/dbxupdate.bin",
		"uefi.org/revocationlistfile/2020-10-12/dbxupdate_x64_1.bin",
	} {
		if err := extractESLsFromOneUpdate(srcDir, update, out); err != nil {
			return nil, xerrors.Errorf("cannot extract ESLs from %s: %w", update, err)
		}
	}

	return out, nil
}
