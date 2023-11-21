package main

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	efi "github.com/canonical/go-efilib"

	"golang.org/x/xerrors"
)

type esl interface {
	get() (*efi.SignatureList, error)
}

type sigDb []esl

func (d sigDb) data() ([]byte, error) {
	var db efi.SignatureDatabase
	for _, e := range d {
		l, err := e.get()
		if err != nil {
			return nil, err
		}
		db = append(db, l)
	}

	buf := new(bytes.Buffer)
	if err := db.Write(buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type devNullSha256Esl struct{}

func (e devNullSha256Esl) get() (*efi.SignatureList, error) {
	h := crypto.SHA256.New()
	return &efi.SignatureList{
		Type: efi.CertSHA256Guid,
		Signatures: []*efi.SignatureData{
			{
				Owner: efi.MakeGUID(0xa0baa8a3, 0x041d, 0x48a8, 0xbc87, [...]uint8{0xc3, 0x6d, 0x12, 0x1b, 0x5e, 0x3d}),
				Data:  h.Sum(nil),
			},
		}}, nil
}

type x509Esl struct {
	cert  []byte
	owner efi.GUID
}

func (x *x509Esl) get() (*efi.SignatureList, error) {
	return &efi.SignatureList{
		Type: efi.CertX509Guid,
		Signatures: []*efi.SignatureData{
			{
				Owner: x.owner,
				Data:  x.cert,
			},
		}}, nil
}

func (x *x509Esl) data() ([]byte, error) {
	l, err := x.get()
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := l.Write(buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type bytesPayload []byte

func (b bytesPayload) data() ([]byte, error) {
	return []byte(b), nil
}

type efiVarPayload interface {
	data() ([]byte, error)
}

type efiVarHdr struct {
	n string
	g efi.GUID
	a efi.VariableAttributes
}

func (h *efiVarHdr) name() string { return h.n }

func (h *efiVarHdr) guid() efi.GUID { return h.g }

func (h *efiVarHdr) attrs() efi.VariableAttributes { return h.a }

type dbVar struct {
	*efiVarHdr
	efiVarPayload
}

func newDbVar(name string, payload efiVarPayload) *dbVar {
	return &dbVar{
		&efiVarHdr{
			n: name,
			g: efi.ImageSecurityDatabaseGuid,
			a: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess | efi.AttributeTimeBasedAuthenticatedWriteAccess},
		payload}
}

type globalVar struct {
	*efiVarHdr
	efiVarPayload
}

func newGlobalVar(name string, attrs efi.VariableAttributes, payload efiVarPayload) *globalVar {
	return &globalVar{
		&efiVarHdr{
			n: name,
			g: efi.GlobalVariable,
			a: attrs},
		payload}
}

type efiVar interface {
	name() string
	guid() efi.GUID
	attrs() efi.VariableAttributes
	data() ([]byte, error)
}

type efiVarData struct {
	name string
	vars []efiVar
}

func newEfiVarData(srcDir string) ([]efiVarData, error) {
	certs, err := makeCertificates(srcDir)
	if err != nil {
		return nil, xerrors.Errorf("cannot make certificates: %w", err)
	}

	if err := readSrcCertificates(srcDir, certs); err != nil {
		return nil, xerrors.Errorf("cannot read src certificates: %w", err)
	}

	return []efiVarData{
		{
			name: "efivars_ms",
			vars: []efiVar{
				newGlobalVar("SecureBoot", efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess, bytesPayload([]byte{0x01})),
				newGlobalVar("PK", efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess,
					&x509Esl{
						cert:  certs["DellPK2016"],
						owner: efi.MakeGUID(0x70564dce, 0x9afc, 0x4ee3, 0x85fc, [...]uint8{0x94, 0x96, 0x49, 0xd7, 0xe4, 0x5c}),
					}),
				newGlobalVar("KEK", efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess,
					sigDb{
						&x509Esl{
							cert:  certs["MicrosoftKEK"],
							owner: efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}),
						},
					}),
				newDbVar("db", sigDb{
					&x509Esl{
						cert:  certs["MicrosoftPCA"],
						owner: efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}),
					},
					&x509Esl{
						cert:  certs["MicrosoftUefiCA"],
						owner: efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}),
					},
				}),
				newDbVar("dbx", sigDb{devNullSha256Esl{}}),
			},
		},
	}, nil
}

func makeOneEFIVar(dir string, name string, data efiVar) error {
	d, err := data.data()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("%s-%s", data.name(), data.guid())), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := binary.Write(f, binary.LittleEndian, uint32(data.attrs())); err != nil {
		return err
	}
	if _, err = f.Write(d); err != nil {
		return err
	}

	return nil
}

func makeOneEFIVars(dstDir string, data *efiVarData) error {
	dir := filepath.Join(dstDir, data.name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	for _, v := range data.vars {
		if err := makeOneEFIVar(dir, data.name, v); err != nil {
			return xerrors.Errorf("cannot create %s-%s: %w", v.name(), v.guid(), err)
		}
	}

	return nil
}

func makeEFIVars(srcDir, dstDir string) error {
	datas, err := newEfiVarData(srcDir)
	if err != nil {
		return err
	}

	for _, data := range datas {
		if err := makeOneEFIVars(dstDir, &data); err != nil {
			return xerrors.Errorf("cannot create %s: %w", data.name, err)
		}
	}

	return nil
}
