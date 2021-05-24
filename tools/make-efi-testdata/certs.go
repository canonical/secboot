package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/xerrors"
)

type certData struct {
	name   string
	issuer string

	extKeyUsage  []x509.ExtKeyUsage
	isCA         bool
	keyUsage     x509.KeyUsage
	serialNumber *big.Int
	subject      pkix.Name

	saveDER bool
}

var certDatas = []certData{
	{
		name:         "TestRoot1",
		isCA:         true,
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		serialNumber: big.NewInt(1),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test Root CA",
		},
	},
	{
		name:         "TestKek1.1",
		issuer:       "TestRoot1",
		isCA:         true,
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		serialNumber: big.NewInt(1001),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test KEK 1",
		},
	},
	{
		name:         "TestUefiCA1.1",
		issuer:       "TestRoot1",
		isCA:         true,
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		serialNumber: big.NewInt(1002),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI CA 1",
		},
	},
	{
		name:         "TestUefiSigning1.1.1",
		issuer:       "TestUefiCA1.1",
		extKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
		serialNumber: big.NewInt(1),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI Secure Boot Signing 1",
		},
	},
	{
		name:         "TestUefiCA1.2",
		issuer:       "TestRoot1",
		isCA:         true,
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		serialNumber: big.NewInt(1003),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI CA 2",
		},
	},
	{
		name:         "TestUefiSigning1.2.1",
		issuer:       "TestUefiCA1.2",
		extKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
		serialNumber: big.NewInt(1),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI Secure Boot Signing 1",
		},
	},
	{
		name:         "TestShimVendorCA",
		isCA:         true,
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		serialNumber: big.NewInt(1),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Vendor Inc."},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI Vendor CA",
		},
		saveDER: true,
	},
	{
		name:         "TestShimVendorSigning.1",
		issuer:       "TestShimVendorCA",
		extKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
		serialNumber: big.NewInt(1001),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Vendor Inc."},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI Vendor Secure Boot Signing 1",
		},
	},
	{
		name:         "TestRoot2",
		isCA:         true,
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		serialNumber: big.NewInt(1),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Another Fake Corporation"},
			Locality:     []string{"Cambridge"},
			Province:     []string{"England"},
			CommonName:   "Test Root CA",
		},
	},
	{
		name:         "TestKek2.1",
		issuer:       "TestRoot2",
		isCA:         true,
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		serialNumber: big.NewInt(1001),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Another Fake Corporation"},
			Locality:     []string{"Cambridge"},
			Province:     []string{"England"},
			CommonName:   "Test KEK 1",
		},
	},
	{
		name:         "TestUefiCA2.1",
		issuer:       "TestRoot2",
		isCA:         true,
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		serialNumber: big.NewInt(1002),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Another Fake Corporation"},
			Locality:     []string{"Cambridge"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI CA 1",
		},
	},
	{
		name:         "TestUefiSigning2.1.1",
		issuer:       "TestUefiCA2.1",
		extKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
		serialNumber: big.NewInt(1),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Another Fake Corporation"},
			Locality:     []string{"Cambridge"},
			Province:     []string{"England"},
			CommonName:   "Test UEFI Secure Boot Signing 1",
		},
	},
	{
		name:         "TestTimestampCA",
		isCA:         true,
		keyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		serialNumber: big.NewInt(1),
		subject: pkix.Name{
			Country:      []string{"GB"},
			Organization: []string{"Fake Corporation"},
			Locality:     []string{"London"},
			Province:     []string{"England"},
			CommonName:   "Test Timestamp CA",
		},
	},
}

func decodePEM(path, t string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("no PEM block")
	}

	if b.Type != t {
		return nil, fmt.Errorf("unexpected PEM block \"%s\"", b.Type)
	}

	return b.Bytes, nil
}

func readRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := decodePEM(path, "RSA PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(data)
}

func makeCertificate(srcDir string, certs map[string][]byte, data *certData) error {
	template := &x509.Certificate{
		BasicConstraintsValid: true,
		ExtKeyUsage:           data.extKeyUsage,
		IsCA:                  data.isCA,
		KeyUsage:              data.keyUsage,
		NotAfter:              time.Date(2120, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:             time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		SerialNumber:          data.serialNumber,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		Subject:               data.subject,
	}

	issuer := template
	if data.issuer != "" {
		issuerBytes, ok := certs[data.issuer]
		if !ok {
			for _, data := range certDatas {
				if data.name == data.issuer {
					if err := makeCertificate(srcDir, certs, &data); err != nil {
						return xerrors.Errorf("cannot create issuer %s: %w", data.issuer, err)
					}
					issuerBytes = certs[data.issuer]
					break
				}
			}
		}
		var err error
		issuer, err = x509.ParseCertificate(issuerBytes)
		if err != nil {
			return err
		}
	}

	key, err := readRSAPrivateKey(filepath.Join(srcDir, "keys", data.name+".key"))
	if err != nil {
		return xerrors.Errorf("cannot read key: %w", err)
	}
	pubKey := &key.PublicKey

	if data.issuer != "" {
		var err error
		key, err = readRSAPrivateKey(filepath.Join(srcDir, "keys", data.issuer+".key"))
		if err != nil {
			return xerrors.Errorf("cannot read key: %w", err)
		}
	}

	h := sha1.Sum(x509.MarshalPKCS1PublicKey(pubKey))
	pubKeySha1 := h[:]

	if !data.isCA {
		template.SubjectKeyId = pubKeySha1
	}

	rng, err := newSeededRNG(pubKeySha1, []byte("CERT-SIGN"))
	certBytes, err := x509.CreateCertificate(rng, template, issuer, pubKey, key)
	if err != nil {
		return err
	}

	certs[data.name] = certBytes

	return nil
}

func makeCertificates(srcDir string) (out map[string][]byte, err error) {
	out = make(map[string][]byte)

	for _, data := range certDatas {
		if err := makeCertificate(srcDir, out, &data); err != nil {
			return nil, xerrors.Errorf("cannot make certificate: %s: %w", data.name, err)
		}
	}
	return out, nil
}

func writeCertificates(srcDir, dstDir string) error {
	out := make(map[string][]byte)

	for _, data := range certDatas {
		if !data.saveDER {
			continue
		}
		if err := makeCertificate(srcDir, out, &data); err != nil {
			return xerrors.Errorf("cannot make certificate %s: %w", data.name, err)
		}
		if err := ioutil.WriteFile(filepath.Join(dstDir, data.name+".cer"), out[data.name], 0644); err != nil {
			return xerrors.Errorf("cannot write certificate %s: %w", data.name, err)
		}
	}

	return nil
}

func readSrcCertificates(srcDir string, certs map[string][]byte) error {
	paths, _ := filepath.Glob(filepath.Join(srcDir, "certs", "*.crt"))
	for _, p := range paths {
		data, err := decodePEM(p, "CERTIFICATE")
		if err != nil {
			return xerrors.Errorf("cannot decode %s: %w", p, err)
		}

		name := filepath.Base(strings.TrimSuffix(p, filepath.Ext(p)))
		certs[name] = data
	}

	return nil
}
