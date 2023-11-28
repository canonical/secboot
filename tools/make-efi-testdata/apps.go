package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"golang.org/x/xerrors"

	efi "github.com/canonical/go-efilib"
	"github.com/snapcore/secboot/internal/testutil"
)

var crossToolchains = map[string]string{
	"amd64": "x86_64-linux-gnu-",
}

type mockAppData struct {
	path          string
	name          string
	makeExtraArgs []string

	signKeys  []string
	signCerts [][]byte
	filename  string
}

func newMockAppData(srcDir, vendorCertDir string, certs map[string][]byte) []mockAppData {
	return []mockAppData{
		{
			path: filepath.Join(srcDir, "shim"),
			name: "mockshim",
			makeExtraArgs: []string{
				"VENDOR_CERT_FILE=" + filepath.Join(vendorCertDir, "TestShimVendorCA.cer"),
				"SHIM_VERSION=15.7",
				"SBAT_VAR_PREVIOUS=sbat,1,2022052400\\\\ngrub,2\\\\n",
				"SBAT_VAR_LATEST=sbat,1,2022111500\\\\nshim,2\\\\ngrub,3\\\\n",
				"WITH_SBAT=1",
				"WITH_SBATLEVEL=1"},
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts: [][]byte{certs["TestUefiSigning1.1.1"]},
			filename:  "mockshim.efi.signed.1.1.1",
		},
		{
			path: filepath.Join(srcDir, "shim"),
			name: "mockshim",
			makeExtraArgs: []string{
				"VENDOR_CERT_FILE=" + filepath.Join(vendorCertDir, "TestShimVendorCA.cer"),
				"SHIM_VERSION=15.3",
				"WITH_SBAT=1"},
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts: [][]byte{certs["TestUefiSigning1.1.1"]},
			filename:  "mockshim_initial_sbat.efi.signed.1.1.1",
		},
		{
			path: filepath.Join(srcDir, "shim"),
			name: "mockshim",
			makeExtraArgs: []string{
				"SHIM_VERSION=15.7",
				"SBAT_VAR_PREVIOUS=sbat,1,2022052400\\\\ngrub,2\\\\n",
				"SBAT_VAR_LATEST=sbat,1,2022111500\\\\nshim,2\\\\ngrub,3\\\\n",
				"WITH_SBAT=1",
				"WITH_SBATLEVEL=1"},
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts: [][]byte{certs["TestUefiSigning1.1.1"]},
			filename:  "mockshim_no_vendor_cert.efi.signed.1.1.1",
		},
		{
			path: filepath.Join(srcDir, "shim"),
			name: "mockshim",
			makeExtraArgs: []string{
				"VENDOR_DB_FILE=" + filepath.Join(vendorCertDir, "TestShimVendorCA.esl"),
				"SHIM_VERSION=15.7",
				"SBAT_VAR_PREVIOUS=sbat,1,2022052400\\\\ngrub,2\\\\n",
				"SBAT_VAR_LATEST=sbat,1,2022111500\\\\nshim,2\\\\ngrub,3\\\\n",
				"WITH_SBAT=1",
				"WITH_SBATLEVEL=1"},
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts: [][]byte{certs["TestUefiSigning1.1.1"]},
			filename:  "mockshim_vendor_db.efi.signed.1.1.1",
		},
		{
			path: filepath.Join(srcDir, "shim"),
			name: "mockshim",
			makeExtraArgs: []string{
				"VENDOR_CERT_FILE=" + filepath.Join(vendorCertDir, "TestShimVendorCA.cer"),
				"SHIM_VERSION=15.7",
				"SBAT_VAR_PREVIOUS=sbat,1,2022052400\\\\ngrub,2\\\\n",
				"SBAT_VAR_LATEST=sbat,1,2022111500\\\\nshim,2\\\\ngrub,3\\\\n",
				"WITH_SBAT=1",
				"WITH_SBATLEVEL=1"},
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.2.1.key"), filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts: [][]byte{certs["TestUefiSigning1.2.1"], certs["TestUefiSigning1.1.1"]},
			filename:  "mockshim.efi.signed.1.2.1+1.1.1",
		},
		{
			path: filepath.Join(srcDir, "shim"),
			name: "mockshim",
			makeExtraArgs: []string{
				"VENDOR_CERT_FILE=" + filepath.Join(vendorCertDir, "TestShimVendorCA.cer"),
				"SHIM_VERSION=15.2"},
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts: [][]byte{certs["TestUefiSigning1.1.1"]},
			filename:  "mockshim_no_sbat.efi.signed.1.1.1",
		},
		{
			path: filepath.Join(srcDir, "grub"),
			name: "mockgrub",
			makeExtraArgs: []string{
				"GRUB_PREFIX=/EFI/ubuntu",
				"WITH_SBAT=1",
			},
			filename: "mockgrub.efi",
		},
		{
			path: filepath.Join(srcDir, "grub"),
			name: "mockgrub_debian",
			makeExtraArgs: []string{
				"GRUB_PREFIX=/EFI/debian",
				"WITH_SBAT=1",
			},
			filename: "mockgrub_debian.efi",
		},
		{
			path:          filepath.Join(srcDir, "grub"),
			name:          "mockgrub_no_prefix",
			makeExtraArgs: []string{"WITH_SBAT=1"},
			filename:      "mockgrub_no_prefix.efi",
		},
		{
			path:     filepath.Join(srcDir, "kernel"),
			name:     "mockkernel1",
			filename: "mockkernel1.efi",
		},
	}
}

func makeOneMockApp(tmpDir, dstDir string, data *mockAppData, arch string) error {
	dir, err := ioutil.TempDir(tmpDir, "mockapp.")
	if err != nil {
		return xerrors.Errorf("cannot create build directory: %w", err)
	}

	efiName := data.name + ".efi"

	args := []string{
		"TOPDIR=" + data.path,
		"NAME=" + data.name}
	args = append(args, data.makeExtraArgs...)

	if runtime.GOARCH != arch {
		args = append(args, "CROSS_COMPILE="+crossToolchains[arch])
	}
	args = append(args, "-f", filepath.Join(data.path, "Makefile"), efiName)

	cmd := exec.Command("make", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return xerrors.Errorf("make failed: %w", err)
	}

	for i, key := range data.signKeys {
		cert, err := ioutil.TempFile(tmpDir, "cert.")
		if err != nil {
			return xerrors.Errorf("cannot create cert: %w", err)
		}
		defer cert.Close()

		b := pem.Block{Type: "CERTIFICATE", Bytes: data.signCerts[i]}
		if _, err := cert.Write(pem.EncodeToMemory(&b)); err != nil {
			return xerrors.Errorf("cannot write cert: %w", err)
		}
		cert.Close()

		cmd := exec.Command("sbsign", "--key", key, "--cert", cert.Name(), "--output", efiName, efiName)
		cmd.Dir = dir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return xerrors.Errorf("cannot sign app: %w", err)
		}
	}

	if err := os.MkdirAll(filepath.Join(dstDir, arch), 0755); err != nil {
		return err
	}

	return testutil.CopyFile(filepath.Join(dstDir, arch, data.filename), filepath.Join(dir, efiName), 0644)
}

func writeShimVendorCertificates(certs map[string][]byte, dir string) error {
	for _, c := range []string{"TestShimVendorCA"} {
		if err := ioutil.WriteFile(filepath.Join(dir, c+".cer"), certs[c], 0644); err != nil {
			return xerrors.Errorf("cannot write %s: %w", c, err)
		}
	}

	db := efi.SignatureDatabase{
		{
			Type: efi.CertX509Guid,
			Signatures: []*efi.SignatureData{
				{
					Owner: efi.MakeGUID(0x84862e0b, 0x24ee, 0x412e, 0x97b0, [...]uint8{0x4f, 0x3a, 0x33, 0x7d, 0xd2, 0xbd}),
					Data:  certs["TestShimVendorCA"],
				},
			},
		},
	}

	buf := new(bytes.Buffer)
	db.Write(buf)

	if err := ioutil.WriteFile(filepath.Join(dir, "TestShimVendorCA.esl"), buf.Bytes(), 0644); err != nil {
		return xerrors.Errorf("cannot write TestShimVendorCA.esl: %w", err)
	}

	return nil
}

func makeMockApps(srcDir, dstDir string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("unsupported OS %s", runtime.GOOS)
	}

	tmpDir, err := ioutil.TempDir("", "gen-efi-testdata.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	certs, err := makeCertificates(srcDir)
	if err != nil {
		return xerrors.Errorf("cannot make certificates: %w", err)
	}

	if err := writeShimVendorCertificates(certs, tmpDir); err != nil {
		return xerrors.Errorf("cannot write certificates to tmpdir: %w", err)
	}

	for _, data := range newMockAppData(srcDir, tmpDir, certs) {
		if err := makeOneMockApp(tmpDir, dstDir, &data, "amd64"); err != nil {
			return xerrors.Errorf("cannot create %s: %w", data.name, err)
		}
	}

	return nil
}
