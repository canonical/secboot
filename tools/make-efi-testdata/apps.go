package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"golang.org/x/xerrors"

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
			path:          filepath.Join(srcDir, "shim"),
			name:          "mockshim_sbat",
			makeExtraArgs: []string{"VENDOR_CERT_FILE=" + filepath.Join(vendorCertDir, "TestShimVendorCA.cer"), "WITH_SBAT=1"},
			signKeys:      []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts:     [][]byte{certs["TestUefiSigning1.1.1"]},
			filename:      "mockshim_sbat.efi.signed.1.1.1",
		},
		{
			path:          filepath.Join(srcDir, "shim"),
			name:          "mockshim_sbat_no_vendor_cert",
			makeExtraArgs: []string{"WITH_SBAT=1"},
			signKeys:      []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts:     [][]byte{certs["TestUefiSigning1.1.1"]},
			filename:      "mockshim_sbat_no_vendor_cert.efi.signed.1.1.1",
		},
		{
			path:          filepath.Join(srcDir, "shim"),
			name:          "mockshim_sbat",
			makeExtraArgs: []string{"VENDOR_CERT_FILE=" + filepath.Join(vendorCertDir, "TestShimVendorCA.cer"), "WITH_SBAT=1"},
			signKeys:      []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.2.1.key")},
			signCerts:     [][]byte{certs["TestUefiSigning1.2.1"]},
			filename:      "mockshim_sbat.efi.signed.1.2.1",
		},
		{
			path:          filepath.Join(srcDir, "shim"),
			name:          "mockshim_sbat",
			makeExtraArgs: []string{"VENDOR_CERT_FILE=" + filepath.Join(vendorCertDir, "TestShimVendorCA.cer"), "WITH_SBAT=1"},
			signKeys:      []string{filepath.Join(srcDir, "keys", "TestUefiSigning2.1.1.key")},
			signCerts:     [][]byte{certs["TestUefiSigning2.1.1"]},
			filename:      "mockshim_sbat.efi.signed.2.1.1",
		},
		{
			path:          filepath.Join(srcDir, "shim"),
			name:          "mockshim_sbat",
			makeExtraArgs: []string{"VENDOR_CERT_FILE=" + filepath.Join(vendorCertDir, "TestShimVendorCA.cer"), "WITH_SBAT=1"},
			signKeys:      []string{filepath.Join(srcDir, "keys", "TestUefiSigning2.1.1.key"), filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts:     [][]byte{certs["TestUefiSigning2.1.1"], certs["TestUefiSigning1.1.1"]},
			filename:      "mockshim_sbat.efi.signed.2.1.1+1.1.1",
		},
		{
			path:          filepath.Join(srcDir, "shim"),
			name:          "mockshim_no_sbat",
			makeExtraArgs: []string{"VENDOR_CERT_FILE=" + filepath.Join(vendorCertDir, "TestShimVendorCA.cer")},
			signKeys:      []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts:     [][]byte{certs["TestUefiSigning1.1.1"]},
			filename:      "mockshim_no_sbat.efi.signed.1.1.1",
		},
		{
			path:      filepath.Join(srcDir, "app"),
			name:      "mockgrub1",
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestShimVendorSigning.1.key")},
			signCerts: [][]byte{certs["TestShimVendorSigning.1"]},
			filename:  "mockgrub1.efi.signed.shim.1",
		},
		{
			path:      filepath.Join(srcDir, "app"),
			name:      "mockgrub1",
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts: [][]byte{certs["TestUefiSigning1.1.1"]},
			filename:  "mockgrub1.efi.signed.1.1.1",
		},
		{
			path:      filepath.Join(srcDir, "app"),
			name:      "mockgrub1",
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.2.1.key")},
			signCerts: [][]byte{certs["TestUefiSigning1.2.1"]},
			filename:  "mockgrub1.efi.signed.1.2.1",
		},
		{
			path:     filepath.Join(srcDir, "app"),
			name:     "mockkernel1",
			filename: "mockkernel1.efi",
		},
		{
			path:      filepath.Join(srcDir, "app"),
			name:      "mockkernel1",
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestShimVendorSigning.1.key")},
			signCerts: [][]byte{certs["TestShimVendorSigning.1"]},
			filename:  "mockkernel1.efi.signed.shim.1",
		},
		{
			path:      filepath.Join(srcDir, "app"),
			name:      "mockkernel1",
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.1.1.key")},
			signCerts: [][]byte{certs["TestUefiSigning1.1.1"]},
			filename:  "mockkernel1.efi.signed.1.1.1",
		},
		{
			path:      filepath.Join(srcDir, "app"),
			name:      "mockkernel1",
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestUefiSigning1.2.1.key")},
			signCerts: [][]byte{certs["TestUefiSigning1.2.1"]},
			filename:  "mockkernel1.efi.signed.1.2.1",
		},
		{
			path:      filepath.Join(srcDir, "app"),
			name:      "mockkernel2",
			signKeys:  []string{filepath.Join(srcDir, "keys", "TestShimVendorSigning.1.key")},
			signCerts: [][]byte{certs["TestShimVendorSigning.1"]},
			filename:  "mockkernel2.efi.signed.shim.1",
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
