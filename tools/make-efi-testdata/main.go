package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/canonical/go-sp800.90a-drbg"

	"golang.org/x/xerrors"
)

var rngSeed = []byte{0x45, 0xef, 0xa4, 0xe4, 0x6a, 0xb7, 0x55, 0x14, 0xcd, 0xce, 0xc2, 0x17, 0x59, 0x77, 0x1a, 0x95,
	0x2e, 0x35, 0x55, 0xfd, 0x94, 0x39, 0x0e, 0x9d, 0x90, 0xbf, 0x7a, 0x3c, 0xc2, 0xe3, 0x9a, 0x84}

func newSeededRNG(nonce, personalization []byte) (*drbg.DRBG, error) {
	return drbg.NewCTRWithExternalEntropy(32, rngSeed, nonce, personalization, nil)
}

func cleanEnv() error {
	os.Clearenv()
	return os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("Usage: %s <in> <out>", os.Args[0])
	}

	srcDir := os.Args[1]
	dstDir := os.Args[2]

	srcDir, err := filepath.Abs(srcDir)
	if err != nil {
		return xerrors.Errorf("cannot determine absolute srcdir: %w", err)
	}

	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return xerrors.Errorf("cannot create destination directory: %w", err)
	}

	// Avoid the host environment influencing the creation of the test data.
	if err := cleanEnv(); err != nil {
		return xerrors.Errorf("cannot clean environment: %w", err)
	}

	if err := makeEFIVars(srcDir, dstDir); err != nil {
		return xerrors.Errorf("cannot create EFI variables: %w", err)
	}

	if err := makeDbUpdates(srcDir, dstDir); err != nil {
		return xerrors.Errorf("cannot create DB updates: %w", err)
	}

	if err := makeMockApps(srcDir, dstDir); err != nil {
		return xerrors.Errorf("cannot create mock EFI apps: %w", err)
	}

	if err := writeCertificates(srcDir, dstDir); err != nil {
		return xerrors.Errorf("cannot write certificates: %w", err)
	}

	if err := makeTCGLogs(srcDir, dstDir); err != nil {
		return xerrors.Errorf("cannot create mock TCG logs: %w", err)
	}

	if err := recordBuildEnv(dstDir); err != nil {
		return xerrors.Errorf("cannot record build environment: %w", err)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
