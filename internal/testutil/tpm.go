// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package testutil

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/tcti"
	"github.com/snapcore/secboot/internal/truststore"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"
	"github.com/snapcore/snapd/snap"

	"golang.org/x/xerrors"
)

var (
	useTpm         bool
	tpmPathForTest string

	UseMssim  bool // Whether use of the TPM simulator is requested
	MssimPort uint // The port number of the TPM interface TCP port

	// EncodedTPMSimulatorEKCertChain is the data that will be passed to secboot.SecureConnectToDefaultTPM
	// when OpenTPMSimulatorForTesting is called.
	EncodedTPMSimulatorEKCertChain []byte
)

func init() {
	flag.BoolVar(&useTpm, "use-tpm", false, "")
	flag.StringVar(&tpmPathForTest, "tpm-path", "/dev/tpm0", "")

	flag.BoolVar(&UseMssim, "use-mssim", false, "")
	flag.UintVar(&MssimPort, "mssim-port", 2321, "")
}

// TPMSimulatorOptions provide the options to LaunchTPMSimulator
type TPMSimulatorOptions struct {
	SourceDir      string // Source directory for the persistent data file
	Manufacture    bool   // Indicates that the simulator should be executed in re-manufacture mode
	SavePersistent bool   // Saves the persistent data file back to SourceDir on exit
}

// LaunchTPMSimulator launches a TPM simulator. A new temporary directory will be created in which the
// simulator will store its persistent data, which will be cleaned up on exit. If opts.SourceDir is
// provided, a pre-existing persistent data file will be copied from this directory to the temporary
// directory. If opts.SavePersistent is set, the persistent data file will be copied back from the
// temporary directory to the source directory on exit.
//
// On success, it returns a function that can be used to stop the simulator and clean up its temporary
// directory.
func LaunchTPMSimulator(opts *TPMSimulatorOptions) (func(), error) {
	// Pick sensible defaults
	if opts == nil {
		opts = &TPMSimulatorOptions{Manufacture: true}
	}
	if opts.SourceDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, xerrors.Errorf("cannot determine cwd: %w", err)
		}
		opts.SourceDir = wd
	}

	// Search for a TPM simulator binary
	mssimPath := ""
	for _, p := range []string{"tpm2-simulator", "tpm2-simulator-chrisccoulson.tpm2-simulator"} {
		var err error
		mssimPath, err = exec.LookPath(p)
		if err == nil {
			break
		}
	}
	if mssimPath == "" {
		return nil, errors.New("cannot find a simulator binary")
	}

	// The TPM simulator creates its persistent storage in its current directory. Ideally, we would create
	// a unique temporary directory for it, but this doesn't work with the snap because it has its own private
	// tmpdir. Detect whether the chosen TPM simulator is a snap, determine which snap it belongs to and create
	// a temporary directory inside its common data directory instead.
	mssimSnapName := ""
	for currentPath, lastPath := mssimPath, ""; currentPath != ""; {
		dest, err := os.Readlink(currentPath)
		switch {
		case err != nil:
			if filepath.Base(currentPath) == "snap" {
				mssimSnapName, _ = snap.SplitSnapApp(filepath.Base(lastPath))
			}
			currentPath = ""
		default:
			if !filepath.IsAbs(dest) {
				dest = filepath.Join(filepath.Dir(currentPath), dest)
			}
			lastPath = currentPath
			currentPath = dest
		}
	}

	// Create the temporary directory.
	tmpRoot := ""
	if mssimSnapName != "" {
		home := os.Getenv("HOME")
		if home == "" {
			return nil, errors.New("cannot determine home directory")
		}
		tmpRoot = snap.UserCommonDataDir(home, mssimSnapName)
		if err := os.MkdirAll(tmpRoot, 0755); err != nil {
			return nil, xerrors.Errorf("cannot create snap common data dir: %w", err)
		}
	}

	mssimTmpDir, err := ioutil.TempDir(tmpRoot, "secboot.mssim")
	if err != nil {
		return nil, xerrors.Errorf("cannot create temporary directory for simulator: %w", err)
	}

	var cmd *exec.Cmd

	// At this point, we have stuff to clean up on early failure.
	cleanup := func() {
		// Defer saving the persistent data and removing the temporary directory
		defer func() {
			// Defer removal of the temporary directory
			defer os.RemoveAll(mssimTmpDir)

			if !opts.SavePersistent {
				// Nothing else to do
				return
			}

			// Open the updated persistent storage
			src, err := os.Open(filepath.Join(mssimTmpDir, "NVChip"))
			switch {
			case os.IsNotExist(err):
				// No storage - this means we failed before the simulator started
				return
			case err != nil:
				fmt.Fprintf(os.Stderr, "Cannot open TPM simulator persistent data: %v\n", err)
				return
			}
			defer src.Close()

			// Atomically write to the source directory
			dest, err := osutil.NewAtomicFile(filepath.Join(opts.SourceDir, "NVChip"), 0644, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot create new atomic file for saving TPM simulator persistent data: %v\n", err)
				return
			}
			defer dest.Cancel()

			if _, err := io.Copy(dest, src); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot copy TPM simulator persistent data: %v\n", err)
				return
			}

			if err := dest.Commit(); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot commit TPM simulator persistent data: %v\n", err)
			}
		}()

		if cmd != nil && cmd.Process != nil {
			// If we've called exec.Cmd.Start, attempt to stop the simulator.
			cleanShutdown := false
			// Defer the call to exec.Cmd.Wait or os.Process.Kill until after we've initiated the shutdown.
			defer func() {
				if cleanShutdown {
					if err := cmd.Wait(); err != nil {
						fmt.Fprintf(os.Stderr, "TPM simulator finished with an error: %v", err)
					}
				} else {
					fmt.Fprintf(os.Stderr, "Killing TPM simulator\n")
					if err := cmd.Process.Kill(); err != nil {
						fmt.Fprintf(os.Stderr, "Cannot send signal to TPM simulator: %v\n", err)
					}
				}
			}()

			tcti, err := tpm2.OpenMssim("", MssimPort, MssimPort+1)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot open TPM simulator connection for shutdown: %v\n", err)
				return
			}

			tpm, _ := tpm2.NewTPMContext(tcti)
			if err := tpm.Shutdown(tpm2.StartupClear); err != nil {
				fmt.Fprintf(os.Stderr, "TPM simulator shutdown failed: %v\n", err)
			}
			if err := tcti.Stop(); err != nil {
				fmt.Fprintf(os.Stderr, "TPM simulator stop failed: %v\n", err)
				return
			}
			if err := tpm.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "TPM simulator connection close failed: %v\n", err)
				return
			}
			cleanShutdown = true
		}
	}

	succeeded := false
	// Defer cleanup on failure
	defer func() {
		if succeeded {
			return
		}
		cleanup()
	}()

	// Copy any pre-existing persistent data in to the temporary directory
	source, err := os.Open(filepath.Join(opts.SourceDir, "NVChip"))
	switch {
	case err != nil && !os.IsNotExist(err):
		return nil, xerrors.Errorf("cannot open source persistent storage: %w", err)
	case err != nil:
		// Nothing to do
	default:
		defer source.Close()
		dest, err := os.Create(filepath.Join(mssimTmpDir, "NVChip"))
		if err != nil {
			return nil, xerrors.Errorf("cannot create temporary storage for simulator: %w", err)
		}
		defer dest.Close()
		if _, err := io.Copy(dest, source); err != nil {
			return nil, xerrors.Errorf("cannot copy persistent storage to temporary location for simulator: %w", err)
		}
	}

	var args []string
	if opts.Manufacture {
		args = append(args, "-m")
	}
	args = append(args, strconv.FormatUint(uint64(MssimPort), 10))

	cmd = exec.Command(mssimPath, args...)
	cmd.Dir = mssimTmpDir // Run from the temporary directory we created
	// The tpm2-simulator-chrisccoulson snap originally had a patch to chdir in to the root of the snap's common data directory,
	// where it would store its persistent data. We don't want this behaviour now. This environment variable exists until all
	// secboot and go-tpm2 branches have been fixed to not depend on this behaviour.
	cmd.Env = append(cmd.Env, "TPM2SIM_DONT_CD_TO_HOME=1")

	if err := cmd.Start(); err != nil {
		return nil, xerrors.Errorf("cannot start simulator: %w", err)
	}

	var tcti *tpm2.TctiMssim
	// Give the simulator 5 seconds to start up
Loop:
	for i := 0; ; i++ {
		var err error
		tcti, err = tpm2.OpenMssim("", MssimPort, MssimPort+1)
		switch {
		case err != nil && i == 4:
			return nil, xerrors.Errorf("cannot open simulator connection: %w", err)
		case err != nil:
			time.Sleep(time.Second)
		default:
			break Loop
		}
	}

	tpm, _ := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	if err := tpm.Startup(tpm2.StartupClear); err != nil {
		return nil, xerrors.Errorf("simulator startup failed: %w", err)
	}

	succeeded = true
	return cleanup, nil
}

// CreateTestCA creates a snakeoil TPM manufacturer CA certificate.
func CreateTestCA() ([]byte, crypto.PrivateKey, error) {
	serial := big.NewInt(rand.Int63())

	keyId := make([]byte, 32)
	if _, err := rand.Read(keyId); err != nil {
		return nil, nil, xerrors.Errorf("cannot obtain random key ID: %w", err)
	}

	key, err := rsa.GenerateKey(RandReader, 768)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot generate RSA key: %w", err)
	}

	t := time.Now()

	template := x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		SerialNumber:       serial,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Snake Oil TPM Manufacturer"},
			CommonName:   "Snake Oil TPM Manufacturer EK Root CA"},
		NotBefore:             t.Add(time.Hour * -24),
		NotAfter:              t.Add(time.Hour * 240),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyId}

	cert, err := x509.CreateCertificate(RandReader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot create certificate: %w", err)
	}

	return cert, key, nil
}

// CreateTestEKCert creates a snakeoil EK certificate for the TPM associated with the supplied TPMContext.
func CreateTestEKCert(tpm *tpm2.TPMContext, caCert []byte, caKey crypto.PrivateKey) ([]byte, error) {
	ek, pub, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), nil, tcg.EKTemplate, nil, nil, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot create EK: %w", err)
	}
	defer tpm.FlushContext(ek)

	serial := big.NewInt(rand.Int63())

	key := rsa.PublicKey{
		N: new(big.Int).SetBytes(pub.Unique.RSA()),
		E: 65537}

	keyId := make([]byte, 32)
	if _, err := rand.Read(keyId); err != nil {
		return nil, xerrors.Errorf("cannot obtain random key ID for EK cert: %w", err)
	}

	t := time.Now()

	tpmDeviceAttrValues := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: tcg.OIDTcgAttributeTpmManufacturer, Value: "id:49424d00"},
			pkix.AttributeTypeAndValue{Type: tcg.OIDTcgAttributeTpmModel, Value: "FakeTPM"},
			pkix.AttributeTypeAndValue{Type: tcg.OIDTcgAttributeTpmVersion, Value: "id:00010002"}}}
	tpmDeviceAttrData, err := asn1.Marshal(tpmDeviceAttrValues)
	if err != nil {
		return nil, xerrors.Errorf("cannot marshal SAN value: %2", err)
	}
	sanData, err := asn1.Marshal([]asn1.RawValue{
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tcg.SANDirectoryNameTag, IsCompound: true, Bytes: tpmDeviceAttrData}})
	if err != nil {
		return nil, xerrors.Errorf("cannot marshal SAN value: %w", err)
	}
	sanExtension := pkix.Extension{
		Id:       tcg.OIDExtensionSubjectAltName,
		Critical: true,
		Value:    sanData}

	template := x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          serial,
		NotBefore:             t.Add(time.Hour * -24),
		NotAfter:              t.Add(time.Hour * 240),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{tcg.OIDTcgKpEkCertificate},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          keyId,
		ExtraExtensions:       []pkix.Extension{sanExtension}}

	root, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, xerrors.Errorf("cannot parse CA certificate: %w", err)
	}

	cert, err := x509.CreateCertificate(RandReader, &template, root, &key, caKey)
	if err != nil {
		return nil, xerrors.Errorf("cannot create EK certificate: %w", err)
	}

	return cert, nil
}

// CertifyTPM certifies the TPM associated with the provided context with a EK certificate.
func CertifyTPM(tpm *tpm2.TPMContext, ekCert []byte) error {
	nvPub := tpm2.NVPublic{
		Index:   tcg.EKCertHandle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPPWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVPlatformCreate),
		Size:    uint16(len(ekCert))}
	index, err := tpm.NVDefineSpace(tpm.PlatformHandleContext(), nil, &nvPub, nil)
	if err != nil {
		return xerrors.Errorf("cannot define NV index for EK certificate: %w", err)
	}
	if err := tpm.NVWrite(tpm.PlatformHandleContext(), index, ekCert, 0, nil); err != nil {
		return xerrors.Errorf("cannot write EK certificate to NV index: %w", err)
	}
	return nil
}

// TrustCA adds the supplied TPM manufacturer CA certificate to the list of built-in roots.
func TrustCA(cert []byte) (restore func()) {
	h := crypto.SHA256.New()
	h.Write(cert)
	truststore.RootCAHashes = append(truststore.RootCAHashes, h.Sum(nil))
	return func() {
		truststore.RootCAHashes = truststore.RootCAHashes[:len(truststore.RootCAHashes)-1]
	}
}

// ResetTPMSimulator issues a Shutdown -> Reset -> Startup cycle of the TPM simulator and then returns a new connection.
func ResetTPMSimulator(tpm *secboot.TPMConnection, tcti *tpm2.TctiMssim) (*secboot.TPMConnection, *tpm2.TctiMssim, error) {
	if err := tpm.Shutdown(tpm2.StartupClear); err != nil {
		return nil, nil, fmt.Errorf("Shutdown failed: %v", err)
	}
	if err := tcti.Reset(); err != nil {
		return nil, nil, fmt.Errorf("resetting the TPM simulator failed: %v", err)
	}
	if err := tpm.Startup(tpm2.StartupClear); err != nil {
		return nil, nil, fmt.Errorf("Startup failed: %v", err)
	}
	if err := tpm.Close(); err != nil {
		return nil, nil, fmt.Errorf("Closing the existing connection failed: %v", err)
	}

	return OpenTPMSimulatorForTesting()
}

func OpenTPMSimulatorForTesting() (*secboot.TPMConnection, *tpm2.TctiMssim, error) {
	if !UseMssim {
		return nil, nil, nil
	}

	if useTpm && UseMssim {
		return nil, nil, errors.New("cannot specify both -use-tpm and -use-mssim")
	}

	var tcti *tpm2.TctiMssim

	restore := MockOpenDefaultTctiFn(func() (io.ReadWriteCloser, error) {
		var err error
		tcti, err = tpm2.OpenMssim("", MssimPort, MssimPort+1)
		return tcti, err
	})
	defer restore()

	var tpm *secboot.TPMConnection
	var err error
	if len(EncodedTPMSimulatorEKCertChain) > 0 {
		tpm, err = secboot.SecureConnectToDefaultTPM(bytes.NewReader(EncodedTPMSimulatorEKCertChain), nil)
	} else {
		tpm, err = secboot.ConnectToDefaultTPM()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("ConnectToDefaultTPM failed: %v", err)
	}

	return tpm, tcti, nil
}

func OpenTPMForTesting() (*secboot.TPMConnection, error) {
	if !useTpm {
		tpm, _, err := OpenTPMSimulatorForTesting()
		return tpm, err
	}

	if useTpm && UseMssim {
		return nil, errors.New("cannot specify both -use-tpm and -use-mssim")
	}

	restore := MockOpenDefaultTctiFn(func() (io.ReadWriteCloser, error) {
		return tpm2.OpenTPMDevice(tpmPathForTest)
	})
	defer restore()

	tpm, err := secboot.ConnectToDefaultTPM()
	if err != nil {
		return nil, fmt.Errorf("ConnectToDefaultTPM failed: %v", err)
	}

	return tpm, nil
}

// MockOpenDefaultTctiFn allows a test to override the default function for creating a TPM connection via
// secboot.ConnectToDefaultTPM and secboot.SecureConnectToDefaultTPM.
func MockOpenDefaultTctiFn(fn func() (io.ReadWriteCloser, error)) (restore func()) {
	origFn := tcti.OpenDefault
	tcti.OpenDefault = fn
	return func() {
		tcti.OpenDefault = origFn
	}
}

func MockEKTemplate(mock *tpm2.Public) (restore func()) {
	orig := tcg.EKTemplate
	tcg.EKTemplate = mock
	return func() {
		tcg.EKTemplate = orig
	}
}

func MakePCREventDigest(alg tpm2.HashAlgorithmId, event string) tpm2.Digest {
	h := alg.NewHash()
	h.Write([]byte(event))
	return h.Sum(nil)
}

func MakePCRValueFromEvents(alg tpm2.HashAlgorithmId, events ...string) tpm2.Digest {
	p := make(tpm2.Digest, alg.Size())
	for _, e := range events {
		h := alg.NewHash()
		h.Write(p)
		h.Write(MakePCREventDigest(alg, e))
		p = h.Sum(nil)
	}
	return p
}
