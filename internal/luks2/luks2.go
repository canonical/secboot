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

package luks2

import (
	"bufio"
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/snapcore/snapd/osutil"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

var (
	RunDir                = "/run"
	SystemdCryptsetupPath = "/lib/systemd/systemd-cryptsetup"
)

func mkFifo() (string, func(), error) {
	// /run is not world writable but we create a unique directory here because this
	// code can be invoked by a public API and we shouldn't fail if more than one
	// process reaches here at the same time.
	dir, err := ioutil.TempDir(RunDir, filepath.Base(os.Args[0])+".")
	if err != nil {
		return "", nil, xerrors.Errorf("cannot create temporary directory: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(dir)
	}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		cleanup()
	}()

	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		return "", nil, xerrors.Errorf("cannot create FIFO: %w", err)
	}

	succeeded = true
	return fifo, cleanup, nil
}

type binaryHdr struct {
	Magic       [6]byte
	Version     uint16
	HdrSize     uint64
	SeqId       uint64
	Label       [48]byte
	CsumAlg     [32]byte
	Salt        [64]byte
	Uuid        [40]byte
	Subsystem   [48]byte
	HdrOffset   uint64
	Padding     [184]byte
	Csum        [64]byte
	Padding4096 [7 * 512]byte
}

type Uint64s uint64

func (u *Uint64s) UnmarshalText(text []byte) error {
	n, err := strconv.ParseUint(string(text), 10, 64)
	if err != nil {
		return err
	}
	*u = Uint64s(n)
	return nil
}

type Ints int

func (i *Ints) UnmarshalText(text []byte) error {
	n, err := strconv.Atoi(string(text))
	if err != nil {
		return err
	}
	*i = Ints(n)
	return nil
}

type Config struct {
	JSONSize     Uint64s `json:"json_size"`
	KeyslotsSize Uint64s `json:"keyslots_size"`
	Flags        []string
	Requirements []string
}

type Token struct {
	Type     string
	Keyslots []Ints
	Params   map[string]interface{}
}

func (t *Token) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}

	m := make(map[string]interface{})
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	for k, v := range m {
		switch k {
		case "type", "keyslots":
		default:
			t.Params[k] = v
		}
	}

	return nil
}

type Digest struct {
	Type       string
	Keyslots   []Ints
	Segments   []Ints
	Salt       []byte
	Digest     []byte
	Hash       string
	Iterations int
}

type Segment struct {
	Type        string
	Offset      uint64
	Size        uint64
	DynamicSize bool
	Encryption  string
}

func (s *Segment) UnmarshalJSON(data []byte) error {
	var d struct {
		Type       string
		Offset     Uint64s
		Size       string
		Encryption string
	}

	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	*s = Segment{
		Type:       d.Type,
		Offset:     uint64(d.Offset),
		Encryption: d.Encryption}
	if d.Size == "dynamic" {
		s.DynamicSize = true
	} else {
		n, err := strconv.ParseUint(d.Size, 10, 64)
		if err != nil {
			return err
		}
		s.Size = n
	}

	return nil
}

type Area struct {
	Type       string
	Offset     Uint64s
	Size       Uint64s
	Encryption string
	KeySize    int `json:"key_size"`
}

type AF struct {
	Type    string
	Stripes int
	Hash    string
}

type KDF struct {
	Type       string
	Salt       []byte
	Hash       string
	Iterations int
	Time       int
	Memory     int
	CPUs       int
}

type Keyslot struct {
	Type     string
	KeySize  int `json:"key_size"`
	Area     Area
	KDF      KDF
	AF       AF
	Priority *int
}

type Metadata struct {
	Keyslots map[Ints]*Keyslot
	Segments map[Ints]*Segment
	Digests  map[Ints]*Digest
	Tokens   map[Ints]*Token
	Config   Config
}

type HdrInfo struct {
	HdrSize  uint64
	Label    string
	Metadata Metadata
}

func toString(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

func getHash(alg string) crypto.Hash {
	switch alg {
	case "sha1":
		return crypto.SHA1
	case "sha224":
		return crypto.SHA224
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	default:
		return 0
	}
}

func decodeAndCheckHeader(r io.ReadSeeker, offset int64, primary bool) (*binaryHdr, error) {
	if _, err := r.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}

	var hdr binaryHdr
	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return nil, xerrors.Errorf("cannot read header: %w", err)
	}
	switch {
	case primary && bytes.Equal(hdr.Magic[:], []byte("LUKS\xba\xbe")):
	case !primary && bytes.Equal(hdr.Magic[:], []byte("SKUL\xba\xbe")):
	default:
		return nil, errors.New("invalid magic")
	}
	if hdr.Version != 2 {
		return nil, errors.New("invalid version")
	}
	if hdr.HdrSize > uint64(math.MaxInt64) {
		return nil, errors.New("header size too large")
	}
	if hdr.HdrOffset > uint64(math.MaxInt64) {
		return nil, errors.New("header offset too large")
	}
	if int64(hdr.HdrOffset) != offset {
		return nil, errors.New("invalid header offset")
	}

	csumHash := getHash(toString(hdr.CsumAlg[:]))
	if csumHash == 0 {
		return nil, errors.New("unsupported checksum alg")
	}

	h := csumHash.New()

	hdrTmp := hdr
	hdrTmp.Csum = [64]byte{}

	if err := binary.Write(h, binary.BigEndian, &hdrTmp); err != nil {
		return nil, xerrors.Errorf("cannot calculate checksum, error serializing header: %w", err)
	}
	if _, err := io.CopyN(h, r, int64(hdr.HdrSize)-int64(binary.Size(hdr))); err != nil {
		return nil, xerrors.Errorf("cannot calculate checksum, error reading JSON metadata: %w", err)
	}

	if !bytes.Equal(h.Sum(nil), hdr.Csum[0:csumHash.Size()]) {
		return nil, errors.New("invalid header checksum")
	}

	return &hdr, nil
}

func DecodeHdr(path string) (*HdrInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	primaryHdr, primaryErr := decodeAndCheckHeader(f, 0, true)

	var secondaryHdr *binaryHdr
	if primaryErr != nil {
		for _, off := range []int64{0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000} {
			secondaryHdr, err = decodeAndCheckHeader(f, off, false)
			if err == nil {
				break
			}
		}
	} else {
		secondaryHdr, _ = decodeAndCheckHeader(f, int64(primaryHdr.HdrSize), false)
	}

	// TODO: Check both JSON areas

	var hdr *binaryHdr
	switch {
	case primaryHdr != nil && secondaryHdr != nil:
		hdr = primaryHdr
		if secondaryHdr.SeqId > primaryHdr.SeqId {
			hdr = secondaryHdr
		}
	case primaryHdr != nil:
		hdr = primaryHdr
	case secondaryHdr != nil:
		hdr = secondaryHdr
	default:
		return nil, xerrors.Errorf("no valid header found, error from decoding primary header: %w", err)
	}

	info := &HdrInfo{
		HdrSize: hdr.HdrSize,
		Label:   toString(hdr.Label[:])}

	if _, err := f.Seek(int64(hdr.HdrOffset)+int64(binary.Size(hdr)), io.SeekStart); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&info.Metadata); err != nil {
		return nil, err
	}

	return info, nil
}

func Activate(volumeName, sourceDevicePath string, key []byte, options []string) error {
	fifoPath, cleanupFifo, err := mkFifo()
	if err != nil {
		return xerrors.Errorf("cannot create FIFO for passing key to systemd-cryptsetup: %w", err)
	}
	defer cleanupFifo()

	cmd := exec.Command(SystemdCryptsetupPath, "attach", volumeName, sourceDevicePath, fifoPath, strings.Join(options, ","))
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "SYSTEMD_LOG_TARGET=console")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return xerrors.Errorf("cannot create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return xerrors.Errorf("cannot create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		rd := bufio.NewScanner(stdout)
		for rd.Scan() {
			fmt.Printf("systemd-cryptsetup: %s\n", rd.Text())
		}
		wg.Done()
	}()
	go func() {
		rd := bufio.NewScanner(stderr)
		for rd.Scan() {
			fmt.Fprintf(os.Stderr, "systemd-cryptsetup: %s\n", rd.Text())
		}
		wg.Done()
	}()

	f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
	if err != nil {
		// If we fail to open the write end, the read end will be blocked in open()
		cmd.Process.Kill()
		return xerrors.Errorf("cannot open FIFO for passing key to systemd-cryptsetup: %w", err)
	}

	if _, err := f.Write(key); err != nil {
		f.Close()
		// The read end is open and blocked inside read(). Closing our write end will result in the
		// read end returning 0 bytes (EOF) and exitting cleanly.
		cmd.Wait()
		return xerrors.Errorf("cannot pass key to systemd-cryptsetup: %w", err)
	}

	f.Close()
	wg.Wait()

	return cmd.Wait()
}

func AddKey(devicePath string, existingKey, key []byte, extraOptionArgs []string) error {
	fifoPath, cleanupFifo, err := mkFifo()
	if err != nil {
		return xerrors.Errorf("cannot create FIFO for passing existing key to cryptsetup: %w", err)
	}
	defer cleanupFifo()

	args := []string{
		// add a new key
		"luksAddKey",
		// read existing key from named pipe
		"--key-file", fifoPath}
	args = append(args, extraOptionArgs...)
	args = append(args,
		// container to add key to
		devicePath,
		// read new key from stdin
		"-")
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = bytes.NewReader(key)

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b

	if err := cmd.Start(); err != nil {
		return xerrors.Errorf("cannot start cryptsetup: %w", err)
	}

	f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
	if err != nil {
		// If we fail to open the write end, the read end will be blocked in open()
		cmd.Process.Kill()
		return xerrors.Errorf("cannot open FIFO for passing existing key to cryptsetup: %w", err)
	}

	if _, err := f.Write(existingKey); err != nil {
		f.Close()
		// The read end is open and blocked inside read(). Closing our write end will result in the
		// read end returning 0 bytes (EOF) and exitting cleanly.
		cmd.Wait()
		return xerrors.Errorf("cannot pass existing key to cryptsetup: %w", err)
	}

	f.Close()
	if err := cmd.Wait(); err != nil {
		return osutil.OutputErr(b.Bytes(), err)
	}
	return nil
}

func SetKeyslotPreferred(devicePath string, slot int) error {
	cmd := exec.Command("cryptsetup", "config", "--priority", "prefer", "--key-slot", strconv.Itoa(slot), devicePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}

	return nil
}
