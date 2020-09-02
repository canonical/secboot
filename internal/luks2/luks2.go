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
	"time"

	"github.com/snapcore/snapd/osutil"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

var (
	RunDir                = "/run"
	SystemdCryptsetupPath = "/lib/systemd/systemd-cryptsetup"
	cryptsetupLockDir     = RunDir + "/cryptsetup"

	keySize = 64
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

type LockMode int

const (
	LockModeShared LockMode = iota
	LockModeExclusive

	LockModeTry LockMode = 1 << 8
)

func (m LockMode) mode() LockMode {
	return m & 0xff
}

func (m LockMode) try() bool {
	return m&LockModeTry > 0
}

func AcquireLock(devicePath string, mode LockMode) (release func(), err error) {
	f, err := os.Open(devicePath)
	if err != nil {
		return nil, xerrors.Errorf("cannot open device: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain file info: %w", err)
	}

	var how int
	switch mode.mode() {
	case LockModeShared:
		how = unix.LOCK_SH
	case LockModeExclusive:
		how = unix.LOCK_EX
	default:
		return nil, errors.New("invalid lock mode")
	}
	if mode.try() {
		how |= unix.LOCK_NB
	}

	isBlockDevice := func() bool {
		return fi.Mode()&os.ModeDevice > 0 && fi.Mode()&os.ModeCharDevice == 0
	}

	var lockPath string
	var devSt unix.Stat_t

	switch {
	case isBlockDevice():
		if err := os.Mkdir(cryptsetupLockDir, 0700); err != nil && !os.IsExist(err) {
			return nil, xerrors.Errorf("cannot create lock directory: %w", err)
		}

		if err := unix.Fstat(int(f.Fd()), &devSt); err != nil {
			return nil, xerrors.Errorf("cannot stat device: %w", err)
		}
		lockPath = filepath.Join(cryptsetupLockDir, fmt.Sprintf("L_%d:%d", unix.Major(devSt.Rdev), unix.Minor(devSt.Rdev)))
	case fi.Mode().IsRegular():
		lockPath = devicePath
	default:
		return nil, errors.New("unsupported file type")
	}

	for {
		lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
		if err != nil {
			return nil, xerrors.Errorf("cannot open lock file for writing: %w", err)
		}

		succeeded := false
		defer func() {
			if succeeded {
				return
			}
			lockFile.Close()
		}()

		if err := unix.Flock(int(lockFile.Fd()), how); err != nil {
			return nil, xerrors.Errorf("cannot obtain lock: %w", err)
		}

		if isBlockDevice() {
			var st unix.Stat_t
			if err := unix.Stat(lockPath, &st); err != nil {
				// The lock file we opened was unlinked by another process releasing its lock.
				lockFile.Close()
				continue
			}

			if devSt.Ino != st.Ino {
				// The lock file we opened was unlinked by another process releasing its lock and someone else
				// has created a new lock file in the meantime.
				lockFile.Close()
				continue
			}
		}

		succeeded = true
		return func() {
			unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
			defer lockFile.Close()
			if !isBlockDevice() {
				return
			}
			if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				// Another process has grabbed the lock
				return
			}
			var st unix.Stat_t
			if err := unix.Stat(lockPath, &st); err != nil {
				// Another process might have deleted the lock file we created whilst we didn't hold the exclusive lock.
				return
			}
			if devSt.Ino != st.Ino {
				// Another process might have deleted and recreated the lock file whilst we didn't hold the exclusive lock.
				return
			}
			os.Remove(lockPath)
		}, nil
	}
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

type jsonNumber string

func (n jsonNumber) int() (int, error) {
	return strconv.Atoi(string(n))
}

func (n jsonNumber) uint64() (uint64, error) {
	return strconv.ParseUint(string(n), 10, 64)
}

type Config struct {
	JSONSize     uint64
	KeyslotsSize uint64
	Flags        []string
	Requirements []string
}

func (c *Config) UnmarshalJSON(data []byte) error {
	var d struct {
		JSONSize     jsonNumber `json:"json_size"`
		KeyslotsSize jsonNumber `json:"keyslots_size"`
		Flags        []string
		Requirements []string
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	*c = Config{
		Flags:        d.Flags,
		Requirements: d.Requirements}
	jsonSize, err := d.JSONSize.uint64()
	if err != nil {
		return xerrors.Errorf("invalid json_size value: %w", err)
	}
	c.JSONSize = jsonSize

	keyslotsSize, err := d.KeyslotsSize.uint64()
	if err != nil {
		return xerrors.Errorf("invalid keyslots_size value: %w", err)
	}
	c.KeyslotsSize = keyslotsSize

	return nil
}

type Token struct {
	Type     string
	Keyslots []int
	Params   map[string]interface{}
}

func (t Token) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	for k, v := range t.Params {
		m[k] = v
	}
	m["type"] = t.Type
	var keyslots []jsonNumber
	for _, s := range t.Keyslots {
		keyslots = append(keyslots, jsonNumber(strconv.Itoa(s)))
	}
	m["keyslots"] = keyslots

	return json.Marshal(m)
}

func (t *Token) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	if ty, ok := m["type"]; ok {
		ts, ok := ty.(string)
		if !ok {
			return errors.New("invalid type field type")
		}
		t.Type = ts
	}
	delete(m, "type")

	if slots, ok := m["keyslots"]; ok {
		slotsI, ok := slots.([]interface{})
		if !ok {
			return errors.New("invalid keyslots field type")
		}
		for _, i := range slotsI {
			s, ok := i.(string)
			if !ok {
				return errors.New("invalid keyslot id type")
			}
			n, err := jsonNumber(s).int()
			if err != nil {
				return xerrors.Errorf("invalid keyslot id: %w", err)
			}
			t.Keyslots = append(t.Keyslots, n)
		}
	}
	delete(m, "keyslots")

	t.Params = m
	return nil
}

type Digest struct {
	Type       string
	Keyslots   []int
	Segments   []int
	Salt       []byte
	Digest     []byte
	Hash       string
	Iterations int
}

func (d *Digest) UnmarshalJSON(data []byte) error {
	var t struct {
		Type       string
		Keyslots   []jsonNumber
		Segments   []jsonNumber
		Salt       []byte
		Digest     []byte
		Hash       string
		Iterations int
	}
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}

	*d = Digest{
		Type:       t.Type,
		Salt:       t.Salt,
		Digest:     t.Digest,
		Hash:       t.Hash,
		Iterations: t.Iterations}

	for _, v := range t.Keyslots {
		s, err := v.int()
		if err != nil {
			return xerrors.Errorf("invalid keyslot id: %w", err)
		}
		d.Keyslots = append(d.Keyslots, s)
	}

	for _, v := range t.Segments {
		s, err := v.int()
		if err != nil {
			return xerrors.Errorf("invalid segment id: %w", err)
		}
		d.Segments = append(d.Segments, s)
	}

	return nil
}

type Integrity struct {
	Type              string
	JournalEncryption string
	JournalIntegrity  string
}

type Segment struct {
	Type        string
	Offset      uint64
	Size        uint64
	DynamicSize bool
	IVTweak     uint64
	Encryption  string
	SectorSize  int
	Integrity   *Integrity
	Flags       []string
}

func (s *Segment) UnmarshalJSON(data []byte) error {
	var d struct {
		Type       string
		Offset     jsonNumber
		Size       jsonNumber
		IVTweak    jsonNumber `json:"iv_tweak"`
		Encryption string
		SectorSize int `json:"sector_size"`
		Integrity  *Integrity
		Flags      []string
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	*s = Segment{
		Type:       d.Type,
		Encryption: d.Encryption,
		SectorSize: d.SectorSize,
		Integrity:  d.Integrity,
		Flags:      d.Flags}

	offset, err := d.Offset.uint64()
	if err != nil {
		return xerrors.Errorf("invalid offset value: %w", err)
	}
	s.Offset = offset

	switch string(d.Size) {
	case "dynamic":
		s.DynamicSize = true
	default:
		sz, err := d.Size.uint64()
		if err != nil {
			return xerrors.Errorf("invalid size value: %w", err)
		}
		s.Size = sz
	}

	ivTweak, err := d.IVTweak.uint64()
	if err != nil {
		return xerrors.Errorf("invalid iv_tweak value: %w", err)
	}
	s.IVTweak = ivTweak

	return nil
}

type Area struct {
	Type       string
	Offset     uint64
	Size       uint64
	Encryption string
	KeySize    int
}

func (a *Area) UnmarshalJSON(data []byte) error {
	var d struct {
		Type       string
		Offset     jsonNumber
		Size       jsonNumber
		Encryption string
		KeySize    int `json:"key_size"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	*a = Area{
		Type:       d.Type,
		Encryption: d.Encryption,
		KeySize:    d.KeySize}

	offset, err := d.Offset.uint64()
	if err != nil {
		return xerrors.Errorf("invalid offset value: %w", err)
	}
	a.Offset = offset

	sz, err := d.Size.uint64()
	if err != nil {
		return xerrors.Errorf("invalid size value: %w", err)
	}
	a.Size = sz

	return nil
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
	KeySize  int
	Area     *Area
	KDF      *KDF
	AF       *AF
	Priority int
}

func (s *Keyslot) UnmarshalJSON(data []byte) error {
	var d struct {
		Type     string
		KeySize  int `json:"key_size"`
		Area     *Area
		KDF      *KDF
		AF       *AF
		Priority *int
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	*s = Keyslot{
		Type:    d.Type,
		KeySize: d.KeySize,
		Area:    d.Area,
		KDF:     d.KDF,
		AF:      d.AF}
	if d.Priority != nil {
		s.Priority = *d.Priority
	} else {
		s.Priority = 1
	}
	return nil
}

type Metadata struct {
	Keyslots map[int]*Keyslot
	Segments map[int]*Segment
	Digests  map[int]*Digest
	Tokens   map[int]*Token
	Config   Config
}

func (m *Metadata) UnmarshalJSON(data []byte) error {
	var d struct {
		Keyslots map[jsonNumber]*Keyslot
		Segments map[jsonNumber]*Segment
		Digests  map[jsonNumber]*Digest
		Tokens   map[jsonNumber]*Token
		Config   Config
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	m.Keyslots = make(map[int]*Keyslot)
	for k, v := range d.Keyslots {
		id, err := k.int()
		if err != nil {
			return xerrors.Errorf("invalid keyslot index: %w", err)
		}
		m.Keyslots[id] = v
	}

	m.Segments = make(map[int]*Segment)
	for k, v := range d.Segments {
		id, err := k.int()
		if err != nil {
			return xerrors.Errorf("invalid segment index: %w", err)
		}
		m.Segments[id] = v
	}

	m.Digests = make(map[int]*Digest)
	for k, v := range d.Digests {
		id, err := k.int()
		if err != nil {
			return xerrors.Errorf("invalid digest index: %w", err)
		}
		m.Digests[id] = v
	}

	m.Tokens = make(map[int]*Token)
	for k, v := range d.Tokens {
		id, err := k.int()
		if err != nil {
			return xerrors.Errorf("invalid token index: %w", err)
		}
		m.Tokens[id] = v
	}

	m.Config = d.Config
	return nil
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

func decodeAndCheckHeader(r io.ReadSeeker, offset int64, primary bool) (*binaryHdr, []byte, error) {
	if _, err := r.Seek(offset, io.SeekStart); err != nil {
		return nil, nil, err
	}

	var hdr binaryHdr
	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return nil, nil, xerrors.Errorf("cannot read header: %w", err)
	}
	switch {
	case primary && bytes.Equal(hdr.Magic[:], []byte("LUKS\xba\xbe")):
	case !primary && bytes.Equal(hdr.Magic[:], []byte("SKUL\xba\xbe")):
	default:
		return nil, nil, errors.New("invalid magic")
	}
	if hdr.Version != 2 {
		return nil, nil, errors.New("invalid version")
	}
	if hdr.HdrSize > uint64(math.MaxInt64) {
		return nil, nil, errors.New("header size too large")
	}
	if hdr.HdrOffset > uint64(math.MaxInt64) {
		return nil, nil, errors.New("header offset too large")
	}
	if int64(hdr.HdrOffset) != offset {
		return nil, nil, errors.New("invalid header offset")
	}

	csumHash := getHash(toString(hdr.CsumAlg[:]))
	if csumHash == 0 {
		return nil, nil, errors.New("unsupported checksum alg")
	}

	h := csumHash.New()

	hdrTmp := hdr
	hdrTmp.Csum = [64]byte{}

	if err := binary.Write(h, binary.BigEndian, &hdrTmp); err != nil {
		return nil, nil, xerrors.Errorf("cannot calculate checksum, error serializing header: %w", err)
	}

	var jsonBuffer bytes.Buffer
	tr := io.TeeReader(r, &jsonBuffer)

	if _, err := io.CopyN(h, tr, int64(hdr.HdrSize)-int64(binary.Size(hdr))); err != nil {
		return nil, nil, xerrors.Errorf("cannot calculate checksum, error reading JSON metadata: %w", err)
	}

	if !bytes.Equal(h.Sum(nil), hdr.Csum[0:csumHash.Size()]) {
		return nil, nil, errors.New("invalid header checksum")
	}

	return &hdr, jsonBuffer.Bytes(), nil
}

func DecodeHdr(path string) (*HdrInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	primaryHdr, primaryJSON, primaryErr := decodeAndCheckHeader(f, 0, true)

	var secondaryHdr *binaryHdr
	var secondaryJSON []byte
	if primaryErr != nil {
		for _, off := range []int64{0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000} {
			secondaryHdr, secondaryJSON, err = decodeAndCheckHeader(f, off, false)
			if err == nil {
				break
			}
		}
	} else {
		secondaryHdr, secondaryJSON, _ = decodeAndCheckHeader(f, int64(primaryHdr.HdrSize), false)
	}

	// TODO: Check both JSON areas

	var hdr *binaryHdr
	var jsonData []byte
	switch {
	case primaryHdr != nil && secondaryHdr != nil:
		hdr = primaryHdr
		jsonData = primaryJSON
		if secondaryHdr.SeqId > primaryHdr.SeqId {
			hdr = secondaryHdr
			jsonData = secondaryJSON
		}
	case primaryHdr != nil:
		hdr = primaryHdr
		jsonData = primaryJSON
	case secondaryHdr != nil:
		hdr = secondaryHdr
		jsonData = secondaryJSON
	default:
		return nil, xerrors.Errorf("no valid header found, error from decoding primary header: %w", err)
	}

	info := &HdrInfo{
		HdrSize: hdr.HdrSize,
		Label:   toString(hdr.Label[:])}

	if err := json.NewDecoder(bytes.NewReader(jsonData)).Decode(&info.Metadata); err != nil {
		return nil, err
	}

	return info, nil
}

func Activate(volumeName, sourceDevicePath string, key []byte, options []string) error {
	var activateOptions []string
	for _, o := range options {
		if strings.HasPrefix(o, "tries=") {
			return errors.New("cannot specify the \"tries=\" option")
		}
		activateOptions = append(activateOptions, o)
	}

	fifoPath, cleanupFifo, err := mkFifo()
	if err != nil {
		return xerrors.Errorf("cannot create FIFO for passing key to systemd-cryptsetup: %w", err)
	}
	defer cleanupFifo()

	cmd := exec.Command(SystemdCryptsetupPath, "attach", volumeName, sourceDevicePath, fifoPath, strings.Join(append(activateOptions, "tries=1"), ","))
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

func Format(devicePath, label string, key []byte, kdf *KDFOptions) error {
	if kdf.Master && len(key) != keySize {
		return fmt.Errorf("expected a key length of %d-bits (got %d)", keySize*8, len(key)*8)
	}

	args := []string{
		// batch processing, no password verification for formatting an existing LUKS container
		"-q",
		// disable locking
		"--disable-locks",
		// formatting a new volume
		"luksFormat",
		// use LUKS2
		"--type", "luks2",
		// read the key from stdin
		"--key-file", "-",
		// use AES-256 with XTS block cipher mode (XTS requires 2 keys)
		"--cipher", "aes-xts-plain64", "--key-size", strconv.Itoa(keySize * 8),
		// set LUKS2 label
		"--label", label}
	args = append(args, kdf.args()...)
	args = append(args,
		// device to format
		devicePath)
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = bytes.NewReader(key)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}

	return nil
}

type KDFOptions struct {
	Master   bool
	IterTime time.Duration
}

func (o KDFOptions) args() []string {
	// Use argon2i as the KDF.
	args := []string{"--pbkdf", "argon2i"}
	if o.Master {
		// For "master" keys, configure the KDF with minimum cost (lowest possible time and memory costs). This
		// is done for keys that have the same entropy as the derived key and therefore increased time or memory
		// cost doesn't provide a security benefit (but does slow down unlocking).
		return append(args, "--pbkdf-force-iterations", "4", "--pbkdf-memory", "32")
	}
	if o.IterTime == 0 {
		return args
	}
	return append(args, "--iter-time", strconv.FormatUint(uint64(o.IterTime/time.Millisecond), 10))
}

func AddKey(devicePath string, existingKey, key []byte, kdf *KDFOptions) error {
	if kdf.Master && len(key) != keySize {
		return fmt.Errorf("expected a key length of %d-bits (got %d)", keySize*8, len(key)*8)
	}

	fifoPath, cleanupFifo, err := mkFifo()
	if err != nil {
		return xerrors.Errorf("cannot create FIFO for passing existing key to cryptsetup: %w", err)
	}
	defer cleanupFifo()

	args := []string{
		// disable locking
		"--disable-locks",
		// add a new key
		"luksAddKey",
		// read existing key from named pipe
		"--key-file", fifoPath}
	args = append(args, kdf.args()...)
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

func ImportToken(devicePath string, token *Token) error {
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return xerrors.Errorf("cannot serialize token: %w", err)
	}
	cmd := exec.Command("cryptsetup", "--disable-locks", "token", "import", devicePath)
	cmd.Stdin = bytes.NewReader(tokenJSON)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}
	return nil
}

func RemoveToken(devicePath string, id int) error {
	cmd := exec.Command("cryptsetup", "--disable-locks", "token", "remove", "--token-id", strconv.Itoa(id), devicePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}
	return nil
}

func KillSlot(devicePath string, slot int, key []byte) error {
	cmd := exec.Command("cryptsetup", "--disable-locks", "luksKillSlot", "--key-file", "-", devicePath, strconv.Itoa(slot))
	cmd.Stdin = bytes.NewReader(key)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}
	return nil
}

func SetKeyslotPriority(devicePath string, slot int, priority string) error {
	cmd := exec.Command("cryptsetup", "--disable-locks", "config", "--priority", priority, "--key-slot", strconv.Itoa(slot), devicePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}

	return nil
}
