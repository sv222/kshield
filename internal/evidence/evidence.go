package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/report"
)

const (
	SchemaVersion = "kshield.evidence/v1"
	ManifestFile  = "manifest.json"
	SignatureFile = "manifest.sig"
)

const (
	SignatureValid      = "valid"
	SignatureInvalid    = "invalid"
	SignatureAbsent     = "absent"
	SignatureNotChecked = "not-checked"
)

const (
	dirMode  = 0o755
	fileMode = 0o644

	maxManifestSize  = 1 << 20
	maxSignatureSize = 1 << 10
)

var (
	errNotRegular = errors.New("not a regular file")
	errTooLarge   = errors.New("file too large")
)

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	SchemaVersion string             `json:"schemaVersion"`
	Tool          report.Tool        `json:"tool"`
	CreatedAt     string             `json:"createdAt"`
	Profile       report.ProfileInfo `json:"profile"`
	Summary       report.Summary     `json:"summary"`
	Inputs        []load.Digest      `json:"inputs"`
	Files         []File             `json:"files"`
	PublicKey     string             `json:"publicKey"`
}

type Result struct {
	Missing   []string
	Changed   []string
	Extra     []string
	Signature string
}

func (r Result) OK() bool {
	return len(r.Missing) == 0 && len(r.Changed) == 0 && len(r.Extra) == 0 && r.Signature != SignatureInvalid
}

var reportFiles = []struct {
	name  string
	write func(io.Writer, *report.Report) error
}{
	{"report.html", report.WriteHTML},
	{"report.json", report.WriteJSON},
	{"report.pdf", report.WritePDF},
	{"report.sarif", report.WriteSARIF},
	{"report.txt", report.WriteText},
}

type packFile struct {
	name string
	data []byte
}

func Build(dir string, r *report.Report, key ed25519.PrivateKey) error {
	created, err := prepareDir(dir)
	if err != nil {
		return err
	}
	files, err := render(r, key)
	if err != nil {
		return err
	}
	if created {
		if err := os.Mkdir(dir, dirMode); err != nil {
			return fmt.Errorf("evidence: %w", err)
		}
	}
	var written []string
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		if err := writeNew(path, f.data, fileMode); err != nil {
			for _, p := range written {
				_ = os.Remove(p)
			}
			if created {
				_ = os.Remove(dir)
			}
			return fmt.Errorf("evidence: %w", err)
		}
		written = append(written, path)
	}
	return nil
}

func prepareDir(dir string) (bool, error) {
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("evidence: %w", err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("evidence: %s is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("evidence: %w", err)
	}
	if len(entries) > 0 {
		return false, fmt.Errorf("evidence: %s is not empty", dir)
	}
	return false, nil
}

func render(r *report.Report, key ed25519.PrivateKey) ([]packFile, error) {
	m := Manifest{
		SchemaVersion: SchemaVersion,
		Tool:          r.Tool,
		CreatedAt:     r.Scan.StartedAt,
		Profile:       r.Profile,
		Summary:       r.Summary,
		Inputs:        slices.Clone(r.Scan.InputDigests),
		Files:         []File{},
	}
	if m.Inputs == nil {
		m.Inputs = []load.Digest{}
	}
	var files []packFile
	for _, rf := range reportFiles {
		var buf bytes.Buffer
		if err := rf.write(&buf, r); err != nil {
			return nil, fmt.Errorf("evidence: %s: %w", rf.name, err)
		}
		files = append(files, packFile{rf.name, buf.Bytes()})
		m.Files = append(m.Files, fileEntry(rf.name, buf.Bytes()))
	}
	slices.SortFunc(m.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	if key != nil {
		m.PublicKey = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	}
	manifest, err := encodeManifest(m)
	if err != nil {
		return nil, err
	}
	files = append(files, packFile{ManifestFile, manifest})
	if key != nil {
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifest)) + "\n"
		files = append(files, packFile{SignatureFile, []byte(sig)})
	}
	return files, nil
}

func fileEntry(name string, data []byte) File {
	sum := sha256.Sum256(data)
	return File{Path: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

func encodeManifest(m Manifest) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("evidence: manifest: %w", err)
	}
	return buf.Bytes(), nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func Verify(dir string, pub ed25519.PublicKey) (Result, error) {
	raw, err := readRegular(filepath.Join(dir, ManifestFile), maxManifestSize)
	if err != nil {
		return Result{}, fmt.Errorf("evidence: not an evidence pack: %s: %w", ManifestFile, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Result{}, fmt.Errorf("evidence: %s: %w", ManifestFile, err)
	}
	if m.SchemaVersion != SchemaVersion {
		return Result{}, fmt.Errorf("evidence: %s: schemaVersion %q, want %q", ManifestFile, m.SchemaVersion, SchemaVersion)
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		if !validName(f.Path) || listed[f.Path] {
			return Result{}, fmt.Errorf("evidence: %s: bad file path %q", ManifestFile, f.Path)
		}
		listed[f.Path] = true
	}
	var res Result
	for _, f := range m.Files {
		state, err := checkFile(dir, f)
		if err != nil {
			return Result{}, err
		}
		switch state {
		case fileMissing:
			res.Missing = append(res.Missing, f.Path)
		case fileChanged:
			res.Changed = append(res.Changed, f.Path)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Result{}, fmt.Errorf("evidence: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		if name != ManifestFile && name != SignatureFile && !listed[name] {
			res.Extra = append(res.Extra, name)
		}
	}
	slices.Sort(res.Missing)
	slices.Sort(res.Changed)
	slices.Sort(res.Extra)
	res.Signature, err = checkSignature(dir, raw, m.PublicKey, pub)
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && name != ManifestFile && name != SignatureFile &&
		!strings.ContainsAny(name, "/\\:\x00") && fs.ValidPath(name)
}

const (
	fileOK = iota
	fileMissing
	fileChanged
)

func checkFile(dir string, f File) (int, error) {
	path := filepath.Join(dir, f.Path)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileMissing, nil
	}
	if err != nil {
		return 0, fmt.Errorf("evidence: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != f.Size {
		return fileChanged, nil
	}
	file, err := openRegular(path, info)
	if errors.Is(err, errNotRegular) {
		return fileChanged, nil
	}
	if err != nil {
		return 0, fmt.Errorf("evidence: %w", err)
	}
	defer func() { _ = file.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, f.Size+1))
	if err != nil {
		return 0, fmt.Errorf("evidence: %w", err)
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fileChanged, nil
	}
	return fileOK, nil
}

func openRegular(path string, info fs.FileInfo) (*os.File, error) {
	if !info.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = f.Close()
		return nil, errNotRegular
	}
	return f, nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, errTooLarge
	}
	f, err := openRegular(path, info)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errTooLarge
	}
	return data, nil
}

func checkSignature(dir string, manifest []byte, listedKey string, pub ed25519.PublicKey) (string, error) {
	path := filepath.Join(dir, SignatureFile)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return SignatureAbsent, nil
	} else if err != nil {
		return "", fmt.Errorf("evidence: %w", err)
	}
	if pub == nil {
		return SignatureNotChecked, nil
	}
	if len(pub) != ed25519.PublicKeySize || listedKey != base64.StdEncoding.EncodeToString(pub) {
		return SignatureInvalid, nil
	}
	sig, err := readRegular(path, maxSignatureSize)
	if errors.Is(err, errNotRegular) || errors.Is(err, errTooLarge) {
		return SignatureInvalid, nil
	}
	if err != nil {
		return "", fmt.Errorf("evidence: %w", err)
	}
	text, ok := strings.CutSuffix(string(sig), "\n")
	if !ok {
		return SignatureInvalid, nil
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, manifest, raw) {
		return SignatureInvalid, nil
	}
	return SignatureValid, nil
}
