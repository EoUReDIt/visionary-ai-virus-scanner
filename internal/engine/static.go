package engine

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/smallstep/pkcs7"
)

// Features is what static analysis learns about a file. It is also the
// evidence handed to the AI layer: a description of the file, never the file.
type Features struct {
	Type        string   `json:"type"`
	Entropy     float64  `json:"entropy"`
	PE          *PEInfo  `json:"pe,omitempty"`
	Signers     []Signer `json:"signers,omitempty"`
	Strings     []string `json:"interesting_strings,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`
	ArchiveInfo string   `json:"archive,omitempty"`
}

type PEInfo struct {
	Machine      string      `json:"machine"`
	IsDLL        bool        `json:"is_dll"`
	IsDriver     bool        `json:"is_driver"`
	Timestamp    uint32      `json:"timestamp"`
	Sections     []PESection `json:"sections"`
	ImportCount  int         `json:"import_count"`
	ImportDLLs   []string    `json:"import_dlls"`
	Capabilities []string    `json:"capabilities,omitempty"`
	HasSignature bool        `json:"has_signature"`
}

type PESection struct {
	Name    string  `json:"name"`
	Size    uint32  `json:"size"`
	Entropy float64 `json:"entropy"`
	Exec    bool    `json:"exec"`
}

type Signer struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	Serial     string `json:"serial"`
	Thumbprint string `json:"thumbprint_sha1"`
	SHA256     string `json:"thumbprint_sha256"`
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var e float64
	n := float64(len(b))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			e -= p * math.Log2(p)
		}
	}
	return math.Round(e*100) / 100
}

func detectType(data []byte, name string) string {
	switch {
	case len(data) > 0x40 && data[0] == 'M' && data[1] == 'Z':
		return "pe"
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		return "zip"
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		return "elf"
	case bytes.HasPrefix(data, []byte("%PDF")):
		return "pdf"
	case bytes.HasPrefix(data, []byte{0xD0, 0xCF, 0x11, 0xE0}):
		return "ole"
	case bytes.HasPrefix(data, []byte{0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0}):
		return "lnk"
	}
	if isScriptExt(strings.ToLower(filepath.Ext(name))) {
		return "script"
	}
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	// UTF-16 text (PowerShell scripts are often saved that way).
	if len(sample) >= 2 && (sample[0] == 0xFF && sample[1] == 0xFE || sample[0] == 0xFE && sample[1] == 0xFF) {
		return "text"
	}
	if len(sample) > 0 && utf8.Valid(sample) && bytes.IndexByte(sample, 0) < 0 {
		if bytes.HasPrefix(sample, []byte("#!")) {
			return "script"
		}
		return "text"
	}
	return "data"
}

func isScriptExt(ext string) bool {
	switch ext {
	case ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
		".py", ".sh", ".sct", ".psd1":
		return true
	}
	return false
}

var execExts = map[string]bool{".exe": true, ".scr": true, ".com": true, ".pif": true, ".dll": true,
	".sys": true, ".cpl": true, ".msi": true, ".bat": true, ".cmd": true, ".ps1": true, ".vbs": true,
	".js": true, ".hta": true, ".lnk": true, ".jar": true}

var decoyExts = map[string]bool{".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".txt": true, ".mp3": true, ".mp4": true,
	".avi": true, ".zip": true, ".rar": true}

// nameHeuristics catches files dressed up as something else.
func nameHeuristics(name, typ string) []Finding {
	var out []Finding
	low := strings.ToLower(name)
	ext := filepath.Ext(low)
	stem := strings.TrimSuffix(low, ext)
	if inner := filepath.Ext(stem); execExts[ext] && decoyExts[inner] {
		out = append(out, Finding{"heuristic", "double-extension", 35,
			fmt.Sprintf("looks like %s but runs as %s", inner, ext)})
	}
	if strings.ContainsRune(name, '‮') {
		out = append(out, Finding{"heuristic", "rtl-override-name", 40,
			"file name uses a right-to-left override to hide its extension"})
	}
	if execExts[ext] && strings.Contains(stem, "      ") {
		out = append(out, Finding{"heuristic", "padded-name", 30, "long run of spaces hides the real extension"})
	}
	if typ == "pe" && decoyExts[ext] {
		out = append(out, Finding{"heuristic", "disguised-executable", 40,
			"Windows executable with a " + ext + " extension"})
	}
	return out
}

type capabilityRule struct {
	name  string
	score int
	all   []string   // every one of these imports...
	any   [][]string // ...and at least one from each group
	about string
}

var packerSections = map[string]string{"upx0": "UPX", "upx1": "UPX", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
	".themida": "Themida", ".aspack": "ASPack", ".enigma1": "Enigma", ".mpress1": "MPRESS", ".petite": "Petite",
	".nsp0": "NsPack"}

func analyzePE(data []byte) (*PEInfo, []Finding) {
	return analyzePEReader(bytes.NewReader(data))
}

func analyzePEReader(r io.ReaderAt) (*PEInfo, []Finding) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, []Finding{{"heuristic", "malformed-pe", 10, "has an MZ header but does not parse as a PE: " + err.Error()}}
	}
	defer f.Close()
	info := &PEInfo{Timestamp: f.TimeDateStamp, IsDLL: f.Characteristics&pe.IMAGE_FILE_DLL != 0}
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		info.Machine = "x64"
	case pe.IMAGE_FILE_MACHINE_I386:
		info.Machine = "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		info.Machine = "arm64"
	default:
		info.Machine = fmt.Sprintf("0x%x", f.Machine)
	}
	var findings []Finding
	var secDir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		info.IsDriver = oh.Subsystem == 1
		if len(oh.DataDirectory) > 4 {
			secDir = oh.DataDirectory[4]
		}
	case *pe.OptionalHeader32:
		info.IsDriver = oh.Subsystem == 1
		if len(oh.DataDirectory) > 4 {
			secDir = oh.DataDirectory[4]
		}
	}
	info.HasSignature = secDir.Size > 8

	packer := ""
	highExec := false
	const maxSectionSample = 2 << 20
	for _, s := range f.Sections {
		ps := PESection{Name: s.Name, Size: s.Size, Exec: s.Characteristics&0x20000000 != 0}
		if sr := s.Open(); sr != nil {
			// Cap per-section entropy reads to 2 MiB so huge .rsrc / overlay
			// sections in installers or games never spike scan RAM.
			if raw, err := io.ReadAll(io.LimitReader(sr, maxSectionSample)); err == nil && len(raw) > 0 {
				ps.Entropy = entropy(raw)
			}
		}
		if p := packerSections[strings.ToLower(s.Name)]; p != "" {
			packer = p
		}
		if ps.Exec && ps.Entropy > 7.2 && ps.Size > 4096 {
			highExec = true
		}
		info.Sections = append(info.Sections, ps)
	}
	imports, _ := f.ImportedSymbols()
	info.ImportCount = len(imports)
	have := map[string]bool{}
	dlls := map[string]bool{}
	for _, im := range imports {
		fn, dll, _ := strings.Cut(im, ":")
		have[strings.ToLower(fn)] = true
		if dll = strings.ToLower(dll); dll != "" && !dlls[dll] {
			dlls[dll] = true
			info.ImportDLLs = append(info.ImportDLLs, dll)
		}
	}
	for _, c := range capabilityRules {
		ok := true
		for _, fn := range c.all {
			ok = ok && have[fn]
		}
		for _, group := range c.any {
			hit := false
			for _, fn := range group {
				hit = hit || have[fn]
			}
			ok = ok && hit
		}
		if ok {
			info.Capabilities = append(info.Capabilities, c.name)
			findings = append(findings, Finding{"heuristic", "capability:" + c.name, c.score, c.about})
		}
	}
	if highExec {
		findings = append(findings, Finding{"heuristic", "encrypted-code-section", 15,
			"executable section is compressed or encrypted (entropy above 7.2)"})
	}
	if packer != "" {
		// Packers and protectors are routine in games (DRM, anti-cheat), so
		// this is context for the other layers rather than a strong signal.
		findings = append(findings, Finding{"heuristic", "packer:" + packer, 5, "packed with " + packer})
	}
	if len(imports) == 0 && !info.IsDLL && !info.IsDriver && f.Machine != 0 {
		// .NET binaries import a single symbol from mscoree.dll, so they
		// never reach zero.
		findings = append(findings, Finding{"heuristic", "no-imports", 10,
			"imports nothing: API calls are resolved at run time or the file is packed"})
	}
	return info, findings
}

// signers extracts the Authenticode certificate chain. It works on any
// platform, which is what lets the certificate blocklist run in tests and on
// offline disks; whether Windows *trusts* the chain is asked separately.
func signers(data []byte) []Signer {
	return signersReader(bytes.NewReader(data), int64(len(data)))
}

func signersReader(r io.ReaderAt, totalSize int64) []Signer {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil
	}
	defer f.Close()
	var dir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 4 {
			dir = oh.DataDirectory[4]
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 4 {
			dir = oh.DataDirectory[4]
		}
	}
	// The security directory's "address" is a file offset, not an RVA.
	off, size := int64(dir.VirtualAddress), int64(dir.Size)
	const maxCertBlob = 4 << 20
	if size <= 8 || off <= 0 || size > maxCertBlob || off+size > totalSize {
		return nil
	}
	blob := make([]byte, size)
	if _, err := r.ReadAt(blob, off); err != nil {
		return nil
	}
	certLen := int(binary.LittleEndian.Uint32(blob[:4]))
	if certLen <= 8 || int64(certLen) > size {
		return nil
	}
	p7, err := pkcs7.Parse(blob[8:certLen])
	if err != nil {
		return nil
	}
	var out []Signer
	for _, c := range p7.Certificates {
		s1 := sha1.Sum(c.Raw)
		s2 := sha256.Sum256(c.Raw)
		out = append(out, Signer{Subject: c.Subject.CommonName, Issuer: c.Issuer.CommonName,
			Serial: hex.EncodeToString(c.SerialNumber.Bytes()), Thumbprint: hex.EncodeToString(s1[:]),
			SHA256: hex.EncodeToString(s2[:])})
	}
	return out
}

func decodeText(data []byte) string {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		var sb strings.Builder
		for i := 2; i+1 < len(data); i += 2 {
			sb.WriteRune(rune(binary.LittleEndian.Uint16(data[i:])))
		}
		return sb.String()
	}
	return string(data)
}

// hasBase64Run reports an unbroken run of base64 characters of at least n.
func hasBase64Run(s string, n int) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' {
			if run++; run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// interestingStrings pulls the handful of strings an analyst would look at
// first: URLs, addresses, registry keys, command lines.
func interestingStrings(data []byte, max int) []string {
	if len(data) > 2<<20 {
		data = data[:2<<20]
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range interestR.FindAll(data, 400) {
		s := strings.TrimSpace(string(m))
		if len(s) > 160 {
			s = s[:160]
		}
		if !seen[s] && utf8.ValidString(s) {
			seen[s] = true
			out = append(out, s)
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

const (
	zipMaxEntries = 2000
	zipMaxMember  = 32 << 20
	zipBudget     = 256 << 20
	zipMaxDepth   = 2
)

// scanZip scans archive members in memory. The limits exist so a crafted
// archive cannot exhaust memory or time (decompression bombs are reported).
func (e *Engine) scanZip(data []byte, depth int, res *Result) {
	e.scanZipReader(bytes.NewReader(data), int64(len(data)), depth, res)
}

func (e *Engine) scanZipReader(r io.ReaderAt, size int64, depth int, res *Result) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return
	}
	res.Features.ArchiveInfo = fmt.Sprintf("%d entries", len(zr.File))
	var total uint64
	bomb := false
	for i, zf := range zr.File {
		if i >= zipMaxEntries || total > zipBudget {
			res.add(Finding{"archive", "archive-truncated", 0, "archive too large to scan completely"})
			break
		}
		if zf.FileInfo().IsDir() {
			continue
		}
		if zf.CompressedSize64 > 0 && zf.UncompressedSize64/zf.CompressedSize64 > 200 && zf.UncompressedSize64 > 50<<20 {
			bomb = true
			continue
		}
		if zf.UncompressedSize64 > zipMaxMember {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			continue // encrypted or damaged member
		}
		member, err := io.ReadAll(io.LimitReader(rc, zipMaxMember+1))
		rc.Close()
		if err != nil || len(member) > zipMaxMember {
			continue
		}
		total += uint64(len(member))
		sub := &Result{Path: zf.Name}
		e.analyze(member, zf.Name, sub, depth+1, false)
		for _, f := range sub.Findings {
			f.Detail = strings.TrimSpace("in " + zf.Name + ": " + f.Detail)
			res.add(f)
		}
		low := strings.ToLower(zf.Name)
		if strings.HasSuffix(low, "vbaproject.bin") {
			t := bytes.ToLower(member)
			if (bytes.Contains(t, []byte("autoopen")) || bytes.Contains(t, []byte("document_open")) ||
				bytes.Contains(t, []byte("workbook_open"))) && (bytes.Contains(t, []byte("shell")) ||
				bytes.Contains(t, []byte("createobject"))) {
				res.add(Finding{"heuristic", "macro-autorun-shell", 35, "document macro runs commands when opened"})
			}
		}
	}
	if bomb {
		res.add(Finding{"archive", "decompression-bomb", 40, "member expands more than 200x past 50 MB"})
	}
}
