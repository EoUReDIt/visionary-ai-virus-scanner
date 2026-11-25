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
	"regexp"
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

var capabilityRules = []struct {
	name  string
	score int
	all   []string   // every one of these imports...
	any   [][]string // ...and at least one from each group
	about string
}{
	{"process-injection", 30, []string{"virtualallocex", "writeprocessmemory"},
		[][]string{{"createremotethread", "ntcreatethreadex", "queueuserapc", "rtlcreateuserthread"}},
		"allocates and writes memory in another process, then starts a thread there"},
	{"process-hollowing", 30, []string{"setthreadcontext", "resumethread"},
		[][]string{{"ntunmapviewofsection", "zwunmapviewofsection"}},
		"unmaps and replaces another process's image"},
	{"keylogging", 15, []string{"getasynckeystate"},
		[][]string{{"setwindowshookexa", "setwindowshookexw"}, {"getforegroundwindow"}},
		"global keyboard hook plus key-state polling"},
	{"download-and-run", 20, nil,
		[][]string{{"urldownloadtofilea", "urldownloadtofilew", "internetreadfile", "winhttpreaddata"},
			{"shellexecutea", "shellexecutew", "winexec", "createprocessa", "createprocessw"}},
		"downloads data and launches programs"},
	{"file-encryption-sweep", 15, []string{"cryptencrypt"},
		[][]string{{"findfirstfilew", "findfirstfilea"}, {"movefileexw", "movefileexa", "deletefilew", "deletefilea"}},
		"walks the disk, encrypts and replaces files"},
	{"credential-access", 20, nil,
		[][]string{{"lsaretrieveprivatedata", "credenumeratea", "credenumeratew", "samiconnect"},
			{"cryptunprotectdata"}},
		"reads stored Windows credentials"},
}

var packerSections = map[string]string{"upx0": "UPX", "upx1": "UPX", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
	".themida": "Themida", ".aspack": "ASPack", ".enigma1": "Enigma", ".mpress1": "MPRESS", ".petite": "Petite",
	".nsp0": "NsPack"}

func analyzePE(data []byte) (*PEInfo, []Finding) {
	f, err := pe.NewFile(bytes.NewReader(data))
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
	for _, s := range f.Sections {
		ps := PESection{Name: s.Name, Size: s.Size, Exec: s.Characteristics&0x20000000 != 0}
		if raw, err := s.Data(); err == nil {
			ps.Entropy = entropy(raw)
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
	f, err := pe.NewFile(bytes.NewReader(data))
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
	off, size := int(dir.VirtualAddress), int(dir.Size)
	if size <= 8 || off <= 0 || off+size > len(data) {
		return nil
	}
	certLen := int(binary.LittleEndian.Uint32(data[off:]))
	if certLen <= 8 || certLen > size {
		return nil
	}
	p7, err := pkcs7.Parse(data[off+8 : off+certLen])
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

type scriptRule struct {
	name  string
	score int
	all   []string
	any   []string
	about string
}

var scriptRules = []scriptRule{
	{"encoded-powershell", 20, []string{"frombase64string"}, []string{"-enc", "encodedcommand", "iex", "invoke-expression"},
		"decodes and runs a base64 payload"},
	{"download-and-execute", 30, nil, nil, ""}, // handled in code: needs one of each group
	{"hidden-window", 10, nil, []string{"-windowstyle hidden", "-w hidden", "-win hidden", "createobject(\"wscript.shell\").run"},
		"runs without a visible window"},
	{"defender-exclusion", 30, []string{"add-mppreference"}, []string{"-exclusionpath", "-exclusionprocess", "-exclusionextension"},
		"adds a Microsoft Defender exclusion"},
	{"persistence-run-key", 15, nil, []string{`currentversion\run`, "schtasks /create", "new-scheduledtask"},
		"registers itself to start automatically"},
	{"uac-bypass", 30, nil, []string{"fodhelper", "eventvwr.exe", `ms-settings\shell\open\command`, "sdclt.exe"},
		"references a known UAC bypass"},
}

var (
	interestR = regexp.MustCompile(`(?i)(https?://[^\s"'<>]{4,150}|\b\d{1,3}(\.\d{1,3}){3}(:\d{2,5})?\b|HKEY_[A-Z_\\a-z0-9 ]{6,100}|[a-z]:\\[^\s"'<>|]{6,120}\.(exe|dll|ps1|bat|vbs|sys)|(powershell|cmd\.exe|rundll32|regsvr32|mshta|certutil|bitsadmin|schtasks|wscript)[^\r\n"']{0,100})`)
)

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

func analyzeScript(data []byte) []Finding {
	if len(data) > 4<<20 {
		data = data[:4<<20]
	}
	text := strings.ToLower(decodeText(data))
	has := func(list []string) bool {
		for _, s := range list {
			if strings.Contains(text, s) {
				return true
			}
		}
		return false
	}
	var out []Finding
	for _, r := range scriptRules {
		if r.about == "" {
			continue
		}
		ok := true
		for _, s := range r.all {
			ok = ok && strings.Contains(text, s)
		}
		if ok && (len(r.any) == 0 || has(r.any)) {
			out = append(out, Finding{"heuristic", "script:" + r.name, r.score, r.about})
		}
	}
	fetch := []string{"downloadstring", "downloadfile", "invoke-webrequest", "iwr ", "bitsadmin /transfer",
		"-urlcache", "urldownloadtofile", "msxml2.xmlhttp", "curl ", "wget ", "start-bitstransfer"}
	run := []string{"iex", "invoke-expression", "start-process", "wscript.shell", "shellexecute", "| sh", "|sh",
		"| bash", "cmd /c", "os.system(", "subprocess."}
	if has(fetch) && has(run) && strings.Contains(text, "http") {
		out = append(out, Finding{"heuristic", "script:download-and-execute", 30, "fetches a remote payload and runs it"})
	}
	if hasBase64Run(text, 1500) {
		out = append(out, Finding{"heuristic", "script:embedded-blob", 15, "carries a long base64 blob"})
	}
	if n := strings.Count(text, "[char]") + strings.Count(text, "chr(") + strings.Count(text, "chrw("); n > 40 {
		out = append(out, Finding{"heuristic", "script:char-code-obfuscation", 15,
			fmt.Sprintf("builds strings from %d character codes", n)})
	}
	return out
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
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
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
