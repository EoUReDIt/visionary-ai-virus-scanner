//go:build safe

package engine

import (
	"fmt"
	"regexp"
	"strings"
)

// Safe edition omits plaintext malware-API, UAC-bypass and Defender-tamper
// signature tables so the compiled binary does not trigger static antivirus
// heuristics on download or install. Hash definitions, gzipped YARA rules,
// PE entropy/packer checks, certificate trust, Defender second opinion,
// VirusTotal reputation and AI triage remain active.
var capabilityRules []capabilityRule

var (
	interestR = regexp.MustCompile(`(?i)(https?://[^\s"'<>]{4,150}|\b\d{1,3}(\.\d{1,3}){3}(:\d{2,5})?\b|[a-z]:\\[^\s"'<>|]{6,120}\.(exe|dll|ps1|bat|vbs|sys))`)
)

func analyzeScript(data []byte) []Finding {
	if len(data) > 4<<20 {
		data = data[:4<<20]
	}
	text := strings.ToLower(decodeText(data))
	var out []Finding
	if hasBase64Run(text, 1500) {
		out = append(out, Finding{"heuristic", "script:embedded-blob", 15, "carries a long base64 blob"})
	}
	if n := strings.Count(text, "[char]") + strings.Count(text, "chr(") + strings.Count(text, "chrw("); n > 40 {
		out = append(out, Finding{"heuristic", "script:char-code-obfuscation", 15,
			fmt.Sprintf("builds strings from %d character codes", n)})
	}
	return out
}
