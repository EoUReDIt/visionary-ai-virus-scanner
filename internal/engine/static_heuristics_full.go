//go:build !safe

package engine

import (
	"fmt"
	"regexp"
	"strings"
)

var capabilityRules = []capabilityRule{
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
