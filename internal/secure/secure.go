// Package secure covers the two things that need the operating system's help:
// checking the computer password before a sensitive change, and keeping API
// keys encrypted at rest.
package secure

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
)

const (
	maxFailures = 5
	lockout     = 5 * time.Minute
)

var ErrLocked = errors.New("too many wrong passwords; try again in a few minutes")

type attempts struct {
	Failures int       `json:"failures"`
	Until    time.Time `json:"until"`
}

func attemptsFile() string { return config.Path("auth.json") }

// VerifyPassword checks the current user's computer password, with a lockout
// after repeated failures so the check cannot be brute-forced locally.
func VerifyPassword(pw string) error {
	var a attempts
	if b, err := os.ReadFile(attemptsFile()); err == nil {
		_ = json.Unmarshal(b, &a)
	}
	if time.Now().Before(a.Until) {
		return ErrLocked
	}
	err := verifyOSPassword(pw)
	if err != nil {
		a.Failures++
		if a.Failures >= maxFailures {
			a = attempts{Until: time.Now().Add(lockout)}
		}
	} else {
		a = attempts{}
	}
	b, _ := json.Marshal(a)
	_ = config.WriteAtomic(attemptsFile(), b, 0o600)
	return err
}

// PromptPassword reads a password from the terminal without echo. When stdin
// is not a terminal it reads one line, so scripts can pipe the password in.
func PromptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	var line string
	_, err := fmt.Fscanln(os.Stdin, &line)
	fmt.Fprintln(os.Stderr)
	return strings.TrimRight(line, "\r\n"), err
}

// Secrets are stored as one encrypted blob (DPAPI on Windows).
func secretsFile() string { return config.Path("secrets.bin") }

func loadSecrets() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(secretsFile())
	if err != nil {
		return m
	}
	plain, err := unprotect(b)
	if err != nil {
		return m
	}
	_ = json.Unmarshal(plain, &m)
	return m
}

func saveSecrets(m map[string]string) error {
	plain, _ := json.Marshal(m)
	enc, err := protect(plain)
	if err != nil {
		return err
	}
	return config.WriteAtomic(secretsFile(), enc, 0o600)
}

// envNames maps a secret to the environment variable that overrides it.
var envNames = map[string]string{
	"gemini":      "GEMINI_API_KEY",
	"anthropic":   "ANTHROPIC_API_KEY",
	"openai":      "OPENAI_API_KEY",
	"virustotal":  "VISIONARY_VT_KEY",
	"otx":         "OTX_API_KEY",
	"nvd":         "NVD_API_KEY",
	"huggingface": "HF_TOKEN",
}

// Secret returns a stored secret, or its environment override.
func Secret(name string) string {
	if env := envNames[name]; env != "" {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return loadSecrets()[name]
}

func SetSecret(name, value string) error {
	m := loadSecrets()
	if value == "" {
		delete(m, name)
	} else {
		m[name] = value
	}
	return saveSecrets(m)
}

func ClearSecrets() error {
	err := os.Remove(secretsFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
