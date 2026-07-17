package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/authhound/radius-client-config/clientconfig"
)

func noPrompt() (string, error) { return "", nil }

func runCapture(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf strings.Builder
	code = run(args, &out, &errBuf, noPrompt)
	return code, out.String(), errBuf.String()
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},                                  // no subcommand
		{"bogus"},                           // unknown subcommand
		{"freeradius"},                      // missing --name/--ip
		{"freeradius", "--name", "probe01"}, // missing --ip
		{"freeradius", "--name", "probe01", "--ip", "10.0.4.999"},
		{"freeradius", "--name", "probe01", "--ip", "10.0.4.20", "--length", "8"},
		{"freeradius", "--name", "probe01", "--ip", "10.0.4.20", "--secret-stdin", "--prompt-secret"},
		{"freeradius", "--name", "probe01", "--ip", "10.0.4.20", "extra-positional"},
		{"freeradius", "--no-such-flag"},
	}
	for _, args := range cases {
		if code, _, _ := runCapture(t, args...); code != exitUsage {
			t.Errorf("run(%q) = %d, want %d", args, code, exitUsage)
		}
	}
}

func TestFreeRADIUSSubcommand(t *testing.T) {
	code, out, _ := runCapture(t, "freeradius", "--name", "probe01", "--ip", "10.0.4.20")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "client probe01 {") || strings.Contains(out, "New-NpsRadiusClient") {
		t.Errorf("unexpected freeradius output:\n%s", out)
	}
}

func TestNPSSubcommand(t *testing.T) {
	code, out, _ := runCapture(t, "nps", "--name", "probe01", "--ip", "10.0.4.20")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "New-NpsRadiusClient -Name 'probe01'") || strings.Contains(out, "client probe01 {") {
		t.Errorf("unexpected nps output:\n%s", out)
	}
}

func TestAllSubcommandPrintsBoth(t *testing.T) {
	code, out, _ := runCapture(t, "all", "--name", "probe01", "--ip", "10.0.4.20")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "client probe01 {") || !strings.Contains(out, "New-NpsRadiusClient") {
		t.Errorf("all should print both outputs:\n%s", out)
	}
}

func TestJSONOutput(t *testing.T) {
	code, out, _ := runCapture(t, "all", "--name", "probe01", "--ip", "10.0.4.20", "--json")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var res clientconfig.Result
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("--json output is not valid JSON: %v", err)
	}
	if res.SchemaVersion != clientconfig.SchemaVersion {
		t.Errorf("schema_version = %q", res.SchemaVersion)
	}
	if !res.SecretGenerated || res.Secret == "" || res.EntropyBits == 0 {
		t.Errorf("generated-secret fields wrong: %+v", res)
	}
}

func TestSecretFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("file-supplied-secret-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCapture(t, "freeradius", "--name", "probe01", "--ip", "10.0.4.20", "--secret-file", path)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, `secret = "file-supplied-secret-123"`) {
		t.Errorf("secret from file not used (trailing newline should be trimmed):\n%s", out)
	}
}

func TestSecretFileRefusesLooseModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCapture(t, "freeradius", "--name", "probe01", "--ip", "10.0.4.20", "--secret-file", path)
	if code != exitError {
		t.Fatalf("exit %d, want %d for a world-readable secret file", code, exitError)
	}
	if !strings.Contains(stderr, "chmod 600") {
		t.Errorf("stderr should tell the user how to fix the mode: %s", stderr)
	}
}

func TestPromptSecretIsUsed(t *testing.T) {
	prompt := func() (string, error) { return "prompted-secret-abcdef", nil }
	var out, errBuf strings.Builder
	code := run([]string{"freeradius", "--name", "probe01", "--ip", "10.0.4.20", "--prompt-secret"}, &out, &errBuf, prompt)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "prompted-secret-abcdef") {
		t.Error("prompted secret not used")
	}
}

func TestWarningsGoToStderrNotStdout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := runCapture(t, "freeradius", "--name", "probe01", "--ip", "10.0.4.20", "--secret-file", path)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr, "WARN") {
		t.Error("short-secret warning missing from stderr")
	}
	if strings.Contains(out, "WARN") {
		t.Error("warnings must not pollute the copy-paste stdout output")
	}
}

func TestVersionAndHelp(t *testing.T) {
	if code, out, _ := runCapture(t, "version"); code != exitOK || !strings.Contains(out, "dev") {
		t.Errorf("version: code %d out %q", code, out)
	}
	if code, out, _ := runCapture(t, "--help"); code != exitOK || !strings.Contains(out, "Usage:") {
		t.Errorf("--help: code %d", code)
	}
}
