// Command radius-client-config generates a FreeRADIUS clients.conf block
// and the matching Windows NPS PowerShell registration from one input set.
// All logic lives in the clientconfig package, which is also what the
// browser WASM build runs — the CLI is a thin argv-and-secrets shell.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/authhound/radius-client-config/clientconfig"
	"golang.org/x/term"
)

const (
	exitOK    = 0
	exitError = 1 // runtime failure (unreadable secret file, no randomness)
	exitUsage = 2 // bad flags or invalid input values
)

// version is stamped by goreleaser; "dev" for go-install and source builds.
var version = "dev"

const usage = `radius-client-config — generate RADIUS client registrations, locally.

Usage:
  radius-client-config <freeradius|nps|all> --name NAME --ip ADDR [options]
  radius-client-config version

Subcommands:
  freeradius   print a FreeRADIUS 3.x clients.conf block
  nps          print the Windows NPS New-NpsRadiusClient PowerShell
  all          print both

Options:
  --name NAME     client name (clients.conf block label / NPS -Name)
  --ip ADDR       IPv4/IPv6 address, or CIDR (FreeRADIUS; NPS caveat emitted)
  --secret-file PATH               use the secret in PATH (must be chmod 600)
  --secret-stdin                   read the secret from standard input
  --prompt-secret                  ask for the secret interactively (no echo)
  --length N      generated-secret length (default 32, min 16, max 128)
  --charset NAME  alnum-symbols (default) or alnum
  --nas-type T    FreeRADIUS nas_type value (omitted when unset)
  --require-message-authenticator  BlastRADIUS hardening (default true)
  --coa-note      append a note about the separate CoA/Disconnect port
  --json          print the versioned JSON document instead of text

The secret is never accepted as a command-line argument: argv leaks into
shell history and ps output. With no secret source given, one is generated
with crypto/rand. Exit codes: 0 ok, 1 runtime failure, 2 usage error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, promptSecretTerminal))
}

// run is main minus the process boundary, so tests can drive it. promptSecret
// supplies the --prompt-secret implementation (a no-echo terminal read in
// production).
func run(args []string, stdout, stderr io.Writer, promptSecret func() (string, error)) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	sub := args[0]
	switch sub {
	case "freeradius", "nps", "all":
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n\n%s", sub, usage)
		return exitUsage
	}

	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "client name")
	ip := fs.String("ip", "", "IPv4/IPv6 address or CIDR")
	secretFile := fs.String("secret-file", "", "path to a file holding the secret")
	secretStdin := fs.Bool("secret-stdin", false, "read the secret from stdin")
	promptFlag := fs.Bool("prompt-secret", false, "prompt for the secret without echo")
	length := fs.Int("length", clientconfig.DefaultSecretLength, "generated-secret length")
	charset := fs.String("charset", clientconfig.CharsetAlnumSymbols, "generation charset")
	nasType := fs.String("nas-type", "", "FreeRADIUS nas_type")
	requireMA := fs.Bool("require-message-authenticator", true, "require Message-Authenticator (BlastRADIUS hardening)")
	coaNote := fs.Bool("coa-note", false, "append the CoA/Disconnect port note")
	asJSON := fs.Bool("json", false, "print the JSON document")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q (flags go after the subcommand)\n", fs.Arg(0))
		return exitUsage
	}

	secret, code := resolveSecretFlags(*secretFile, *secretStdin, *promptFlag, stderr, promptSecret)
	if code != exitOK {
		return code
	}

	req := clientconfig.Request{
		Name:                        *name,
		Address:                     *ip,
		Secret:                      secret,
		SecretLength:                *length,
		SecretCharset:               *charset,
		NASType:                     *nasType,
		RequireMessageAuthenticator: requireMA,
		CoANote:                     *coaNote,
	}
	res, err := clientconfig.Generate(req)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
		return exitOK
	}

	for _, w := range res.Warnings {
		fmt.Fprintf(stderr, "WARN  %s\n", w)
	}
	switch sub {
	case "freeradius":
		fmt.Fprint(stdout, res.FreeRADIUS)
	case "nps":
		fmt.Fprint(stdout, res.NPS)
	case "all":
		fmt.Fprint(stdout, res.FreeRADIUS)
		fmt.Fprintln(stdout)
		fmt.Fprint(stdout, res.NPS)
	}
	return exitOK
}

// resolveSecretFlags returns the user-supplied secret ("" means generate).
// Mirrors authhound-probe's credential handling: sources are mutually
// exclusive, files must not be group/world-readable, and exactly one
// trailing newline is trimmed so `echo secret > f` works as expected.
func resolveSecretFlags(file string, fromStdin, prompt bool, stderr io.Writer, promptSecret func() (string, error)) (string, int) {
	n := 0
	for _, set := range []bool{file != "", fromStdin, prompt} {
		if set {
			n++
		}
	}
	if n > 1 {
		fmt.Fprintln(stderr, "choose only one of --secret-file, --secret-stdin, or --prompt-secret")
		return "", exitUsage
	}
	switch {
	case file != "":
		s, err := readSecretFile(file)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return "", exitError
		}
		return s, exitOK
	case fromStdin:
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(stderr, "error: reading secret from stdin: %v\n", err)
			return "", exitError
		}
		return trimOneNewline(string(b)), exitOK
	case prompt:
		s, err := promptSecret()
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return "", exitError
		}
		return s, exitOK
	}
	return "", exitOK
}

func readSecretFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("refusing to read %s: it is readable by other users on this host (mode %#o); run: chmod 600 %s",
			path, info.Mode().Perm(), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return trimOneNewline(string(b)), nil
}

// trimOneNewline removes exactly one trailing line ending (\n or \r\n) — no
// more, so a secret that legitimately ends in whitespace survives a here-doc.
func trimOneNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
		s = strings.TrimSuffix(s, "\r")
	}
	return s
}

func promptSecretTerminal() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("--prompt-secret needs a terminal; use --secret-stdin or --secret-file when piping")
	}
	fmt.Fprint(os.Stderr, "Enter shared secret: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading secret: %w", err)
	}
	return string(b), nil
}
