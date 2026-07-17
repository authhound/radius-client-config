// Package clientconfig generates matching RADIUS client registrations for
// FreeRADIUS (a clients.conf block) and Windows NPS (a New-NpsRadiusClient
// one-liner) from one set of inputs. It is the shared core behind the
// radius-client-config CLI and the in-browser WASM build on authhound.com.
//
// Everything here is pure computation: no network, no filesystem, no
// telemetry (purity_test.go enforces the import list). Secrets are generated
// with crypto/rand and returned to the caller only inside the rendered
// output and the Result struct — never logged.
package clientconfig

import (
	"fmt"
	"net/netip"
	"strings"
)

// Charset names accepted in Request.SecretCharset.
const (
	// CharsetAlnumSymbols is the default: 62 alphanumerics plus 14 symbols
	// chosen to never need escaping in clients.conf double quotes or
	// PowerShell single quotes (no ' " \ $ ` { } or spaces).
	CharsetAlnumSymbols = "alnum-symbols"
	// CharsetAlnum is a 62-symbol fallback for NAS gear that rejects
	// punctuation in shared secrets.
	CharsetAlnum = "alnum"
)

const (
	// MinSecretLength is the shortest secret this tool will generate. RFC 6614
	// and current FreeRADIUS docs both push for long secrets; 16 is the floor,
	// not the recommendation.
	MinSecretLength = 16
	// DefaultSecretLength balances entropy (~199 bits from the default
	// charset) against NAS gear that truncates long secrets.
	DefaultSecretLength = 32
	// NPSMaxSecretLength is the longest shared secret Windows NPS accepts.
	NPSMaxSecretLength = 128
)

// Request is the single input set both renderers consume. The JSON field
// names are the WASM API and the CLI --json schema; see docs/json-schema.md.
type Request struct {
	// Name labels the clients.conf block and becomes the NPS -Name.
	Name string `json:"name"`
	// Address is an IPv4/IPv6 host address or CIDR prefix.
	Address string `json:"address"`
	// Secret, when non-empty, is used as-is (user-supplied). When empty, a
	// secret is generated with crypto/rand.
	Secret string `json:"secret,omitempty"`
	// SecretLength applies only when generating; 0 means DefaultSecretLength.
	SecretLength int `json:"secret_length,omitempty"`
	// SecretCharset applies only when generating; "" means CharsetAlnumSymbols.
	SecretCharset string `json:"secret_charset,omitempty"`
	// NASType, when set, is emitted as FreeRADIUS nas_type. It has no NPS
	// equivalent (NPS -VendorName defaults to "RADIUS Standard").
	NASType string `json:"nas_type,omitempty"`
	// RequireMessageAuthenticator toggles the post-BlastRADIUS hardening line
	// in both outputs. nil means true: hardening is the default and callers
	// must opt out explicitly.
	RequireMessageAuthenticator *bool `json:"require_message_authenticator,omitempty"`
	// CoANote appends a one-line note about the separate CoA/Disconnect port.
	CoANote bool `json:"coa_note,omitempty"`
}

// validName keeps the name usable as a bare clients.conf block label and an
// NPS -Name without quoting surprises in either syntax: [A-Za-z0-9._-]{1,64}.
// (Hand-rolled rather than regexp to keep the regexp engine out of the WASM
// binary.)
func validName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isWordChar(s[i]) && s[i] != '.' {
			return false
		}
	}
	return true
}

// validNASType matches the shape of documented FreeRADIUS nas_type values
// (cisco, livingston, other, ...) without hardcoding the list, which is
// dictionary-driven and grows over time: [A-Za-z0-9_-]{1,32}.
func validNASType(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isWordChar(s[i]) {
			return false
		}
	}
	return true
}

func isWordChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// resolved is a validated Request plus everything derived from it that the
// renderers need.
type resolved struct {
	req         Request
	addr        netip.Addr   // set when Address is a host
	prefix      netip.Prefix // set when isCIDR
	isCIDR      bool
	secret      string
	generated   bool
	entropyBits int // 0 when the secret is user-supplied
	charsetSize int // 0 when the secret is user-supplied
	requireMA   bool
	warnings    []string
}

// addressString returns the canonical form used in both outputs.
func (r *resolved) addressString() string {
	if r.isCIDR {
		return r.prefix.String()
	}
	return r.addr.String()
}

// validate checks the request and resolves the secret (generating one if
// none was supplied). It is the only place input errors are produced, so the
// CLI can map any error from here to its usage exit code.
func validate(req Request) (*resolved, error) {
	r := &resolved{req: req, requireMA: true}
	if req.RequireMessageAuthenticator != nil {
		r.requireMA = *req.RequireMessageAuthenticator
	}

	if !validName(req.Name) {
		return nil, fmt.Errorf("name %q: must be 1-64 characters from A-Z a-z 0-9 . _ - (it becomes the clients.conf block label and the NPS -Name)", req.Name)
	}

	if err := parseAddress(req.Address, r); err != nil {
		return nil, err
	}

	if req.NASType != "" && !validNASType(req.NASType) {
		return nil, fmt.Errorf("nas_type %q: must be 1-32 characters from A-Z a-z 0-9 _ -", req.NASType)
	}

	if err := resolveSecret(req, r); err != nil {
		return nil, err
	}
	return r, nil
}

func parseAddress(s string, r *resolved) error {
	if s == "" {
		return fmt.Errorf("address is required (an IPv4/IPv6 host address or CIDR prefix)")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("address %q: not a valid CIDR prefix: %v", s, err)
		}
		if p.Addr().Zone() != "" {
			return fmt.Errorf("address %q: IPv6 zone IDs cannot appear in a client registration", s)
		}
		if masked := p.Masked(); masked != p {
			return fmt.Errorf("address %q: CIDR has host bits set; did you mean %s?", s, masked)
		}
		r.isCIDR = true
		r.prefix = p
		return nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("address %q: not a valid IPv4 or IPv6 address: %v", s, err)
	}
	if a.Zone() != "" {
		return fmt.Errorf("address %q: IPv6 zone IDs cannot appear in a client registration", s)
	}
	r.addr = a.Unmap()
	return nil
}

func resolveSecret(req Request, r *resolved) error {
	if req.Secret != "" {
		r.secret = req.Secret
		if len(req.Secret) < MinSecretLength {
			r.warnings = append(r.warnings, fmt.Sprintf(
				"supplied secret is %d characters; anything under %d is weak for RADIUS — consider generating one instead", len(req.Secret), MinSecretLength))
		}
		if len(req.Secret) > NPSMaxSecretLength {
			r.warnings = append(r.warnings, fmt.Sprintf(
				"supplied secret is %d characters; NPS rejects secrets over %d — the NPS output will not work as-is", len(req.Secret), NPSMaxSecretLength))
		}
		if s := unsafeSecretChars(req.Secret); s != "" {
			r.warnings = append(r.warnings, fmt.Sprintf(
				"supplied secret contains %s — FreeRADIUS quoting gets tricky with these; verify the block with radiusd -XC before relying on it", s))
		}
		return nil
	}

	length := req.SecretLength
	if length == 0 {
		length = DefaultSecretLength
	}
	if length < MinSecretLength {
		return fmt.Errorf("secret_length %d: minimum is %d", length, MinSecretLength)
	}
	if length > NPSMaxSecretLength {
		return fmt.Errorf("secret_length %d: maximum is %d (the NPS shared-secret limit)", length, NPSMaxSecretLength)
	}
	charset := req.SecretCharset
	if charset == "" {
		charset = CharsetAlnumSymbols
	}
	chars, err := charsetChars(charset)
	if err != nil {
		return err
	}
	secret, err := generateSecret(length, chars)
	if err != nil {
		return err
	}
	r.secret = secret
	r.generated = true
	r.charsetSize = len(chars)
	r.entropyBits = EntropyBits(length, len(chars))
	if length > 64 {
		r.warnings = append(r.warnings,
			"some NAS gear silently truncates secrets longer than 64 characters — if only this device fails to authenticate, regenerate with a shorter length")
	}
	return nil
}

// unsafeSecretChars reports which characters in a user-supplied secret can
// interfere with clients.conf quoting or config-parse expansion ($ triggers
// ${...} expansion inside FreeRADIUS double-quoted strings). Empty means safe.
func unsafeSecretChars(s string) string {
	var found []string
	for _, c := range []string{`"`, `'`, `\`, "$", "`", "{", "}", " "} {
		if strings.Contains(s, c) {
			if c == " " {
				c = "spaces"
			}
			found = append(found, c)
		}
	}
	if len(found) == 0 {
		return ""
	}
	return strings.Join(found, " ")
}
