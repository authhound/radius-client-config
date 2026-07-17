package clientconfig

import (
	"strings"
	"testing"
)

func TestGeneratedSecretUsesOnlyCharsetCharacters(t *testing.T) {
	for _, tc := range []struct {
		charset string
		allowed string
	}{
		{CharsetAlnumSymbols, alnumChars + symbolChars},
		{CharsetAlnum, alnumChars},
	} {
		res, err := Generate(Request{Name: "probe01", Address: "10.0.4.20", SecretLength: 100, SecretCharset: tc.charset})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Secret) != 100 {
			t.Fatalf("charset %s: secret length %d, want 100", tc.charset, len(res.Secret))
		}
		for _, c := range res.Secret {
			if !strings.ContainsRune(tc.allowed, c) {
				t.Fatalf("charset %s: secret contains %q, outside its alphabet", tc.charset, c)
			}
		}
	}
}

func TestGeneratedSecretsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		res, err := Generate(Request{Name: "probe01", Address: "10.0.4.20"})
		if err != nil {
			t.Fatal(err)
		}
		if seen[res.Secret] {
			t.Fatal("crypto/rand produced a repeated 32-char secret — randomness source is broken")
		}
		seen[res.Secret] = true
	}
}

// The default charset must never require escaping in either output syntax.
func TestDefaultCharsetHasNoQuotingHazards(t *testing.T) {
	for _, c := range []string{`"`, `'`, `\`, "$", "`", "{", "}", " "} {
		if strings.Contains(alnumChars+symbolChars, c) {
			t.Errorf("default charset contains %q, which needs escaping in clients.conf or PowerShell", c)
		}
	}
}

func TestEntropyBits(t *testing.T) {
	cases := []struct {
		length, setSize, want int
	}{
		{32, 76, 199}, // default: 32 * log2(76) = 199.9…
		{32, 62, 190}, // alnum:   32 * log2(62) = 190.5…
		{16, 76, 99},
		{0, 76, 0},
		{32, 1, 0},
	}
	for _, tc := range cases {
		if got := EntropyBits(tc.length, tc.setSize); got != tc.want {
			t.Errorf("EntropyBits(%d, %d) = %d, want %d", tc.length, tc.setSize, got, tc.want)
		}
	}
}

func TestDefaultGenerationReportsEntropy(t *testing.T) {
	res, err := Generate(Request{Name: "probe01", Address: "10.0.4.20"})
	if err != nil {
		t.Fatal(err)
	}
	if res.EntropyBits != 199 {
		t.Errorf("default EntropyBits = %d, want 199", res.EntropyBits)
	}
	want := "Secret: 32 chars from a 76-symbol set ≈ 199 bits of entropy."
	for surface, out := range map[string]string{"freeradius": res.FreeRADIUS, "nps": res.NPS} {
		if !strings.Contains(out, want) {
			t.Errorf("%s output missing entropy note %q", surface, want)
		}
	}
}

func TestLongSecretTruncationWarning(t *testing.T) {
	res, err := Generate(Request{Name: "probe01", Address: "10.0.4.20", SecretLength: 65})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "truncates") {
		t.Errorf("length 65 should warn about NAS truncation, got %v", res.Warnings)
	}
}
