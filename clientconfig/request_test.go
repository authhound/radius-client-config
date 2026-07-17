package clientconfig

import (
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestValidateRejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		req     Request
		wantErr string // substring of the expected error
	}{
		{"empty name", Request{Address: "10.0.4.20"}, "name"},
		{"name with space", Request{Name: "probe 01", Address: "10.0.4.20"}, "name"},
		{"name with quote", Request{Name: "probe'01", Address: "10.0.4.20"}, "name"},
		{"name too long", Request{Name: strings.Repeat("a", 65), Address: "10.0.4.20"}, "name"},
		{"missing address", Request{Name: "probe01"}, "address is required"},
		{"bad address", Request{Name: "probe01", Address: "10.0.4.999"}, "not a valid"},
		{"hostname rejected", Request{Name: "probe01", Address: "nas.example.com"}, "not a valid"},
		{"cidr host bits", Request{Name: "probe01", Address: "10.0.4.20/24"}, "did you mean 10.0.4.0/24"},
		{"v6 zone", Request{Name: "probe01", Address: "fe80::1%eth0"}, "zone"},
		{"v6 zone cidr", Request{Name: "probe01", Address: "fe80::1%eth0/64"}, "zone"},
		{"length below minimum", Request{Name: "probe01", Address: "10.0.4.20", SecretLength: 8}, "minimum is 16"},
		{"length above NPS limit", Request{Name: "probe01", Address: "10.0.4.20", SecretLength: 129}, "maximum is 128"},
		{"unknown charset", Request{Name: "probe01", Address: "10.0.4.20", SecretCharset: "hex"}, "secret_charset"},
		{"bad nas_type", Request{Name: "probe01", Address: "10.0.4.20", NASType: "cis co"}, "nas_type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Generate(tc.req)
			if err == nil {
				t.Fatalf("Generate(%+v) succeeded, want error containing %q", tc.req, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateAcceptsGoodAddresses(t *testing.T) {
	for _, addr := range []string{
		"10.0.4.20", "192.168.0.0/24", "2001:db8::10", "2001:db8::/64", "0.0.0.0/0",
	} {
		if _, err := Generate(Request{Name: "probe01", Address: addr}); err != nil {
			t.Errorf("address %q rejected: %v", addr, err)
		}
	}
}

func TestIPv4MappedV6IsUnmapped(t *testing.T) {
	res, err := Generate(Request{Name: "probe01", Address: "::ffff:10.0.4.20"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.FreeRADIUS, "ipaddr = 10.0.4.20\n") {
		t.Errorf("4-in-6 address not unmapped:\n%s", res.FreeRADIUS)
	}
}

func TestUserSuppliedSecretWarnings(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		want   string // substring of a warning, "" for no warnings
	}{
		{"good secret", "adequate-length-secret-here!", ""},
		{"short secret", "hunter2hunter2", "under 16 is weak"},
		{"over NPS limit", strings.Repeat("x", 129), "NPS rejects"},
		{"dollar sign", "pass$word-of-adequate-length", "quoting"},
		{"embedded quote", `pass"word-of-adequate-length`, "quoting"},
		{"embedded space", "pass word of adequate length", "quoting"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Generate(Request{Name: "probe01", Address: "10.0.4.20", Secret: tc.secret})
			if err != nil {
				t.Fatal(err)
			}
			if res.SecretGenerated {
				t.Error("SecretGenerated = true for a user-supplied secret")
			}
			if res.EntropyBits != 0 {
				t.Errorf("EntropyBits = %d for a user-supplied secret, want 0", res.EntropyBits)
			}
			if tc.want == "" {
				if len(res.Warnings) != 0 {
					t.Errorf("unexpected warnings: %v", res.Warnings)
				}
				return
			}
			if !strings.Contains(strings.Join(res.Warnings, "\n"), tc.want) {
				t.Errorf("warnings %v do not contain %q", res.Warnings, tc.want)
			}
		})
	}
}

func TestMessageAuthenticatorDefaultsOn(t *testing.T) {
	res, err := Generate(Request{Name: "probe01", Address: "10.0.4.20"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.FreeRADIUS, "require_message_authenticator = yes") {
		t.Error("hardening not on by default in FreeRADIUS output")
	}
	if !strings.Contains(res.NPS, "-AuthAttributeRequired $true") {
		t.Error("hardening not on by default in NPS output")
	}

	res, err = Generate(Request{Name: "probe01", Address: "10.0.4.20", RequireMessageAuthenticator: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.FreeRADIUS, "require_message_authenticator") {
		t.Error("opt-out still emits require_message_authenticator")
	}
	if !strings.Contains(res.NPS, "-AuthAttributeRequired $false") {
		t.Error("opt-out should still state the NPS default explicitly")
	}
}
