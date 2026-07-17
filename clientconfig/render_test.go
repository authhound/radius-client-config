package clientconfig

import (
	"strings"
	"testing"
)

// fixedReq returns a fully-specified request so renderer tests are
// deterministic (no generated secret).
func fixedReq() Request {
	return Request{
		Name:    "probe01",
		Address: "10.0.4.20",
		Secret:  "fixed-secret-for-render-tests!",
		NASType: "other",
		CoANote: true,
	}
}

func TestRenderFreeRADIUS(t *testing.T) {
	res, err := Generate(fixedReq())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"client probe01 {\n",
		"\tipaddr = 10.0.4.20\n",
		"\tsecret = \"fixed-secret-for-render-tests!\"\n",
		"\tnas_type = other\n",
		"\trequire_message_authenticator = yes\n",
		"/etc/freeradius/3.0/clients.conf",
		"/etc/raddb/clients.conf",
		"freeradius -XC && systemctl reload freeradius",
		"radiusd -XC && systemctl reload radiusd",
		"3.2.5+ / 3.0.27+",
		"UDP 3799",
	} {
		if !strings.Contains(res.FreeRADIUS, want) {
			t.Errorf("FreeRADIUS output missing %q:\n%s", want, res.FreeRADIUS)
		}
	}
	if !strings.HasSuffix(strings.TrimRight(res.FreeRADIUS, "\n"), "does not configure CoA.") {
		t.Error("CoA note should be the last line when requested")
	}
}

func TestRenderNPS(t *testing.T) {
	res, err := Generate(fixedReq())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"New-NpsRadiusClient -Name 'probe01' -Address '10.0.4.20' -SharedSecret 'fixed-secret-for-render-tests!' -AuthAttributeRequired $true\n",
		"ELEVATED PowerShell",
		"Restart-Service IAS",
		"nps.msc > RADIUS Clients and Servers > RADIUS Clients",
		"128 characters",
		"nas_type is FreeRADIUS-only",
		"UDP 3799",
	} {
		if !strings.Contains(res.NPS, want) {
			t.Errorf("NPS output missing %q:\n%s", want, res.NPS)
		}
	}
}

func TestNATNoteInBothOutputsVerbatim(t *testing.T) {
	res, err := Generate(Request{Name: "probe01", Address: "10.0.4.20"})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(NATNote, "\n") {
		for surface, out := range map[string]string{"freeradius": res.FreeRADIUS, "nps": res.NPS} {
			if !strings.Contains(out, "# "+line) {
				t.Errorf("%s output missing NAT note line %q", surface, line)
			}
		}
	}
}

func TestCIDRHandling(t *testing.T) {
	req := fixedReq()
	req.Address = "192.168.0.0/24"
	res, err := Generate(req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.FreeRADIUS, "\tipaddr = 192.168.0.0/24\n") {
		t.Error("FreeRADIUS output should pass the CIDR through unchanged")
	}
	if !strings.Contains(res.NPS, "-Address '192.168.0.0/24'") {
		t.Error("NPS output should carry the CIDR")
	}
	if !strings.Contains(res.NPS, "Windows Server 2016 and later") {
		t.Error("NPS output should caveat CIDR support")
	}
}

func TestSecretQuoting(t *testing.T) {
	if got := quoteFreeRADIUS(`a"b\c`); got != `"a\"b\\c"` {
		t.Errorf("quoteFreeRADIUS = %s", got)
	}
	if got := quotePowerShell("it's"); got != "'it''s'" {
		t.Errorf("quotePowerShell = %s", got)
	}
}

func TestNoNasTypeLineWhenUnset(t *testing.T) {
	res, err := Generate(Request{Name: "probe01", Address: "10.0.4.20"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.FreeRADIUS, "nas_type") {
		t.Error("nas_type emitted without being requested")
	}
	if strings.Contains(res.NPS, "VendorName") {
		t.Error("VendorName comment emitted without nas_type being set")
	}
}

// The rendered outputs must embed the exact secret from the Result, so the
// CLI/WASM parity check can compare whole documents.
func TestSecretConsistentAcrossResult(t *testing.T) {
	res, err := Generate(Request{Name: "probe01", Address: "10.0.4.20"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.FreeRADIUS, res.Secret) || !strings.Contains(res.NPS, res.Secret) {
		t.Error("Result.Secret does not appear in both rendered outputs")
	}
}
